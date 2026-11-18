-- Protocol Reverse schema (kept general Agent/MCP/Skill/tool/LLM + protocol tables).
-- Idempotent: CREATE IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS.

-- Protocol Agent PostgreSQL schema (单一数据源)
-- 幂等：可重复执行（IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS）。

-- =====================================================================
-- 0. 通用：updated_at 触发器
-- =====================================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- =====================================================================
-- C. LLM profiles
-- =====================================================================
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    format           TEXT NOT NULL CHECK (format IN ('openai','anthropic','openai-responses')),
    base_url         TEXT,
    proxy            TEXT,
    model            TEXT NOT NULL,
    api_key          TEXT,
    api_key_hint     TEXT,
    rate_per_second  DOUBLE PRECISION NOT NULL DEFAULT 0,
    rate_per_minute  DOUBLE PRECISION NOT NULL DEFAULT 0,
    context_window_k INTEGER NOT NULL DEFAULT 0,
    -- 思考参数拆成两个独立字段：thinking_type=思考开关(''/disabled/enabled)，
    -- reasoning_effort=思考强度(''/low/medium/high/xhigh/max)，互不牵连。
    reasoning_effort TEXT NOT NULL DEFAULT '',
    thinking_type    TEXT NOT NULL DEFAULT '',
    is_default       BOOLEAN NOT NULL DEFAULT false,
    -- 轮询(故障转移)参数，见 docs/LLM轮询设计.md：
    --   priority     顺位，越大越先被选中；激活配置(is_default)永远排链首，与本值无关。
    --   pool_exclude true=不作为故障转移目标(仍可被 agent/任务显式绑定使用)。
    priority         INTEGER NOT NULL DEFAULT 0,
    pool_exclude     BOOLEAN NOT NULL DEFAULT false,
    -- streaming=true(默认)走流式 SSE；false 走真·非流式(stream:false，一次性 JSON)。
    streaming        BOOLEAN NOT NULL DEFAULT true,
    -- 单次回复的输出上限(token)。0=不发送该字段，由服务端默认值决定——保持既有行为。
    -- 与 context_window_k(模型总容量，仅本地用于压缩阈值)是两回事：本值会随请求发出。
    max_tokens       INTEGER NOT NULL DEFAULT 0,
    -- 输出上限用哪个请求字段名，仅对 format='openai' 生效：
    --   ''                      = max_tokens(默认，兼容绝大多数网关)
    --   'max_completion_tokens' = 新字段；OpenAI 推理模型(o 系列/GPT-5)只认它，
    --                             发 max_tokens 会被 unsupported_parameter 拒绝。
    -- anthropic(max_tokens 必填)与 openai-responses(max_output_tokens)自带字段名，不受此值影响。
    max_tokens_field TEXT NOT NULL DEFAULT '',
    -- 自定义会话头：非空时每次请求带一个该名字的 HTTP 头，头值=当前运行的 session id
    -- (chat 会话/worker 意图)。用于某些按 session-id 头做提示缓存/粘性路由的网关。''=不发送。
    session_header_key TEXT NOT NULL DEFAULT '',
    -- 重试覆盖：次数 0=用全局默认/-1=关闭/>0=该值；间隔 0=用默认指数退避/>0=固定毫秒。
    -- 三组分别对应建连重试、空响应重试、同 provider 安全窗口重试，详见下方 ALTER 处注释。
    retry_connect_attempts    INTEGER NOT NULL DEFAULT 0,
    retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0,
    retry_empty_attempts      INTEGER NOT NULL DEFAULT 0,
    retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0,
    retry_stream_attempts     INTEGER NOT NULL DEFAULT 0,
    retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_one_default ON llm_profiles(is_default) WHERE is_default;

DROP TRIGGER IF EXISTS trg_llm_upd ON llm_profiles;

CREATE TRIGGER trg_llm_upd BEFORE UPDATE ON llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 轮询顺位/排除标记；补旧库。默认 0 / false = 全部配置都参与轮询。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS priority     INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS pool_exclude BOOLEAN NOT NULL DEFAULT false;

-- 流式开关；补旧库。默认 true = 保持既有的流式行为，旧配置无感升级。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS streaming    BOOLEAN NOT NULL DEFAULT true;

-- 放开 format 约束以容纳 openai-responses(OpenAI Responses API)；补旧库。
-- 每次启动执行,幂等:先删旧 CHECK 再建含三值的新 CHECK。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;

ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_format_check
    CHECK (format IN ('openai','anthropic','openai-responses'));

-- 输出上限及其字段名；补旧库。默认 0 / '' = 不发送上限、沿用 max_tokens 字段名，
-- 旧配置行为完全不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens       INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens_field TEXT    NOT NULL DEFAULT '';

-- 同 format：先删再建，保证每次启动幂等。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_field_check;

ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_field_check
    CHECK (max_tokens_field IN ('','max_completion_tokens'));

ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_check;

ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_check
    CHECK (max_tokens >= 0);

-- 自定义会话头名；补旧库。默认 '' = 不发送，旧配置行为不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS session_header_key TEXT NOT NULL DEFAULT '';

-- 单配置的重试覆盖（见 docs/LLM重试设计.md）。三组各自一对「次数 + 固定间隔」，
-- 语义统一：次数 0=沿用全局默认、-1=关闭该层重试、>0=用该值；间隔 0=沿用该层的
-- 默认指数退避、>0=改用这个固定毫秒数。全部默认 0，所以旧库/旧配置行为不变。
--   connect = 建连重试（SDK doStream：连接重置/超时/429/5xx，流开始前）
--   empty   = 空响应重试（SDK：完成但没有任何 content block，仅 openai 格式）
--   stream  = 同 provider 安全窗口重试（本项目 task_llm：未交付输出前的断流重放）
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_attempts    INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_attempts      INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_attempts     INTEGER NOT NULL DEFAULT 0;

ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0;

-- 同 format：先删再建，保证每次启动幂等。次数下限 -1(关闭)，间隔不能为负。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_retry_check;

ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_retry_check CHECK (
    retry_connect_attempts >= -1 AND retry_empty_attempts >= -1 AND retry_stream_attempts >= -1
    AND retry_connect_interval_ms >= 0 AND retry_empty_interval_ms >= 0 AND retry_stream_interval_ms >= 0);

-- 思考开关字段 thinking_type，从旧的单一 reasoning_effort 语义一次性拆分而来。
-- schema.sql 每次启动都执行，故迁移必须只跑一次：仅当该列尚不存在时才回填，
-- 否则每次启动都会把用户后来手动设的组合覆盖回去。旧 reasoning_effort 语义：
--   'off'                    → 显式关闭  → thinking_type='disabled'，强度清空
--   'low/medium/high/max'    → 开启+强度 → thinking_type='enabled'，强度保留
--   ''                       → 不发送    → 两者皆空(默认)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'llm_profiles' AND column_name = 'thinking_type'
    ) THEN
        ALTER TABLE llm_profiles ADD COLUMN thinking_type TEXT NOT NULL DEFAULT '';
        UPDATE llm_profiles SET thinking_type = 'enabled'
            WHERE reasoning_effort IN ('low','medium','high','max');
        UPDATE llm_profiles SET thinking_type = 'disabled', reasoning_effort = ''
            WHERE reasoning_effort = 'off';
    END IF;
END $$;

-- LLM 轮询熔断状态：某个配置连续失败(余额不足/key 失效/限流)后进入冷却，冷却期内
-- 轮询直接跳过它。内存态为准，这里落库只为重启后不丢冷却窗口——加载时只取尚未
-- 到期的行(open_until > now)，已到期的自然回到"正常"，等下一次调用半开试探。
CREATE TABLE IF NOT EXISTS llm_profile_health (
    profile_id  BIGINT PRIMARY KEY REFERENCES llm_profiles(id) ON DELETE CASCADE,
    fails       INTEGER NOT NULL DEFAULT 0,  -- 当前连续失败次数(成功即清零)
    trips       INTEGER NOT NULL DEFAULT 0,  -- 累计熔断次数,用于冷却时间指数退避
    open_until  TIMESTAMPTZ,                 -- 冷却截止;NULL/过期 = 未熔断
    last_error  TEXT NOT NULL DEFAULT '',
    last_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
-- D2. 用户 / 角色 / 审计
-- =====================================================================
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL CHECK (username ~ '^[A-Za-z0-9_.-]{1,64}$'),
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator'
                  CHECK (role IN ('admin','operator','viewer')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username_ci ON users (lower(username));

DROP TRIGGER IF EXISTS trg_users_upd ON users;
CREATE TRIGGER trg_users_upd BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id    BIGINT,
    username   TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    status     INTEGER NOT NULL DEFAULT 0,
    ip         TEXT NOT NULL DEFAULT '',
    detail     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username, ts DESC);

-- =====================================================================
-- E. Agents / 提示词模板 / 变量目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS agents (
    id                BIGSERIAL PRIMARY KEY,
    key               TEXT NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    name              TEXT NOT NULL,
    description       TEXT,
    role              TEXT NOT NULL,
    builtin           BOOLEAN NOT NULL DEFAULT true,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    llm_profile_id    BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    current_prompt_id BIGINT,
    max_turns         INTEGER NOT NULL DEFAULT 0,
    run_seconds       INTEGER NOT NULL DEFAULT 1200,
    web_search        BOOLEAN NOT NULL DEFAULT false,
    interactive_shell BOOLEAN NOT NULL DEFAULT false,
    wrapup_prompt     TEXT NOT NULL DEFAULT '',
    wrapup_max_turns  INTEGER NOT NULL DEFAULT 0,
    task_timeout_wrapup_prompt    TEXT NOT NULL DEFAULT '',
    task_timeout_wrapup_max_turns INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agents_role_ck CHECK (role IN ('main','assistant','subagent'))
);

-- Only protocol-level roles remain: an orchestrator, chat assistants, and the
-- six phase sub-agents. Recreate the check on existing installs.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='agents'::regclass AND conname='agents_role_ck'
          AND pg_get_constraintdef(oid) LIKE '%goals%'
    ) THEN
        ALTER TABLE agents DROP CONSTRAINT agents_role_ck;
        ALTER TABLE agents ADD CONSTRAINT agents_role_ck
            CHECK (role IN ('main','assistant','subagent'));
    END IF;
END $$;

-- Trigger-based post-processing belonged to the removed pentest planner.
ALTER TABLE agents DROP COLUMN IF EXISTS trigger_run_mode;
ALTER TABLE agents DROP COLUMN IF EXISTS trigger_merge_mode;
ALTER TABLE agents DROP COLUMN IF EXISTS trigger_max_parallel;

-- per-agent LLM 绑定(agent 级默认模型):列自初版即在上方 CREATE 中,此 ALTER 仅为极旧库兜底(幂等)。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;

-- run_seconds 单次 run 墙钟默认 600→1200:只改列默认(影响将来新插入的行),不动旧库存量行。
ALTER TABLE agents ALTER COLUMN run_seconds SET DEFAULT 1200;

CREATE INDEX IF NOT EXISTS idx_agents_llm_profile ON agents(llm_profile_id) WHERE llm_profile_id IS NOT NULL;

DROP TRIGGER IF EXISTS trg_agents_upd ON agents;

CREATE TRIGGER trg_agents_upd BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS agent_prompts (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version       INT NOT NULL,
    template_text TEXT NOT NULL,
    note          TEXT,
    updated_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, version)
);

-- 循环外键：agents.current_prompt_id → agent_prompts.id（需在两表创建后加）
DO $$ BEGIN
    ALTER TABLE agents ADD CONSTRAINT fk_agents_curprompt
        FOREIGN KEY (current_prompt_id) REFERENCES agent_prompts(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_prompt_vars (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    var_name    TEXT NOT NULL,
    description TEXT,
    example     TEXT,
    source      TEXT NOT NULL CHECK (source IN ('exploration','runtime','distilled')),
    UNIQUE (agent_id, var_name)
);

-- =====================================================================
-- F. MCP 服务
-- =====================================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    transport   TEXT NOT NULL CHECK (transport IN ('stdio','http','sse')),
    command     TEXT,
    args        JSONB NOT NULL DEFAULT '[]',
    env         JSONB NOT NULL DEFAULT '{}',
    url         TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    insecure    BOOLEAN NOT NULL DEFAULT false,  -- http: 跳过 TLS 证书校验(自签证书场景, issue #108)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Allow legacy MCP SSE servers on databases created before SSE support.
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_transport_check;

ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_transport_check
    CHECK (transport IN ('stdio','http','sse'));

-- 旧库补列(schema.sql 每次启动都会 Exec)。
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS insecure BOOLEAN NOT NULL DEFAULT false;

DROP TRIGGER IF EXISTS trg_mcp_upd ON mcp_servers;

CREATE TRIGGER trg_mcp_upd BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS mcp_tools_cache (
    id            BIGSERIAL PRIMARY KEY,
    server_id     BIGINT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    tool_name     TEXT NOT NULL,
    description   TEXT,
    schema        JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, tool_name)
);

-- =====================================================================
-- G. 可见性：agent × mcp / skill
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_visibility (
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_kind TEXT   NOT NULL CHECK (resource_kind IN ('mcp')),
    resource_id   BIGINT NOT NULL,
    mcp_tool_name TEXT   NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, resource_kind, resource_id, mcp_tool_name)
);

CREATE INDEX IF NOT EXISTS idx_vis_resource ON agent_visibility(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS agent_skill_visibility (
    agent_id   BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    skill_name TEXT   NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, skill_name)
);

CREATE INDEX IF NOT EXISTS idx_askv_skill ON agent_skill_visibility(skill_name);

-- Skill 调用账本（见 db/skill_usage.go）。一次 Skill() 调用一行，只记维度不记正文。
-- 刻意不设外键：任务/会话删除后统计仍要保留（与 llm_usage 同理），skill 本身也只是
-- 文件系统上的目录名，没有对应的表。
CREATE TABLE IF NOT EXISTS skill_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    skill          TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT,
    args_len       INTEGER NOT NULL DEFAULT 0,
    -- false = 模型点名了一个不存在的 skill(未命中)。这类行同样保留：它反映"想用但没有"
    -- 的缺口，是补 skill 的依据。
    found          BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_skill_usage_skill ON skill_usage(skill, ts DESC);

CREATE INDEX IF NOT EXISTS idx_skill_usage_task  ON skill_usage(task_id);

-- 工具调用账本（见 db/tool_usage.go）。一次实际 CoreTool.Call 一行，只记归属维度，
-- 不保存工具参数或返回内容。刻意不设外键，任务、会话或自定义工具删除后仍保留统计。
CREATE TABLE IF NOT EXISTS tool_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool_key       TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage(tool_key, ts DESC);

CREATE INDEX IF NOT EXISTS idx_tool_usage_task ON tool_usage(task_id);

ALTER TABLE tool_usage ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'unknown';

-- =====================================================================
-- H. 内置工具目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS tools (
    key         TEXT PRIMARY KEY,
    system      BOOLEAN NOT NULL DEFAULT true,
    description TEXT    NOT NULL DEFAULT '',
    schema      JSONB   NOT NULL DEFAULT '{}',
    agents      JSONB   NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT    NOT NULL DEFAULT 'builtin',
    exec        JSONB   NOT NULL DEFAULT '{}',
    deferred    BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_tools_upd ON tools;

CREATE TRIGGER trg_tools_upd BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- I. 会话（对话页）
-- =====================================================================
-- Removed pentest domain left this trigger behind on upgraded databases; it
-- writes to the dropped finding_retests table and breaks every conversation
-- delete. Drop it (and its function) before creating the new schema.
DROP TRIGGER IF EXISTS trg_conversation_retest_delete ON conversations;
DROP FUNCTION IF EXISTS stop_deleted_conversation_retest();

CREATE TABLE IF NOT EXISTS conversations (
    id             BIGSERIAL PRIMARY KEY,
    agent_key      TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    pinned_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE conversations ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_conversations_llm_profile ON conversations(llm_profile_id) WHERE llm_profile_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_conversations_pinned ON conversations(pinned_at DESC) WHERE pinned_at IS NOT NULL;

DROP TRIGGER IF EXISTS trg_conversations_upd ON conversations;

CREATE TRIGGER trg_conversations_upd BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS conversation_activities (
    id                 BIGSERIAL PRIMARY KEY,
    conversation_id    BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_conv_act ON conversation_activities(conversation_id, id);

CREATE INDEX IF NOT EXISTS idx_conv_act_tool_call ON conversation_activities(conversation_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');

-- =====================================================================
-- M. 后端日志持久化
-- =====================================================================
CREATE TABLE IF NOT EXISTS server_logs (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    level      TEXT NOT NULL DEFAULT 'info',
    tag        TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_server_logs_id ON server_logs(id DESC);

-- Independent /btw history and the latest provider-ready main checkpoint.
CREATE TABLE IF NOT EXISTS side_question_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id BIGINT,
    exploration_id BIGINT,
    intent_id BIGINT,
    run_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    CHECK ((conversation_id IS NOT NULL AND task_id IS NULL AND exploration_id IS NULL AND intent_id IS NULL)
        OR (conversation_id IS NULL AND task_id IS NOT NULL AND exploration_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_side_sessions_conv ON side_question_sessions(conversation_id);

CREATE INDEX IF NOT EXISTS idx_side_sessions_task ON side_question_sessions(task_id);

CREATE INDEX IF NOT EXISTS idx_side_sessions_exp ON side_question_sessions(exploration_id);

CREATE INDEX IF NOT EXISTS idx_side_sessions_intent ON side_question_sessions(intent_id);

CREATE TABLE IF NOT EXISTS side_question_requests (
    id TEXT PRIMARY KEY,
    ordinal BIGSERIAL UNIQUE,
    session_key TEXT NOT NULL REFERENCES side_question_sessions(session_key) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    client_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed','cancelled','interrupted')),
    error TEXT NOT NULL DEFAULT '',
    model JSONB NOT NULL,
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence BIGINT NOT NULL DEFAULT 0,
    usage JSONB NOT NULL DEFAULT '{}',
    UNIQUE(session_key,generation,client_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_side_request_running ON side_question_requests(session_key) WHERE status='running';

CREATE INDEX IF NOT EXISTS idx_side_requests_history ON side_question_requests(session_key,ordinal DESC);

-- Additive v3 archive fields; old archives restore these as empty objects.
ALTER TABLE side_question_sessions ADD COLUMN IF NOT EXISTS memory JSONB NOT NULL DEFAULT '{}';

ALTER TABLE side_question_requests ADD COLUMN IF NOT EXISTS context_info JSONB NOT NULL DEFAULT '{}';

-- ============================================================================
-- Protocol reverse-engineering domain (Protocol Agent platform)
--
-- One protocol_case is one reverse-engineering engagement. The Python toolchain
-- writes findings.json; the runner mirrors that file into the normalized tables
-- below so the UI can query assets/frames/fields/codes directly. The raw file is
-- also kept in protocol_cases.findings for fidelity and forward compatibility.
-- ============================================================================

CREATE TABLE IF NOT EXISTS protocol_cases (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    install_root  TEXT NOT NULL DEFAULT '',
    device_ip     TEXT NOT NULL DEFAULT '',
    auth_level    TEXT NOT NULL DEFAULT 'read-only'
                  CHECK (auth_level IN ('read-only','write','destructive','full')),
    status        TEXT NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft','queued','running','paused','done','failed')),
    mode          TEXT NOT NULL DEFAULT 'static'
                  CHECK (mode IN ('live','static')),
    workdir       TEXT NOT NULL DEFAULT '',
    config        JSONB NOT NULL DEFAULT '{}',
    findings      JSONB NOT NULL DEFAULT '{}',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_protocol_cases_status ON protocol_cases(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_protocol_cases_created ON protocol_cases(created_at DESC);

-- Cross-case protocol fingerprints. P6 upserts a compact summary after a case
-- passes gate F; P1/P4 query it as a hypothesis, never as confirmed evidence.
CREATE TABLE IF NOT EXISTS protocol_knowledge (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    vendor         TEXT NOT NULL DEFAULT '',
    model          TEXT NOT NULL DEFAULT '',
    protocol       TEXT NOT NULL DEFAULT '',
    ports          TEXT NOT NULL DEFAULT '',
    magic          TEXT NOT NULL DEFAULT '',
    frame_summary  TEXT NOT NULL DEFAULT '',
    code_summary   TEXT NOT NULL DEFAULT '',
    state_summary  TEXT NOT NULL DEFAULT '',
    fingerprint    JSONB NOT NULL DEFAULT '{}',
    source_case_id BIGINT REFERENCES protocol_cases(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_protocol_knowledge_ports ON protocol_knowledge(ports);
CREATE INDEX IF NOT EXISTS idx_protocol_knowledge_magic ON protocol_knowledge(magic);

CREATE TABLE IF NOT EXISTS protocol_phases (
    case_id     BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,
    gate        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','running','pass','fail','skip')),
    detail      TEXT NOT NULL DEFAULT '',
    evidence    JSONB NOT NULL DEFAULT '{}',
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, phase)
);

CREATE INDEX IF NOT EXISTS idx_protocol_phases_status ON protocol_phases(status);

CREATE TABLE IF NOT EXISTS protocol_assets (
    id           BIGSERIAL PRIMARY KEY,
    case_id      BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    ext          TEXT NOT NULL DEFAULT '',
    score        INTEGER NOT NULL DEFAULT 0,
    comm_exports INTEGER NOT NULL DEFAULT 0,
    machine      TEXT NOT NULL DEFAULT '',
    md5          TEXT NOT NULL DEFAULT '',
    config_ips   JSONB NOT NULL DEFAULT '[]',
    grade        TEXT NOT NULL DEFAULT 'static',
    evidence     JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, path)
);

CREATE INDEX IF NOT EXISTS idx_protocol_assets_case_score ON protocol_assets(case_id, score DESC);

CREATE TABLE IF NOT EXISTS protocol_streams (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    pcap       TEXT NOT NULL DEFAULT '',
    stream     INTEGER NOT NULL DEFAULT 0,
    src        TEXT NOT NULL DEFAULT '',
    dst        TEXT NOT NULL DEFAULT '',
    sport      INTEGER NOT NULL DEFAULT 0,
    dport      INTEGER NOT NULL DEFAULT 0,
    protocol   TEXT NOT NULL DEFAULT '',
    bytes      BIGINT NOT NULL DEFAULT 0,
    frames     BIGINT NOT NULL DEFAULT 0,
    grade      TEXT NOT NULL DEFAULT 'traffic',
    evidence   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, pcap, stream)
);

CREATE TABLE IF NOT EXISTS protocol_frames (
    id           BIGSERIAL PRIMARY KEY,
    case_id      BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    frame_key    TEXT NOT NULL,
    protocol     TEXT NOT NULL DEFAULT '',
    stream       INTEGER NOT NULL DEFAULT 0,
    magic        TEXT NOT NULL DEFAULT '',
    alt_magic    TEXT NOT NULL DEFAULT '',
    header_size  INTEGER NOT NULL DEFAULT 0,
    len_offset   INTEGER NOT NULL DEFAULT 0,
    len_size     INTEGER NOT NULL DEFAULT 0,
    endian       TEXT NOT NULL DEFAULT '',
    len_bias     INTEGER NOT NULL DEFAULT 0,
    frames       BIGINT NOT NULL DEFAULT 0,
    bytes        BIGINT NOT NULL DEFAULT 0,
    carrier      TEXT NOT NULL DEFAULT '',
    inner_layout TEXT NOT NULL DEFAULT '',
    channels     TEXT NOT NULL DEFAULT '',
    commands_observed INTEGER NOT NULL DEFAULT 0,
    grade        TEXT NOT NULL DEFAULT 'traffic',
    detail       JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, frame_key)
);

CREATE TABLE IF NOT EXISTS protocol_field_maps (
    id            BIGSERIAL PRIMARY KEY,
    case_id       BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    map_key       TEXT NOT NULL,
    direction     TEXT NOT NULL DEFAULT '',
    samples       INTEGER NOT NULL DEFAULT 0,
    frame_len_min INTEGER NOT NULL DEFAULT 0,
    frame_len_max INTEGER NOT NULL DEFAULT 0,
    grade         TEXT NOT NULL DEFAULT 'traffic',
    fields        JSONB NOT NULL DEFAULT '[]',
    tail          JSONB NOT NULL DEFAULT '{}',
    payload       JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, map_key)
);

CREATE TABLE IF NOT EXISTS protocol_function_codes (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    layer      TEXT NOT NULL DEFAULT '',
    code       INTEGER NOT NULL DEFAULT 0,
    code_key   TEXT NOT NULL DEFAULT '',
    label      TEXT NOT NULL DEFAULT '',
    grade      TEXT NOT NULL DEFAULT 'static',
    evidence   TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    verified   BOOLEAN NOT NULL DEFAULT false,
    -- semantic=true marks a human/LLM-assigned label. A later P4 re-run must not
    -- overwrite it with the raw export-table string.
    semantic   BOOLEAN NOT NULL DEFAULT false,
    payload    JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE protocol_function_codes ADD COLUMN IF NOT EXISTS semantic BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE protocol_function_codes ADD COLUMN IF NOT EXISTS code_key TEXT NOT NULL DEFAULT '';

-- code_key preserves composite service/sub-code identities such as 0x58/0x39.
-- Backfill old rows from the raw payload first; fall back to the parsed integer.
UPDATE protocol_function_codes c
SET code_key = COALESCE(
    (
        SELECT string_agg(
            CASE
                WHEN part ~ '^[0-9]+$' THEN '0x' || LOWER(TO_HEX(part::bigint))
                WHEN part ~ '^0x[0-9a-f]+$' THEN
                    '0x' || COALESCE(NULLIF(LTRIM(SUBSTRING(part FROM 3), '0'), ''), '0')
                ELSE part
            END,
            '/'
        )
        FROM regexp_split_to_table(
            LOWER(REGEXP_REPLACE(BTRIM(c.payload->>'code'), '\s+', '', 'g')),
            '/'
        ) AS t(part)
    ),
    '0x' || LOWER(TO_HEX(c.code))
)
WHERE c.code_key = '';

-- The old unique key included the label and used semantic rows as a family-wide
-- suppressor. Keep one row per real code identity so 0x58 and its sub-codes can
-- coexist; prefer a semantic row when duplicates already exist.
ALTER TABLE protocol_function_codes DROP CONSTRAINT IF EXISTS protocol_function_codes_case_id_layer_code_label_key;
DELETE FROM protocol_function_codes a
USING protocol_function_codes b
WHERE a.case_id = b.case_id
  AND a.layer = b.layer
  AND a.code_key = b.code_key
  AND (
      (a.semantic = false AND b.semantic = true)
      OR (a.semantic = b.semantic AND a.id < b.id)
  );
CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_codes_key
    ON protocol_function_codes(case_id, layer, code_key);

CREATE INDEX IF NOT EXISTS idx_protocol_codes_case ON protocol_function_codes(case_id, layer, code);

CREATE INDEX IF NOT EXISTS idx_protocol_codes_label ON protocol_function_codes(label);

-- verified is reserved for live-verified codes; static/inferred/traffic must not
-- display as confirmed.
UPDATE protocol_function_codes SET verified = false WHERE verified AND grade <> 'live';

CREATE TABLE IF NOT EXISTS protocol_probes (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    probe_key  TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',
    spec       TEXT NOT NULL DEFAULT '',
    host       TEXT NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 0,
    action     TEXT NOT NULL DEFAULT '',
    request    TEXT NOT NULL DEFAULT '',
    response   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT '',
    grade      TEXT NOT NULL DEFAULT 'live',
    payload    JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_protocol_probes_case ON protocol_probes(case_id, created_at DESC);

-- Existing installs predate the column; ADD IF NOT EXISTS keeps schema.sql
-- runnable before migrations 0003 on an already-initialized database.
ALTER TABLE protocol_probes ADD COLUMN IF NOT EXISTS probe_key TEXT NOT NULL DEFAULT '';

-- Stable probe identity: re-syncing the same findings upserts the probe instead
-- of re-inserting it, so [probe:<id>] references in delivered documents survive.
CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_probes_key
    ON protocol_probes(case_id, probe_key) WHERE probe_key <> '';

CREATE TABLE IF NOT EXISTS protocol_notes (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT '',
    payload    JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS protocol_reports (
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    doc_type   TEXT NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    content    TEXT NOT NULL DEFAULT '',
    version    INTEGER NOT NULL DEFAULT 1,
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ,
    approved_version INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, doc_type)
);

ALTER TABLE protocol_reports ADD COLUMN IF NOT EXISTS approved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE protocol_reports ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE protocol_reports ADD COLUMN IF NOT EXISTS approved_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS protocol_report_versions (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    doc_type   TEXT NOT NULL,
    version    INTEGER NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    content    TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, doc_type, version)
);

CREATE INDEX IF NOT EXISTS idx_protocol_report_versions ON protocol_report_versions(case_id, doc_type, version DESC);

INSERT INTO protocol_report_versions(case_id,doc_type,version,title,content)
SELECT case_id,doc_type,version,title,content FROM protocol_reports
ON CONFLICT (case_id,doc_type,version) DO NOTHING;

CREATE TABLE IF NOT EXISTS protocol_artifacts (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    size       BIGINT NOT NULL DEFAULT 0,
    sha256     TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_protocol_artifacts_case ON protocol_artifacts(case_id, created_at DESC);

CREATE TABLE IF NOT EXISTS protocol_events (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    phase      TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT 'log'
                CHECK (kind IN ('log','stdout','stderr','phase','gate','status','artifact','error')),
    message    TEXT NOT NULL DEFAULT '',
    payload    JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_protocol_events_case ON protocol_events(case_id, id);

-- One row per sub-agent delegation. The main orchestrator creates a running row
-- before invoking the phase sub-agent; the sub-agent finishes it through
-- protocol_report_phase, and the parent falls back to the final text if not.
CREATE TABLE IF NOT EXISTS protocol_phase_jobs (
    id          BIGSERIAL PRIMARY KEY,
    job_id      TEXT NOT NULL UNIQUE,
    case_id     BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,
    agent_key   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'running'
                CHECK (status IN ('running','done','error','cancelled')),
    task        TEXT NOT NULL DEFAULT '',
    expected    TEXT NOT NULL DEFAULT '',
    result      JSONB NOT NULL DEFAULT '{}',
    error       TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_protocol_phase_jobs_case ON protocol_phase_jobs(case_id, phase, id DESC);

CREATE TABLE IF NOT EXISTS protocol_subagent_runs (
    id          BIGSERIAL PRIMARY KEY,
    case_id     BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,
    agent_key   TEXT NOT NULL,
    session_id  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'running'
                CHECK (status IN ('running','pass','partial','fail','error')),
    summary     TEXT NOT NULL DEFAULT '',
    evidence    JSONB NOT NULL DEFAULT '{}',
    artifacts   JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_protocol_subagent_case ON protocol_subagent_runs(case_id, phase, id DESC);

-- Circular FK: agents.current_prompt_id -> agent_prompts.id.
DO $$ BEGIN
    ALTER TABLE agents ADD CONSTRAINT fk_agents_curprompt
        FOREIGN KEY (current_prompt_id) REFERENCES agent_prompts(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Lightweight LLM usage ledger (also created idempotently by EnsureLLMUsageTable).
CREATE TABLE IF NOT EXISTS llm_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_id     TEXT,
    task_id        TEXT,
    exploration_id BIGINT,
    worker         TEXT,
    model          TEXT,
    profile_name   TEXT,
    latency_ms     INTEGER,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_read     INTEGER NOT NULL DEFAULT 0,
    cache_write    INTEGER NOT NULL DEFAULT 0,
    status         TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_task  ON llm_usage(task_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_model ON llm_usage(task_id, model);
CREATE INDEX IF NOT EXISTS idx_llm_usage_exp   ON llm_usage(exploration_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_session ON llm_usage(session_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_ts ON llm_usage(ts);

-- V2 (PLAN-V2): destructive-campaign approval gate. campaign_runner refuses any
-- destructive campaign unless the referenced approval row is approved here.
CREATE TABLE IF NOT EXISTS protocol_approvals (
    id           BIGSERIAL PRIMARY KEY,
    case_id      BIGINT NOT NULL REFERENCES protocol_cases(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL DEFAULT 'campaign',
    payload      JSONB NOT NULL DEFAULT '{}',
    risk         TEXT NOT NULL DEFAULT 'destructive',
    status       TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT '',
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    note         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_protocol_approvals_case ON protocol_approvals(case_id, id DESC);

-- V2: cross-case vulnerability knowledge (CVE priors enriched with the 14-class
-- taxonomy; facts live in plc-intel/icsvuln, this is the semantic mapping layer).
CREATE TABLE IF NOT EXISTS vuln_knowledge (
    id        BIGSERIAL PRIMARY KEY,
    cve_id    TEXT,
    source    TEXT NOT NULL DEFAULT 'manual',
    vclass    INTEGER,
    vendor    TEXT,
    product   TEXT,
    protocol  TEXT,
    summary   TEXT,
    refs      JSONB NOT NULL DEFAULT '[]',
    confidence TEXT,
    class_basis TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, source)
);
-- Idempotent for databases created before the two columns existed.
ALTER TABLE vuln_knowledge ADD COLUMN IF NOT EXISTS confidence TEXT;
ALTER TABLE vuln_knowledge ADD COLUMN IF NOT EXISTS class_basis TEXT;
