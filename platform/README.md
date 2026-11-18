# Protocol Reverse Platform

工业私有协议逆向分析工具，保留通用 Agent / MCP / Skill / 工具 / LLM 能力，移除了渗透测试领域（任务/资产/漏洞/流量/拦截/通知/同步等）。

## 能力

- **协议案例**：安装目录、设备 IP、授权级别、pcap、通信 DLL。
- **P1–P6 Agent 分析流程**：资产侦察 → 流量获取 → 帧结构 → 静态挖码 → 动态验证 → 定名交付。
- **静态分析后端**：PE（recon_pe/extract_codes）、ELF（纯 Python）、.NET（ILSpyCmd）、
  Ghidra headless、IDA headless 桥接；未安装专用工具时自动回退到 binary_survey/strings。
- **会话/状态机**：请求-响应配对、会话、重试/超时、TCP 分片/重传、消息类型
  状态迁移与最小会话序列；P5 按状态验证而不是只逐条探针。
- **流量洞察**：TLS/压缩/高熵载荷特征、CRC 参数集搜索、zlib/gzip/raw-deflate
  解压、字段变异差分和粗略消息状态转移。
- **P5 声明式探针**：JSON 描述帧字段、序列号、校验、超时/重试和期望响应；
  默认 dry-run，write+ 授权才允许 live `--execute`。
- **静态分析缓存**：Ghidra/ILSpy 结果按文件 SHA256 缓存，跨阶段/跨案例复用。
- **门 A–F**：资产、pcap、零重同步帧、功能码、探针、交付文档。
- **结果**：通信资产、帧格式、字段划分、功能码、探针覆盖率和四份 Markdown 报告；报告可打包导出、查看版本历史并人工批准。
- **案例维护**：编辑案例参数、上传 pcap、通信 DLL/安装包等工件。
- **后台抓包**：选择网卡、设置过滤和时长，启动/停止 tshark，产物直接进入案例 pcaps。
- **阶段任务运维**：每次阶段委派写入 `protocol_phase_jobs`；支持单阶段取消，不影响其它并行阶段；服务重启后保留任务历史和失败原因。
- **pcap 质量**：自动检查包数、时长、端点数、协议和告警。
- **pcap 上传**、实时日志（SSE）、工作空间。
- **Agent**：`protocol` 主控 + `protocol_p1`…`protocol_p6` 六个阶段子 Agent；主 Agent 通过
  `protocol_delegate_phase` 下发任务，子 Agent 自行选择 Bash/Python/文件工具，平台用确定性规则判门。
- **跨案例知识库**：P6 通过门 F 后写入端口/magic/帧/码表/状态机指纹；
  P1/P4 可查询相似案例作为假设，并必须用当前证据确认。
- **Golden 案例**：`examples/golden/manifest.json` 版本化期望值，CI 校验 manifest；
  本地可对真实 case findings 做关键输出回归。
- **通用平台**：对话、Agent 管理、MCP、Skill、工具目录/自定义工具、LLM 多配置/模型池。
- **LLM 录制**：按 Agent + Session 查看每次模型请求/响应、token、延迟和错误；不再使用旧任务筛选。
- **登录**：多用户 + 角色（admin/operator/viewer）+ JWT。

## 已移除的内容

- 前端页面：任务、渗透发现、资产、流量、ScopeSentry 同步、工具执行历史、拦截审批、通知、仪表盘、系统配置。
- 内置 Agent：goals / planner / worker / mainagent / auto / pentest / reporter / retester。
- 内置工具：资产图、漏洞、任务、流量、拦截、跨任务编排等工具。
- 后端包：`traffic`、`enrich`、`guard`、`intercept`、`evidence`、`notify`、`report`。
- 数据库表：tasks/asset/finding/traffic/intercept/notification/sync 等；启动时只保留 31 张基础表，加上 LLM records/usage 共 33 张。
- Skill：`api-recon`、`scopesentry`；MCP：ScopeSentry 占位；流量 MITM 默认关闭。
- 运行时死代码：对话触发队列、计划引擎兼容层、任务型旁路问题、页面内一键更新/回滚
  （selfupdate）、审批 UI、mock 演示子系统。
- 前端 `lib/api.ts` / `lib/types.ts` 中不再使用的渗透 API 方法与类型。
- 过期的 Docker/Compose/安装/更新文件；构建与启动改用仓库内脚本。
- 确定性“运行全部”、单阶段运行、案例停止按钮与 `protocol_run_phase` 工具；阶段只能由
  主 Agent 通过 `protocol_delegate_phase` 下发给子 Agent。

## 目录

```text
protocol_agent_v0.2/
├── agent/                 # report.py 等 Python 脚本
├── tools/                 # recon/frame/field/code/client/dissector
├── examples/              # 金标准案例
└── platform/
    ├── cmd/protocol-agent/         # 启动入口
    ├── agent/             # ChatAgent、prompt、LLM provider、skills/MCP 装配
    ├── norma/             # Agent Harness SDK
    ├── protocol/          # 案例工作目录 + 门判定（不直接执行阶段）
    ├── db/                # 协议表、Agent/MCP/Skill/tool/LLM、对话、日志
    ├── server/            # 通用 API + 协议 API
    └── web/               # Next.js UI
```

## 运行

准备 PostgreSQL、Python 3.10+（`pefile`、`capstone`）、Wireshark/tshark。

`config.json`：

```json
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "pagent",
    "password": "",
    "dbname": "protocol_platform",
    "sslmode": "disable"
  },
  "skill_dir": "./skills",
  "protocol": {
    "tools_dir": "../tools",
    "runs_dir": "./data/protocol_cases",
    "python": "python",
    "tshark": "tshark",
    "spec": ""
  }
}
```

相对路径按 `platform/` 解析为绝对路径。`protocol.spec` 是 P5 的可选默认协议族，留空表示
由 P5 子 Agent 根据 pcap、DLL 和 findings 自行判断。

可选静态分析后端（按需安装，不随仓库分发）：

```powershell
cd E:\protocol_agent_v0.2\tools
.\install-analyzers.ps1                 # 安装 ILSpyCmd，检测 Ghidra/IDA/binutils
.\install-analyzers.ps1 -DownloadGhidra  # 额外下载并解压 Ghidra
```

Ghidra 需设置 `GHIDRA_HOME`；ILSpyCmd 需要 .NET SDK（仅有运行时不够）；IDA 是商业软件，需自行安装 `idat64/idat` 并加入 PATH。
「协议逆向 → 工具链」会显示这些后端是否可用，以及缺失时的回退提示。

本机也可以使用已经打好的 Windows x64 离线分析器包（不进入 Git）：

```text
E:\protocol_agent_v0.2\offline\analyzers-win-x64-ghidra12.2-dotnet10-20261102.zip
```

包内包含 Ghidra 12.2、JDK 25、.NET SDK 10.0.403、ILSpyCmd 11.2 和全部分析脚本。
解压后运行：

```powershell
cd analyzers-win-x64
.\verify.ps1
.\start-platform.ps1 -Platform ..\..\platform\platform.exe
```

平台会自动发现 `offline/analyzers-win-x64`，无需特殊启动方式；`activate.ps1` /
`start-platform.ps1` 仍可用于显式设置 `GHIDRA_HOME/JAVA_HOME/DOTNET_ROOT/PATH`。
离线包没有包含 Python、Wireshark/tshark、IDA 或 PostgreSQL。

## 构建

前端静态导出后再用 `embedui` 标签把 `server/webui/dist` 嵌入二进制：

```bash
cd web
npm run build:static          # 跨平台（内部设置 NEXT_EXPORT=1）
cd ..
rm -rf server/webui/dist
cp -r web/out server/webui/dist
go build -tags embedui -o platform.exe ./cmd/protocol-agent
```

跨平台发布包用 `./build.sh`（会自动导出前端并交叉编译）。开发模式用 `./dev.sh`
（后端 :8787 + Next dev :3000）。

**Windows 构建注意事项**：

- 使用 `npm run build:static`，不要手写 `NEXT_EXPORT=1 next build`（npm 在 cmd.exe
  下不识别 Unix 环境变量前缀）。
- Next 构建 worker 默认限制为 2 并发（可用 `NEXT_BUILD_WORKERS` 覆盖），Go 编译默认
  `GOMAXPROCS=1`（可用环境变量覆盖）：这两项用于规避本机高并发时的原生崩溃。
- `build.sh` 在没有 `rsync` 时回退为 `cp -R`，Windows Git Bash 可直接运行。

运行日志写入 `<data>/logs/platform.log`（10 MiB × 5 自动轮转），同时保留终端输出与
数据库 `server_logs`（保留最近 5 万行）。

## 运行

```powershell
cd E:\protocol_agent_v0.2\platform
.\platform.exe -addr :8787
# 或
.\start.bat
```

Linux/macOS 用 `./start.sh`。打开 `http://localhost:8787`，首次进入 `/setup`。
忘记密码可运行 `./reset-password.sh`（默认重置 Protocol Agent 管理员），或使用：

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
UPDATE users SET password_hash = crypt('新密码', gen_salt('bf', 10))
WHERE lower(username) = 'protocol';
```

启用 HTTPS：

```powershell
.\platform.exe -addr :8787 -tls-cert cert.pem -tls-key key.pem
```

也可用 `PROTOCOL_AGENT_TLS_CERT` / `PROTOCOL_AGENT_TLS_KEY` 环境变量；两者必须同时提供。

## 协议 Agent

平台**只支持 Agent 驱动分析**，没有“一键跑脚本”或单阶段手动运行入口。LLM 是必需项。

1. 「系统 → LLM」配置并激活一个支持 tool calling 的模型。
2. 案例详情上传/确认 pcap，点「启动 Agent 分析」。
3. 主 Agent 按数据依赖自行编排：`protocol_delegate_phase` 默认异步返回 job_id，可同时
   启动多个无依赖阶段；再用 `protocol_wait_phases` 等待本批结果。
4. 子 Agent 各自在隔离的 `findings_path` 上工作，自行选择 Bash/Python/文件工具、现成
   脚本或临时脚本，完成后 `protocol_sync_findings(..., path=findings_path, phase="Pn")`
   合并入库，再 `protocol_report_phase` 汇报。
5. 平台按 findings/报告做确定性门判定，把阶段状态与门结果写回案例；主 Agent 根据
   `passed / gate / next_hint` 决定下一批、重试或请求人工。
6. 六阶段全通过后案例状态变为 `done`；主 Agent 会话结束但未全通过时变为 `paused`。

并行示例：P1 分析安装目录时可以同时启动 P2 解析已有 pcap 或后台抓包；已有 pcap 时
P3 也可以与 P1/P2 同时启动。P4 等 P1 的 DLL/资产，P5 等 P4 的功能码，P6 等前置阶段。
子 Agent 写的 findings 由服务端按 section 合并，不会因为并行而互相覆盖。

新建案例中的「P5 动态验证协议族」是可选提示，不是流水线步骤：已知设备协议时可填
`wago` / `codesys` / `fins` / `enip` / `napro` / `s7smart` / `umas`；留空/Auto 时由 P5
子 Agent 自行判断，未知协议会写自定义只读探针或记录静态降级。

UI 的「阶段进度」是只读视图；执行细节和工具调用在自动打开的协议主控对话中查看。

**阶段并发**：每个案例默认最多 4 个阶段同时运行，可用
`PROTOCOL_AGENT_MAX_CONCURRENCY` 调整。阶段详情卡片上的停止按钮只取消该阶段；
任务状态与结果持久化在 `protocol_phase_jobs`，重启后仍可查询。

**运行预算（默认）**：主 Agent 4 小时、80 个工具回合；每个阶段子 Agent 20 分钟、
60 个工具回合。子 Agent 使用自己的预算，不会继承主 Agent 当时的剩余时间；达到软预算
会在回合边界进入收尾并保存 findings，超过软预算 10 分钟的硬兜底会以命名原因中断，
避免出现匿名的 `context deadline exceeded`。预算可在「系统 → Agent」里逐个调整。

## 主要 API

| 方法 | 路径 |
|---|---|
| GET/POST | `/api/protocol/cases` |
| GET/PATCH/DELETE | `/api/protocol/cases/{id}` |
| POST | `/api/protocol/cases/{id}/agent-run` |
| POST | `/api/protocol/cases/{id}/pcaps` |
| POST | `/api/protocol/cases/{id}/artifacts` |
| GET/POST | `/api/protocol/cases/{id}/capture` |
| POST | `/api/protocol/cases/{id}/capture/stop` |
| GET | `/api/protocol/capture/interfaces` |
| GET | `/api/protocol/cases/{id}/reports/export` |
| GET | `/api/protocol/cases/{id}/reports/{doc}/versions` |
| POST | `/api/protocol/cases/{id}/reports/{doc}/approve` |
| GET | `/api/protocol/cases/{id}/pcaps/quality` |
| GET | `/api/protocol/cases/{id}/metrics` |
| GET | `/api/protocol/cases/{id}/phase-jobs` |
| POST | `/api/protocol/cases/{id}/phase-jobs/{phase}/cancel` |
| GET | `/api/protocol/cases/{id}/findings` |
| GET | `/api/protocol/cases/{id}/reports` |
| GET | `/api/protocol/cases/{id}/events/stream` |
| GET | `/api/protocol/findings` / `/api/protocol/stats` |
| GET/POST | `/api/users`（admin） |
| GET | `/api/audit`（admin） |
| GET | `/api/agents` / `/api/mcp` / `/api/skills` / `/api/tools` |
| GET | `/api/llm/profiles` / `/api/llm/pool` / `/api/llm/records` |

## 运维与迁移

- 数据库迁移：启动自动执行 `db/migrations/*.up.sql`，状态记录在 `schema_migrations`。
  `go run ./cmd/migrate -status` 查看；`-down-to <version>` 回滚到指定版本。
- 保留策略（默认关闭）：`PROTOCOL_AGENT_RETENTION_LLM_RECORDS_DAYS`、
  `_LLM_USAGE_DAYS`、`_TOOL_USAGE_DAYS`、`_PROTOCOL_EVENTS_DAYS`、`_PCAP_DAYS`；
  后台按 `PROTOCOL_AGENT_RETENTION_INTERVAL_MINUTES`（默认 1440）执行。
- 每案例磁盘配额：`PROTOCOL_AGENT_CASE_DISK_QUOTA_MB`，默认 4096 MB；上传 pcap/
  artifact 和启动后台抓包前检查。
- 服务安装：Windows 用 `scripts/install-service.ps1`（`-Uninstall` 卸载）；
  Linux 用 `scripts/install-service.sh`，unit 模板为 `scripts/protocol-agent.service`。
- 恢复演练：`scripts/restore.ps1 -Backup <zip> -VerifyOnly` 校验备份；
  去掉 `-VerifyOnly` 会恢复到临时数据库并查询 `agents`，默认完成后删除临时库。

## 测试、依赖与备份

- 一键本地检查：`scripts/test-all.ps1`（Python 分析器测试 + Go 测试 + TypeScript/npm 测试）。
- Golden 校验：`python tools/golden_check.py --validate`；有本地数据时可用
  `--check --data-root platform/data/protocol_cases`。
- CI：`.github/workflows/ci.yml` 运行 Go/Node/Python 测试，并提供 PostgreSQL
  service 运行 `go test -tags integration ./db -run Integration`；同时校验 Playwright
  用例列表和 golden manifest。
- Playwright：`npm run e2e:list` 可列出用例；设置 `E2E_BASE_URL`、`E2E_USERNAME`、
  `E2E_PASSWORD`、`E2E_CASE_ID` 后可跑真实浏览器 E2E。
- Python 依赖：`tools/requirements.txt`（pefile、capstone）；`tools/doctor.py` 输出 JSON
  体检报告；工具链页也会检查 Python 模块和 tshark。
- 备份：`scripts/backup.ps1` 生成包含 PostgreSQL dump、`data/`、`config.json`、
  `secret.key`、`jwt.key` 和 `skills/` 的 zip；备份文件默认写入被 gitignore 的 `backups/`。
- 案例详情「阶段进度」下新增运行统计：阶段运行次数/平均耗时，以及按子 Agent 汇总的
  LLM 调用与 token。LLM usage 账本现在也记录 `session_id`。

## 用户与角色

系统支持多用户：

| 角色 | 权限 |
|---|---|
| `admin` | 全部权限，含用户管理、审计日志 |
| `operator` | 分析、案例、Agent/MCP/Skill/工具、LLM 配置 |
| `viewer` | 只读查询（GET） |

「系统 → 用户」可新建用户、调整角色、禁用账号和重置密码；「系统 → 审计」记录登录、
配置、案例、用户等写操作。默认迁移旧版单管理员密码为 `protocol` 管理员。

## 密钥与审计

- LLM API Key 使用 AES-256-GCM 加密后写入数据库，密钥文件为可执行文件旁的
  `secret.key`（权限 0600，已在 `.gitignore` 中排除）。
- **备份数据库时必须同时备份 `secret.key`**，否则已加密的 API Key 无法解密。
- 所有非 GET 的 API 写请求会写入 `audit_log`，包含用户、角色、方法、路径、状态和 IP；
  登录成功/失败和 RBAC 拒绝也会记录。
- 注意：命令文本级的设备写操作拦截仍是启发式防线；生产环境仍建议把设备访问限制在
  专用网段/代理。

## 安全与门禁

仅用于已授权协议逆向和本地验证。授权级别现在由平台在工具层强制：

- `read-only`：P5 只允许 `client_harness identify/hello/poll/info` 和被动抓包；自定义探针、
  `code/session` 动作、`nc/socat/ssh/curl` 等可发送任意数据的命令会被拒绝。
- `write`：允许写变量/参数，但复位、擦除、刷写、重启等破坏性命令仍被拒绝。
- `destructive/full`：允许破坏性操作；仍受 SDK 的灾难性命令底线约束。
- 主协议 Agent 只负责编排，Bash/Write/Edit 被工具层禁用；执行只能交给阶段子 Agent。
- 文件写入限制在案例工作目录内，禁止修改安装目录或系统路径。
- 被拒绝的操作会写入案例事件日志，子 Agent 会收到明确的拒绝原因。

门禁已收紧：A 需有路径和得分的资产；B 需非空 pcap；C 需有确认帧；D 需有指令级或
流量出处的功能码占比 ≥60%；E 需 live 验证通过，或有明确离线/跳过原因的静态降级
（在线失败不算通过）；F 需 01–04 四份文档齐全、必填章节完整，并引用有效证据 ID
（[asset/code/frame/field/probe:<id>]，合计 ≥8 个）。findings 还必须通过 JSON
结构校验和阶段 section 所有权检查。

证据等级 `traffic > live > static > inferred`；推断不得写成已确认。

## 许可

基于早期版本精简，AGPL-3.0。完整多智能体/渗透版本备份在 `../platform_backup_20261030.tar.gz`。
