# 纯 Agent 驱动改造说明

## 目标

移除路线 A（平台确定性 P1–P6 流水线），案例只能由协议主 Agent 编排、六个阶段子 Agent
执行。平台不再直接运行任何阶段脚本，只负责：

- 提供案例工作目录与 pcap 上传；
- 把 `findings.json` 同步到数据库；
- 按 findings/报告做确定性门判定；
- 维护案例/阶段状态与事件日志。

## 后端

- 删除 `POST /api/protocol/cases/{id}/run`、`/phases/{phase}/run`、`/stop` 及对应 handler。
- 删除 `protocol_run_phase` 宿主工具并从 `tools` 表清理旧行；主 Agent 只剩
  `protocol_delegate_phase` 这一条阶段执行入口。
- `protocol.Runner` 收敛为路径锚点 + 门判定 + pcap 收集，不再包含 `RunAll/RunPhases/
  RunPhase` 或 Python 子进程执行代码。
- `protocol_delegate_phase` 开始时把阶段置为 `running`、案例置为 `running`，完成后写入
  `pass/fail` 与门证据；六阶段全通过时案例 `done`。
- 主 Agent 会话结束时若仍未全通过，案例转 `paused` 并记录原因；服务重启时自动把遗留
  `running` 案例/阶段/子 Agent run 收尾为中断状态。
- 子 Agent 提示词新增已解析的 `tools_dir`、`python`、`tshark`、`client_harness spec`，
  避免在 Windows 上依赖 PATH 自行探测。
- 主 Agent 提示词与 Skill 明确：平台没有一键流水线或单阶段工具，禁止主 Agent 直接跑
  Python/Bash 代替子 Agent。启动时通过 `protocol_prompt_agent_only_v3` 迁移旧提示词。
- 修复旧库遗留触发器 `trg_conversation_retest_delete`：它引用已删除的
  `finding_retests` 表，导致删除对话直接报错；schema 启动时自动 DROP。

## 前端

- 案例详情删除“运行全部”、阶段卡片播放按钮、“停止”按钮。
- 主操作改为「启动 Agent 分析」，运行中显示「Agent 分析中…」并禁用重复启动。
- 「阶段进度」只读展示由 Agent 驱动的阶段状态与门结果；详细过程在自动打开的协议主控
  对话中查看。
- 案例列表删除行内“运行”按钮。
- 工具链页增加 `tshark` 路径与缺失检查。

## 验证

- `go build ./...`、`go test ./...`、`npx tsc --noEmit`、`NEXT_EXPORT=1 npx next build`
  全部通过；18 个页面静态导出。
- `/run`、`/phases/P1/run`、`/stop` 均返回 404。
- `/api/tools` 有 8 个协议工具（含异步 `protocol_wait_phases`），`protocol_run_phase` 已不存在。
- 当前主 Agent 提示词已迁移为新版，不再包含 `protocol_run_phase`。
- 新建测试案例点击启动后状态 `draft → running`；LLM 调用失败、主会话结束后自动转为
  `paused`，并写入“Agent 会话已结束，六阶段尚未全部通过”。
- 已完成的 WAGO 案例保持 `done`；对话删除恢复正常。

## 运行预算修复（15 分钟中断）

- 原因：主 Agent 的 `run_seconds=1200` 对应的 tool context 会传递给同步执行的子 Agent。
  主 Agent 前面已用掉约 5 分钟后，子 Agent 只拿到剩余约 15 分钟，最终在模型流式输出阶段
  被父 context 的 deadline 打断，因此显示为匿名 `deadline_exceeded`。
- 修复：主 Agent 默认预算提升到 4 小时/80 回合；六个阶段子 Agent 默认 20 分钟/60 回合。
  迁移只改动仍为默认值的 Agent，保留用户自定义。
- 子 Agent 会脱离父级预算 deadline（阶段拥有完整预算），但仍继承用户停止、进程退出和
  硬超时等显式取消。
- 新增命名硬超时 `run_hard_timeout`：软预算 + 10 分钟仍未结束（模型流或工具挂死）时
  带明确原因中断；软预算本身仍在回合边界正常收尾。
- 子 Agent 提示词注入本阶段预算，并要求批量执行、一次成文，接近上限时先
  `protocol_sync_findings`，再 `protocol_report_phase` 报 partial，避免反复小段编辑空转。

## 并行编排改造

- `protocol_delegate_phase` 改为异步：立即返回 `job_id`，同一阶段只允许一个运行中的 job。
- 新增 `protocol_wait_phases(case_id, phases, timeout_seconds)`：批量等待或查询阶段结果；
  `timeout_seconds=0` 只读取当前状态。
- 主 Agent 提示词改为“数据依赖”而非固定顺序：P1/P2 可并行，已有 pcap 时 P3 也可并行；
  P4 等 P1，P5 等 P4，P6 等前置阶段。主 Agent 自行决定批次。
- 并行安全：每次子 Agent 获得独立的 `.runs/<run>/findings.json` 快照，完成后由服务端
  按阶段拥有的 section 合并到 canonical findings.json（per-case 锁 + 原子写）。
  P1 资产、P3 帧/字段、P4 功能码、P5 探针各自替换自己的 section；notes/phases 去重追加；
  streams 按 pcap+stream 合并。子 Agent 不再直接改 canonical 文件。
- `protocol_sync_findings` 增加 `path`/`phase` 参数，用于把隔离文件合并回数据库。
- 所有 protocol/p1-p6 提示词通过 `protocol_prompt_parallel_v11` 一次性迁移。

验证：`TestMergeProtocolRunFindingsParallelSections` 覆盖 P1/P2 并行合并、P3 不覆盖
P1 资产、P1 重跑替换自身 section、notes 去重；Go 构建通过。

## P0 安全与可信度加固

- 授权级别从“提示词约束”升级为工具层强制：
  - 主协议 Agent 禁用 Bash/Write/Edit，只保留编排与报告工具；
  - 子 Agent 使用 `ModeDefault` + 权限回调；
  - `read-only` 下 P5 仅允许 `client_harness` 的 identify/hello/poll/info 和被动抓包；
    自定义探针、code/session、任意网络客户端被拒绝；
  - `write` 仍拒绝复位/擦除/刷写/重启；`destructive/full` 才放行；
  - 文件写入限定在案例工作目录；拒绝事件写入案例日志。
- 门禁强化：P1 路径+得分；P2 pcap 非空；P3 确认帧；P4 有指令级/流量出处功能码占比
  ≥60%；P5 live 通过或有明确 reason 的离线降级；P6 四份 01–04 文档、必填章节和
  有效证据 ID 引用（合计 ≥8 个）。
- findings 校验：JSON 结构/数组元素校验；阶段只能改自己负责的 section，越权写入直接失败。
- P5 提示词与门禁对齐：在线失败不得伪装成离线降级。
- 说明：命令文本匹配仍是启发式防线；生产环境还需要设备网段出站隔离/代理。

## P0 安全基础设施

- LLM API Key 使用 AES-256-GCM 加密后写入 `llm_profiles.api_key`；本地密钥文件为
  `secret.key`（0600，已 gitignore），启动时自动迁移旧明文 Key。备份数据库必须同时
  备份 `secret.key`。
- 多用户与 RBAC：新增 `users` 表（admin/operator/viewer），旧单管理员密码自动迁移为
  Protocol Agent 管理员；JWT 带用户 id/角色，服务端每次请求按数据库当前角色鉴权。
- 路由权限：viewer 仅 GET；operator 可分析/配置；admin 额外拥有用户管理和审计权限。
- 用户管理：`系统 → 用户` 支持新建、角色调整、启用/禁用、重置密码；禁止删除自己或
  最后一个启用管理员。
- 审计：`audit_log` 记录所有非 GET API 写请求、登录成功/失败、RBAC 拒绝，含用户、
  角色、方法、路径、状态、IP；`系统 → 审计` 提供查询页面。
- TLS：新增 `-tls-cert/-tls-key` 或 `PROTOCOL_AGENT_TLS_CERT/KEY`，启用 HTTPS（TLS 1.2+）；
  已用自签证书在 :8788 实际验证。
- `reset-password.sh` 改为更新 `users` 表并确保 Protocol Agent 管理员启用。

## P1 能力补齐（第一批）

- 案例详情支持编辑名称/描述/安装目录/设备 IP/授权/spec/DLL 路径。
- 新增工件上传：DLL、安装包、固件等落到 `<case>/artifacts/`；上传 .dll 自动写入
  `golden_artifacts.comm_dll`。
- 新增后台抓包控制：`tshark -D` 网卡列表、启动/停止/状态 API；详情页可选择网卡、
  捕获过滤和时长，抓包直接写入 `<case>/pcaps/`。
- P5 探针要求记录 `code`；详情页显示功能码覆盖率（已验证/总数）。
- P6 报告支持打包为 zip 下载（四份 Markdown）。
- 已验证：案例编辑、工件上传、抓包启动/超时/手动停止、报告 zip 内容、临时案例清理。

## P1 能力补齐（第二批）

- P2 pcap 质量：`GET /cases/{id}/pcaps/quality` 用 tshark 统计包数、时长、端点、
  协议并给出包数过少/时长不足/单向流量告警；详情页新增「pcap 质量」页签。
- P6 报告版本：`protocol_report_versions` 保存每次内容版本；报告页可查看版本历史并
  并排对比，管理员/操作员可「批准当前版本」，记录批准人和批准版本。
- P1/P4 非 PE 分析：新增 `tools/binary_survey.py`，支持 ELF/Mach-O/.NET/安装包/
  配置文件，补充分数、架构、CLR/关键词证据并可 `--append` 到隔离 findings。
- P3/P4 提示词增加可选 ilspycmd/dotnet/readelf/objdump/Ghidra headless/IDA MCP 路线。
- 阶段并发上限：每案例默认 4，`PROTOCOL_AGENT_MAX_CONCURRENCY` 可调。

## P3/P4 深度分析后端

- 新增 `binary_survey.py`：ELF/Mach-O/.NET/安装包/配置关键词侦察。
- 新增 `elf_analyze.py`：纯 Python 解析 ELF32/64 符号表、导入导出、通信关键词。
- 新增 `dotnet_analyze.py`：ILSpyCmd 反编译 .NET，提取常量/枚举/功能码和关键词。
- 新增 `ghidra_analyze.py` + `GhidraExport.java`：Ghidra headless 桥接，导出函数、
  外部符号和字符串。
- 新增 `ida_analyze.py` + `ida_export.py`：IDA headless 桥接（需合法 IDA 安装）。
- 新增 `traffic_insights.py`：高熵/TLS/压缩特征、CRC 候选、粗略消息状态转移。
- 工具链页新增「可选分析后端」状态；缺失时 P1/P3/P4 自动回退到 binary_survey/strings，
  不伪造结果。
- 安装脚本 `tools/install-analyzers.ps1|.sh`；Ghidra/IDA 不随项目分发。

## 离线分析器包（Windows x64）

- 位置：`offline/analyzers-win-x64-ghidra12.2-dotnet10-20261102.zip`（本地，不进入 Git）。
- 内容：Ghidra 12.2 PUBLIC、Microsoft JDK 25.0.5、.NET SDK 10.0.403、
  ILSpyCmd 11.2.0.10050、全部 analyzer Python/Java 脚本。
- 平台自动发现 `offline/analyzers-win-x64`；`activate.ps1` 仍可显式设置 `GHIDRA_HOME/JAVA_HOME/DOTNET_ROOT/PATH`；
  `start-platform.ps1` 用该环境启动平台；`verify.ps1` 检查版本。
- Ghidra 已用 JDK 25 实测 `analyzeHeadless`；对 WBCComm.dll 导出 1000 函数、
  200 外部符号、500 字符串。ILSpyCmd 对 .NET SDK 程序集实测反编译成功。
- 不包含 Python、Wireshark/tshark、IDA、PostgreSQL；IDA 仍按许可证自行安装。
- 包 SHA256：`99c76311240b83ab0566ff8a4bea9a67ec1cb860dcd27481a676c71badd9d506`。

## P2 并行编排运维加固

- `protocol_phase_jobs` 持久化每次阶段委派：job_id、阶段、Agent、状态、任务、结果、
  错误、开始/结束时间；服务重启把 running job 收尾为 cancelled，阶段失败为中断。
- 新增 `protocol_cancel_phase` 工具、`GET /phase-jobs`、`POST /phase-jobs/{phase}/cancel`；
  阶段卡片运行中显示停止按钮，只取消该阶段，不影响其它并行阶段/主会话。
- `protocol_wait_phases` 在重启后可从持久化 job 读取最后状态，而不是只看到空 registry。
- 提示词迁移改为只在当前版本仍是内置默认（system/内置默认/恢复为内置默认）时覆盖；
  用户通过 UI 编辑过的提示词不会被版本升级覆盖。
- 每案例并发上限默认 4（`PROTOCOL_AGENT_MAX_CONCURRENCY`）。

## 旧任务语义与未使用资源清理

- LLM 录制页移除任务筛选、任务列、任务删除和 `LLMTask` 类型；改为 Agent + Session
  视角，保留模型/Session 筛选、请求响应详情和下载。
- 新 LLM 调用通过 `llmrec.WithWorker` 写入 agent key（protocol/protocol_pN/自定义 agent），
  旧记录该列为空。
- 移除内置 browser MCP（Playwright）种子与数据库授权/工具缓存；MCP 页面仍支持手动添加
  通用 MCP 服务器。
- 移除 `playwright-cli` Skill 目录、Agent 可见性、调用记录；Skill 仅保留 protocol-reverse。
- 一次性清理使用 setting flag `cleanup_legacy_browser_v1`，避免影响后来手动添加的 MCP。

## 工程质量与可运维性

- 新增 Python 分析器单测（CRC/熵/ELF 头/binary_survey）和 `scripts/test-all.ps1`；
  GitHub Actions 运行 Go/Node/Python 测试。
- 新增 `tools/requirements.txt`、`tools/doctor.py`；工具链检查增加 Python 依赖
  pefile/capstone、tshark 和可选分析器状态。
- LLM usage 账本增加 `session_id`，案例运行统计按阶段统计运行次数/平均耗时，并按
  protocol_pN 汇总调用与 token；详情页「阶段进度」新增运行统计卡。
- `scripts/backup.ps1` 备份 PostgreSQL dump、data、config、secret.key、jwt.key、skills。
- LLM 录制页改为 Agent/Session 视角；移除了旧任务字段/接口。

## P5 spec 可选化

- 新建案例的 `client_harness spec` 改为可选项，默认留空，不再默认 `wago`。
- 平台 `protocol.spec` 默认也改为空；空/auto 时 P5 子 Agent 根据 pcap、DLL、端口和
  findings 判断协议族，匹配不到就写自定义只读客户端；设备离线则记录静态降级。
- UI 标签改为「P5 动态验证协议族（可选）」，并列出内置 spec 与自动判断说明。
- P5 提示词迁移（`protocol_prompt_parallel_v11`）明确禁止空 spec 时盲用 wago。

## LLM 配置管理修复

- 删除配置失败：`DeleteProfileContext` 仍在查询已移除的 `tasks` / `task_llm_profiles`，
  重写为仅处理 `llm_profiles` 自身与 schema 的 FK 动作。
- 允许删除激活配置：删除后按 `priority DESC, id ASC` 自动激活下一个；删除最后一个时
  `clearLLM` 清空内存中的 provider。
- 编辑时 API Key 留空：前端不再发送空的 `api_key`，后端保留原值；新增明确提示。
- 已通过 API 验证：删除激活配置返回 200、自动切换；编辑不传 key 后 hint 保留；删除
  测试配置后清理。

## 使用前提

- 必须先在「系统 → LLM」配置并激活一个支持 tool calling 的模型；没有 LLM 无法分析。
- 子 Agent 仍可使用 `tools/` 下的 Python 脚本，但由 Agent 自己决定何时、如何调用，
  平台不再代跑。
