# 更新日志

## [0.14.14-v2] - 2026-11-18

品牌重塑：Protocol Agent → **ICS VulnAgent（工控系统脆弱性分析与利用智能体）**。

- 前端：应用标题/描述/登录页/侧边栏品牌/案例列表与详情文案全面改为
  智能体定位（九阶段流水线叙事，协议逆向是基座而非全部）。
- 主控 agent 种子与 DB 行更名「工控脆弱性分析与利用」；主控提示词身份
  同步（提示词预算内）。
- 发布准备：根 README 重写（定位/核心设计/快速开始/产物/安全声明）；
  LICENSE（AGPL-3.0）提升到根；.gitignore 排除 runtime/offline/运行数据/
  密钥/构建产物/**实验室 pcap 样本**（含真实设备流量，默认不公开）。
- 敏感清理：p769_offline.py 硬编码管理员密码改为 --pass/环境变量必填；
  全仓扫描确认无其他硬编码密钥（jwt.key/secret.key/config.json 不入库）。
- git 仓库初始化（便携 MinGit 入 runtime\git），首次提交 661 文件；
  scripts/publish-github.ps1 一键创建远端并推送（需 gh auth login）。

## [0.14.13-v2] - 2026-11-18

P7-P9 离线补齐：老案例（test~test10）批量完成离线可做的漏洞挖掘阶段。

- 新工具 `tools/p769_offline.py`：无设备、无子代理的批量管线——P7 三工具
  （device_profile/applicability/vuln_intel，厂商线索从 comm_assets 关键词
  推断）→ LLM 批量直判裁决（POST /api/llm/complete，thinking disabled；
  未知子模板按证据落定 + deterministic 假设定终态；write/destructive 类
  无可回放帧不得 confirmed）→ P8 离线终态（fuzz → fuzz-deferred-live）→
  P9 exp_gen + 工具生成 05 报告 → findings/config/P7-P9 阶段行/门事件/
  报告登记一次性回写 DB。门 G/H/I 判定与 gate.go 同规则复算。
- 增量可重跑：applicability 重生成不覆盖已终态假设；上轮无帧 confirmed
  会重置重裁；LLM 坏 JSON 重试一次。
- 结果：10 个老案例 P7 全过（static 5 个 P8/P9 全过并产出 05 报告）；
  新增确认漏洞 48 条、EXP 17 条；全库 60 confirmed / 359 假设。
  live 老案例按设计只到 P7（门 H 需 campaign≥1）。
- 新增 6 项纯函数单测（test_p769_offline.py）。

## [0.14.12-v2] - 2026-11-18

设计收紧：static（离线）模式不再执行 P8 campaign/fuzz。

- 依据全流程实测（案例 28）：static 无设备，fuzz 类假设只能
  inconclusive-offline，P8 还白建了 25 条离线重放语料 campaign 记录。
- P8 子代理提示词加模式分流：static 禁止执行任何 campaign、禁止构建离线
  重放语料；fuzz 类假设裁决 inconclusive（verdict=fuzz-deferred-live，注明
  需 live 复跑），deterministic 类按 P7 证据复核定终态，campaign 只写计划
  JSON；live 才按 campaign_runner 流程实际执行。子代理 focus 文案同步
  P7/P8/P9 模式分流。
- 门 H 分流：static 只要求假设全终态（不再要求 campaign≥1），live 维持
  campaign≥1；新增 TestGateHStaticVsLiveCampaignRequirement。
- 主控规则 13 与 P8 失败 hint 同步；P8 模板顺带修正 inconcomplete 错别字。
- 提示词总量压回 13500 预算内（13500→13487）；全部 Go 包测试通过。

## [0.14.11-v2] - 2026-11-18

漏洞与利用代码直观化：已确认漏洞卡片 + 假设可展开 + EXP 路径修复。

- 「已确认漏洞」卡片区（红色强调）：每条 confirmed 假设一张卡——名称/
  类别/风险/verdict 徽章、**verdict_reason 人话结论**、证据引用（pcap 帧
  定位等）、验证方案、直通「查看 EXP 脚本」按钮与 sha16。
- 「全部假设」表：confirmed 置顶，任意行点击展开判定规则/结论/证据/EXP
  入口/模板与时间。
- 修复 EXP 查看对真实 P9 数据失效的问题：P9 把脚本生成到
  `.runs/<阶段run>/exploits/`，登记的是绝对路径且重试后指向过期 run 目录。
  端点改为：接受绝对路径（workdir 前缀校验）+ 不存在时按文件名在
  exploits/ 与 .runs/*/exploits/ 回退查找（仍在 workdir 内）。
- 验证于案例 28 真实数据：12 张确认卡（含 TM221CE24B 匿名身份泄露结论）、
  EXP 弹窗取回 2941B 真实脚本（sha16 与登记一致）。

## [0.14.10-v2] - 2026-11-18

完成态竞态修复：最后阶段过门后案例可能永远卡在 running。

- 症状：案例 28（M221-2）P1-P9 九门全 PASS、主控已发总结（18:50），但案例
  状态 53 分钟后仍是 running，阻塞再次启动分析。
- 根因：完成检查只在门写入后做一次，而此时该阶段自己的 job 还在运行
  标记里 → 检查被跳过；兜底的主控 turn-end 回调又因主控协程已结束
  （重启/超时）不再触发。
- 修复：抽出 maybeCompleteProtocolCase，门写入后与 job finish 后双检查
  （AllPhasesPass && 无运行 job && 状态为 running 才翻转 done 并发事件）。
- 存量恢复：案例 28 状态手工翻转为 done（附恢复原因事件）。

## [0.14.9-v2] - 2026-11-18

漏洞知识库精简：剔除纯 IT 厂商条目（可复现）。

- vuln_knowledge 删除 851 行（18505→17654，CVE 13896→13193），黑名单
  34 家纯办公/端侧 IT 厂商（microsoft/google/oracle/intel/python/debian…）；
  14 类覆盖率微升至 97.4%。
- 刻意保留灰色地带：组件库（linux/openssl/curl/busybox/libexpat/xmlsoft/
  vnc/ntp 等——V8 固件与组件类的匹配目标）、网络边界厂商（cisco/fortinet/
  aruba/paloalto——OT 常见）、医疗设备商（icsvuln 原生收录）、全部
  空 vendor 行（均来自 plc-intel 工控源）。
- `tools/vuln_kb_import.py` 同步加 IT_VENDOR_EXCLUDE 过滤（--keep-it-vendors
  可关闭），重新导入不会带回噪音；新增 2 个过滤单测（共 10 项过）。

## [0.14.8-v2] - 2026-11-18

新增仪表盘：平台以「工控系统脆弱性分析与利用」整体姿态呈现。

- 后端 `GET /api/protocol/dashboard`（db.VulnDashboard 聚合）：跨案例
  findings JSONB 统计假设（按状态/14 类/风险）、EXP（按级别）、campaign
  （按模式）、审批队列（pending + 最近 6 条）、vuln_knowledge 规模与
  14 类覆盖率、最近 10 条流水、逐案例 P7-P9 姿态表。
- SQL 防御：findings 里的 JSON null 字面量（P7 未落section 时会写
  `"vuln_hypotheses": null`）不被 COALESCE 捕获，jsonb_array_elements
  会整查询报错导致全部计数静默归零——统一改 `jsonb_typeof` 门卫；
  `config->'vuln_enabled' = 'true'` 在键缺失时返回 SQL NULL，扫不进
  bool，包 COALESCE(..., false)。
- 前端 `/dashboard`：五指标卡、类别分布条形图+状态徽章、审批队列、
  最近流水（点击跳案例）、各案例挖掘态势表（P7/P8/P9 状态色块、
  confirmed/hyps、EXP 数）；侧边栏新增「总览」分组（仪表盘），根路由
  重定向 /protocol/cases → /dashboard。
- 新增集成测试 TestIntegrationVulnDashboard（JSON null + 正常数组双
  案例）；全部 Go 包测试通过。
- 首屏即真实数据：M221-2 案例 P7 已产出 40 假设/12 confirmed。

## [0.14.7-v2] - 2026-11-18

续跑修复：已过 P6 的案例开 vuln_enabled 后主控实际会继续 P7-P9。

- 根因：主控提示词 buildProtocolAgentPrompt 写死「完成 P1→P6」，V2 集成时
  未改——即使案例开了 vuln_enabled，主控也不知道要派发 P7-P9。
- 提示词按 vuln_enabled 分叉：目标 P1→P9，新增规则 12-14（P7 测绘工具链、
  P8 审批硬闸与 verify/fuzz、P9 exp_gen 与 05 报告），续跑指引「已通过
  P1-P6 的案例从 P7 开始，不要重跑」；非漏洞案例提示词与原来逐字一致。
- protocolPhaseNextHint 增加 P7/P8/P9 的通过/未通过指引（含门 G/H/I 补救
  动作），P6 通过后的 hint 按开关分流（继续 P7 vs 六阶段总结）。
- 完成态文案分流：六阶段全部通过 / P1-P9 全部通过（含漏洞挖掘与 EXP）；
  暂停原因同步分流。AllPhasesPass 已按 ActivePhaseOrder 校验（P7-P9 未过
  不会提前标 done）。
- 新增回归测试 TestMasterPromptVulnAware / TestPhaseNextHintVulnAware；
  Go 全部包测试通过。

## [0.14.6-v2] - 2026-11-18

工具链解析永久修复：config.json 写入 protocol.python / protocol.tshark。

- 症状：工具链页报 tshark、python:pefile/capstone 缺失。根因是绕过
  start-windows.ps1 直接启动 platform.exe 时没有 PROTOCOL_AGENT_*
  环境变量，python 退回 PATH 上的系统 Python313（无 pefile/capstone）、
  tshark 不在 PATH。实际上 runtime\python（3.10.11，pefile 2024.8.26 +
  capstone 5.0.7）与 runtime\wireshark\tshark.exe（3.0.6）一直都在。
- 修复：平台解析优先级为 env > config.json protocol 块 > PATH 默认，
  现把两个绝对路径固化进 platform\config.json，任何方式启动都生效。
- 验证：GET /api/protocol/tools/check → ready=true、missing=0，
  python/tshark 均指向 runtime 目录。

## [0.14.5-v2] - 2026-11-18

新建/编辑案例弹窗增加「启用漏洞挖掘（P7-P9）」开关。

- 新建案例弹窗：开关写入 `config.vuln_enabled`，创建即激活 P7-P9；
  未开启行为与原来完全一致（只做 P1-P6 协议逆向）。
- 编辑案例弹窗：开关回显当前值，可随时开/关（运行中修改不影响已完成阶段）。
- 清理：删除此前 UI 验证遗留的临时案例（v2-ui-verify-tmp ×2、v2-ui-e2e-tmp）。

## [0.14.4-v2] - 2026-11-18

漏洞挖掘视图演示补全：三类过程数据上界面 + EXP 脚本在线查看。

- `protocol-vuln-view.tsx` 新增三个板块（按 P7→P8→P9 动线排序）：
  适用性判定（47 子模板三态徽章 适用/不适用/待探测 + 统计行 + 待探测任务）、
  CVE 情报匹配（来源联通徽章 plc_intel/icsvuln/kb + merged CVE 表，取自
  findings.vuln_surface.intel_matches）、campaign 执行记录（模式徽章
  确定性验证/灰盒Fuzz、审批引用、发包数、红线/熔断/crash 标记与结果摘要）。
- EXP 资产表加「查看」按钮：`GET /api/protocol/cases/{id}/exploit?path=`
  端点（workdir 内相对路径强校验防穿越、256KB 上限）返回脚本内容，
  前端 Dialog 展示（sha16/字节数/复制按钮，ScrollArea 代码区）。
- 演示数据修复：案例 26 演示 findings 之前只注入 DB，被服务重启后的
  file→DB 同步覆盖；现以磁盘 findings.json 为正本注入（scripts/demo26_build.py，
  含适用性 10 模板、本地库 6 条真实 WAGO CVE、2 campaign、5 假设），
  并用 `exp_gen.py` 真实生成 2 个 EXP 脚本（case-26/exploits/）。
- 部署修复：start-windows.ps1 不带 `-DbPort 5433` 时会连 5432（ARTEX 的 PG）
  并在失败 finally 里把 5433 停掉——重启务必带 `-DbPort 5433`。
- 回归：tsc 零错、npm test 12 项过、Go server/db/protocol 包测试全绿。

## [0.14.3-v2] - 2026-11-18

前端 P7-P9 适配（漏洞挖掘视图，内嵌 UI 重建）。

- `protocol-api.ts`：新增 V2 类型（DeviceProfile/VulnHypothesis/ExploitAsset/
  ProtocolApproval）、`V2_PHASES` 与 P7-P9 的 `PHASE_META`（门 G/H/I）、
  `approvals/createApproval/decideApproval` 三个 API 封装。
- 新组件 `protocol-vuln-view.tsx`：设备能力矩阵（能力×三承载，证据引用）、
  漏洞假设列表（状态/风险/检测模式/审批标记徽章）、destructive 审批面板
  （列表+裁决，对接 operator 创建 / admin 裁决）、EXP 资产表；未开 vuln_enabled
  的案例显示引导提示。
- 案例详情页新增「漏洞挖掘」页签（会话状态机与报告之间）；阶段进度页按
  `config.vuln_enabled` 动态渲染 P7-P9 卡片；`GET /cases/{id}`（detail）与
  `/phases` 一致地合成 not_started 的 P7-P9 行。
- 构建链验证：npm ci → `tsc --noEmit` 零错误 → `npm test` 12 项全过 →
  `build:static`（264 文件）→ 拷入 `server/webui/dist` → `-tags embedui` 重建；
  部署后从平台端口验证内嵌 chunk 含漏洞挖掘组件；UI 数据源端到端断言
  （临时案例：detail phases 含 P1-P9 / findings.raw 可解析 / 审批创建→列表→
  裁决链全通）。
- 回归：Go 7 包全绿、Python 56 项全绿。

## [0.14.2-v2] - 2026-11-18

M2 首项：ARTEX-IOT 固件轨 API 桥（`tools/artex_bridge.py`，纯标准库）。

- `handoff`：从 findings 生成协议侧摘要（端口/协议/功能码锚点/解析组件聚焦指令）
  → `POST /api/tasks` 建任务（firmware_vendor/version 自动绑定）→ multipart 上传
  固件（sha256 判重）→ findings 登记 `vuln_surface.firmware_track.handoff`。
- `pull`：拉任务状态 / 组件清单（按固件 sha 过滤）/ 探索发现 / 反编译函数索引 →
  写 `firmware_track.pull`；组件自动生成 V8B 假设、ARTEX finding 生成带审批标记的
  定向假设（14 类关键词映射）。
- `campaign`：协议侧种子（probes 请求帧）× 反编译焦点函数（parse/recv/crc 类）→
  生成 campaign_runner 定向 campaign JSON（destructive，Guardian 默认开）。
- 鉴权：读 ARTEX `jwt.key` 自签 7 天服务 token（HS256/sub=ARTEX），不改用户密码。
- **WAGO 闭环实测**（对 8787 真实实例）：handoff 建任务 #1 + 固件上传成功 →
  pull 拉取写回 → campaign 生成（wago spec 握手帧种子）→ campaign_runner 无审批
  被硬闸拦截（exit 5）、显式批准后 dry-run 通过。
- 新增 5 项单测（token/摘要/映射/焦点筛选/campaign 生成），工具链累计 49 项全绿。
- **FX5U/MELSOFT harness spec**（`client_harness.py` 新 `melsec` 载体 + `fx5u` spec）：
  0x57xx/0xD7xx 21B 头（u16le len@19）、5a0000ff 开通道、identify/auth/session 三帧
  原样回放（case-19 真机 FX5U-32MR/ES live 验证帧）；+3 项单测（含 socketpair 收帧解析）。
- **次要攻击面探测** `tools/surface_probe.py`（V9/V12 执行工具，只读定向）：
  web（banner/管理路径关键词/浅层穿越）、snmp（默认团体字 sysDescr/private 可写告警）、
  enip（ListIdentity 单播设备识别）；结果写 `vuln_surface.secondary_scan`；+4 项单测
  （本地 HTTP/ENIP socketpair/findings 写回），工具链累计 56 项全绿。
- **前端数据链**：`GET /cases/{id}/phases` 与阶段快照按 `vuln_enabled` 合成 P7-P9
  not_started 行（含门 G/H/I），关掉开关自动回 P1-P6——案例详情阶段页签动态显示 V2 阶段；
  已用一次性案例（建→验→删）双向验证。
- 事故修复：一次重启误将 `PROTOCOL_AGENT_PG_DSN`（测试库）带入平台环境导致连错库，
  已用干净环境重启恢复；教训——启动平台前必须清空该变量。

## [0.14.1-v2] - 2026-11-18

M1 收尾：vuln_knowledge 语义层存量标注全链路。

- 新增 admin 端点 `POST /api/llm/complete`（单发补全，profile 引用、key 不出平台），
  支持按请求覆盖 `thinking_type/reasoning_effort`（推理模型思考烧光预算导致空正文的
  问题在端点层显式判错），配套 `agent.CompleteOnce` 原语。RBAC 仅 admin。
- 新增 `tools/vuln_kb_import.py`：读取 icsvuln（13,453 条 ICS 相关）与 plc-intel
  （5,052 条）→ CWE→14 类确定性归类（高置信 7,468）→ 关键词兜底（中/低置信）→
  幂等 upsert 入库；`--refine` 将非高置信条目分批（20 条/批）送平台 LLM 归类回写
  （逐批增量落盘防中断）。
- `vuln_intel.py` 新增 `--kb` 查询模式：直查平台 vuln_knowledge 语义层
  （vendor/product/protocol/vclass 过滤），P7 情报步骤三源合一。
- vuln_knowledge 表新增 `confidence/class_basis` 列（幂等 ALTER）。
- 存量导入结果：18,505 行 / 13,896 去重 CVE；确定性置信分布 high 7,468 /
  medium 3,818 / low 3,957 / unclassified 3,262；LLM 精修完成 6,322/7,219 条
  （361 批、5 批失败重试可补），最终 **vclass 覆盖率 97.3%**。

## [0.14.0-v2] - 2026-11-18

V2 第一批（PLAN-V2 M0 + P7/P8/P9 骨架全量落地）。漏洞挖掘阶段为案例级开关
（`config.vuln_enabled`，默认关闭，P1–P6 旧案例行为不变）。

### M0 前置修复

- **job 生命周期**：阶段 job 的 context 改挂 `context.WithoutCancel`（保留 values、
  剥离会话轮取消），主 Agent 轮结束不再腰斩后台子 Agent；`clearProtocolJobs`
  删除案例时同步取消运行中 job（`AbortTaskDeleted`），不再留孤儿。
- **tshark 响亮失败**：`frame_hypothesis.py`/`field_map.py` 检查 returncode/stderr，
  失败显式报错而非伪装"无发现"；统一 `encoding="utf-8"`；支持
  `PROTOCOL_AGENT_TSHARK` 环境变量。
- **client_harness 短帧加固**：wago/fins/umas 流程对短帧抛 `ShortResponse`
  （带帧内容），`post_ack` 恢复调用方超时而非固定 4s。
- **findings 覆盖保护**：`session_model.py`/`traffic_insights.py` 检测到其他阶段
  成果段时拒绝无 `--append` 整文件覆盖。

### P7–P9 漏洞挖掘阶段（Go 平台）

- 新增 `protocol_p7/p8/p9` 子 Agent（seed + 提示词；P8 预算 7200s），
  依赖链 P7←P6、P8←P7、P9←P8；`phaseOrder`/`gateOf` 扩展 G/H/I。
- 确定性门 G（画像+适用性全落态+直判全裁决）/ H（假设全终态+崩溃留档）/
  I（EXP 覆盖 write/destructive 确认项+05 号漏洞报告）。
- findings 新 section：`device_profile`、`vuln_surface`、`vuln_hypotheses`、
  `campaigns`、`crash_samples`、`exploit_assets`（P7–P9 所有权隔离 + 合并规则）。
- **审批硬闸**：新表 `protocol_approvals` + API（operator 建/查，admin 裁决，
  重复裁决 409）；`campaign_runner` 对 destructive campaign 强制校验审批
  （平台 API 或显式离线批准），LLM 无法绕过。新表 `vuln_knowledge`（CVE→14类语义层）。

### P7–P9 Python 工具链（tools/，零第三方依赖）

- `vuln_templates.py`：14 类 47 个子模板（前置条件谓词 DSL/风险级/直判|模糊）。
- `device_profile.py`：能力画像（traffic/live/static/inferred 证据分级，支持
  port_HEX/endpoints 等真实 findings 形态）。
- `applicability.py`：三态适用性评估 + 假设种子 + 探测任务生成。
- `vuln_intel.py`：plc-intel API + icsvuln SQLite 双库查询桥（协议字段精确匹配）。
- `campaign_runner.py`：verify/fuzz 双模式引擎——probe_dsl 变异内核（校验和自动
  修复）、响应分类器（错误码梯度伪覆盖）、UCB1 调度、黑名单静态校验、
  速率预算/熔断、Guardian 子进程监护、崩溃去重+复现×3+截断最小化。
- `guardian.py`：ping + 最小 SNMPv1 sysUpTime（重置=重启 oracle），红线退出码 2。
- `exp_gen.py`：confirmed 假设编译独立 EXP 脚本（授权横幅/参数化/结果 JSON），
  登记 `exploit_assets`。

### 验证

- Go 7 包全量测试通过（含 PG 集成，独立测试库）；Python 36 项测试通过（新增 15 项）。
- 真实案例（case-20 FX5U/SLMP）离线链路验证：画像提取 8 项能力，47 子模板
  → 29 applicable / 18 unknown（探测任务正确生成）。
- 审批流端到端冒烟通过（建→查→裁决→重复裁决拦截）。

## [0.13.7-engineering] - 2026-11-03

### 运维与测试

- 新增 `schema_migrations` 和编号迁移（`db/migrations/*.up.sql|down.sql`），
  平台启动自动执行；`cmd/migrate -status` 查看状态，`-down-to N` 回滚。
- 新增保留策略（默认关闭，按天配置）：`PROTOCOL_AGENT_RETENTION_*_DAYS`，
  清理 llm_records/llm_usage/tool_usage/protocol_events，并可清理旧 pcap。
- 新增每案例磁盘配额 `PROTOCOL_AGENT_CASE_DISK_QUOTA_MB`，默认 4096 MB，
  pcap/artifact 上传和后台抓包前检查。
- 新增 `scripts/restore.ps1` 备份恢复演练：`-VerifyOnly` 校验 dump，
  默认恢复到临时数据库后查询 agents 并清理。
- `doctor.py` 复用 Wireshark 路径发现；`capture.py` 通过 `tshark -D` 动态选网卡；
  `skill_dir` 相对路径改为按程序目录解析。
- 新增 Windows 服务安装脚本和 Linux systemd unit/安装脚本。
- 新增 Postgres 集成测试（findings 去重、phase jobs、LLM/tool usage、迁移状态），
  CI 增加 PostgreSQL service 和 integration step。
- 新增 Playwright E2E 配置与登录/案例/运行统计/报告用例（未设置环境变量时跳过），
  CI 增加 Playwright 用例列表校验。
- 新增大型会话性能测试（10000 对请求响应 <5s）和抓包网卡解析测试。
- 发布二进制统一以 `-tags embedui` 构建内嵌前端；`package-release.ps1`
  打包前校验二进制确实内嵌了 Web UI，防止再发布出“前端未内嵌”的 stub 版本。
- 新增 slim / windows-x64-full 初始化发行包与一键启动
  （`deploy/start-windows.ps1`、Dockerfile、docker-compose）。

### 验证

- Python 17 项测试通过；Go、前端测试通过。
- 本机迁移 v1/v2 已应用；Postgres 集成测试通过。
- 动态网卡抓包实测成功；doctor 正确识别 tshark。
- Golden 4 个案例本地检查通过；Playwright 4 个用例可列出。
- 发布二进制实测内嵌前端：`/setup` 与静态资源返回 200；
  full 包一键启动在隔离端口验证通过。

## [0.13.6-engineering] - 2026-11-03

### P1 分析深度

- 新增 `session_model.py`：请求-响应配对、会话、重试/超时、TCP 分片/重传、
  消息类型状态迁移和最小会话序列，结果写入 `notes(kind=session-model)`。
- `traffic_insights.py` 增强：CRC 参数集搜索、zlib/gzip/raw-deflate/bz2/lzma
  解压尝试、TLS 版本/SNI/握手类型、字段变异差分；CRC 识别支持初值/多项式/
  反射/异或/端序组合。
- 新增 `probe_dsl.py`：JSON 探针规格（帧字段、序列号、校验、timeout/retries/
  expected），默认 dry-run，write+ 才能 `--execute`；P5 先用状态迁移再逐状态验证。
- `ghidra_analyze.py` / `dotnet_analyze.py` 增加 SHA256 分析结果缓存，跨阶段/
  跨案例复用；新增 `analyzer_cache.py`。
- 新增 `protocol_knowledge` 表和 `protocol_lookup_knowledge` 工具：P6 通过门 F
  后自动写入端口/magic/帧/码表/状态机指纹；P1/P4 查询相似案例作为假设，必须用
  当前证据重新确认。
- 案例详情新增“会话状态机”页签，展示流、请求/响应数、重试/超时、TCP 空洞/重叠、
  状态迁移和最小会话序列。
- 新增 `examples/golden/manifest.json` 和 `tools/golden_check.py`；CI 增加 manifest
  校验，本地可用 `--check --data-root` 检查关键输出回归。

### 验证

- Python 测试 14 项通过；新增 session、CRC 参数、压缩、差分、DSL、缓存测试。
- Go、前端测试通过；工具链检查 missing=[]。
- Ghidra/ILSpy 缓存实测命中；案例 9 的 P4/P6 门禁仍通过。

## [0.13.5-engineering] - 2026-11-03

### 证据链与门禁

- 门 D 从“功能码 ≥1”收紧为“有指令级或流量出处的功能码占比 ≥60%”，并在
  gate evidence 中输出 instruction/traffic/sourced 数量与比例。
- 门 F 要求 01–04 四份文档齐全、每份至少两个 Markdown 标题、必填章节完整，
  并引用有效证据 ID：`[asset:<id>]`、`[code:<id>]`、`[frame:<id>]`、
  `[field:<id>]`、`[probe:<id>]`；01/02/03/04 至少各引用对应类型，合计 ≥8 个。
- 门 F 会校验引用 ID 是否属于当前案例 findings，失效引用直接拒绝。
- `verified` 仅对 `grade=live` 成立；static/inferred/traffic 不再显示“已验证”。
- UI 的等级徽章增加中文说明，inferred 明确标注“推断，未确认”。
- P6 提示词增加报告章节、证据 ID 引用和“推断不得写成已确认”的约束；
  提示词迁移版本提升到 v13。
- 为已有案例报告追加自动生成“证据索引”，案例 9/5/10 通过新门 F；案例 2 的
  04 字段划分文档本身内容不足，按新门禁保持失败，等待补写。

### 验证

- 案例 9 门 D：54/54 有出处（100%），其中 44 条指令级、30 条流量级。
- 案例 9 门 F：4 份文档、100 个有效证据 ID、0 个失效引用。
- 新增门 D 比例、`codeEvidenceKinds`、报告前缀和证据引用解析单测。
- Go、Python、前端测试全部通过。


## [0.13.4-engineering] - 2026-11-03

### 功能码归一化

- `protocol_function_codes` 新增 `code_key`，用原始功能码字符串（如 `0x58/0x39`）
  作为稳定身份，不再只依赖解析后的整数 `code`。
- 唯一键从 `(case_id, layer, code, label)` 改为 `(case_id, layer, code_key)`；
  删除会按 `(layer, code)` 抑制整个功能码族的 `WHERE NOT EXISTS semantic=true` 逻辑。
- P4/P6 同步时按 `code_key` 做 upsert，semantic 行保留人工/LLM 标签，非 semantic
  行随 findings 更新。
- 旧数据库启动时自动回填 `code_key`、去重并迁移唯一索引。
- 案例 9 归一化功能码从 42 条恢复为 54 条，`0x58` 族的 13 个子码完整保留；
  UI 优先显示原始子码写法（如 `0x58/0x01`）。

### 验证

- 新增 `codeKeyFor` 单测；连续两次导入案例 9 findings 均保持 54 条、20 条 semantic 行。
- Go、Python、前端测试全部通过。


## [0.13.3-engineering] - 2026-11-03

### 运行统计

- 修复 `llm_usage.session_id` 从未写入的问题；阶段子 Agent 和会话请求现在都会记录
  对应的 `proto-<case>-pN-...` / `conv-<id>` 会话。
- 案例详情“运行统计”的 LLM 用量表恢复按阶段 Agent 展示调用次数、输入/输出 token
  和缓存读 token。
- 回填历史阶段用量：按 `protocol_subagent_runs` 的时间窗口与 agent key 关联已有
  `llm_usage` 记录，案例 9 的 P1–P6 共 366 条记录已恢复归属。
- 新增 `llmrec` 会话覆盖测试和真实数据库写入校验。

### 验证

- 案例 9 的 `/api/protocol/cases/9/metrics` 返回 6 个阶段 Agent 的 token 统计。
- `llm_usage` 新写入行包含 `session_id`；历史回填后按阶段查询正常。
- Go、Python、前端测试全部通过。


## [0.13.2-engineering] - 2026-11-03

### 品牌统一

- 项目源码、文档、脚本、配置示例和前端界面统一使用 Protocol Agent 名称。
- Go 模块路径改为 `github.com/Autumn-27/protocol-agent`，启动入口改为
  `cmd/protocol-agent`；环境变量统一为 `PROTOCOL_AGENT_*`。
- 登录、初始化和密码重置的默认管理员用户名改为 `protocol`；旧管理员账号和审计记录已迁移。
- 前端登录 token、Cookie、聊天折叠状态和发送模式存储键改为 `protocol_agent_*`，
  旧登录状态需要重新登录。
- 离线分析器环境变量和 Ghidra 项目名改为 Protocol Agent；加密密钥派生保持
  与已有密文兼容，不破坏已保存的 LLM API Key。

### UI 中文化

- 齿轮“界面偏好”面板的主题、字体、布局、导航栏、侧边栏选项全部改为中文。
- 主题模式、主题预设、布局预设、侧边栏样式和折叠方式的中文标签统一。
- 字体名称、协议名、模型名等专有名词保留原文。

### 验证

- 源码、前端产物、配置示例和文档扫描无旧品牌字符串，文件名无旧品牌。
- 前端静态构建、Go 测试、Python 测试和 TypeScript 检查通过。
- 平台重启后登录页显示 Protocol Agent，`/api/auth/status` 正常。


## [0.13.1-engineering] - 2026-11-03

### P4 Ghidra 集成

- P4 子 Agent 任务头注入 `analyzer_bundle`、`ilspycmd`、`ghidra_analyze` 路径和
  `JAVA_HOME/DOTNET_ROOT/GHIDRA_HOME`，不再让子 Agent 自己猜 PATH。
- P4 提示词增加静态后端决策：.NET 用 ILSpyCmd；原生 PE/ELF 在符号剥离、码表位于
  间接跳转、需要 WSA send/recv xref、或存在多个候选二进制等复杂场景时优先 Ghidra。
- Ghidra 调用要求先分析 1–2 个关键二进制，Bash 设置 `timeout_ms=600000` 或后台运行；
  不可用、超时、目标过大或目标简单时记录 `ghidra-skipped` 并回退到 capstone。
- `ghidra_analyze.py` 捕获超时和异常，写入 `ghidra-timeout`/`ghidra-error` 备注，
  避免阶段因 Ghidra 失败直接中断。
- 提示词迁移版本提升到 `protocol_prompt_parallel_v12`；内置默认提示词自动更新，
  用户自定义提示词保留。

### 工具调用统计

- 恢复 `agent.ToolResolve` 接线：按 `tools` 表的启用状态和 Agent 绑定过滤工具，
  应用描述/参数覆盖与默认值注入。
- 恢复 `meterTool` 埋点：目录工具、核心工具、MCP/host 工具都写入 `tool_usage`；
  Skill 保留独立 `skill_usage` 统计，避免重复计数。
- “系统工具”卡片的调用次数恢复；核心工具（Read/Bash 等）显示在“实际调用结果”
  表中，但因没有 `tools` 表行，不会生成系统工具卡片。
- 工具页的 Agent 绑定、启停和描述覆盖现在会在运行时生效，不再只是保存到数据库。

### 验证

- Go 新增分析器路径解析、P4 提示词注入和 P4 Ghidra 决策测试。
- Go 新增 ToolResolve 测试：绑定/启停过滤、描述覆盖、默认值注入、调用计数与失败放行。
- Python 新增 Ghidra 超时回退测试；总测试数 6 项。


## [0.13.0-engineering] - 2026-11-02

### 工程质量

- 新增 Python analyzer 单测和 `scripts/test-all.ps1`；新增 GitHub Actions CI。
- 新增 `tools/requirements.txt`、`tools/doctor.py`；工具链页检查 pefile/capstone/tshark。
- LLM usage 增加 `session_id`；案例详情新增阶段运行统计与按 Agent token 汇总。
- 新增 `scripts/backup.ps1`，备份数据库、data、配置和密钥。
- LLM 录制页移除任务筛选/删除，改为 Agent + Session；新调用写入 agent key。
- 移除 browser MCP 与 playwright-cli Skill 的种子、授权和调用记录。

### 验证

- Python 5 项单测、Go 测试、TypeScript、npm 7 项测试通过。
- 工具链检查 ready=true；ILSpyCmd/Ghidra 自动发现；MCP 空、Skill 仅 protocol-reverse。
- pcap 质量、报告版本/批准、阶段 job 持久化回归通过。


## [0.12.0-legacy-cleanup] - 2026-11-02

### 清理

- LLM 录制页移除任务筛选/任务列/任务删除，改为 Agent + Session 视角。
- 移除旧 `LLMTask` 前后端类型与任务记录 API。
- 新 LLM 调用记录写入 agent key（protocol/protocol_pN），不再依赖旧 worker 解析。
- 删除内置 browser MCP、playwright-cli Skill、相关 Agent 可见性和调用记录。
- MCP/Skill 通用管理能力保留；MCP 页面现在为空，可按需手动添加。

### 验证

- `/api/mcp` 为空；`/api/skills` 仅 protocol-reverse。
- 数据库 browser MCP=0、playwright 可见性/usage=0。
- LLM 录制页构建产物包含 Agent/Session，不再包含“删除任务对话”。
- Go 构建/测试、TypeScript、Next 导出通过，服务已重启。


## [0.11.0-parallel-ops] - 2026-11-02

### 新增

- 阶段任务持久化表 `protocol_phase_jobs`：状态、结果、错误、起止时间可跨重启查询。
- 单阶段取消：`protocol_cancel_phase`、phase-jobs API、阶段卡片停止按钮。
- 重启恢复：遗留 running job 标记 cancelled，阶段中断可见。
- 提示词迁移只在仍为内置默认时覆盖，保留用户在 UI 的编辑。

### 验证

- 阶段 job 创建/完成/最近历史读取验证通过。
- cancel 无运行任务返回 409；工具列表包含 protocol_cancel_phase。
- 提示词 v11 已包含取消工具；Go 构建/测试、TypeScript、Next 导出通过。


## [0.10.1-offline-analyzers] - 2026-11-02

### 新增

- Windows x64 离线分析器包：Ghidra 12.2、JDK 25、.NET SDK 10.0.403、
  ILSpyCmd 11.2、全部分析脚本和启动/校验脚本。
- 平台自动发现 `offline/analyzers-win-x64`；包内 `activate.ps1` 仍可显式配置环境；
  `start-platform.ps1` 直接以该环境启动平台。
- 离线包 SHA256：`99c76311240b83ab0566ff8a4bea9a67ec1cb860dcd27481a676c71badd9d506`。

### 验证

- Ghidra 12.2 + JDK 25 对 WBCComm.dll 导出 1000 函数、200 外部符号、500 字符串。
- ILSpyCmd 11.2 + .NET SDK 10 对 .NET 程序集反编译并提取 184 个常量候选。
- 平台在离线包环境中工具链检查显示 ILSpyCmd/Ghidra 可用。


## [0.10.0-p3p4-depth] - 2026-11-02

### 新增

- ELF 分析后端 `elf_analyze.py`（纯 Python，符号/导入导出/通信关键词）。
- .NET 反编译后端 `dotnet_analyze.py`（ILSpyCmd）。
- Ghidra headless 桥接 `ghidra_analyze.py` + `GhidraExport.java`。
- IDA headless 桥接 `ida_analyze.py` + `ida_export.py`（需合法 IDA）。
- 流量洞察 `traffic_insights.py`：TLS/压缩/高熵特征、CRC 候选、消息状态转移。
- 安装/检测脚本与工具链页“可选分析后端”状态，缺失时自动回退。
- P1/P3/P4 提示词接入上述后端；提示词迁移 v10。

### 验证

- Python 脚本语法检查、binary_survey/dotnet_analyze/traffic_insights 实测。
- WAGO pcap 流量洞察生成状态机 notes；dotnet_analyze 对非 .NET DLL 正确回退。
- Go 构建/测试、TypeScript 通过。


## [0.9.0-p1-depth] - 2026-11-02

### 新增

- P2 pcap 质量评估：包数、时长、端点、协议和告警，详情页新增页签。
- P6 报告版本历史、双版本并排对比、人工批准（记录批准人和版本）。
- `tools/binary_survey.py`：覆盖 ELF/Mach-O/.NET/安装包/配置文件的静态侦察，
  支持 `--append`，P1/P4 提示词已接入。
- P3/P4 增加 .NET/ELF 专用工具（ilspycmd/dotnet/readelf/objdump/Ghidra/IDA MCP）
  的可选分析路线。
- 每案例阶段并发上限默认 4，可用 `PROTOCOL_AGENT_MAX_CONCURRENCY` 调整。

### 验证

- pcap 质量接口在 WAGO 案例返回 2 个 pcap、包数/时长/端点数据正常。
- 报告版本接口返回当前版本；P1 prompt 已包含 binary_survey。
- 工件上传、抓包、报告导出、案例编辑回归通过。
- Go 构建/测试、TypeScript、Next 静态导出通过。


## [0.8.0-p1-capabilities] - 2026-11-02

### 新增

- 案例编辑：名称、描述、安装目录、设备 IP、授权、P5 spec、通信 DLL。
- 工件上传：DLL/安装包/固件等保存到案例 artifacts；上传 DLL 自动更新
  `golden_artifacts.comm_dll`。
- 后台抓包：网卡列表、启动/停止/状态 API；详情页可选择网卡、过滤和时长，产物写入
  案例 pcaps/。
- P5 探针记录功能码并显示覆盖率。
- P6 报告打包 zip 下载。

### 验证

- 案例创建/编辑/工件上传/删除、抓包启动/超时/手动停止、报告 zip 内容均通过 API 验证。
- Go 构建/测试、TypeScript、Next 静态导出通过。


## [0.7.0-p0-security] - 2026-11-02

### 安全基础设施

- LLM API Key 改为 AES-256-GCM 加密存储，新增本地 `secret.key`；启动自动迁移旧明文 Key。
- 新增多用户 `users` 表与 admin/operator/viewer RBAC；旧单管理员密码自动迁移为
  Protocol Agent 管理员。JWT 带用户 id/角色，服务端按数据库当前角色鉴权。
- viewer 仅允许 GET；operator 可分析与配置；用户管理和审计仅 admin。
- 新增 `系统 → 用户`：新建、改角色、启停、重置密码；保护最后一个启用管理员。
- 新增 `audit_log` 与 `系统 → 审计`：记录非 GET 写请求、登录成功/失败、RBAC 拒绝。
- 新增 `-tls-cert/-tls-key` 与 `PROTOCOL_AGENT_TLS_CERT/KEY`，启用 TLS 1.2+ HTTPS。
- `reset-password.sh` 更新为 users 表，并确保 Protocol Agent 管理员启用。

### 验证

- API Key 加密/解密与旧明文迁移验证通过。
- 管理员/只读用户登录、RBAC 200/403、审计记录验证通过。
- 自签证书 HTTPS 健康检查通过。
- Go 构建/测试、TypeScript、Next 静态导出通过。


## [0.6.0-p0-hardening] - 2026-11-02

### 安全

- 授权级别改为工具层强制：主 Agent 禁用 Bash/Write/Edit；子 Agent 按
  read-only/write/destructive/full 拦截 Bash、文件写入和 MCP 浏览器交互。
- read-only 的 P5 只允许 client_harness identify/hello/poll/info 与被动抓包。
- 写/复位/擦除/刷写等命令按授权级别拒绝；拒绝事件写入案例日志。
- 文件写入限制在案例工作目录。

### 门禁与 findings

- 门 A–F 收紧：pcap 非空、确认帧、有出处功能码、live/有原因降级、四份文档。
- findings 增加 JSON 结构与数组元素校验。
- 并行合并增加阶段 section 所有权检查，越权写入直接失败。
- P5 提示词与门禁对齐：在线失败不得伪装成离线降级。

### 验证

- 新增授权命令、文件路径、findings 校验、越权 section、强化门禁单测。
- WAGO 金标准在新门禁下 P1–P6 全部通过。


## [0.5.1-p5-spec-optional] - 2026-10-30

### 变更

- `client_harness spec` 改为 P5 可选协议族提示，默认不再填 `wago`。
- 平台 `protocol.spec` 默认改为空；空/auto 时 P5 根据 pcap、DLL、端口和 findings
  自行判断，未知协议写自定义只读探针或静态降级。
- 新建案例 UI 标签、占位符和帮助说明同步更新。


## [0.5.0-parallel] - 2026-10-30

### 新增

- 阶段委派改为异步：`protocol_delegate_phase` 立即返回 `job_id`，主 Agent 可同时启动
  多个无依赖阶段。
- 新增 `protocol_wait_phases`，支持批量等待/查询阶段结果。
- P1/P2、已有 pcap 时的 P3 可并行；主 Agent 按数据依赖自行编排，不再固定线性顺序。
- 每个子 Agent 使用隔离的 findings 快照，服务端按阶段 section 合并，避免并行覆盖。

### 变更

- 主 Agent 与 P1–P6 提示词迁移为并行编排版本（`protocol_prompt_parallel_v5`）。
- `protocol_sync_findings` 支持 `path`/`phase`，合并隔离 findings。
- 协议工具数量变为 8。

### 验证

- 并行合并单元测试通过；Go 构建/测试通过。


## [0.4.2-llm-profile] - 2026-10-30

### 修复

- 修复 LLM 配置无法删除：旧删除事务仍查询已移除的 `tasks` 表，任何删除都会报错。
- 允许删除当前激活配置：删除后自动激活剩余配置中优先级最高的一个；删除最后一个配置时
  清空运行中的 provider，LLM 进入未配置状态。
- 编辑 LLM 配置时 API Key 留空不再发送空值，服务端保留原 Key；UI 增加“Key 已保存”
  提示，只有填写新值才覆盖。
- 删除配置前增加确认提示。


## [0.4.1-run-budget] - 2026-10-30

### 修复

- 修复阶段子 Agent 继承主 Agent 剩余墙钟预算、在流式输出阶段被匿名 deadline 打断的问题。
- 主 Agent 默认预算改为 4 小时/80 回合；阶段子 Agent 默认 20 分钟/60 回合。
- 新增 `run_hard_timeout` 命名硬超时（软预算 + 10 分钟），不再出现匿名
  `context deadline exceeded`。
- 子 Agent 脱离父级预算 deadline，但保留用户停止/进程退出等显式取消。
- 子 Agent 提示词注入本阶段预算，并要求批量执行、接近上限时先保存 findings 并报 partial。


## [0.4.0-agent-only] - 2026-10-30

### 变更

- 删除确定性 P1–P6 流水线：`/run`、单阶段运行、`/stop`、`protocol_run_phase` 工具及
  Runner 的阶段执行代码全部移除。
- 案例只能通过「启动 Agent 分析」由主 Agent 编排、P1–P6 子 Agent 执行。
- 阶段卡片改为只读进度；运行中禁用重复启动；案例状态自动维护
  `running → done/paused`。
- 子 Agent 提示词注入已解析的 Python/tshark/tools 路径，支持 Windows 直接调用。
- 服务重启自动收尾遗留 running 案例、阶段和子 Agent run。
- 修复旧库遗留复测触发器导致删除对话失败的问题。
- 文案与 API 文档同步为纯 Agent 驱动。

### 验证

- Go 构建/测试、TypeScript 检查、Next 静态导出通过。
- 旧确定性接口 404；协议工具从 8 个减为 7 个。
- 失败路径验证：Agent 启动后案例 `running`，会话结束未全通过转 `paused`。

## [0.3.1-cleanup] - 2026-10-30

### 变更

- 前端删除 181 个无引用的渗透/任务/审批/更新 API 方法，`types.ts` 从 1805 行裁剪到约 430 行。
- 删除 mock 演示子系统、审批 UI 残留、流量工具门控、Agent 触发字段和三个死工具库。
- 后端删除对话触发队列、selfupdate、计划引擎兼容层、任务型旁路问题分支和 Agent 触发列。
- 删除不可达的仪表盘 token 聚合与审批裁判统计。
- 恢复 `PUT /api/settings`，LLM 录制、LLM 轮询与绑定兜底开关重新可用。
- Agent 角色收敛为 `main` / `assistant` / `subagent`；启动时删除 `agents.trigger_*` 列。
- 删除过期 Docker/Compose/安装/更新文件；启动脚本改为直接 exec。

### 验证

- Go 构建/测试、TypeScript 检查、Next 静态导出均通过。
- 18 个页面全部 200；旧渗透 API 全部 404；通用与协议 API 认证后 200。
- 金标准 WAGO 案例重跑：P1–P6 全 PASS，2 资产 / 48 功能码 / 1 探针 / 4 文档。
- 数据库 33 张表、7 个 Agent、无触发列、无渗透表。

## [0.3.0-selective] - 2026-10-30

### 变更

- 恢复完整项目后，选择性删除渗透测试内容；保留通用 Agent / MCP / Skill / 工具 / LLM 能力。
- 内置 Agent 只保留协议主控 + 六个阶段子 Agent。
- 删除渗透前端页面、组件、导航与 API 路由。
- 删除渗透内置工具、`ToolSet` 领域工具和工具种子。
- 删除 `api-recon`、`scopesentry` Skill 与 ScopeSentry MCP 占位。
- 删除后端包：traffic、enrich、guard、intercept、evidence、notify、report。
- 删除渗透 DB store 与表；schema 仅保留通用与协议表。
- Manager 收敛为 PostgreSQL/LLM/WebSearch；不再启动任务引擎、调度器和通知投递器。
- 流量 MITM 默认关闭。

### 保留

- 协议案例、P1–P6、门 A–F、发现/报告、pcap 上传、实时日志、工作空间。
- 对话、Agent 管理、MCP、Skill、工具目录/自定义工具、LLM 配置/模型池/录制。

### 验证

- Go 构建通过；前端 20 页静态导出通过；二进制 29 MB。
- 金标准 WAGO 案例：P1–P6 全 PASS，2 资产 / 3 帧 / 48 码 / 1 探针 / 4 文档。
- 旧渗透 API 404；通用与协议 API 200。
- 数据库 33 张表；Agent 7 个；Skill 2 个；协议工具 8 个。