---
name: protocol-reverse
description: 工业私有协议逆向案例需要按 P1-P6 状态机推进、判定门、解释 findings.json 或生成交付文档时调用。
mcps:
  - browser
---

# Protocol Reverse（工业私有协议逆向）

本 skill 与案例工作目录的 `findings.json`、`references/PLAYBOOK.md`、
`references/PROMPT.md` 配套使用。平台没有一键流水线：主控 Agent 编排，六个阶段子 Agent
执行，平台只按 findings 做确定性门判定。

## 何时使用

- 用户给出上位机安装目录、设备 IP、pcap 或通信 DLL，要求恢复私有协议；
- 需要判断某阶段能否进入下一阶段（门 A–F）；
- 需要给功能码/字段命名，或生成、润色四份交付文档；
- 需要解释某个工具失败、降级或结论可疑。

## 运行方式

1. 在案例详情点「启动 Agent 分析」，或调用：
   `POST /api/protocol/cases/{id}/agent-run`
2. 主控 Agent 的循环：
   - `protocol_get_case(case_id)` 读 phases/findings/reports，确认已有输入与已通过阶段；
   - `protocol_delegate_phase(case_id, phase, task, expected_output)` 异步下发阶段
     （同一阶段同时只允许一个 job）；
   - `protocol_wait_phases(case_id, phases=[...], timeout_seconds=...)` 取门结果；
   - 多阶段等待默认任一完成即返回（`return_on_any=false` 可等全部）；返回值里的
     `ready_phases` 直接给出当前可启动阶段：P2 门 B → P3（不等 P1），P1 门 A → P4
     （不等 P2）；P5 等 P3/P4 都通过，P6 等 P5 通过；
   - `passed=true` 启动下游；`passed=false` 只重试失败阶段并改写 task；同一阶段连续
     失败 2 次或出现 `needs_human` 时停止，向操作者说明缺什么。
3. 子 Agent 自行选择 Bash/Python/文件工具或现成脚本，只写隔离 findings；服务端合并后
   由平台判门。子 Agent 自报的 pass 不作为最终结论。

## 阶段与门（与平台实现一致）

| 阶段 | 职责与产出 | 门 |
|---|---|---|
| P1 资产侦察 | 从安装目录/安装包找通信承载体、端口与配置线索；写 `comm_assets`/notes | A：得分>0 的通信资产 ≥1 |
| P2 流量获取 | 按 mode 解析既有 pcap（live 无包时后台抓包 + H1 等待）；写 notes/streams | B：≥1 个非空 pcap（`pcaps/` 或 config 引用） |
| P3 流量分析 | **只依据流量**推断功能码语义、帧格式、字段划分、会话状态机 | C：确认帧 ≥1，且 traffic 功能码 ≥1 或 session-model ≥1 |
| P4 静态分析 | **只依据通信文件**推断功能码语义、帧格式、字段划分 | D：静态功能码有指令级出处 ≥60% |
| P5 交叉验证 | P3×P4 逐码佐证 → 合并重写最终结果 → 按授权动态验证或降级 | E：每个最终码有 verdict 一致的佐证、最终记录 ≥1，且 live 验证或带 reason 降级 |
| P6 文档交付 | 基于 P5 最终结果定名，生成 01–04 四份文档 | F：文档/章节/证据引用通过，且满足语义校验（覆盖、live→probe、冲突/降级标注） |

## 案例模式

- **live**：建案必须填设备 IP。P2 可后台抓包；P5 可按授权连接设备验证，设备不可达才降级。
- **static**：建案必须提供 pcap。P2 只解析既有包、禁止启动抓包；P5 不连接设备，
  写带 reason 的 `p5-degraded`。

## 执行原则

1. **先看状态再动手**：用 `protocol_get_case` 确认 phases/findings，门未通过不要跳下游。
2. **阶段边界清晰**：P3 不读 P4 静态结论，P4 不读 P3 流量结论；交叉只在 P5 做。
3. **证据分级**：`traffic` > `live` > `static` > `inferred`；`inferred` 不得写成已确认。
4. **最终结果只认 P5**：P5 会把帧/字段/功能码合并重写为单条最终记录并标 `verdict`；
   P6 不回到 P3/P4 中间态。
5. **安全**：案例 authorization 就是操作者的 H2 授权范围；read-only 只读，write 可写，
   destructive/full 可破坏类；越权由平台工具层拦截，不要绕过；探针单步、前后快照。
6. **同一阶段连续失败 2 次**：停止并输出卡点报告（现象/已试/假设），请求人工介入（H3）。

## 工具速查

- P1：`recon_pe.py`、`binary_survey.py`、`elf_analyze.py`、`dotnet_analyze.py`、
  `ghidra_analyze.py`、`ida_analyze.py`
- P2：`capture.py`（watch/list/ports）
- P3：`frame_hypothesis.py`、`field_map.py`、`session_model.py`、`traffic_insights.py`
- P4：`extract_codes.py`、Ghidra/ILSpy/IDA 桥接
- P5：`spec_match.py`、`client_harness.py`、`probe_dsl.py`、`dll_driver.ps1`
- P6：`protocol_write_report`、`protocol_update_code`；`dissector_gen.py` 可选

## 参考

- `references/PLAYBOOK.md`：完整 SOP、判据、坑清单、安全框架。
- `references/PROMPT.md`：主控提示词参考（编排、门、停止条件）。