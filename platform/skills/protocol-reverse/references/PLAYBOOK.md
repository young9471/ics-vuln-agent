# PLAYBOOK —— 工业私有协议逆向方法论手册

> 来源：WAGO/CODESYS、Schneider M580/TM221、Siemens S7-200 SMART、OMRON CP1L-E、
> Rockwell MicroLogix 等实战。本手册定义“怎么分析”；主控 Agent 负责编排，阶段子 Agent
> 负责执行，平台只按 findings 做确定性门判定。

---

## 0. 用法

- 每阶段开始读 §3 对应 SOP，异常先查 §4 坑清单；
- 所有结论必须带证据等级（§5），推进只看 §2 的门；
- 平台没有一键流水线：用 `protocol_delegate_phase` 下发阶段，子 Agent 只写隔离
  findings，服务端合并后再判门。

## 1. 输入 / 输出契约

**输入**：
| 项 | 必需性 | 说明 |
|---|---|---|
| 上位机安装目录 | 必需 | PE/.NET/ELF、配置、安装包来源 |
| 设备 IP | live 必需 | static 模式可空；live 模式建案时强制校验 |
| pcap | static 必需 | 可填服务器路径或建案后上传；live 可选 |
| 授权范围 | 必需 | `read-only` / `write` / `destructive` / `full`，即 H2 结论 |
| 通信 DLL | 可选 | 明确承载体时可缩短 P1 |

**输出**：`01_通信文件清单与架构`、`02_功能码表`、`03_帧格式详解`、`04_字段划分`
（门 F 必需）；可选 `可工作客户端`、Wireshark dissector。findings 是唯一证据源，
报告必须引用其中的证据。

## 2. 流程状态机与门

```
        ┌──────── P3 流量分析 ──门C──┐
P1 ─A→ P2 ─B→                        → P5 ─E→ P6 ─F
        └──────── P4 静态分析 ──门D──┘
```

- P3 与 P4 可并行：P3 只依赖 pcap，P4 只依赖 P1 的通信文件；两者互不读取对方结论。
- P5 依赖 P3+P4：先交叉佐证，再合并重写最终结果，最后按授权验证或降级。
- static：P2 只解析既有 pcap，P5 不连接设备；live：P2 可抓包，P5 可在线验证。
- **调度**：P1/P2 启动后不要等整批。`protocol_wait_phases` 多阶段默认任一完成即返回
  （`return_on_any=false` 才等全部），返回值 `ready_phases` 直接列出可启动阶段：
  P2 门 B → 立即 P3（不等 P1），P1 门 A → 立即 P4（不等 P2）。P5 等 P3+P4 都通过，
  P6 等 P5 通过。

| 门 | 准出条件（平台确定性判定） |
|---|---|
| A | `comm_assets` 中得分 >0 的资产 ≥1 |
| B | 至少 1 个存在的非空 pcap（`config` 引用或 `<workdir>/pcaps/`） |
| C | 确认帧 ≥1（`frames>0` 且有头长/魔数），且 traffic 功能码 ≥1 或 `session-model` ≥1 |
| D | 静态功能码（排除纯流量码）有指令级出处 ≥60%，且至少 1 条 |
| E | 每个最终码都有 verdict 一致的佐证、最终记录 ≥1，且 live 验证或带 reason 的降级 |
| F | 01–04 齐全、章节与证据引用通过；02 覆盖最终码 ≥60%、live 码引用 probe、冲突标“待验证”、降级注明原因 |

报告选取：同前缀多份时，平台优先**当前已审批**版本，其次**最近更新**版本。

## 3. 各阶段 SOP

### P1 资产侦察（recon_pe.py / binary_survey.py）

1. 目录全扫描（≤3 层），收集 exe/dll/ini/xml/cfg/安装包；
2. 通信嫌疑打分：导入 WS2_32/wsock32/mswsock（+30）、导出通信类符号（+20）、
   文件名含 comm/net/tcp/eth/gateway/driver（+10）、多目录同名 DLL 副本族（+5，MD5 去重）；
3. 配置文件解码：IP、端口（可能是十六进制 DWORD，如 0x0997=2455）、路由、驱动名；
4. 运行态确认：`netstat -ano` + 进程映射；谁持有到设备的连接，谁就是一手实现；
5. 安装包（MSI/NSIS/7z/ZIP/自解压）先解包；工具缺失记录回退，不伪造。

### P2 流量获取（capture.py）

- 已有 pcap：只认 `config.golden_artifacts`、`config.pcap`、`<workdir>/pcaps/`；
  命中即解析，**不要在本机磁盘搜索 pcap**；
- **live 且无 pcap**：后台启动
  `python <tools_dir>/capture.py watch --host <device_ip> --out <workdir>/pcaps/session.pcapng --duration 1800`；
  device_ip 未知则省略 `--host`；多网卡/空包用 `capture.py list` + `--interface`；
- **H1**：给操作者 2 分钟点击脚本（启动软件→打开工程→连接/登录→停留 30s→≥3 种操作→登出），
  强调“报错没关系，报错前的握手与请求同样有效”；
- 每 20–60 秒轮询 pcap 增长与 netstat；覆盖 ≥3 种操作后做 TCP/UDP 分层统计（老协议常走 UDP）；
- 等待操作者时 `status=partial` 并记录已有 pcap；只有抓包不可用才请求上传；
- **static**：只解析，禁止启动抓包；缺 pcap 报 fail。

### P3 流量分析（frame_hypothesis.py / field_map.py / session_model.py）★核心

> 只依据 pcap：推断功能码语义、帧格式、字段划分；不读 P4 静态结论。

1. 对每条流拟合 (魔数, 头长, 长度偏移/位宽, 端序, 偏置)；**全帧零重同步**才算确认；
2. 方向判别（tshark follow 缩进=Node1→Node0）；请求/响应配对；
3. **ACK/侧信道帧**：是否存在第二魔数（如 0x6666），漏掉会断连；
4. 隧道：外层服务码载荷内出现规律结构时递归内层；
5. 字段划分：按 (FC/通道/命令) 对齐样本，分类 `常量/长度/事务号/计数器/ASCII/变异数据`；
   每个字段必须带变异证据（N/N 样本规则），addr/count 语义命名标“推断”；
6. 功能码：按实际出现的码赋语义假设（读/写/登录/心跳/下载/启停），
   `layer/source="traffic"`、`grade=traffic|inferred`、evidence 带帧号/流号；
7. `session_model.py --pcap ... --findings ... --out ... --append` 生成请求-响应配对、
   重试/超时、状态迁移，写入 `notes(kind=session-model)`；
8. 高熵/TLS/压缩/校验异常时运行 `traffic_insights.py`（CRC 参数集、解压、字段变异）。

**门 C**：确认帧 ≥1 且 traffic 码或 session-model ≥1。

### P4 静态分析（extract_codes.py + Ghidra/ILSpy/IDA）★

> 只依据通信文件：推断功能码语义、帧格式、字段划分；不读 P3 流量结论、不发包。

1. 选承载体：优先符号可读的 DLL/EXE（C++ 导出类、调试字符串、.NET 元数据）；
2. 函数边界：导出表地址排序；无导出时用字符串入口日志锚定；
3. 提码模式：
   - A 码入缓冲区：`mov eax,imm` + `mov word ptr[..],ax`；
   - B 码作参数：公共发送/执行辅助函数的调用点 `push imm`；排除假立即数（0xff=超时），
     注意 capstone 个位数不加 0x 前缀；
   - C 跨模块命名：宿主按名导入厂商构造器（`??0C...@@`），码↔类名可直连；
4. 配置 blob：.rdata/.data 中的端口/Protocol-ID/校验长度/分片大小；**配置≠线上**；
5. 名字表：连续服务名串（阈值降到 3，避免漏 Run/Stop/Login）；名字表顺序≠码编号；
6. 复杂场景（无导出/加壳/码在间接跳转/需追 send-recv xref/多候选 DLL）优先 Ghidra；
   结果按 SHA256 缓存；不可用时用 capstone 定向反汇编，记 `ghidra-skipped` + reason；
7. 静态帧：从写缓冲 mov 序列/长度计算/魔数/校验调用推断头长/长度字段/端序；
   `frames=0`、`source="static"`、每条给 `key`；静态字段用 `off/size/class/values[]`。

**门 D**：静态码有指令级出处 ≥60%。

### P5 交叉验证（spec_match.py / client_harness.py / probe_dsl.py）★核心

**步骤 1：交叉佐证（必做）**
- P3 流量码 × P4 静态码逐码对照：matched / conflicting / single-source；
- 写 `notes(kind=code-reconciliation)`，items 或 pairs 每项
  `{code, traffic, static, verdict, note}`；**每个最终码都必须有 verdict 一致的佐证**。

**步骤 2：合并重写最终结果（同步时整段覆盖三区）**
- `function_codes`：一码一条，合并 label/evidence，标 verdict、verified、grade、source；
- `frame_formats`：一布局一条；流量帧保留 `frames>0/source=traffic`，静态帧保留
  `frames=0/source=static`；标 verdict，不留重复条目；
- `field_maps`：一方向/布局一条，字段统一 `off/size/class/values[]`；
- `notes(kind=session-model-final)`：payload 直接含 stream/states/transitions 或
  verified_transitions/summary（禁止再嵌套一层 payload），标已验证/未验证。

**步骤 3：动态验证或降级**
1. 读 `session-model`，按登录/心跳/下载/启停/登出顺序设计探针；
2. 协议族：先跑 `spec_match.py --findings <findings_path>`，按 recommended/score 选
   `client_harness.py --spec`；未知协议用 `probe_dsl.py`（先 `--dry-run`，write+ 才
   `--execute`）；
3. live 验证升级路径，**每级失败立即下探**：
   - L1 重放：原样重放帧（验证方向/会话依赖）；
   - L2 变异：改单字段观察响应（码在头还是载荷）；
   - L3 构造：按格式构造请求逐码触发（read-only 白名单；write/full 按授权做写/启停/下载）；
   - L4 真库驱动：32 位宿主加载厂商 DLL 调高层 API（需 WSAStartup、缓冲区清零、位数匹配）；
4. 探针纪律：每码之间状态轮询确认设备无损；记录成功/未实现/失聪/断连；
5. `mode=static`：不连接设备，写 `p5-degraded`（status=skipped，reason=static 模式）；
6. `mode=live`：设备不可达/失败写 `p5-degraded`（reason）或 `p5-live status=failed`，
   不得伪装降级；live 码必须能在 02 中对应 probe 证据。

**门 E**：每个最终码有 verdict 一致佐证、最终记录 ≥1，且 live 验证或带 reason 降级。

### P6 文档交付

1. 直接使用 P5 最终合并结果与 `session-model-final`；先读 code-reconciliation 与 probes；
2. 三源合流定名：操作对齐 > 二进制符号名 > 公开资料（可派 web 子代理检索）；
3. 用 `protocol_update_code` 更新 label/grade；`protocol_write_report` 写回四份文档：
   `01_通信文件清单与架构`、`02_功能码表`、`03_帧格式详解`、`04_字段划分`；
4. 证据引用优先业务键：`[asset:<path>]`、`[code:<code_key>]`、`[frame:<frame_key>]`、
   `[field:<map_key>]`、`[probe:<probe_key>]`；数字 ID 兼容。每份至少 1 个本类型引用，
   合计 ≥8 个有效引用；
5. 语义要求：02 覆盖最终码 ≥60%；live 码引用 probe；conflicting 标“待验证”；
   降级探针注明“降级/离线”与 reason；inferred 必须写“推断/未验证”；
6. 报告可在案例详情页“批准当前版本”；门 F 优先使用已审批版本。

## 4. 坑清单（症状 → 根因 → 对策）

| # | 症状 | 根因 | 对策 |
|---|---|---|---|
| 1 | 第一帧有响应，第二帧后连接被重置 | 漏了交换后的 ACK/侧信道帧（如 0x6666） | P3 强制检查第二魔数 |
| 2 | 所有功能码返回同一错误码 | 码放错层（头部字段可能是协议ID/版本） | L2 变异：改头不改载荷对比 |
| 3 | 校验怎么算都对不上 | 覆盖范围猜错，或线上无校验 | 找 DLL 校验函数看参数；试“无校验” |
| 4 | 配置里的协议ID/端口与线上不符 | 配置默认值 ≠ 实际使用值 | 以抓包为准，配置只作线索 |
| 5 | P/Invoke 调 DLL 立即崩溃 | 缓冲区未清零/未 WSAStartup/位数不符 | L4 预解三坑 |
| 6 | 字符串表缺 Run/Stop/Login | 最短长度阈值过高 | 阈值降到 3 |
| 7 | 功能码提取串到相邻函数 | 扫描窗口越过函数边界 | 导出表边界裁剪/首匹配 |
| 8 | 名字表序号与功能码对不上 | 名字表只是词汇表 | 只作定名候选，不做映射 |
| 9 | 目标描述文件全乱码 | 厂商加密格式 | 跳过并记“不承载协议” |
| 10 | 按“知名端口”扑空 | 厂商变种改用网关端口 | 以 netstat+抓包为准 |
| 11 | 多目录同名 DLL 分析不完 | 副本族 | MD5 去重 |
| 12 | 响应方向解析混乱 | tshark follow 缩进语义搞反 | 缩进=Node1→Node0 |
| 13 | 巨型 EXE 无从下手 | Delphi/加壳/静态链接 | 字符串/导入/RTTI 锚定局部 |
| 14 | 工具 --out/-w 崩溃或抓包失败 | 输出目录不存在 | 写文件前先建目录 |
| 15 | 帧拟合“巨帧”假阳性 | H 搜索范围从 8 起、无护栏 | H 从 4 起；均长 ≤1024B 且帧数 ≥3 |
| 16 | .NET/WPF + 原生 DLL 混合 | 单一 WinSock 启发式漏报 | 原生看导入导出、托管看元数据；RTTI 是命名金矿 |
| 17 | 工程协议不占独立端口 | 搭在标准载体上（UMAS over Modbus FC90） | 先做端口/FC 直方图，私有 FC 即入口 |
| 18 | 工具启动 NameError | 修坑时漏 import | 改动后先跑 `--help`/最小 smoke |
| 19 | netstat 线程崩溃、映射丢失 | 中文 Windows GBK 解码 | `encoding="utf-8", errors="replace"` |
| 20 | MBAP 重放全被拒 | canned PDU 已含 unit，组帧又追加 | 约定 PDU 含 unit；`FC|0x80,0x01` 是诊断信号 |
| 21 | 全端口扫描全假阴性 | 小型 PLC TCP 栈被并发压垮 | 工控探测 ≤10 并发 + 关键端口单连复测 |
| 22 | 拟合器“碎片”式过度切分 | 错位字节周期退化解 | 人工复核帧数/均长；手工零重同步是一审 |
| 23 | TCP 端口开放但抓不到会话 | 实际走 UDP（FINS/UDP 9600） | 同时看 conv,tcp 与 conv,udp；field_map 用 udp 模式 |
| 24 | Lua dissector 加载不生效/冲突 | Wireshark 旧插件抢注端口 | 检查 plugins 目录、去掉 stderr 抑制 |
| 25 | 同码在 P3/P4 重复或 verdict 对不上 | 未合并或佐证漏码 | P5 必须一码一条 + 全量佐证；门 E 校验覆盖/一致性 |
| 26 | 报告引用 ID 失效 | 历史版本依赖漂移 ID/预测未来 ID | 使用稳定业务键或当前 protocol_get_case ID，不预测 |
| 27 | 字段/状态机渲染不完整 | agent 输出形态漂移（offset/width、嵌套 payload） | 平台规范化 + 用标准键；异常形态先查 findings |
| 28 | 门 F 选中旧文档/旧引用 | 同前缀历史变体更长 | 门 F 取已审批/最新版本；清理历史变体 |

## 5. 证据分级与 findings 契约

等级（高→低）：`traffic`（真实流量）＞`live`（主动触发且合法响应）＞`static`（指令级
证据）＞`inferred`（证据支持的推断）。每条结论、每个功能码/字段都要带等级；inferred
不得写成已确认。

**findings sections 与归属**：
- P1：`comm_assets`、notes；
- P2：`streams`、notes；
- P3：`frame_formats`/`field_maps`/`function_codes`（source/layer=traffic）、`streams`、
  notes(session-model)；
- P4：`function_codes`（source=static-instruction）、`frame_formats`/`field_maps`
  （source=static，帧 frames=0、必须 key）；
- P5：重写上述三区为最终合并记录（verdict/verified/source）、`probes`、
  notes(code-reconciliation / session-model-final)；
- P6：`protocol_reports` 与功能码语义（label/grade）。

服务端会做形态规范化（丢弃空 kind notes、解包嵌套状态机 payload、统一字段键）与 notes
去重/限额；证据 ID 在同步之间保持稳定，跨重置建议用业务键。

## 6. 安全与授权

- `read-only`（默认）：只读探针与被动抓包；probe_dsl 只 dry-run；
- `write`：可写变量/参数、下载、启停、code/session；
- `destructive` / `full`：可复位/擦除/刷写等破坏类；full 必须实际执行需要的验证，不能
  降级成纯只读；
- 案例 authorization 就是 H2 结论，不再二次确认；超出授权必须停下说明；
- 平台按授权在工具层拦截越权命令（分段校验），被拒不要绕过；
- 探针单步、限速、可中止，前后设备状态快照；生产设备默认只读，状态复查不一致立即停止。

## 7. 人机协作点

| 点 | 时机 | 内容 |
|---|---|---|
| H1 | P2 | 2 分钟点击脚本（启动软件→工程→连接/登录→≥3 操作→登出），强调“报错没关系” |
| H2 | 建案时 | 授权范围确认（案例 authorization 即结论） |
| H3 | 任何时候 | 无法自动判别的对话框/异常，描述并请操作者复述 |

## 8. 判据速查

- 帧格式定稿 ⟺ 全帧零重同步；
- 隧道判定 ⟺ 外层服务码载荷内存在 `[前缀][子码]…` 且响应回显子码；
- 功能码有效性 ⟺ 响应含码回显 + 状态字段（区别于无响应=失聪）；
- “未实现” ⟺ 多个码返回同一状态码且无数据（如 0x8212）；
- 设备无损 ⟺ 前后只读状态码一致；
- 交叉佐证通过 ⟺ 每个最终码有 verdict 一致的 pair，且最终记录存在。

## 9. 工具索引

- 资产/静态：`recon_pe.py`、`binary_survey.py`、`elf_analyze.py`、`dotnet_analyze.py`、
  `ghidra_analyze.py`、`ida_analyze.py`、`extract_codes.py`；
- 流量/帧：`frame_hypothesis.py`、`field_map.py`、`session_model.py`、`traffic_insights.py`；
- 抓包/验证：`capture.py`、`spec_match.py`、`client_harness.py`、`probe_dsl.py`、
  `dll_driver.ps1`；
- 交付：`protocol_write_report`、`protocol_update_code`、`dissector_gen.py`（可选）。

## 10. 金标准案例摘要（回归基线）

- WAGO 750-8202 + CODESYS V2.3：TCP 2455（CCCC/6666，24B 头）+ TCP 6626
  （9×u16 头，协议 ID 0x1288）；60+ 码恢复，13 码 live；
- Schneider M580 / TM221：UMAS over Modbus 502 / FC90；内层 `[5A][通道][命令]`；
- Siemens S7-200 SMART：PPI over TPKT/COTP（TCP 102），响应子功能=请求+0x40；
- OMRON CP1L-E：FINS/UDP 9600（TCP 9600 开着但未用）；15 命令恢复；
- Rockwell MicroLogix 1400：PCCC over CIP over ENIP（TCP 44818）。