# ICS VulnAgent

**工控系统脆弱性分析与利用智能体**（ICS Vulnerability Analysis & Exploitation Agent）。

以私有协议逆向为基座，九阶段流水线把一台 PLC/DCS 设备从"协议未知"推进到
"漏洞确认 + 可复现 EXP"：

```
P1 资产侦察 → P2 流量获取 → P3 流量分析 → P4 静态分析 → P5 交叉验证 → P6 文档交付
                                    （私有协议逆向基座，门 A–F）
→ P7 漏洞面测绘 → P8 验证与 Fuzz → P9 EXP 与报告
                                    （脆弱性分析与利用，门 G–I）
```

## 核心设计

- **LLM 编排 + 确定性门控**：主控 Agent 按数据依赖并行调度九个子 Agent；
  每个阶段的"通过"由平台按结构化 findings 确定性判定（门 A–I），不信任
  LLM 自报。证据分级 `traffic > live > static > inferred`，推断不得写成已确认。
- **设备能力画像 × 三态适用性**：14 类漏洞 47 个子模板，按"能力 × 承载机制"
  矩阵判定 applicable / not_applicable / unknown（未知转探测任务），不假设
  每台设备都有全部攻击面。
- **双轨执行**：协议灰盒轨（全设备，语法/状态/伪覆盖引导的自研 campaign
  fuzz 引擎）+ 固件轨（可取固件设备，桥接 ARTEX-IOT 固件审计平台）。
- **本地 CVE 情报层**：plc-intel / icsvuln 双库 → `vuln_knowledge` 语义层
  （14 类标注），P7 按厂商/型号/协议匹配先验，不从零开始挖。
- **安全硬闸**：destructive 操作走 operator 申请 → admin 审批；campaign
  执行器内置黑名单静态校验；Guardian 以 SNMP sysUpTime 监测设备复位红线，
  触发即停。static（离线）模式不执行任何发包 campaign，fuzz 假设标记
  `fuzz-deferred-live` 待真机复跑。
- **EXP 由分析结果生成**：P9 的 `exp_gen.py` 从假设的证据帧（P2/P3/P4 提取
  的真实流量帧）编译零依赖 Python 脚本（replay/poc/chain 三级，自带
  `--dry-run`），不是从漏洞库搬运现成 EXP。

## 快速开始（Windows 10/11 x64）

```powershell
# 1. 安装后端依赖（PostgreSQL 17 / Python 3.10+pefile+capstone / tshark，一次即可）
powershell -ExecutionPolicy Bypass -File deploy\install-deps-windows.ps1

# 2. 启动（默认 :8787；与其他项目端口冲突时指定端口）
powershell -ExecutionPolicy Bypass -File deploy\start-windows.ps1 -Address ':8790' -DbPort 5433
```

首次访问进入 `/setup` 创建管理员，LLM API Key 在系统设置中配置。
新建案例时打开「启用漏洞挖掘（P7-P9）」开关即进入完整九阶段；不开则只做协议逆向。

已有 P1-P6 结果的案例可离线批量补齐 P7-P9（无设备、无子代理）：

```powershell
$env:ICS_AGENT_API_PASS = "<管理员密码>"
runtime\python\python.exe tools\p769_offline.py --static-old
```

## 仪表盘与产物

- **仪表盘**（`/dashboard`）：已确认漏洞、14 类分布、EXP 资产、审批队列、
  逐案例 P7-P9 姿态。
- **案例详情 → 漏洞挖掘**：设备能力矩阵、适用性三态、CVE 情报匹配、
  已确认漏洞卡片（判定结论 + 证据 + 一键查看 EXP 源码）、campaign 记录、
  destructive 审批面板。
- **交付文档**：01-04 协议逆向四份 + 05 漏洞利用与验证报告。

## 目录

```text
platform/       Go 平台 + Next.js 内嵌前端（-tags embedui 单二进制）
tools/          P1-P9 Python 工具链（画像/适用性/情报/campaign/Guardian/EXP/离线补齐）
scripts/        测试、备份/恢复、服务安装、打包
deploy/         Windows 依赖安装、一键启动、Docker
examples/       golden 案例期望值
runtime/        依赖安装后生成（pgsql/python/wireshark/git，不入库）
```

## 开发

```bash
cd platform && go test ./...
cd web && npm ci && npm test && npx tsc --noEmit
cd tools/tests && python test_v2_tools.py   # 及其余 test_*.py
```

完整检查见 `scripts/test-all.ps1`。设计文档见 `PLAN-V2.md`，
版本演进见 `platform/CHANGELOG.md`。

## 安全与许可

仅用于**授权范围内**的实验室设备安全研究、学术评测与防御加固。
禁止对未授权目标使用。详见应用内《使用须知与免责声明》。

AGPL-3.0（见 `LICENSE`）。实验室抓包样本（`*.pcapng`）与运行数据
（`platform/data/`、密钥文件）不随仓库分发。
