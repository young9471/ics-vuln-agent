#!/usr/bin/env python3
"""V2 漏洞检测子模板库（P7）：14 类 × 子模板，声明式定义。

每个子模板描述：风险级（read/write/destructive）、检测模式（deterministic=直判类
/fuzz=模糊类）、前置条件（对 device_profile 能力矩阵的谓词）、判定要素与探测计划。
配套 PLAN-V2.md §3.3/§3.4/§3.8。

前置条件谓词 DSL（由 applicability.py 求值）：
  {"cap": "memory_read", "via": "any"}   能力存在（via: protocol|service|physical|any）
  {"all": [pred, ...]} / {"any": [pred, ...]} / {"not": pred}
能力矩阵取值约定：None=未探测（→unknown）；空容器=已探测不存在；非空=存在（带证据）。
"""
import json
import sys

# ---------------------------------------------------------------------------
# 能力清单（与 device_profile.py 的矩阵行一致）
# ---------------------------------------------------------------------------
CAPABILITIES = (
    "identity_query", "status_query", "auth", "session_mgmt", "memory_read",
    "memory_write", "file_access", "program_transfer", "run_stop",
    "firmware_update", "firmware_binary", "protection", "time_sync",
    "discovery", "web_service", "ftp_service", "snmp_service",
    "telnet_service", "ssh_service", "shell", "force_table",
)

C1, C2, C3 = "信息泄露", "协议认证", "远程启停"
C4, C5, C6 = "内存读写", "控制逻辑篡改", "读写保护破解"
C7, C8, C9 = "拒绝服务", "固件与组件", "次要攻击面"
C10, C11, C12 = "重放与欺骗", "加密与降级", "发现协议滥用"
C13, C14 = "I/O与物理操纵", "工程侧客户端"

R, W, D = "read", "write", "destructive"

TEMPLATES = [
    # ---- 1 信息泄露（直判/只读） -------------------------------------------
    dict(id="V1A-anon-identity", vclass=1, vclass_name=C1, risk=R,
         detection="deterministic", cwe=["CWE-200"],
         name="匿名身份/版本/型号/安全状态泄露",
         requires={"cap": "identity_query", "via": "any"},
         plan="先从 P2 流量提取身份应答（零风险），再无会话发身份查询，"
              "对比工程软件可见信息集合；安全状态字段（Web/写保护开关）单列。",
         verdict="匿名通道返回版本/型号/安全状态任一字段即 confirmed。"),
    dict(id="V1B-anon-config-read", vclass=1, vclass_name=C1, risk=R,
         detection="deterministic", cwe=["CWE-200", "CWE-532"],
         name="匿名配置区读取（网络参数/工程名/历史凭据）",
         requires={"cap": "memory_read", "via": "any"},
         plan="只读扫描系统区/配置区（%SW、网关表、项目名区），标注匿名可读范围。",
         verdict="匿名读到配置内容即 confirmed，同时产出内存暴露地图。"),
    dict(id="V1C-error-oracle", vclass=1, vclass_name=C1, risk=R,
         detection="deterministic", cwe=["CWE-209"],
         name="错误消息差异化信息泄露",
         requires=None,
         plan="对同一字段发送边界内外取值，比较错误码/文案差异；记录可作 oracle 的差分。",
         verdict="错误内容随请求内部状态变化即 auxiliary 发现。"),
    dict(id="V1D-topology-leak", vclass=1, vclass_name=C1, risk=R,
         detection="deterministic", cwe=["CWE-200"],
         name="拓扑/邻居/网关信息泄露",
         requires={"any": [{"cap": "status_query", "via": "any"},
                           {"cap": "file_access", "via": "any"}]},
         plan="读状态区/路由表/邻居表，提取网络拓扑信息。"),

    # ---- 2 协议认证（直判） -------------------------------------------------
    dict(id="V2A-auth-not-enforced", vclass=2, vclass_name=C2, risk=W,
         detection="deterministic", cwe=["CWE-306", "CWE-862"],
         name="认证不执行（匿名特权操作）",
         requires={"any": [{"cap": "memory_write", "via": "any"},
                           {"cap": "program_transfer", "via": "any"},
                           {"cap": "run_stop", "via": "any"}]},
         plan="权限差分：不登录直接做写类/停机/下装操作； destructive 部分走审批后 verify。",
         verdict="匿名特权操作成功且状态 oracle 确认即 confirmed。"),
    dict(id="V2B-weak-default-creds", vclass=2, vclass_name=C2, risk=R,
         detection="deterministic", cwe=["CWE-798", "CWE-521"],
         name="弱/默认/硬编码凭据",
         requires={"cap": "auth", "via": "any"},
         plan="候选来源=P4 静态挖出的硬编码口令+厂商默认表+空口令；小规模尝试（限速）。",
         verdict="任一候选登录成功即 confirmed。"),
    dict(id="V2C-plaintext-password", vclass=2, vclass_name=C2, risk=R,
         detection="deterministic", cwe=["CWE-319"],
         name="口令明文/可逆传输",
         requires={"cap": "auth", "via": "any"},
         plan="纯流量判定：对 P2 登录帧做 field_map 分类，识别口令字段编码。",
         verdict="口令以明文或可逆编码出现即 confirmed（traffic 级证据）。"),
    dict(id="V2D-client-side-auth", vclass=2, vclass_name=C2, risk=W,
         detection="deterministic", cwe=["CWE-603"],
         name="客户端侧鉴权（服务器不校验）",
         requires={"cap": "auth", "via": "any"},
         plan="错误口令登录后立即做特权操作（读/写各一）。",
         verdict="服务器不拒绝即 confirmed。"),
    dict(id="V2E-session-defects", vclass=2, vclass_name=C2, risk=W,
         detection="deterministic", cwe=["CWE-384", "CWE-613"],
         name="会话管理缺陷（重用/固定/断链残留）",
         requires={"any": [{"cap": "session_mgmt", "via": "any"},
                           {"cap": "auth", "via": "any"}]},
         plan="会话号重放；登录前申请的会话登录后继续用；断链重连旧会话做特权操作。"),
    dict(id="V2F-no-bruteforce-lockout", vclass=2, vclass_name=C2, risk=R,
         detection="deterministic", cwe=["CWE-307"],
         name="暴力破解无锁定/限速",
         requires={"cap": "auth", "via": "any"},
         plan="连续 N 次错口令后测第 N+1 次的时延与结果；限速执行。",
         verdict="无任何锁定/延迟迹象即 confirmed。"),
    dict(id="V2G-self-declared-privilege", vclass=2, vclass_name=C2, risk=W,
         detection="deterministic", cwe=["CWE-285"],
         name="权限自声明被信任",
         requires={"cap": "auth", "via": "any"},
         plan="登录帧中客户端角色/权限字段改为最高权限再登录，随后做特权操作。"),

    # ---- 3 远程启停（destructive/审批） -------------------------------------
    dict(id="V3A-unauth-runstop", vclass=3, vclass_name=C3, risk=D,
         detection="deterministic", cwe=["CWE-862"],
         name="无鉴权远程启停",
         requires={"cap": "run_stop", "via": "any"},
         plan="Dummy 程序运行中；匿名/错口令发 STOP，三路 oracle（状态查询/Guardian 心跳/"
              "扫描指标）确认翻转，再 RUN 恢复。必须人工审批 + Guardian 在线。"),

    # ---- 4 内存读写 ---------------------------------------------------------
    dict(id="V4A-anon-memory-map", vclass=4, vclass_name=C4, risk=R,
         detection="deterministic", cwe=["CWE-200", "CWE-862"],
         name="匿名内存读测绘（内存暴露地图）",
         requires={"cap": "memory_read", "via": "any"},
         plan="只读地址空间扫描（各内存区×步长），产出匿名可读区地图。"),
    dict(id="V4B-anon-memory-write", vclass=4, vclass_name=C4, risk=W,
         detection="deterministic", cwe=["CWE-862"],
         name="无鉴权内存写（实验室标记区）",
         requires={"cap": "memory_write", "via": "any"},
         plan="仅写事先规划的安全暂存地址，写后读回校验；保护区内写入走审批。",
         verdict="读回一致即 confirmed。"),
    dict(id="V4C-oob-rw", vclass=4, vclass_name=C4, risk=D,
         detection="fuzz", cwe=["CWE-125", "CWE-787"],
         name="越界读/写（长度字段超范围）",
         requires={"any": [{"cap": "memory_read", "via": "any"},
                           {"cap": "memory_write", "via": "any"}]},
         plan="campaign fuzz：对 length 类字段做边界值族变异，oracle 看返回数据量与崩溃。",
         verdict="响应数据超出请求范围=confirmed 泄露；崩溃=转 P9。"),
    dict(id="V4D-zone-isolation", vclass=4, vclass_name=C4, risk=R,
         detection="deterministic", cwe=["CWE-284"],
         name="数据面/工程面内存隔离缺失",
         requires={"cap": "memory_read", "via": "any"},
         plan="用数据协议（如 Modbus）尝试读工程协议专属区（配置/程序/保护标志）。"),

    # ---- 5 控制逻辑篡改 -----------------------------------------------------
    dict(id="V5A-unauth-program-upload", vclass=5, vclass_name=C5, risk=R,
         detection="deterministic", cwe=["CWE-200"],
         name="无鉴权程序上载（工程窃取）",
         requires={"cap": "program_transfer", "via": "any"},
         plan="匿名发起上载，拿到工程即同时构成信息泄露+IP 窃取。"),
    dict(id="V5B-unauth-program-download", vclass=5, vclass_name=C5, risk=D,
         detection="deterministic", cwe=["CWE-284", "CWE-494"],
         name="无鉴权程序下载（逻辑篡改）",
         requires={"cap": "program_transfer", "via": "any"},
         plan="仿真器先行；真机仅 Dummy 程序：下装→重上载→字节级比对。必须审批。"),
    dict(id="V5C-tamper-check-bypass", vclass=5, vclass_name=C5, risk=D,
         detection="deterministic", cwe=["CWE-345"],
         name="程序完整性校验绕过",
         requires={"cap": "program_transfer", "via": "any"},
         plan="故意发校验和错误的程序块，PLC 接受即无完整性校验。必须审批。"),

    # ---- 6 读写保护破解 -----------------------------------------------------
    dict(id="V6A-protection-status", vclass=6, vclass_name=C6, risk=R,
         detection="deterministic", cwe=["CWE-200"],
         name="保护状态探测",
         requires={"cap": "protection", "via": "any"},
         plan="读保护等级/锁定位，记录保护面与空白面。"),
    dict(id="V6B-protection-bypass", vclass=6, vclass_name=C6, risk=W,
         detection="deterministic", cwe=["CWE-863"],
         name="保护旁路矩阵（空口令/失败后直操作/侧门）",
         requires={"cap": "protection", "via": "any"},
         plan="空/默认口令登录；登录失败后直接操作；第二通道（Web/Modbus/SNMP）尝试同一操作。"),
    dict(id="V6C-reboot-unprotected", vclass=6, vclass_name=C6, risk=D,
         detection="deterministic", cwe=["CWE-1188"],
         name="重启后保护默认关闭",
         requires={"cap": "protection", "via": "any"},
         plan="合法手段重启（或等待 Guardian 恢复窗口）后立即读保护状态。必须审批。"),
    dict(id="V6D-protection-flag-writable", vclass=6, vclass_name=C6, risk=W,
         detection="deterministic", cwe=["CWE-284"],
         name="保护配置位可被内存写够到（4+6 组合链）",
         requires={"all": [{"cap": "protection", "via": "any"},
                           {"cap": "memory_write", "via": "any"}]},
         plan="定位保护标志位地址，尝试标记写（仿真优先）；成立即组合链高影响。"),

    # ---- 7 拒绝服务 ---------------------------------------------------------
    dict(id="V7A-malformed-crash", vclass=7, vclass_name=C7, risk=D,
         detection="fuzz", cwe=["CWE-476", "CWE-400"],
         name="畸形帧崩溃/挂起/重启",
         requires=None,
         plan="campaign fuzz 全字段变异；oracle 多通道投票区分 crash/hang/reboot/降级。",
         verdict="sysUpTime 重置=重启；超时存活=hang；复现率×3。"),
    dict(id="V7B-resource-exhaustion", vclass=7, vclass_name=C7, risk=D,
         detection="deterministic", cwe=["CWE-400"],
         name="资源耗尽（会话表/重组队列）",
         requires=None,
         plan="受控并发建连至上限，观察新连接与旧会话行为；限速+Guardian+审批。"),
    dict(id="V7C-discovery-storm", vclass=7, vclass_name=C7, risk=D,
         detection="deterministic", cwe=["CWE-400"],
         name="发现协议风暴致 CPU 过载/重启",
         requires={"cap": "discovery", "via": "any"},
         plan="受控速率递增发现请求，Guardian 监控时延劣化；隔离网段执行，必须审批。"),

    # ---- 8 固件与组件 -------------------------------------------------------
    dict(id="V8A-hardcoded-creds", vclass=8, vclass_name=C8, risk=R,
         detection="deterministic", cwe=["CWE-798"],
         name="固件/厂商 DLL 硬编码凭据",
         requires={"cap": "firmware_binary", "via": "any"},
         fallback="无固件时降级到厂商 DLL/工程软件静态分析（P4）。",
         plan="字符串+反编译定位口令比较函数；发现的候选进入 V2B 验证。"),
    dict(id="V8B-outdated-components", vclass=8, vclass_name=C8, risk=R,
         detection="deterministic", cwe=["CWE-1104"],
         name="过时易攻击组件（busybox/openssl/httpd…）",
         requires={"cap": "firmware_binary", "via": "any"},
         plan="组件版本指纹比对公开 CVE 库（vuln_intel --component）。"),
    dict(id="V8C-debug-backdoor", vclass=8, vclass_name=C8, risk=R,
         detection="deterministic", cwe=["CWE-489"],
         name="调试后门服务/隐藏接口",
         requires=None,
         plan="画像端口扫描的非常见端口+固件服务清单交叉；telnet/UDP 后门口令探测。"),
    dict(id="V8D-unsigned-firmware-update", vclass=8, vclass_name=C8, risk=D,
         detection="deterministic", cwe=["CWE-494"],
         name="固件更新无签名校验",
         requires={"cap": "firmware_update", "via": "any"},
         plan="仿真环境构造固件下装观察行为，或静态分析更新流程校验逻辑（CRC=无签名）。"
              "必须审批。"),
    dict(id="V8E-unsigned-removable-boot", vclass=8, vclass_name=C8, risk=D,
         detection="deterministic", cwe=["CWE-494"],
         name="可移动介质自举无校验",
         requires={"cap": "firmware_update", "via": "physical"},
         plan="SD/记忆卡装载带修改的工程/固件，观察是否验签。必须审批。"),

    # ---- 9 次要攻击面 -------------------------------------------------------
    dict(id="V9A-web-surface", vclass=9, vclass_name=C9, risk=W,
         detection="deterministic", cwe=["CWE-22", "CWE-77"],
         name="嵌入式 Web 面（穿越/注入/弱会话/明文管理）",
         requires={"cap": "web_service", "via": "any"},
         plan="目录/路径穿越探测、默认凭据、HTTP 明文、nuclei 模板化扫描。"),
    dict(id="V9B-ftp-surface", vclass=9, vclass_name=C9, risk=W,
         detection="deterministic", cwe=["CWE-521"],
         name="FTP 服务（默认凭据/匿名访问）",
         requires={"cap": "ftp_service", "via": "any"},
         plan="匿名登录+默认凭据表；可写目录即高影响。"),
    dict(id="V9C-snmp-default-community", vclass=9, vclass_name=C9, risk=R,
         detection="deterministic", cwe=["CWE-798"],
         name="SNMP 默认团体字（public/private 读写）",
         requires={"cap": "snmp_service", "via": "any"},
         plan="v1/v2c 默认团体字 get/set 探测；write 团体字=高影响。"),
    dict(id="V9D-remote-admin-exposed", vclass=9, vclass_name=C9, risk=R,
         detection="deterministic", cwe=["CWE-489"],
         name="telnet/SSH 管理面暴露",
         requires={"any": [{"cap": "telnet_service", "via": "any"},
                           {"cap": "ssh_service", "via": "any"}]},
         plan="默认凭据尝试+版本漏洞匹配。"),

    # ---- 10 重放与欺骗 ------------------------------------------------------
    dict(id="V10A-privileged-replay", vclass=10, vclass_name=C10, risk=W,
         detection="deterministic", cwe=["CWE-294"],
         name="特权帧事后重放",
         requires=None,
         plan="从 P2 流量提取写类/启停帧，事后原样重发（probe_dsl --from-pcap + 时序）。",
         verdict="设备执行即 confirmed——与认证存在与否无关。"),
    dict(id="V10B-slave-spoofing", vclass=10, vclass_name=C10, risk=W,
         detection="deterministic", cwe=["CWE-290"],
         name="从站欺骗（假遥测注入 SCADA）",
         requires=None,
         plan="抢答主站轮询（比真 PLC 更快应答）；实验网内用测试主站验证。"),
    dict(id="V10C-session-predictable", vclass=10, vclass_name=C10, risk=W,
         detection="deterministic", cwe=["CWE-330"],
         name="会话号可预测/可复用",
         requires={"cap": "session_mgmt", "via": "any"},
         plan="多次建连观察会话 ID 分配规律；预测下一个并使用。"),

    # ---- 11 加密与降级 ------------------------------------------------------
    dict(id="V11A-no-encryption", vclass=11, vclass_name=C11, risk=R,
         detection="deterministic", cwe=["CWE-319"], absence_is_finding=True,
         name="全程明文（无任何加密）",
         requires=None,
         plan="纯流量判定：P2/P3 检查协议无 TLS/加密层。缺失本身即 confirmed。"),
    dict(id="V11B-crypto-downgrade", vclass=11, vclass_name=C11, risk=W,
         detection="deterministic", cwe=["CWE-757", "CWE-327"],
         name="加密可选时可降级协商",
         requires={"any": [{"cap": "auth", "via": "any"},
                           {"cap": "session_mgmt", "via": "any"}]},
         plan="客户端请求明文/低版本模式，观察服务器是否接受。"),
    dict(id="V11C-no-cert-validation", vclass=11, vclass_name=C11, risk=R,
         detection="deterministic", cwe=["CWE-295"],
         name="客户端不校验证书/自签证书",
         requires=None,
         plan="静态检查工程软件/客户端库证书校验逻辑（P4）。"),

    # ---- 12 发现协议滥用 ----------------------------------------------------
    dict(id="V12A-discovery-storm", vclass=12, vclass_name=C12, risk=D,
         detection="deterministic", cwe=["CWE-400"],
         name="发现洪泛致设备异常",
         requires={"cap": "discovery", "via": "any"},
         plan="受控递增广播发现；Guardian 监控。与 V7C 合并执行。"),
    dict(id="V12B-discovery-amplification", vclass=12, vclass_name=C12, risk=R,
         detection="deterministic", cwe=["CWE-406"],
         name="发现应答反射放大",
         requires={"cap": "discovery", "via": "any"},
         plan="测应答/请求字节比（放大比>1 且可伪造源即记录）。"),

    # ---- 13 I/O 与物理操纵 ---------------------------------------------------
    dict(id="V13A-direct-output-write", vclass=13, vclass_name=C13, risk=D,
         detection="deterministic", cwe=["CWE-862"],
         name="物理输出直写",
         requires={"cap": "memory_write", "via": "any"},
         plan="输出映像区写标记点，物理采样/输入回读确认。必须审批+采样硬件。"),
    dict(id="V13B-force-table", vclass=13, vclass_name=C13, risk=D,
         detection="deterministic", cwe=["CWE-862"],
         name="强制表（force）无鉴权可用",
         requires={"cap": "force_table", "via": "any"},
         plan="尝试匿名进入/退出 force 模式。必须审批。"),
    dict(id="V13C-time-tamper", vclass=13, vclass_name=C13, risk=W,
         detection="deterministic", cwe=["CWE-862"],
         name="时间同步篡改（协议内/SNTP 写）",
         requires={"cap": "time_sync", "via": "any"},
         plan="无鉴权写时钟，观察日志与时间逻辑影响；测试后恢复时间。"),

    # ---- 14 工程侧客户端（可选） ---------------------------------------------
    dict(id="V14A-project-file-parse", vclass=14, vclass_name=C14, risk=R,
         detection="deterministic", cwe=["CWE-502"],
         name="工程文件解析漏洞（打工程站）",
         requires=None,
         plan="P4 逆向工程软件文件解析路径；模糊工程文件喂给隔离工程站。可选排期。"),
]

BY_ID = {t["id"]: t for t in TEMPLATES}


# ---------------------------------------------------------------------------
# 谓词求值：True / False / "unknown"
# ---------------------------------------------------------------------------
def eval_node(node, matrix):
    if node is None:
        return True
    if isinstance(node, dict) and "cap" in node:
        row = matrix.get(node["cap"])
        if row is None:
            return "unknown"          # 未探测
        via = node.get("via", "any")
        carriers = [c for c in (row.get("protocol"), row.get("service"),
                                row.get("physical")) if c]
        if via == "any":
            return bool(carriers)
        return bool(row.get(via))
    if isinstance(node, dict) and "any" in node:
        vals = [eval_node(n, matrix) for n in node["any"]]
        if True in vals:
            return True
        if "unknown" in vals:
            return "unknown"
        return False
    if isinstance(node, dict) and "all" in node:
        vals = [eval_node(n, matrix) for n in node["all"]]
        if False in vals:
            return False
        if "unknown" in vals:
            return "unknown"
        return True
    if isinstance(node, dict) and "not" in node:
        v = eval_node(node["not"], matrix)
        return "unknown" if v == "unknown" else (not v)
    return False                      # 无法识别的谓词按不满足处理


def classify(template, matrix):
    """三态：applicable / not_applicable / unknown（→生成探测任务）。"""
    v = eval_node(template.get("requires"), matrix)
    if v is True:
        return "applicable"
    if v is False:
        return "not_applicable"
    return "unknown"


def missing_caps(node, matrix, out=None):
    """谓词树里取值为 unknown 的能力名（用于生成 P7a 探测任务）。"""
    if out is None:
        out = set()
    if node is None:
        return out
    if isinstance(node, dict) and "cap" in node:
        if matrix.get(node["cap"]) is None:
            out.add(node["cap"])
    elif isinstance(node, dict):
        for key in ("any", "all"):
            for n in node.get(key, []) or []:
                missing_caps(n, matrix, out)
        if "not" in node:
            missing_caps(node["not"], matrix, out)
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(description="列出/检索漏洞检测子模板")
    ap.add_argument("--class", dest="vclass", type=int, default=None)
    ap.add_argument("--id")
    ap.add_argument("--risk", choices=(R, W, D))
    ap.add_argument("--detection", choices=("deterministic", "fuzz"))
    args = ap.parse_args()
    out = TEMPLATES
    if args.vclass:
        out = [t for t in out if t["vclass"] == args.vclass]
    if args.risk:
        out = [t for t in out if t["risk"] == args.risk]
    if args.detection:
        out = [t for t in out if t["detection"] == args.detection]
    if args.id:
        t = BY_ID.get(args.id)
        print(json.dumps(t, ensure_ascii=False, indent=2) if t else "{}")
        return 0 if t else 1
    print(json.dumps({"count": len(out), "templates": out}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
