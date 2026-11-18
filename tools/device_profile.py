#!/usr/bin/env python3
"""P7a 设备能力画像：把 P1–P6 findings + 可选主动探测归并为能力矩阵。

能力矩阵是 applicability.py 三态判定的输入。行=能力（vuln_templates.CAPABILITIES），
列=承载机制（protocol/service/physical），值=证据引用列表（带 grade）。
取值约定：能力缺失（键不存在）=未探测 unknown；空列表=已探测不存在；非空=存在。

证据来源与等级：
  traffic  P2 流量里实际出现过的操作/服务（comm_assets、function_codes）
  live     主动探测结果（--scan / --identity-json / probes）
  static   P1 工程软件指纹、P4 静态结论（notes）
  inferred 关键词启发（待 P5 主动确认）

用法：
  python device_profile.py --findings <findings.json> [--host 192.168.1.10]
      [--scan-ports 21,22,23,80,443,502,102,44818] [--snmp-probe]
      [--identity-json '{"vendor":"WAGO","model":"750-8202","firmware":"14"}']
"""
import argparse
import datetime
import json
import re
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F            # noqa: E402
from vuln_templates import CAPABILITIES  # noqa: E402

# TCP 端口 → (服务能力, 备注)。工控 + 管理面（PLAN-V2 §3.6/§9 类）。
PORT_CAPS = {
    80: ("web_service", "http"), 443: ("web_service", "https"),
    21: ("ftp_service", "ftp"), 22: ("ssh_service", "ssh"),
    23: ("telnet_service", "telnet"), 2222: ("ssh_service", "ssh-alt"),
    161: ("snmp_service", "snmp/udp-tcp"), 162: ("snmp_service", "snmp-trap"),
    44818: ("identity_query", "enip"), 8080: ("web_service", "http-alt"),
}
DEFAULT_PORTS = "21,22,23,80,443,135,502,102,1200,1211,44818,2222,8080"
ICS_PORTS = {502, 102, 44818, 9600, 1200, 1211, 1217}

# function_codes/notes 关键词 → 能力（inferred 级，待 P5 确认）。
KEYWORD_CAPS = [
    (("stop", "run", "start", "启停", "运行控制"), "run_stop"),
    (("password", "login", "auth", "口令", "登录", "密码"), "auth"),
    (("upload", "download", "program", "上载", "下载", "工程", "项目"), "program_transfer"),
    (("write", "写入", "写"), "memory_write"),
    (("read", "读取", "读"), "memory_read"),
    (("identity", "version", "model", "识别", "版本", "型号"), "identity_query"),
    (("status", "state", "状态"), "status_query"),
    (("time", "clock", "时钟", "时间"), "time_sync"),
    (("protect", "lock", "keyword", "保护", "锁定", "口令保护"), "protection"),
    (("session", "会话"), "session_mgmt"),
    (("force", "强制"), "force_table"),
    (("firmware", "update", "升级", "固件"), "firmware_update"),
]
SERVICE_KEYWORDS = [
    (("web", "http", "网页"), "web_service"),
    (("ftp",), "ftp_service"),
    (("snmp",), "snmp_service"),
    (("telnet",), "telnet_service"),
    (("ssh",), "ssh_service"),
]


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def ev(ref, grade):
    return {"ref": ref, "grade": grade}


def put(matrix, cap, via, ref, grade):
    row = matrix.setdefault(cap, {"protocol": [], "service": [], "physical": []})
    if via not in row:
        row[via] = []
    row[via].append(ev(ref, grade))


def scan_tcp(host, ports, timeout=1.5):
    """主动 TCP 连接扫描 → {port: open}。"""
    out = {}
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                out[p] = True
        except OSError:
            out[p] = False
    return out


def keyword_hits(text):
    text = text.lower()
    caps = set()
    for kws, cap in KEYWORD_CAPS:
        if any(k in text for k in kws):
            caps.add(cap)
    return caps


def parse_ports_from_text(*texts):
    """从 evidence/endpoints 等自由文本里提取端口号。

    真实 findings 里的形态：evidence 列表含 "port_HEX1388"（MELSEC 5000）、
    streams.endpoints 形如 "192.168.1.101:2145 <-> 192.168.1.10:5000"。
    """
    out = set()
    for t in texts:
        if not t:
            continue
        s = str(t)
        for m in re.finditer(r"port_HEX([0-9a-fA-F]+)", s):
            out.add(int(m.group(1), 16))
        for m in re.finditer(r":(\d{2,5})(?:\D|$)", s):
            p = int(m.group(1))
            if 0 < p < 65536:
                out.add(p)
    return out


def build(findings_path, host=None, ports=None, snmp_probe=False, identity=None):
    data = F.load(findings_path)
    matrix = {}
    facts = {"vendor": None, "model": None, "firmware": None, "os": None,
             "device_ip": None}
    if identity:
        for k in ("vendor", "model", "firmware", "os", "device_ip"):
            if identity.get(k):
                facts[k] = identity[k]

    # --- traffic 级：comm_assets/streams 的端口与协议线索（P2 实证） -----------
    ports_seen_traffic = set()
    proto_hints = set()
    for a in data.get("comm_assets", []):
        ev = a.get("evidence") or []
        if not isinstance(ev, list):
            ev = [ev]
        ports_seen_traffic |= parse_ports_from_text(*ev)
        for key in ("dst_port", "src_port", "port"):     # 显式整型端口字段
            v = a.get(key)
            if isinstance(v, int):
                ports_seen_traffic.add(v)
        for e in ev:
            e = str(e).upper()
            if any(k in e for k in ("SLMP", "MELSEC", "MODBUS", "S7", "UMAS",
                                    "ENIP", "FINS", "CODESYS", "ETHERNET/IP")):
                proto_hints.add(e.split("_")[0])
        ip = a.get("device_ip") or a.get("dst_ip")
        if ip and not facts["device_ip"]:
            facts["device_ip"] = ip
    for s in data.get("streams", []):
        ports_seen_traffic |= parse_ports_from_text(s.get("endpoints"))
    for p in sorted(ports_seen_traffic):
        cap = PORT_CAPS.get(p)
        if cap and p not in (161, 162):          # TCP 流量才作数
            put(matrix, cap[0], "service", f"traffic:port:{p}", "traffic")
        elif p in ICS_PORTS or p >= 1024:
            put(matrix, "identity_query", "protocol",
                f"traffic:port:{p}", "traffic")
    if proto_hints:
        put(matrix, "identity_query", "protocol",
            f"traffic:proto:{sorted(proto_hints)}", "traffic")
        put(matrix, "memory_read", "protocol",
            f"traffic:proto:{sorted(proto_hints)}", "inferred")

    # --- traffic/inferred 级：function_codes 语义启发 ------------------------
    for fc in data.get("function_codes", []):
        label = " ".join(str(fc.get(k, "")) for k in
                         ("label", "name", "note", "desc", "summary", "code"))
        for cap in keyword_hits(label):
            put(matrix, cap, "protocol",
                f"function_code:{fc.get('code', fc.get('id', '?'))}:{label[:40]}", "inferred")

    # --- static 级：notes 关键词（P1/P4 结论） -------------------------------
    for n in data.get("notes", []):
        text = " ".join(str(n.get(k, "")) for k in ("note", "text", "title", "kind"))
        for kws, cap in SERVICE_KEYWORDS:
            if any(k in text.lower() for k in kws):
                put(matrix, cap, "service", f"note:{str(n.get('note', text))[:60]}", "static")
        if "固件" in text or "firmware" in text.lower():
            put(matrix, "firmware_binary", "physical", f"note:{text[:60]}", "static")

    # --- live 级：主动扫描 ----------------------------------------------------
    scanned = {}
    if host and ports:
        scanned = scan_tcp(host, ports)
        for p, open_ in scanned.items():
            if not open_:
                continue
            cap = PORT_CAPS.get(p)
            if cap:
                put(matrix, cap[0], "service", f"scan:tcp:{p}({cap[1]})", "live")
            else:
                put(matrix, "status_query", "service", f"scan:tcp:{p}", "live")
        # 工控协议端口开放 ⇒ 协议面存在（identity/memory 至少待确认）
        ics = ICS_PORTS & {p for p, o in scanned.items() if o}
        if ics:
            put(matrix, "identity_query", "protocol",
                f"scan:ics-port:{sorted(ics)}", "live")
            put(matrix, "memory_read", "protocol",
                f"scan:ics-port:{sorted(ics)}", "inferred")
        if host:
            facts["device_ip"] = facts["device_ip"] or host
    if snmp_probe and host:
        try:
            from guardian import snmp_get          # 延迟导入，保持可独立运行
            up = snmp_get(host, "public", "1.3.6.1.2.1.1.3.0", timeout=2.0)
            if up is not None:
                put(matrix, "snmp_service", "service", "probe:snmp:sysUpTime", "live")
                put(matrix, "status_query", "service", "probe:snmp:sysUpTime", "live")
        except Exception:
            pass

    # --- live 级：probes（P5 结果） ------------------------------------------
    for pr in data.get("probes", []):
        kind = str(pr.get("kind", ""))
        if "identity" in kind or "info" in kind:
            put(matrix, "identity_query", "protocol", f"probe:{pr.get('id', '?')}", "live")
        if "status" in kind:
            put(matrix, "status_query", "protocol", f"probe:{pr.get('id', '?')}", "live")

    # --- 固件可得性判定 -------------------------------------------------------
    firmware_obtainable = "none"
    if matrix.get("shell", {}).get("service") or matrix.get("shell", {}).get("protocol"):
        firmware_obtainable = "shell"
    elif matrix.get("firmware_binary"):
        firmware_obtainable = "image"
    elif matrix.get("firmware_update"):
        firmware_obtainable = "update-package"

    tracks = ["protocol"]                          # 协议轨全设备
    if firmware_obtainable != "none":
        tracks.append("firmware")

    # 未涉及的能力显式置 None（unknown 语义由缺键表达）
    profile = {
        "ts": now(),
        "facts": facts,
        "matrix": matrix,
        "ports_scanned": scanned,
        "firmware_obtainable": firmware_obtainable,
        "tracks": tracks,
        "grade_note": "inferred 条目需 P5 主动确认后方可支撑 confirmed 结论",
    }
    return profile


def main():
    ap = argparse.ArgumentParser(description="设备能力画像（P7a）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--host", default=None, help="主动扫描目标 IP（缺省仅归并 findings）")
    ap.add_argument("--scan-ports", default=DEFAULT_PORTS)
    ap.add_argument("--snmp-probe", action="store_true", help="UDP SNMP sysUpTime 探测")
    ap.add_argument("--identity-json", default=None,
                    help='人工事实 {"vendor":..,"model":..,"firmware":..}')
    args = ap.parse_args()

    ports = None
    if args.host:
        ports = [int(x) for x in args.scan_ports.split(",") if x.strip().isdigit()]
    identity = json.loads(args.identity_json) if args.identity_json else None

    profile = build(args.findings, args.host, ports, args.snmp_probe, identity)
    data = F.load(args.findings)
    # 画像整节替换（每次重新测绘）
    data["device_profile"] = profile
    F.save(args.findings, data)
    caps_present = sorted(c for c, row in profile["matrix"].items()
                          if any(row.get(v) for v in ("protocol", "service", "physical")))
    print(json.dumps({
        "findings": args.findings,
        "capabilities_present": caps_present,
        "firmware_obtainable": profile["firmware_obtainable"],
        "tracks": profile["tracks"],
        "ports_open": sorted(p for p, o in profile["ports_scanned"].items() if o),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
