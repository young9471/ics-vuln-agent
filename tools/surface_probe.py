#!/usr/bin/env python3
"""P7a 次要攻击面探测（V9/V12 执行工具，PLAN-V2 §3.3 类 9/12）。

三个子命令（全部只读、定向单播/单连接，不做广播风暴）：
  web   HTTP banner/标题/Server 头 + 常见管理路径存在性 + 浅层路径穿越探测
  snmp  默认团体字探测（sysDescr/sysName/sysUpTime），复用 guardian 的 SNMPv1 实现
  enip  ENIP ListIdentity 单播发现（TCP 44818，设备型号/厂商清单）

输出 JSON；--findings 可选写入 vuln_surface.secondary_scan。
"""
import argparse
import datetime
import json
import socket
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F                      # noqa: E402

WEB_PROBE_PATHS = ("/", "/index.html", "/login.html", "/admin.html",
                   "/config.html", "/status.html")
TRAVERSAL_PROBE = "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def probe_web(host, port=80, timeout=4.0):
    out = {"surface": "web", "open": False, "findings": []}
    base = f"http://{host}:{port}"
    banner, title, server = "", "", ""
    for path in WEB_PROBE_PATHS:
        try:
            req = urllib.request.Request(base + path,
                                         headers={"User-Agent": "protocol-agent-probe"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "replace")
                out["open"] = True
                server = (server or r.headers.get("Server", "")).strip()
                low = body.lower()
                if "<title>" in low and not title:
                    title = body.split("<title>", 1)[1].split("</title>", 1)[0][:80]
                for kw in ("password", "login", "admin", "config"):
                    if kw in low:
                        out["findings"].append({"path": path, "keyword": kw,
                                                "note": f"管理面关键词 {kw}"})
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and path == "/":
                out["open"] = True
                out["findings"].append({"path": path, "note": f"受保护({e.code})"})
        except OSError:
            continue
    # 浅层路径穿越（只探测不利用：看是否 200 且含 passwd 特征）
    try:
        req = urllib.request.Request(base + TRAVERSAL_PROBE)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(1024).decode("utf-8", "replace")
            if "root:" in body:
                out["findings"].append({"path": TRAVERSAL_PROBE,
                                        "note": "路径穿越命中（passwd 可读）",
                                        "severity": "high"})
    except OSError:
        pass
    out["banner"] = {"server": server, "title": title}
    return out


def probe_snmp(host, communities=("public", "private"), timeout=2.0):
    from guardian import snmp_get
    out = {"surface": "snmp", "open": False, "communities": []}
    for comm in communities:
        desc = snmp_get(host, comm, "1.3.6.1.2.1.1.1.0", timeout=timeout)
        if desc is not None:
            out["open"] = True
            name = snmp_get(host, comm, "1.3.6.1.2.1.1.5.0", timeout=timeout)
            out["communities"].append({
                "community": comm,
                "sysdescr_raw": desc,
                "sysname_ticks": name,
                "write_default": comm == "private"})
    if out["open"] and any(c["write_default"] for c in out["communities"]):
        out["findings"] = [{"note": "private 默认团体字有效（可写）", "severity": "high"}]
    else:
        out["findings"] = []
    return out


def probe_enip(host, port=44818, timeout=2.0):
    """ENIP ListIdentity 单播（定向，非广播）。响应含设备厂商/型号。"""
    out = {"surface": "enip", "open": False, "findings": []}
    # 正确的 24B ENIP 头：cmd=0x0063(listIdentity) LE, len=0, session=0, status=0,
    # context=0, options=0
    req = (0x63).to_bytes(2, "little") + b"\x00\x00" + b"\x00" * 20
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            hdr = s.recv(24)
            if len(hdr) < 24:
                return out
            plen = int.from_bytes(hdr[2:4], "little")
            body = b""
            while len(body) < plen:
                chunk = s.recv(plen - len(body))
                if not chunk:
                    break
                body += chunk
        out["open"] = True
        # 响应里设备名是可读 ASCII；提取 productName 字段附近的可打印串
        ascii_run = b""
        best = b""
        for b in body:
            if 32 <= b < 127:
                ascii_run += bytes([b])
            else:
                if len(ascii_run) > len(best):
                    best = ascii_run
                ascii_run = b""
        if len(ascii_run) > len(best):
            best = ascii_run
        out["device_hint"] = best.decode("ascii", "replace")[:60]
    except OSError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser(description="次要攻击面探测（V9/V12，只读定向）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("web", "snmp", "enip"):
        p = sub.add_parser(name)
        p.add_argument("--host", required=True)
        p.add_argument("--port", type=int,
                       default={"web": 80, "snmp": 161, "enip": 44818}[name])
        p.add_argument("--timeout", type=float, default=3.0)
        p.add_argument("--findings", default=None)
    args = ap.parse_args()

    if args.cmd == "web":
        result = probe_web(args.host, args.port, args.timeout)
    elif args.cmd == "snmp":
        result = probe_snmp(args.host, timeout=args.timeout)
    else:
        result = probe_enip(args.host, args.port, args.timeout)
    result["ts"] = now()
    result["host"] = args.host

    if args.findings:
        data = F.load(args.findings)
        surface = data.get("vuln_surface") or {}
        scan = surface.setdefault("secondary_scan", [])
        scan = [s for s in scan
                if not (s.get("surface") == result["surface"]
                        and s.get("host") == result["host"])]
        scan.append(result)
        surface["secondary_scan"] = scan
        data["vuln_surface"] = surface
        F.save(args.findings, data)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
