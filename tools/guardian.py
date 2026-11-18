#!/usr/bin/env python3
"""P8 设备监护服务（Guardian）：测试前快照、测试中健康监测、红线熔断。

监测通道：
  ping     系统 ping 子进程（可达性）
  snmp     最小 SNMPv1 GET sysUpTime（1.3.6.1.2.1.1.3.0）——重置 = 设备重启（最强 oracle）

事件类型：reachable / unreachable / snmp_reset（重启）/ snmp_fail / restored
退出码：0 正常结束；2 红线（连续不可达 ≥3 次，或发生 snmp_reset）。

用法：
  python guardian.py snapshot --host 192.168.1.10
  python guardian.py watch --host 192.168.1.10 --duration 600 --interval 3 \
      [--community public] [--json-out events.json]
"""
import argparse
import datetime
import json
import socket
import struct
import subprocess
import sys
import time

SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
RED_LINE = 2


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------- 最小 SNMPv1
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _encode_oid(oid):
    out = bytearray([0x2B])                       # 1.3 折叠
    for part in oid.split(".")[2:]:
        n = int(part)
        seg = [n & 0x7F]
        n >>= 7
        while n:
            seg.insert(0, 0x80 | (n & 0x7F))
            n >>= 7
        out.extend(seg)
    return bytes(out)


def _parse_asn1(data, pos=0):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length


def snmp_get(host, community, oid, timeout=2.0, port=161):
    """SNMPv1 GET → 数值（sysUpTime 为 timeTicks 整数）；失败返回 None。"""
    varbind = _encode_oid(oid) + b"\x05\x00"      # OID + NULL
    pdu = (_ber(0x30, _ber(0x02, b"\x01\x00") + _ber(0x04, community.encode())
                + _ber(0xA0, _ber(0x02, b"\x01\x00") + _ber(0x02, b"\x01\x00")
                       + _ber(0x02, b"\x01\x00") + _ber(0x30, varbind)))
           )
    msg = _ber(0x30, _ber(0x02, b"\x00") + pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, (host, port))
            data, _ = s.recvfrom(2048)
    except OSError:
        return None
    try:
        # 逐层剥到 varbind-list 里的值
        def walk(buf):
            tag, body, nxt = _parse_asn1(buf, 0)
            if tag in (0x30, 0xA0):
                inner = []
                p = 0
                while p < len(body):
                    t, b2, p2 = _parse_asn1(body, p)
                    inner.append((t, b2))
                    p = p2
                for t, b2 in inner:
                    if t in (0x30, 0xA0):
                        r = walk(_ber(t, b2))
                        if r is not None:
                            return r
                    if t in (0x41, 0x42, 0x43):     # TimeTicks/Counter/Gauge
                        return int.from_bytes(b2, "big")
                return None
            return None
        return walk(data)
    except (IndexError, ValueError):
        return None


def ping(host, timeout_ms=1000):
    """系统 ping 可达性（Windows -n 1 -w，Linux -c 1 -W）。"""
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host] if sys.platform == "win32" \
        else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 2).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def snapshot(host, community="public"):
    return {"ts": now(), "host": host,
            "reachable": ping(host),
            "snmp_uptime": snmp_get(host, community, SYSUPTIME_OID)}


def watch(host, duration, interval=3.0, community="public"):
    """监测循环。返回 (events, red_line_hit: bool)。"""
    events = []
    baseline_up = snmp_get(host, community, SYSUPTIME_OID)
    last_up = baseline_up
    consec_fail = 0
    red = False
    if baseline_up is not None:
        events.append({"ts": now(), "kind": "snmp_ok", "uptime": baseline_up})
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(interval)
        alive = ping(host)
        up = snmp_get(host, community, SYSUPTIME_OID)
        if not alive:
            consec_fail += 1
            events.append({"ts": now(), "kind": "unreachable", "consec": consec_fail})
            if consec_fail >= 3:
                red = True
                events.append({"ts": now(), "kind": "red_line", "reason": "unreachable x3"})
                break
        else:
            if consec_fail:
                events.append({"ts": now(), "kind": "restored"})
            consec_fail = 0
        if up is not None and last_up is not None and up < last_up:
            events.append({"ts": now(), "kind": "snmp_reset", "was": last_up, "now": up})
            red = True
            break
        if up is not None:
            last_up = up
    return events, red


def main():
    ap = argparse.ArgumentParser(description="设备监护 Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("snapshot")
    p1.add_argument("--host", required=True)
    p1.add_argument("--community", default="public")
    p2 = sub.add_parser("watch")
    p2.add_argument("--host", required=True)
    p2.add_argument("--duration", type=float, required=True)
    p2.add_argument("--interval", type=float, default=3.0)
    p2.add_argument("--community", default="public")
    p2.add_argument("--json-out", default=None)
    args = ap.parse_args()

    if args.cmd == "snapshot":
        print(json.dumps(snapshot(args.host, args.community), ensure_ascii=False))
        return 0
    events, red = watch(args.host, args.duration, args.interval, args.community)
    out = {"host": args.host, "events": events, "red_line": red, "ts": now()}
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
    print(json.dumps(out, ensure_ascii=False))
    return RED_LINE if red else 0


if __name__ == "__main__":
    sys.exit(main())
