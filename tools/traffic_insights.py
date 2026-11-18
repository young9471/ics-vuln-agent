#!/usr/bin/env python3
"""P3 traffic insights: obfuscation signatures, CRC candidates and a rough state model.

This tool is intentionally heuristic. It does not claim a protocol is encrypted or
that a checksum is confirmed; every result is written as an evidence-labelled
note so the P3/P4 agents can refine it.

Usage:
  python traffic_insights.py --pcap case.pcapng --tshark "C:/Program Files/Wireshark/tshark.exe" \
      --out findings.json --append
"""
import argparse
import bz2
import collections
import gzip
import json
import lzma
import math
import struct
import subprocess
import sys
import zlib


def run_tshark(tshark, pcap, fields, limit=20000):
    cmd = [tshark, "-r", pcap, "-c", str(limit), "-T", "fields"] + sum((["-e", f] for f in fields), [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or "tshark failed")
    return [line.split("\t") for line in p.stdout.splitlines() if line.strip()]


def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


SIGNATURES = [
    (b"\x16\x03", "TLS handshake record"),
    (b"\x17\x03", "TLS application data"),
    (b"\x1f\x8b", "gzip"),
    (b"\x78\x01", "zlib (no compression/fast)"),
    (b"\x78\x9c", "zlib (default)"),
    (b"\x78\xda", "zlib (best)"),
    (b"PK\x03\x04", "ZIP/JAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]


def crc8(data, poly=0x07):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c


def crc16(data, poly, init):
    c = init
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def crc16_modbus(data):
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def crc32(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    return c ^ 0xFFFFFFFF


def reflect(value, width):
    out = 0
    for _ in range(width):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def crc_generic(data, width, poly, init, refin=False, refout=False, xorout=0):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = init & mask
    for byte in data:
        if refin:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        else:
            crc ^= byte << (width - 8)
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & mask if crc & top else (crc << 1) & mask
    if refin != refout:
        crc = reflect(crc, width)
    return (crc ^ xorout) & mask


# name: (width, polynomial, init, refin, refout, xorout)
CRC_PARAMS = {
    "crc8": (8, 0x07, 0x00, False, False, 0x00),
    "crc8-maxim": (8, 0x8C, 0x00, True, True, 0x00),
    "crc16-ccitt": (16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16-xmodem": (16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16-modbus": (16, 0xA001, 0xFFFF, True, True, 0x0000),
    "crc16-usb": (16, 0x8005, 0xFFFF, True, True, 0xFFFF),
    "crc32-ieee": (32, 0xEDB88320, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "crc32c": (32, 0x82F63B78, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "crc32-mpeg2": (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000),
}


def crc_with(name, data):
    width, poly, init, refin, refout, xorout = CRC_PARAMS[name]
    return crc_generic(data, width, poly, init, refin, refout, xorout)


def infer_crc(messages):
    messages = [m for m in messages if len(m) >= 5]
    if len(messages) < 3:
        return []
    shortest = min(len(m) for m in messages)
    out = []
    seen = set()
    for name, (width, poly, init, refin, refout, xorout) in CRC_PARAMS.items():
        n = width // 8
        for start in range(0, min(8, shortest - n) + 1):
            for endian in ("big", "little"):
                good = 0
                for m in messages:
                    if len(m) < n + start + 1:
                        continue
                    body, tail = m[start:-n], m[-n:]
                    want = struct.unpack((">" if endian == "big" else "<") + {1: "B", 2: "H", 4: "I"}[n],
                                         tail)[0]
                    if crc_generic(body, width, poly, init, refin, refout, xorout) == want:
                        good += 1
                if good >= 3 and good >= int(len(messages) * 0.8):
                    key = (name, start, endian, n)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "algorithm": name, "width": width, "poly": hex(poly), "init": hex(init),
                        "refin": refin, "refout": refout, "xorout": hex(xorout),
                        "checksum_bytes": n, "body_offset": start, "endian": endian,
                        "matched": good, "messages": len(messages),
                        "confidence": round(good / len(messages), 3),
                    })
    return out


def compression_candidates(messages):
    out = []
    for m in messages:
        if len(m) < 8 or len(m) > 4 * 1024 * 1024:
            continue
        attempts = [
            ("zlib", lambda d: zlib.decompress(d)),
            ("raw-deflate", lambda d: zlib.decompress(d, -15)),
            ("gzip", gzip.decompress),
            ("bz2", bz2.decompress),
            ("lzma", lzma.decompress),
        ]
        for name, fn in attempts:
            try:
                plain = fn(m)
            except Exception:
                continue
            if not plain:
                continue
            out.append({
                "method": name,
                "compressed_len": len(m),
                "plain_len": len(plain),
                "compressed_entropy": round(entropy(m), 3),
                "plain_entropy": round(entropy(plain), 3),
                "plain_prefix_hex": plain[:32].hex(),
                "grade": "traffic",
            })
            break
    return out


def differential_fields(messages, max_offsets=24):
    if len(messages) < 3:
        return []
    width = min(len(m) for m in messages)
    if width < 4:
        return []
    constant, varying = [], []
    samples = {}
    for off in range(width):
        vals = {m[off] for m in messages}
        if len(vals) == 1:
            constant.append({"offset": off, "value": next(iter(vals))})
        else:
            varying.append(off)
            samples[off] = sorted(vals)[:8]
    if not varying or len(varying) > max_offsets:
        return []
    return [{
        "kind": "field-variation", "grade": "inferred",
        "messages": len(messages), "common_prefix_len": width,
        "constant_offsets": constant[:64],
        "varying_offsets": varying,
        "varying_samples": {str(k): [hex(v) for v in vs] for k, vs in list(samples.items())[:16]},
    }]


def tls_observations(tshark, pcap, limit=20000):
    fields = ["tls.record.version", "tls.handshake.type", "tls.handshake.extensions_server_name"]
    try:
        rows = run_tshark(tshark, pcap, fields, limit)
    except Exception:
        return []
    versions, handshakes, snis = collections.Counter(), collections.Counter(), collections.Counter()
    for row in rows:
        row += [""] * (3 - len(row))
        if row[0]:
            versions[row[0]] += 1
        if row[1]:
            handshakes[row[1]] += 1
        if row[2]:
            snis[row[2]] += 1
    out = []
    if versions or handshakes or snis:
        out.append({
            "kind": "tls-observation", "grade": "traffic",
            "versions": dict(versions), "handshake_types": dict(handshakes),
            "server_names": dict(snis),
            "summary": "观察到 TLS 流量；证书/密钥线索仍需 tshark 导出或静态分析确认",
        })
    return out


def analyze(rows):
    streams = collections.defaultdict(lambda: {"c2s": [], "s2c": []})
    for r in rows:
        r += [""] * (10 - len(r))
        src, dst = r[1], r[2]
        sp = r[3] or r[5]
        dp = r[4] or r[6]
        payload = r[7] if len(r) > 7 else ""
        if not payload:
            payload = r[8] if len(r) > 8 else ""
        if not payload:
            continue
        try:
            p = bytes.fromhex(payload.replace(":", ""))
        except ValueError:
            continue
        if not p:
            continue
        a = (src, sp)
        b = (dst, dp)
        if a <= b:
            key, direction = (a, b), "c2s"
        else:
            key, direction = (b, a), "s2c"
        streams[key][direction].append(p)

    notes = []
    for (a, b), dirs in streams.items():
        messages = dirs["c2s"] + dirs["s2c"]
        if not messages:
            continue
        lens = [len(m) for m in messages]
        high_entropy = sum(1 for m in messages if len(m) >= 8 and entropy(m) >= 7.2)
        sig_hits = collections.Counter()
        for m in messages:
            for sig, label in SIGNATURES:
                if m.startswith(sig):
                    sig_hits[label] += 1
        if high_entropy >= max(3, len(messages) // 4):
            notes.append({
                "kind": "payload-obfuscation", "stream": f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}",
                "grade": "inferred", "messages": len(messages),
                "high_entropy_messages": high_entropy,
                "samples": [m[:32].hex() for m in messages[:3]],
                "summary": "高熵消息占比较高，可能存在加密/压缩；需结合握手帧和静态线索确认",
            })
        for label, count in sig_hits.items():
            notes.append({
                "kind": "payload-signature", "stream": f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}",
                "grade": "traffic", "signature": label, "count": count,
            })
        crcs = infer_crc(messages)
        for c in crcs:
            c.update({"kind": "crc-candidate", "stream": f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}",
                      "grade": "traffic", "message_length_range": [min(lens), max(lens)],
                      "summary": "CRC 参数候选，需用断点/改字节实验确认覆盖范围"})
            notes.append(c)
        for comp in compression_candidates(messages[:200]):
            comp.update({"kind": "compression-candidate",
                         "stream": f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}"})
            notes.append(comp)
        for diff in differential_fields(messages[:200]):
            diff["stream"] = f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}"
            notes.append(diff)
        # Rough state model: message type = first two bytes after the most common
        # 2-byte prefix (or first two bytes when no prefix is observed).
        prefix_counts = collections.Counter(m[:2] for m in messages if len(m) >= 2)
        prefix = prefix_counts.most_common(1)[0][0] if prefix_counts else b""
        def kind(m):
            rest = m[2:] if prefix and m.startswith(prefix) else m
            return rest[:2].hex() if rest else m[:2].hex()
        transitions = collections.Counter()
        prev = {"c2s": None, "s2c": None}
        for direction in ("c2s", "s2c"):
            for m in dirs[direction]:
                k = kind(m)
                if prev[direction]:
                    transitions[(prev[direction], k)] += 1
                prev[direction] = k
        if transitions:
            top = [{"from": x, "to": y, "count": n} for (x, y), n in transitions.most_common(10)]
            notes.append({
                "kind": "state-machine", "stream": f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}",
                "grade": "inferred", "message_prefix": prefix.hex(),
                "transitions": top, "summary": "按前两字节粗分消息类型的转移频次，仅供参考",
            })
    return notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()
    # M0-4: same overwrite guard as session_model — see there.
    if Path(args.out).exists() and not args.append:
        try:
            with open(args.out, encoding="utf-8") as f:
                prior = json.load(f)
        except (OSError, ValueError):
            prior = {}
        foreign = {k for k, v in (prior or {}).items()
                   if k not in ("schema", "notes") and v}
        if foreign:
            print(f"error: {args.out} 已包含其他阶段的成果段（{', '.join(sorted(foreign))}），"
                  "漏加 --append 会整文件覆盖丢失。请加 --append 合并，或确认后删除该文件重跑。",
                  file=sys.stderr)
            return 1
    fields = ["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "udp.srcport", "udp.dstport", "tcp.payload", "udp.payload", "frame.time_epoch"]
    try:
        rows = run_tshark(args.tshark, args.pcap, fields)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    notes = analyze(rows)
    notes.extend(tls_observations(args.tshark, args.pcap))
    data = {"schema": "protocol-agent/findings/v1", "notes": [], "comm_assets": [],
            "phases": [], "pitfalls_hit": []}
    if args.append:
        try:
            with open(args.out, encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    existing = {json.dumps(n, sort_keys=True, ensure_ascii=False) for n in data.get("notes", [])}
    added = 0
    for n in notes:
        key = json.dumps(n, sort_keys=True, ensure_ascii=False)
        if key not in existing:
            data.setdefault("notes", []).append(n)
            existing.add(key)
            added += 1
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"messages_scanned={len(rows)} notes_added={added} out={args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())