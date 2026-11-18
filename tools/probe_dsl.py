#!/usr/bin/env python3
"""P5 declarative probe DSL.

A probe spec is JSON: transport, request template/fields/sequence/checksum,
timeout, retries and optional expected response. The default is a dry run; live
sending requires --execute and should only be used after the operator grants
write authorization for the target device.

Example:
  python probe_dsl.py --spec probe.json --dry-run
  python probe_dsl.py --spec probe.json --execute --out result.json
"""
import argparse
import json
import socket
import struct
import subprocess
import sys
import time


def _pack_int(value, size, endian):
    return int(value).to_bytes(size, "big" if endian == "big" else "little", signed=False)


def _crc_generic(data, width, poly, init, refin=False, refout=False, xorout=0):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = init & mask

    def reflect(v):
        r = 0
        for _ in range(width):
            r = (r << 1) | (v & 1)
            v >>= 1
        return r

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
        crc = reflect(crc)
    return (crc ^ xorout) & mask


CHECKSUMS = {
    "none": None,
    "sum8": (8, None, 0, False, False, 0),
    "sum16": (16, None, 0, False, False, 0),
    "crc8": (8, 0x07, 0x00, False, False, 0x00),
    "crc16-ccitt": (16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16-xmodem": (16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16-modbus": (16, 0xA001, 0xFFFF, True, True, 0x0000),
    "crc32": (32, 0xEDB88320, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "crc32c": (32, 0x82F63B78, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
}


def _covered(frame, coverage):
    start = int(coverage[0]) if coverage else 0
    end = int(coverage[1]) if coverage and len(coverage) > 1 else len(frame)
    if end < 0:
        end = len(frame) + end
    return frame[start:end]


def build_request(request, sequence_value=None):
    frame = bytearray(bytes.fromhex((request.get("hex") or "").replace(" ", "").replace(":", "")))
    for field in request.get("fields", []) or []:
        off = int(field.get("offset", 0))
        size = int(field.get("size", 1))
        endian = field.get("endian", "big")
        value = field.get("value", 0)
        need = off + size
        if len(frame) < need:
            frame.extend(b"\x00" * (need - len(frame)))
        frame[off:need] = _pack_int(value, size, endian)
    seq = request.get("sequence")
    if seq:
        value = seq.get("start", 1) if sequence_value is None else sequence_value
        off, size, endian = int(seq.get("offset", 0)), int(seq.get("size", 2)), seq.get("endian", "big")
        end = off + size
        if len(frame) < end:
            frame.extend(b"\x00" * (end - len(frame)))
        frame[off:end] = _pack_int(value, size, endian)
    checksum = request.get("checksum") or {"type": "none"}
    ctype = checksum.get("type", "none")
    if ctype not in CHECKSUMS:
        raise ValueError(f"unknown checksum type: {ctype}")
    if ctype != "none":
        width, poly, init, refin, refout, xorout = CHECKSUMS[ctype]
        n = width // 8
        if ctype == "sum8":
            value = sum(_covered(frame, checksum.get("coverage"))) & 0xFF
        elif ctype == "sum16":
            value = sum(_covered(frame, checksum.get("coverage"))) & 0xFFFF
        else:
            value = _crc_generic(_covered(frame, checksum.get("coverage")), width, poly, init, refin, refout, xorout)
        endian = checksum.get("endian", "big")
        raw = _pack_int(value, n, endian)
        where = checksum.get("offset", "tail")
        if where == "tail":
            frame.extend(raw)
        else:
            off = int(where)
            end = off + n
            if len(frame) < end:
                frame.extend(b"\x00" * (end - len(frame)))
            frame[off:end] = raw
    return bytes(frame)


def check_expect(response, expect):
    if not expect:
        return True, ""
    if "min_bytes" in expect and len(response) < int(expect["min_bytes"]):
        return False, f"response shorter than {expect['min_bytes']}"
    if "max_bytes" in expect and len(response) > int(expect["max_bytes"]):
        return False, f"response longer than {expect['max_bytes']}"
    contains = (expect.get("contains_hex") or "").replace(" ", "").replace(":", "")
    if contains and bytes.fromhex(contains) not in response:
        return False, "expected byte sequence not found"
    return True, ""


def extract_from_pcap(pcap, tshark, stream, direction, index):
    fields = ["tcp.stream", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.payload",
              "udp.stream", "udp.srcport", "udp.dstport", "udp.payload"]
    cmd = [tshark, "-r", pcap, "-T", "fields"] + sum((["-e", f] for f in fields), [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or "tshark failed")
    matches = []
    for line in p.stdout.splitlines():
        row = line.split("\t") + [""] * (len(fields) - len(line.split("\t")))
        if row[0] == str(stream) or row[6] == str(stream):
            payload = bytes.fromhex((row[5] or row[9]).replace(" ", ""))
            if payload:
                matches.append((row[1], int(row[3] or row[7] or 0), row[2], int(row[4] or row[8] or 0), payload))
    if not matches:
        raise RuntimeError("no payload found for requested stream")
    if direction == "s2c":
        matches.reverse()
    return matches[min(index, len(matches) - 1)]


def execute(spec, request_bytes):
    transport = (spec.get("transport") or "tcp").lower()
    host, port = spec["host"], int(spec["port"])
    timeout = float(spec.get("timeout_ms", 3000)) / 1000.0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        if transport == "tcp":
            sock.connect((host, port))
        sock.sendall(request_bytes) if transport == "tcp" else sock.sendto(request_bytes, (host, port))
        response = sock.recv(65535)
        return response, int((time.monotonic() - start) * 1000), ""
    except OSError as exc:
        return b"", int((time.monotonic() - start) * 1000), str(exc)
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--execute", action="store_true", help="actually send (default: dry run)")
    ap.add_argument("--out", default="")
    ap.add_argument("--from-pcap", default="")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--stream", type=int, default=0)
    ap.add_argument("--direction", choices=["c2s", "s2c"], default="c2s")
    ap.add_argument("--index", type=int, default=0)
    args = ap.parse_args()
    with open(args.spec, encoding="utf-8") as f:
        spec = json.load(f)
    if args.from_pcap:
        spec.setdefault("host", "")
        spec.setdefault("port", 0)
        src, sport, dst, dport, payload = extract_from_pcap(
            args.from_pcap, args.tshark, args.stream, args.direction, args.index)
        spec["request"] = {"hex": payload.hex()}
        spec.setdefault("host", dst if args.direction == "c2s" else src)
        spec.setdefault("port", dport if args.direction == "c2s" else sport)
        if not spec.get("host"):
            spec["host"] = dst
        if not spec.get("port"):
            spec["port"] = dport
    request = build_request(spec.get("request") or {})
    result = {
        "name": spec.get("name", ""), "transport": spec.get("transport", "tcp"),
        "host": spec.get("host", ""), "port": spec.get("port", 0),
        "request_hex": request.hex(), "dry_run": not args.execute,
    }
    if args.execute:
        response, elapsed, error = execute(spec, request)
        ok, reason = check_expect(response, spec.get("expect"))
        result.update({
            "response_hex": response.hex(), "response_len": len(response),
            "elapsed_ms": elapsed, "status": "error" if error else "ok",
            "error": error, "expect_ok": ok, "expect_reason": reason,
        })
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    return 0 if result.get("status", "ok") == "ok" and result.get("expect_ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())