#!/usr/bin/env python3
"""P1/P4 ELF survey and symbol extractor (stdlib only).

Parses ELF32/ELF64 section/symbol tables, finds imports/exports and communication
keywords. It is a complement to binary_survey.py and a fallback when readelf,
Ghidra or IDA are not installed.

Usage:
  python elf_analyze.py --root /opt/vendor --out findings.json --append
  python elf_analyze.py --path /opt/vendor/bin/plc --out findings.json --append
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

COMM_WORDS = [
    "socket", "connect", "send", "recv", "bind", "listen", "accept", "tcp", "udp",
    "ssl", "tls", "openssl", "modbus", "plc", "protocol", "serial", "termios",
    "read", "write", "ioctl", "can", "profinet", "ethernet",
]


def u(data, off, size, endian):
    if off + size > len(data):
        return 0
    return int.from_bytes(data[off:off + size], "little" if endian == "<" else "big")


def elf_header(data):
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    cls = data[4]
    endian = "<" if data[5] == 1 else ">"
    machine = u(data, 18, 2, endian)
    arch = {3: "x86", 62: "x64", 40: "arm", 183: "arm64", 243: "riscv"}.get(machine, f"elf-{machine}")
    if cls == 2:
        if len(data) < 64:
            return None
        shoff = u(data, 40, 8, endian)
        shentsize = u(data, 58, 2, endian)
        shnum = u(data, 60, 2, endian)
        shstrndx = u(data, 62, 2, endian)
        sym_size = 24
    else:
        shoff = u(data, 32, 4, endian)
        shentsize = u(data, 46, 2, endian)
        shnum = u(data, 48, 2, endian)
        shstrndx = u(data, 50, 2, endian)
        sym_size = 16
    return {"cls": cls, "endian": endian, "arch": arch, "shoff": shoff,
            "shentsize": shentsize, "shnum": shnum, "shstrndx": shstrndx, "sym_size": sym_size}


def sections(data, h):
    out = []
    for i in range(h["shnum"]):
        off = h["shoff"] + i * h["shentsize"]
        if off + h["shentsize"] > len(data):
            break
        e = h["endian"]
        if h["cls"] == 2:
            name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
        else:
            name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(e + "IIIIIIIIII", data, off)
        out.append({"name_off": name, "type": typ, "addr": addr, "offset": offset,
                    "size": size, "link": link, "entsize": entsize})
    if h["shstrndx"] < len(out):
        s = out[h["shstrndx"]]
        strtab = data[s["offset"]:s["offset"] + s["size"]]
        for sec in out:
            n = sec["name_off"]
            end = strtab.find(b"\0", n)
            sec["name"] = strtab[n:end].decode("ascii", "ignore") if end >= 0 else ""
    return out


def symbols(data, h, secs):
    out = []
    for sec in secs:
        if sec.get("name") not in (".symtab", ".dynsym") or sec["entsize"] <= 0:
            continue
        strsec = secs[sec["link"]] if sec["link"] < len(secs) else None
        if not strsec:
            continue
        strtab = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        count = sec["size"] // sec["entsize"]
        for i in range(count):
            off = sec["offset"] + i * sec["entsize"]
            if off + h["sym_size"] > len(data):
                break
            if h["cls"] == 2:
                name, info, other, shndx, value, size = struct.unpack_from(h["endian"] + "IBBHQQ", data, off)
            else:
                name, value, size, info, other, shndx = struct.unpack_from(h["endian"] + "IIIBBH", data, off)
            end = strtab.find(b"\0", name)
            nm = strtab[name:end].decode("ascii", "ignore") if name < len(strtab) and end >= 0 else ""
            if not nm:
                continue
            typ = info & 0xF
            bind = info >> 4
            out.append({"name": nm, "type": typ, "bind": bind,
                        "undefined": shndx == 0, "value": value, "size": size})
    return out


def strings(data):
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        out.add(m.group().decode("ascii", "ignore"))
    return out


def analyze_file(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    h = elf_header(data)
    if not h:
        return None
    secs = sections(data, h)
    syms = symbols(data, h, secs)
    imports = sorted({s["name"] for s in syms if s["undefined"]})
    exports = sorted({s["name"] for s in syms if not s["undefined"] and s["type"] in (1, 2, 10)})
    strs = strings(data[:8 * 1024 * 1024])
    hits = [w for w in COMM_WORDS if any(w in x.lower() for x in imports + exports + list(strs)[:20000])]
    score = 0
    if imports: score += 8
    if exports: score += 5
    score += min(20, len(hits) * 2)
    if score <= 0:
        return None
    return {
        "path": path, "name": os.path.basename(path), "score": score,
        "comm_exports": len(exports), "machine": h["arch"], "md5": hashlib.md5(data).hexdigest(),
        "net": any(x in hits for x in ("socket", "connect", "tcp", "udp")),
        "ext": os.path.splitext(path)[1].lower(), "grade": "static",
        "evidence": {"format": "ELF", "arch": h["arch"], "imports": imports[:80],
                     "exports": exports[:80], "keyword_hits": hits},
    }


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
        for n in filenames:
            p = os.path.join(dirpath, n)
            try:
                if os.path.isfile(p) and os.path.getsize(p) > 0:
                    yield p
            except OSError:
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path")
    ap.add_argument("--root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()
    if not args.path and not args.root:
        ap.error("--path or --root required")
    data = {"schema": "protocol-agent/findings/v1", "comm_assets": [], "notes": [],
            "phases": [], "pitfalls_hit": []}
    if args.append:
        try:
            existing = json.load(open(args.out, encoding="utf-8"))
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    assets = data.setdefault("comm_assets", [])
    seen = {a.get("path") for a in assets if isinstance(a, dict)}
    paths = [args.path] if args.path else walk(args.root)
    added = 0
    for p in paths:
        a = analyze_file(p)
        if not a or a["path"] in seen:
            continue
        assets.append(a)
        seen.add(a["path"])
        added += 1
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"added={added} total_assets={len(assets)} out={args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())