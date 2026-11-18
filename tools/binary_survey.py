#!/usr/bin/env python3
"""P1/P4 supplementary binary survey.

PE files are handled in depth by recon_pe.py. This tool covers the rest of an
installation tree: ELF, Mach-O, .NET assemblies, installers/archives and
arbitrary binaries. It records static, evidence-labelled communication
candidates into findings.json (--append preserves previous sections).

Usage:
  python binary_survey.py --root "C:/Program Files/Vendor" --out findings.json --append
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "System Volume Information"}
MAX_SCAN_BYTES = 8 * 1024 * 1024

KEYWORDS = [
    "socket", "connect", "send", "recv", "ws2_32", "wsock32", "tcp", "udp",
    "modbus", "plc", "protocol", "device", "port", "host", "192.168.", "10.",
    "172.16.", "ethernet", "serial", "rs485", "opc", "profinet", "ethernet/ip",
]

TEXT_EXT = {
    ".ini", ".cfg", ".conf", ".config", ".xml", ".json", ".yaml", ".yml",
    ".txt", ".csv", ".log", ".properties", ".reg",
}
BINARY_EXT = {
    ".exe", ".dll", ".sys", ".so", ".elf", ".bin", ".out", ".com", ".ocx",
    ".jar", ".war", ".apk", ".msi", ".cab", ".zip", ".7z", ".rar", ".gz",
    ".tar", ".tgz", ".iso", ".img", ".hex", ".fw",
}


def fmt_size(n):
    if n > 1024 * 1024:
        return f"{n / 1024 / 1024:.1f}MB"
    if n > 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}B"


def read_head(path, limit=MAX_SCAN_BYTES):
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def pe_info(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    net = False
    if magic == 0x20B and opt + 112 + 16 <= len(data):
        rva = struct.unpack_from("<I", data, opt + 112 + 14 * 8)[0]
        net = rva != 0
    elif magic == 0x10B and opt + 96 + 14 * 8 <= len(data):
        rva = struct.unpack_from("<I", data, opt + 96 + 14 * 8)[0]
        net = rva != 0
    arch = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm"}.get(machine, f"0x{machine:x}")
    return "PE/.NET" if net else "PE", arch, net


def elf_info(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    cls, endian = data[4], data[5]
    machine = struct.unpack_from("<H" if endian == 1 else ">H", data, 18)[0]
    arch = {3: "x86", 62: "x64", 183: "arm64", 40: "arm", 243: "riscv"}.get(machine, f"elf-{machine}")
    return ("ELF", "64" if cls == 2 else "32"), arch, False


def macho_info(data):
    if len(data) < 8:
        return None
    magics = {b"\xfe\xed\xfa\xce": "macho32", b"\xfe\xed\xfa\xcf": "macho64",
              b"\xce\xfa\xed\xfe": "macho32", b"\xcf\xfa\xed\xfe": "macho64"}
    kind = magics.get(data[:4])
    if not kind:
        return None
    return kind.upper(), "arm64" if b"arm64" in data[:4096] else "x86/x64", False


def archive_info(data, ext):
    if data[:4] == b"PK\x03\x04":
        return "ZIP/JAR/APK"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:4] == b"Rar!":
        return "RAR"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:4] == b"MSCF":
        return "CAB"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "MSI/OLE"
    if ext in {".msi", ".cab", ".zip", ".7z", ".rar", ".gz", ".tar", ".tgz", ".iso", ".img", ".fw"}:
        return ext.lstrip(".").upper()
    return None


def binary_info(path, data):
    for fn in (pe_info, elf_info, macho_info):
        info = fn(data)
        if info:
            return info
    kind = archive_info(data, os.path.splitext(path)[1].lower())
    if kind:
        return kind, "-", False
    return None


def extract_strings(data):
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        out.add(m.group().decode("ascii", "ignore").lower())
    # UTF-16LE strings (common in .NET/Windows resources)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        out.add(m.group().decode("utf-16le", "ignore").lower())
    return out


def score_for(path, data, info):
    kind, arch, net = info
    ext = os.path.splitext(path)[1].lower()
    score = 0
    reasons = []
    if net:
        score += 15
        reasons.append(".NET CLR header")
    if kind.startswith("PE"):
        score += 10
        reasons.append("PE executable")
    elif kind == "ELF":
        score += 8
        reasons.append("ELF executable")
    elif kind.startswith("MACHO"):
        score += 8
        reasons.append("Mach-O executable")
    elif any(k in kind for k in ("ZIP", "7Z", "RAR", "CAB", "MSI", "GZIP")):
        score += 3
        reasons.append("installer/archive")
    hits = []
    if data:
        text = " ".join(extract_strings(data))
        for kw in KEYWORDS:
            if kw in text:
                hits.append(kw)
        if hits:
            score += min(20, len(hits) * 2)
            reasons.append("keywords: " + ",".join(hits[:8]))
    if ext in {".dll", ".exe", ".so", ".elf", ".ocx", ".sys"}:
        score += 3
    return score, reasons, hits, ext


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if not st.st_size:
                continue
            yield path, st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--max-assets", type=int, default=200)
    args = ap.parse_args()

    data = {"schema": "protocol-agent/findings/v1", "comm_assets": [], "notes": [],
            "phases": [], "pitfalls_hit": []}
    if args.append:
        try:
            with open(args.out, encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    assets = data.setdefault("comm_assets", [])
    seen = {a.get("path") for a in assets if isinstance(a, dict)}
    added = 0
    scanned = 0
    for path, st in walk_files(args.root):
        scanned += 1
        head = read_head(path)
        info = binary_info(path, head)
        if not info:
            ext = os.path.splitext(path)[1].lower()
            if ext not in TEXT_EXT:
                continue
            text = head.decode("utf-8", "ignore").lower()
            hits = [k for k in KEYWORDS if k in text]
            if not hits:
                continue
            info = ("config/text", "-", False)
        score, reasons, hits, ext = score_for(path, head, info)
        if score <= 0 or path in seen:
            continue
        try:
            md5 = hashlib.md5(head).hexdigest()
        except Exception:
            md5 = ""
        assets.append({
            "path": path,
            "name": os.path.basename(path),
            "score": score,
            "comm_exports": 0,
            "machine": info[1],
            "md5": md5,
            "net": bool(info[2]),
            "ext": ext,
            "size": st.st_size,
            "grade": "static",
            "evidence": {"survey": reasons, "keywords": hits, "size": st.st_size},
        })
        seen.add(path)
        added += 1
        if added >= args.max_assets:
            break
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"scanned={scanned} added={added} total_assets={len(assets)} out={args.out}")


if __name__ == "__main__":
    sys.exit(main())