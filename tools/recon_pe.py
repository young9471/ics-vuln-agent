#!/usr/bin/env python3
"""P1 asset recon: score PE files in an install tree for communication relevance.

Heuristics distilled from the WAGO/CODESYS case:
  - imports WS2_32 / WSOCK32 / MSWSOCK           +30
  - exports C++ comm-flavored symbols            +20
  - filename contains comm/net/tcp/eth/gateway   +10
  - identical copies in multiple dirs (family)   +5 (dedup by MD5, keep first)
  - size > 8MB (main executable, worth noting)   +5

Also dumps: config files with IP/port-looking tokens, and flags
encrypted/garbage resource files as skip.

Usage:
  python recon_pe.py --root "E:\\SomeVendor" [--depth 3] --out findings.json
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F  # noqa: E402

try:
    import pefile
except ImportError:
    sys.exit("pip install pefile")

SOCK_DLLS = {b"ws2_32.dll", b"wsock32.dll", "ws2_32.dll", "wsock32.dll", "mswsock.dll"}
COMM_SYMBOL = re.compile(rb"Connect|Socket|Comm|Protocol|Channel|TCPIP|Ethernet", re.I)
COMM_NAME = re.compile(r"comm|net|tcp|eth|gate|driv|sock", re.I)
IP_TOKEN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_TOKEN = re.compile(r"\bport\b|\banschluss", re.I)


def file_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def score_pe(path):
    """Return (score, detail dict) for a PE file."""
    score, detail = 0, {"path": path, "imports": [], "comm_exports": 0,
                        "machine": None, "net": False}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except Exception as e:
        return None, {"path": path, "error": str(e)}
    detail["machine"] = hex(pe.FILE_HEADER.Machine)
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace")
        detail["imports"].append(dll)
        if dll.lower() in {d.lower() for d in SOCK_DLLS}:
            score += 30
    # exports require a second parse (cheap enough per candidate)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        n = sum(1 for e in getattr(pe, "DIRECTORY_ENTRY_EXPORT", []).symbols
                if e.name and COMM_SYMBOL.search(e.name))
        detail["comm_exports"] = n
        if n:
            score += min(20, n // 5 + 10)
    except Exception:
        pass
    if COMM_NAME.search(os.path.basename(path)):
        score += 10
    if os.path.getsize(path) > 8 << 20:
        score += 5
    detail["score"] = score
    return score, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--min-score", type=int, default=25)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    seen_md5, candidates, configs = {}, [], []
    root = args.root.rstrip("\\/")
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth >= args.depth:
            dirnames[:] = []
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ext in (".dll", ".exe", ".ocx"):
                score, detail = score_pe(p)
                if score is None:
                    continue
                md5 = file_md5(p)
                detail["md5"] = md5
                if md5 in seen_md5:
                    detail["duplicate_of"] = seen_md5[md5]
                    detail["score"] = 0  # dedup: keep first copy only
                else:
                    seen_md5[md5] = p
                    if detail["score"] >= args.min_score:
                        candidates.append(detail)
            elif ext in (".ini", ".cfg", ".xml", ".config", ".txt"):
                try:
                    text = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                hits = set(IP_TOKEN.findall(text))
                if hits or PORT_TOKEN.search(text):
                    configs.append({"path": p, "ips": sorted(hits)[:10]})

    candidates.sort(key=lambda d: -d["score"])
    data = F.load(args.out)
    F.add(data, "phases", {"phase": "P1", "status": "done",
                           "assets_found": len(candidates)})
    for c in candidates:
        F.add(data, "comm_assets", {**c, "grade": "static"})
    for c in configs[:40]:
        F.add(data, "notes", {"kind": "config-with-ip", **c})
    F.save(args.out, data)

    print(f"{'score':>5}  {'commExp':>7}  path")
    for c in candidates:
        print(f"{c['score']:>5}  {c['comm_exports']:>7}  {c['path']}"
              + (f"  (dup of {c['duplicate_of']})" if c.get("duplicate_of") else ""))
    print(f"\n{len(candidates)} communication assets >= {args.min_score} -> {args.out}")


if __name__ == "__main__":
    main()
