#!/usr/bin/env python3
"""P4 .NET helper: decompile CLR assemblies with ILSpyCmd when available.

The project does not redistribute ILSpy (NuGet tool). install-analyzers.ps1 can
install it into tools/bin; otherwise this script records an explicit
dotnet-decompile-unavailable note and leaves binary_survey results intact.

Usage:
  python dotnet_analyze.py --path WBCComm.dll --out findings.json --append
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from binary_survey import binary_info, read_head
except Exception:
    binary_info, read_head = None, None
try:
    from analyzer_bundle import analyzer_env, find_ilspy as bundle_ilspy
except Exception:
    analyzer_env, bundle_ilspy = None, None
try:
    import analyzer_cache
except Exception:
    analyzer_cache = None

COMM_WORDS = ["socket", "connect", "send", "recv", "tcp", "udp", "protocol", "plc",
              "modbus", "serial", "device", "port", "dllimport", "extern"]


def find_ilspy():
    if bundle_ilspy:
        p = bundle_ilspy()
        if p:
            return p
    for c in [shutil.which("ilspycmd"), shutil.which("ilspycmd.exe"),
              os.path.join(HERE, "bin", "ilspycmd.exe"), os.path.join(HERE, "bin", "ilspycmd")]:
        if c and os.path.isfile(c):
            return c
    return None


def is_dotnet(path):
    if not binary_info:
        return True
    data = read_head(path, 2 * 1024 * 1024)
    info = binary_info(path, data)
    return bool(info and info[2])


def scan_cs(root):
    codes, hits = [], []
    for dirpath, _, names in os.walk(root):
        for n in names:
            if not n.lower().endswith(".cs"):
                continue
            p = os.path.join(dirpath, n)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            low = text.lower()
            for w in COMM_WORDS:
                if w in low:
                    hits.append(w)
            for m in re.finditer(r"(?:const|enum\s+\w+|=\s*)\s*(?:int|uint|short|ushort|byte)?\s*([A-Za-z_]\w*)\s*=\s*(0x[0-9a-fA-F]+|\d+)", text):
                label, val = m.group(1), m.group(2)
                try:
                    code = int(val, 0)
                except ValueError:
                    continue
                if 0 <= code <= 0xFFFF and not label.lower().startswith(("version", "size", "length")):
                    codes.append({"code": code, "label": label, "evidence": p})
    return codes, sorted(set(hits))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args()
    data = {"schema": "protocol-agent/findings/v1", "comm_assets": [], "notes": [],
            "function_codes": [], "phases": [], "pitfalls_hit": []}
    if args.append:
        try:
            existing = json.load(open(args.out, encoding="utf-8"))
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    assets = data.setdefault("comm_assets", [])
    codes = data.setdefault("function_codes", [])
    notes = data.setdefault("notes", [])
    data["notes"] = [n for n in data.get("notes", []) if not str(n.get("kind", "")).startswith("dotnet-")]
    if analyzer_cache and not args.no_cache:
        cached = analyzer_cache.load(args.path, "ilspy", "11.2")
        if cached:
            existing = {(c.get("code"), c.get("label")) for c in codes if isinstance(c, dict)}
            for c in cached.get("codes", []):
                key = (c.get("code"), c.get("label"))
                if key in existing:
                    continue
                item = dict(c)
                item["source"] = "ILSpyCmd (cache)"
                item["evidence"] = args.path
                codes.append(item)
                existing.add(key)
            hits = cached.get("hits", [])
            if hits:
                assets.append({"path": args.path, "name": os.path.basename(args.path),
                               "score": min(40, 10 + len(hits) * 2), "comm_exports": 0,
                               "machine": "dotnet", "md5": "", "net": True,
                               "ext": os.path.splitext(args.path)[1].lower(), "grade": "static",
                               "evidence": {"dotnet": True, "keyword_hits": hits, "cached": True}})
            json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
            print(f"dotnet cache hit codes={len(cached.get('codes', []))} out={args.out}")
            return 0
    ilspy = find_ilspy()
    if not is_dotnet(args.path):
        notes.append({"kind": "dotnet-skip", "path": args.path, "grade": "static",
                      "reason": "not a CLR assembly"})
        json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("not a .NET assembly")
        return 0
    if not ilspy:
        notes.append({"kind": "dotnet-decompile-unavailable", "path": args.path,
                      "grade": "static", "reason": "ILSpyCmd not installed",
                      "hint": "run tools/install-analyzers.ps1 or dotnet tool install --tool-path tools/bin ilspycmd"})
        json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("ILSpyCmd not installed")
        return 0
    outdir = tempfile.mkdtemp(prefix="dotnet-decompile-")
    try:
        p = subprocess.run([ilspy, "-o", outdir, args.path], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=args.timeout,
                           env=analyzer_env() if analyzer_env else None)
        if p.returncode != 0:
            notes.append({"kind": "dotnet-decompile-error", "path": args.path,
                          "grade": "static", "error": (p.stderr or p.stdout or "")[:2000]})
        found, hits = scan_cs(outdir)
        existing = {(c.get("code"), c.get("label")) for c in codes if isinstance(c, dict)}
        for c in found:
            if (c["code"], c["label"]) in existing:
                continue
            codes.append({"code": f"0x{c['code']:04x}", "label": c["label"], "layer": "dotnet",
                          "grade": "static", "evidence": c["evidence"], "source": "ILSpyCmd"})
        if hits:
            assets.append({"path": args.path, "name": os.path.basename(args.path),
                           "score": min(40, 10 + len(hits) * 2), "comm_exports": 0,
                           "machine": "dotnet", "md5": "", "net": True, "ext": os.path.splitext(args.path)[1].lower(),
                           "grade": "static", "evidence": {"dotnet": True, "keyword_hits": hits,
                                                           "decompiled_files": len(found)}})
        if analyzer_cache and not args.no_cache:
            analyzer_cache.store(args.path, "ilspy", "11.2", {"codes": found, "hits": hits})
        json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"decompiled_codes={len(found)} keyword_hits={hits} out={args.out}")
    finally:
        shutil.rmtree(outdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())