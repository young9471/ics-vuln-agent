#!/usr/bin/env python3
"""Ghidra headless bridge. Ghidra itself is not redistributed; set GHIDRA_HOME
or add analyzeHeadless to PATH (install-analyzers.ps1 prints setup steps)."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from analyzer_bundle import analyzer_env, find_ghidra

try:
    import analyzer_cache
except Exception:
    analyzer_cache = None

HERE = os.path.dirname(os.path.abspath(__file__))


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def find_headless():
    found = find_ghidra()
    if found:
        return found
    for c in [shutil.which("analyzeHeadless"), shutil.which("analyzeHeadless.bat")]:
        if c:
            return c
    home = os.environ.get("GHIDRA_HOME", "")
    if home:
        for n in ("analyzeHeadless.bat", "analyzeHeadless"):
            p = os.path.join(home, "support", n)
            if os.path.isfile(p):
                return p
    for base in (r"C:\ghidra", r"C:\Program Files\ghidra", os.path.expanduser("~/ghidra")):
        if not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            for n in ("analyzeHeadless.bat", "analyzeHeadless"):
                p = os.path.join(base, name, "support", n)
                if os.path.isfile(p):
                    return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args()
    data = {"schema": "protocol-agent/findings/v1", "comm_assets": [], "notes": [],
            "phases": [], "pitfalls_hit": []}
    if args.append:
        try:
            existing = json.load(open(args.out, encoding="utf-8"))
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    data["notes"] = [n for n in data.get("notes", []) if not str(n.get("kind", "")).startswith("ghidra-")]
    data["comm_assets"] = [a for a in data.get("comm_assets", []) if not (isinstance(a, dict) and a.get("evidence", {}).get("ghidra"))]
    if analyzer_cache and not args.no_cache:
        cached = analyzer_cache.load(args.path, "ghidra", "12.2")
        if cached:
            data.setdefault("comm_assets", []).extend(cached.get("comm_assets", []))
            data.setdefault("notes", []).extend(cached.get("notes", []))
            write_json(args.out, data)
            print(f"ghidra cache hit out={args.out}")
            return 0
    headless = find_headless()
    if not headless:
        data.setdefault("notes", []).append({
            "kind": "ghidra-unavailable", "path": args.path, "grade": "static",
            "reason": "analyzeHeadless not found",
            "hint": "set GHIDRA_HOME or run tools/install-analyzers.ps1",
        })
        write_json(args.out, data)
        print("Ghidra analyzeHeadless not found")
        return 0
    project = tempfile.mkdtemp(prefix="ghidra-project-")
    out = os.path.join(project, "ghidra-export.tsv")
    try:
        cmd = [headless, project, "ProtocolAgent", "-import", args.path,
               "-scriptPath", HERE, "-postScript", "GhidraExport.java", out,
               "-deleteProject"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=args.timeout, env=analyzer_env())
        except subprocess.TimeoutExpired:
            data.setdefault("notes", []).append({
                "kind": "ghidra-timeout", "path": args.path, "grade": "static",
                "reason": f"analyzeHeadless exceeded {args.timeout}s",
                "hint": "retry with fewer binaries or fall back to capstone",
            })
            write_json(args.out, data)
            print(f"ghidra timeout after {args.timeout}s")
            return 0
        except Exception as e:
            data.setdefault("notes", []).append({
                "kind": "ghidra-error", "path": args.path, "grade": "static",
                "error": str(e)[:4000],
            })
            write_json(args.out, data)
            print(f"ghidra error: {e}")
            return 0
        if p.returncode != 0 or not os.path.exists(out):
            data.setdefault("notes", []).append({
                "kind": "ghidra-error", "path": args.path, "grade": "static",
                "error": ((p.stderr or "") + "\n" + (p.stdout or ""))[:4000],
            })
        else:
            funcs, exts, strings = [], [], []
            for line in open(out, encoding="utf-8", errors="ignore"):
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 3 and parts[0] == "FUNC":
                    funcs.append({"address": parts[1], "name": parts[2]})
                elif len(parts) >= 2 and parts[0] == "EXT":
                    exts.append(parts[1])
                elif len(parts) >= 3 and parts[0] == "STRING":
                    strings.append({"address": parts[1], "value": parts[2]})
            asset = {
                "path": args.path, "name": os.path.basename(args.path), "score": 20,
                "comm_exports": len(exts), "machine": "ghidra", "md5": "",
                "ext": os.path.splitext(args.path)[1].lower(), "grade": "static",
                "evidence": {"ghidra": True, "functions": len(funcs), "external_symbols": exts[:100],
                             "communication_strings": strings[:200]},
            }
            note = {
                "kind": "ghidra-export", "path": args.path, "grade": "static",
                "functions": funcs[:1000], "external_symbols": exts[:200],
                "strings": strings[:500],
            }
            data.setdefault("comm_assets", []).append(asset)
            data.setdefault("notes", []).append(note)
            if analyzer_cache and not args.no_cache:
                analyzer_cache.store(args.path, "ghidra", "12.2", {"comm_assets": [asset], "notes": [note]})
        write_json(args.out, data)
        print(f"ghidra out={args.out}")
    finally:
        shutil.rmtree(project, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
