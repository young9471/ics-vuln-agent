#!/usr/bin/env python3
"""IDA headless bridge. IDA is commercial and cannot be redistributed; install
it yourself and add idat64/idat to PATH. Results are optional evidence."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def find_ida():
    for c in (shutil.which("idat64"), shutil.which("idat"), shutil.which("idat64.exe"), shutil.which("idat.exe")):
        if c:
            return c
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
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
    data["notes"] = [n for n in data.get("notes", []) if not str(n.get("kind", "")).startswith("ida-")]
    ida = find_ida()
    if not ida:
        data.setdefault("notes", []).append({
            "kind": "ida-unavailable", "path": args.path, "grade": "static",
            "reason": "idat64/idat not found on PATH",
            "hint": "install IDA and add its bin directory to PATH (license required)",
        })
        json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("IDA idat64/idat not found")
        return 0
    tmp = tempfile.mkdtemp(prefix="ida-export-")
    out = os.path.join(tmp, "ida-export.tsv")
    try:
        script = os.path.join(HERE, "ida_export.py")
        cmd = [ida, "-A", '-S"%s %s"' % (script, out), args.path]
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=args.timeout)
        if not os.path.exists(out):
            data.setdefault("notes", []).append({
                "kind": "ida-error", "path": args.path, "grade": "static",
                "error": ((p.stderr or "") + "\n" + (p.stdout or ""))[:4000],
            })
        else:
            funcs, names, strings = [], [], []
            for line in open(out, encoding="utf-8", errors="ignore"):
                p = line.rstrip("\n").split("\t")
                if len(p) < 3:
                    continue
                if p[0] == "FUNC":
                    funcs.append({"address": p[1], "name": p[2]})
                elif p[0] == "NAME":
                    names.append({"address": p[1], "name": p[2]})
                elif p[0] == "STRING":
                    strings.append({"address": p[1], "value": p[2]})
            data.setdefault("notes", []).append({
                "kind": "ida-export", "path": args.path, "grade": "static",
                "functions": funcs[:1000], "names": names[:1000], "strings": strings[:500],
            })
        json.dump(data, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"ida out={args.out}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
