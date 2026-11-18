#!/usr/bin/env python3
"""Validate or run the golden-case expectations without committing raw case data."""
import argparse
import json
import os
import sys
from pathlib import Path


def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError("manifest must contain a cases array")
    for i, case in enumerate(data["cases"]):
        if not isinstance(case, dict) or "case_id" not in case or "expected" not in case:
            raise ValueError(f"cases[{i}] needs case_id and expected")
        for key in ("min_assets", "min_frames", "min_codes", "required_docs"):
            if key not in case["expected"]:
                raise ValueError(f"cases[{i}].expected missing {key}")
    return data


def check_case(case, data_root):
    path = Path(data_root) / f"case-{case['case_id']}" / "findings.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        findings = json.load(f)
    exp = case["expected"]
    counts = {
        "min_assets": len(findings.get("comm_assets", []) or []),
        "min_frames": len(findings.get("frame_formats", []) or []),
        "min_codes": len(findings.get("function_codes", []) or []),
    }
    bad = [f"{key}={counts[key]} < {exp[key]}" for key in counts if counts[key] < exp[key]]
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="examples/golden/manifest.json")
    ap.add_argument("--data-root", default=os.environ.get("PROTOCOL_AGENT_GOLDEN_DATA", "platform/data/protocol_cases"))
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--require-data", action="store_true")
    args = ap.parse_args()
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 1
    print(f"manifest ok: {len(manifest['cases'])} cases")
    if args.validate and not args.check:
        return 0
    failed = 0
    skipped = 0
    for case in manifest["cases"]:
        result = check_case(case, args.data_root)
        if result is None:
            skipped += 1
            print(f"case {case['case_id']}: skip (no local findings)")
            continue
        if result:
            failed += 1
            print(f"case {case['case_id']}: FAIL " + "; ".join(result))
        else:
            print(f"case {case['case_id']}: ok")
    if skipped and args.require_data:
        print(f"missing data for {skipped} case(s)", file=sys.stderr)
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
