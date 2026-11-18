#!/usr/bin/env python3
"""Shared findings store: evidence-graded, JSON-backed.

All tools merge their results into one findings.json via `merge_file()` /
CLI `--out`. Schema is append-friendly; unknown sections are preserved.

Evidence grades (high -> low): traffic > live > static > inferred.
"""
import argparse
import datetime
import json
import os

GRADES = ("traffic", "live", "static", "inferred")


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def load(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {"schema": "protocol-agent/findings/v1", "created": now(),
            "phases": {}, "comm_assets": [], "streams": [], "frame_formats": [],
            "field_maps": [], "function_codes": [], "pitfalls_hit": [],
            "probes": [], "notes": []}


def save(path, data):
    data["updated"] = now()
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def check_grade(grade):
    if grade not in GRADES:
        raise ValueError(f"grade must be one of {GRADES}, got {grade!r}")


def add(data, section, item):
    """Append item to a list section, stamping time if absent."""
    if section not in data or not isinstance(data[section], list):
        data[section] = []
    if isinstance(item, dict):
        item.setdefault("ts", now())
    data[section].append(item)


def merge_file(path, section, item):
    data = load(path)
    add(data, section, item)
    save(path, data)
    return data


def main():
    ap = argparse.ArgumentParser(description="findings store CLI")
    ap.add_argument("--file", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show")
    p_add = sub.add_parser("add")
    p_add.add_argument("--section", required=True)
    p_add.add_argument("--json", required=True, help="JSON literal of the item")
    args = ap.parse_args()

    if args.cmd == "show":
        print(json.dumps(load(args.file), ensure_ascii=False, indent=2))
    else:
        item = json.loads(args.json)
        merge_file(args.file, args.section, item)
        print(f"appended to [{args.section}] in {args.file}")


if __name__ == "__main__":
    main()
