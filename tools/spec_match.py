#!/usr/bin/env python3
"""Rank built-in client_harness specs against case findings hints.

P5 uses this to pick `client_harness.py --spec <name>` deterministically instead
of guessing from memory.

Usage:
  python spec_match.py --findings findings.json
  python spec_match.py --port 502 --port 2455
  python spec_match.py --findings findings.json --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from client_harness import SPECS  # noqa: E402


def normalize_magic(value):
    if value is None:
        return ""
    text = str(value).lower().replace(" ", "")
    return text if all(c in "0123456789abcdef" for c in text) else ""


def collect_hints(findings, extra_ports):
    ports = set(int(p) for p in extra_ports or [])
    magics = []
    text_parts = []
    if not isinstance(findings, dict):
        return ports, magics, ""
    for stream in findings.get("streams") or []:
        if not isinstance(stream, dict):
            continue
        for key in ("sport", "dport"):
            try:
                port = int(stream.get(key) or 0)
            except (TypeError, ValueError):
                port = 0
            if port > 0:
                ports.add(port)
        text_parts.append(str(stream.get("protocol") or ""))
    for probe in findings.get("probes") or []:
        if isinstance(probe, dict):
            try:
                port = int(probe.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if port > 0:
                ports.add(port)
    for frame in findings.get("frame_formats") or []:
        if not isinstance(frame, dict):
            continue
        for key in ("magic", "alt_magic"):
            magic = normalize_magic(frame.get(key))
            if magic:
                magics.append(magic)
        for key in ("carrier", "inner_layout", "protocol"):
            if frame.get(key):
                text_parts.append(str(frame.get(key)))
    return ports, magics, " ".join(text_parts).lower()


def score_spec(name, spec, ports, magics, text):
    score = 0
    reasons = []
    frame = spec.get("frame") or {}
    port = int(spec.get("port") or 0)
    if port and port in ports:
        score += 50
        reasons.append("observed port %d" % port)
    magic = normalize_magic(frame.get("magic"))
    if magic and magics:
        for seen in magics:
            if seen.startswith(magic) or magic.startswith(seen):
                score += 30
                reasons.append("magic %s matched %s" % (magic, seen))
                break
    carrier = str(frame.get("carrier") or "").lower()
    if carrier and carrier in text:
        score += 20
        reasons.append("carrier %s mentioned" % carrier)
    transport = str(frame.get("transport") or "").lower()
    if transport and transport in text:
        score += 5
        reasons.append("transport %s mentioned" % transport)
    return score, reasons


def rank(findings, extra_ports):
    ports, magics, text = collect_hints(findings, extra_ports)
    ranked = []
    for name, spec in SPECS.items():
        score, reasons = score_spec(name, spec, ports, magics, text)
        if score > 0:
            ranked.append({
                "spec": name,
                "name": spec.get("name", name),
                "port": spec.get("port"),
                "score": score,
                "reasons": reasons,
            })
    ranked.sort(key=lambda item: (-item["score"], item["spec"]))
    return {
        "hints": {"ports": sorted(ports), "magics": magics},
        "ranked": ranked,
        "recommended": ranked[0]["spec"] if ranked else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Rank client_harness specs for a case")
    parser.add_argument("--findings", default="", help="findings.json path")
    parser.add_argument("--port", action="append", default=[], help="extra observed port; repeatable")
    args = parser.parse_args()

    findings = {}
    if args.findings:
        try:
            with open(args.findings, "r", encoding="utf-8") as fh:
                findings = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"error": "cannot read findings: %s" % exc}, ensure_ascii=False))
            return 1
    result = rank(findings, args.port)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())