#!/usr/bin/env python3
"""P3 session/state model: request-response pairing, sessions, retries, timeouts.

The output is evidence-labelled notes (kind=session-model) appended to findings.
It is intentionally protocol-agnostic: it pairs client->server messages with the
next server->client message, reassembles TCP segments by sequence number, and
uses a configurable message-type window (default first 2 payload bytes) to build
a transition graph and a minimal session sequence.

Usage:
  python session_model.py --pcap case.pcapng --tshark tshark --out findings.json --append
  python session_model.py --pcap case.pcapng --out findings.json --type-offset 1 --type-size 1
"""
import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path


FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack",
    "tcp.flags", "tcp.len", "tcp.payload", "udp.srcport", "udp.dstport", "udp.payload",
]


def run_tshark(tshark, pcap, limit=50000):
    cmd = [tshark, "-r", pcap, "-c", str(limit), "-T", "fields"] + sum((["-e", f] for f in FIELDS), [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or "tshark failed")
    return [line.split("\t") for line in p.stdout.splitlines() if line.strip()]


def _hex_bytes(value):
    try:
        return bytes.fromhex((value or "").replace(":", "").replace(" ", ""))
    except ValueError:
        return b""


def _parse_row(row, index):
    row = list(row) + [""] * (len(FIELDS) - len(row))
    tcp_payload = _hex_bytes(row[11])
    udp_payload = _hex_bytes(row[14])
    is_tcp = bool(row[4] or row[5] or row[6] or tcp_payload)
    payload = tcp_payload if is_tcp else udp_payload
    if not payload:
        return None
    ts = float(row[1]) if row[1] else float(index)
    if is_tcp:
        endpoint = (row[2], int(row[5] or 0))
        peer = (row[3], int(row[6] or 0))
        key = ("tcp", row[4] or "|".join(sorted([f"{row[2]}:{row[5]}", f"{row[3]}:{row[6]}"])))
        seq = int(row[7] or 0)
    else:
        endpoint = (row[2], int(row[12] or 0))
        peer = (row[3], int(row[13] or 0))
        key = ("udp", "|".join(sorted([f"{row[2]}:{row[12]}", f"{row[3]}:{row[13]}"])))
        seq = 0
    return {
        "key": key, "ts": ts, "src": endpoint, "dst": peer, "payload": payload,
        "seq": seq, "ack": int(row[8] or 0), "flags": row[9], "tcp_len": int(row[10] or 0),
        "frame": int(row[0] or 0), "tcp": is_tcp,
    }


def group_packets(rows):
    streams = {}
    for index, row in enumerate(rows):
        packet = _parse_row(row, index)
        if not packet:
            continue
        stream = streams.setdefault(packet["key"], {
            "key": packet["key"], "packets": [], "client": packet["src"], "server": packet["dst"],
        })
        stream["packets"].append(packet)
    return streams


def reassemble_tcp(packets):
    """Return per-direction messages without changing the original packets."""
    messages = []
    by_direction = collections.defaultdict(list)
    for p in packets:
        by_direction[p["src"]].append(p)
    gaps_total = overlaps_total = 0
    for src, items in by_direction.items():
        items.sort(key=lambda p: (p["seq"], p["ts"]))
        expected = None
        buffer = bytearray()
        first = None
        segments = 0
        gaps = overlaps = 0
        for p in items:
            payload = p["payload"]
            if expected is None:
                expected = p["seq"] + len(payload)
                buffer = bytearray(payload)
                first = p
                segments = 1
                continue
            if p["seq"] < expected:
                skip = expected - p["seq"]
                if skip >= len(payload):
                    overlaps += 1
                    continue
                overlaps += 1
                payload = payload[skip:]
                seq = expected
            else:
                seq = p["seq"]
            if seq > expected:
                gaps += 1
                messages.append({
                    "ts": first["ts"] if first else p["ts"], "frame": first["frame"] if first else p["frame"],
                    "src": src, "payload": bytes(buffer), "fragments": max(1, segments),
                })
                buffer = bytearray()
                first = p
                segments = 0
            buffer.extend(payload)
            segments += 1
            expected = seq + len(payload)
        if buffer:
            messages.append({
                "ts": first["ts"] if first else 0, "frame": first["frame"] if first else 0,
                "src": src, "payload": bytes(buffer), "fragments": max(1, segments),
            })
        gaps_total += gaps
        overlaps_total += overlaps
    return messages, {"gaps": gaps_total, "overlaps": overlaps_total}


def type_label(payload, offset, size):
    part = payload[offset:offset + size]
    return part.hex() if part else "-"


def pair_messages(messages, client, timeout_s):
    client_msgs = sorted([m for m in messages if m["src"] == client], key=lambda m: m["ts"])
    server_msgs = sorted([m for m in messages if m["src"] != client], key=lambda m: m["ts"])
    pairs, unmatched, timeouts = [], 0, []
    j = 0
    for req in client_msgs:
        while j < len(server_msgs) and server_msgs[j]["ts"] < req["ts"]:
            j += 1
        if j >= len(server_msgs):
            unmatched += 1
            timeouts.append({"frame": req["frame"], "type": req["type"], "late_by_s": None,
                             "reason": "no response observed"})
            continue
        resp = server_msgs[j]
        j += 1
        latency = max(0.0, resp["ts"] - req["ts"])
        if latency > timeout_s:
            timeouts.append({"frame": req["frame"], "type": req["type"],
                             "late_by_s": round(latency, 3), "reason": "response after timeout"})
        pairs.append((req, resp, latency))
    return pairs, unmatched, timeouts


def infer_type_window(findings_path):
    if not findings_path:
        return None
    try:
        with open(findings_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    for fm in data.get("field_maps", []) or []:
        for field in fm.get("fields", []) or []:
            name = str(field.get("name", "")).lower()
            cls = str(field.get("class", "")).lower()
            if cls in ("type", "command", "cmd", "service") or any(
                    word in name for word in ("service", "code", "cmd", "function", "opcode")):
                off, size = field.get("off"), field.get("size")
                if isinstance(off, int) and isinstance(size, int) and size > 0:
                    return off, size
    return None


def build_stream_model(stream, timeout_s, type_offset, type_size, reassemble=False):
    packets = stream["packets"]
    tcp_packets = [p for p in packets if p["tcp"]]
    if reassemble:
        messages, frag = reassemble_tcp(tcp_packets)
    else:
        messages = [{
            "ts": p["ts"], "frame": p["frame"], "src": p["src"], "payload": p["payload"],
            "fragments": 1,
        } for p in tcp_packets]
        _, frag = reassemble_tcp(tcp_packets)
    if not messages:
        messages = [{
            "ts": p["ts"], "frame": p["frame"], "src": p["src"], "payload": p["payload"],
            "fragments": 1,
        } for p in packets if not p["tcp"]]
    if not messages:
        return None
    for m in messages:
        m["type"] = type_label(m["payload"], type_offset, type_size)
    client = messages[0]["src"]
    server = next((m["src"] for m in messages if m["src"] != client), stream["server"])
    pairs, unmatched, timeouts = pair_messages(messages, client, timeout_s)
    transitions = collections.Counter((req["type"], resp["type"]) for req, resp, _ in pairs)
    retries = []
    previous = None
    for req in sorted([m for m in messages if m["src"] == client], key=lambda m: m["ts"]):
        if previous and req["payload"] == previous["payload"]:
            retries.append({"frame": req["frame"], "type": req["type"],
                            "since_frame": previous["frame"], "delta_s": round(req["ts"] - previous["ts"], 3)})
        previous = req
    minimal = []
    seen = set()
    for req, resp, _ in pairs:
        key = (req["type"], resp["type"])
        if key in seen:
            continue
        seen.add(key)
        minimal.append({"request": req["type"], "response": resp["type"],
                        "request_frame": req["frame"], "response_frame": resp["frame"]})
    states = sorted({m["type"] for m in messages if m["type"] != "-"})
    return {
        "kind": "session-model", "grade": "traffic",
        "stream": f"{client[0]}:{client[1]}<->{server[0]}:{server[1]}",
        "client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
        "messages": len(messages), "requests": len([m for m in messages if m["src"] == client]),
        "responses": len([m for m in messages if m["src"] != client]),
        "paired": len(pairs), "unmatched_requests": unmatched,
        "states": states,
        "transitions": [{"from": a, "to": b, "count": n} for (a, b), n in transitions.most_common(50)],
        "minimal_sequence": minimal[:32],
        "retries": retries[:50],
        "timeouts": timeouts[:50],
        "fragments": frag,
        "summary": "按消息类型窗口聚合的会话模型；retry/timeout 为时序推断，需 P5 状态验证",
    }


def build_models(rows, timeout_s=10.0, type_offset=0, type_size=2, max_streams=50, reassemble=False):
    streams = group_packets(rows)
    models = []
    for stream in list(streams.values())[:max_streams]:
        model = build_stream_model(stream, timeout_s, type_offset, type_size, reassemble)
        if model:
            models.append(model)
    return models


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0, help="response timeout seconds")
    ap.add_argument("--findings", default="", help="read field_maps and infer the service/command window")
    ap.add_argument("--type-offset", type=int, default=None)
    ap.add_argument("--type-size", type=int, default=None)
    ap.add_argument("--max-streams", type=int, default=50)
    ap.add_argument("--reassemble", action="store_true", help="merge contiguous TCP segments before pairing")
    args = ap.parse_args()
    # M0-4: running without --append used to silently replace the whole
    # findings file, destroying other phases' sections. Refuse when the file
    # already holds foreign sections; re-running this tool's own notes stays
    # allowed.
    if Path(args.out).exists() and not args.append:
        try:
            with open(args.out, encoding="utf-8") as fh:
                prior = json.load(fh)
        except (OSError, ValueError):
            prior = {}
        foreign = {k for k, v in (prior or {}).items()
                   if k not in ("schema", "notes") and v}
        if foreign:
            print(f"error: {args.out} 已包含其他阶段的成果段（{', '.join(sorted(foreign))}），"
                  "漏加 --append 会整文件覆盖丢失。请加 --append 合并，或确认后删除该文件重跑。",
                  file=sys.stderr)
            return 1
    try:
        rows = run_tshark(args.tshark, args.pcap)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    inferred = infer_type_window(args.findings)
    type_offset = args.type_offset if args.type_offset is not None else (inferred[0] if inferred else 0)
    type_size = args.type_size if args.type_size is not None else (inferred[1] if inferred else 2)
    notes = build_models(rows, args.timeout, type_offset, type_size, args.max_streams, args.reassemble)
    data = {"schema": "protocol-agent/findings/v1", "notes": []}
    if args.append and Path(args.out).exists():
        try:
            with open(args.out, encoding="utf-8") as fh:
                existing = json.load(fh)
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    existing = {json.dumps(n, sort_keys=True, ensure_ascii=False) for n in data.get("notes", [])}
    added = 0
    for note in notes:
        key = json.dumps(note, sort_keys=True, ensure_ascii=False)
        if key not in existing:
            data.setdefault("notes", []).append(note)
            existing.add(key)
            added += 1
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"streams={len(notes)} notes_added={added} out={args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())