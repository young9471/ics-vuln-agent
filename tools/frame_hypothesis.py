#!/usr/bin/env python3
"""P3 frame-hypothesis fitter & validator.

For every TCP stream in a pcap, brute-force the framing parameter space:

    magic size M (2 or 4 bytes at offset 0; or none)
    header size H, length-field offset L (0..H-S), size S (2/4),
    endianness E, length bias B (extra bytes after payload)

Chain-parse the whole stream; a hypothesis is CONFIRMED only when it covers
the stream exactly with zero resynchronization (PLAYBOOK P3 gate).
A second magic (ACK frames, e.g. 0x6666) is discovered automatically by
resuming from the first failure position with a new alternate magic.

Usage:
  python frame_hypothesis.py --pcap session.pcapng [--streams auto]
                             [--max-streams 8] --out findings.json
"""
import argparse
import json
import os
import struct
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F  # noqa: E402

TSHARK = os.environ.get("PROTOCOL_AGENT_TSHARK", "tshark")  # or full path


def sh(*args):
    # M0-2: a failing tshark must be loud. Returning empty stdout used to turn a
    # broken pcap or a missing tshark into "0 confirmed" with exit code 0 — a
    # silent false negative that poisoned gate decisions downstream.
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise SystemExit(f"tshark not found: {args[0]} "
                         "(set PROTOCOL_AGENT_TSHARK or add Wireshark to PATH)")
    if p.returncode != 0 or (not p.stdout.strip() and p.stderr.strip()):
        raise SystemExit(f"{args[0]} failed (exit {p.returncode}): {p.stderr.strip()[:500]}")
    return p.stdout


def list_streams(pcap):
    out = sh(TSHARK, "-r", pcap, "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
             "-T", "fields", "-e", "tcp.stream")
    return sorted({int(x) for x in out.split() if x.strip().isdigit()})


def follow_raw(pcap, n):
    """Return (c2s, s2c) byte buffers. Indented lines = node1->node0 (pitfall #12)."""
    out = sh(TSHARK, "-r", pcap, "-q", "-z", f"follow,tcp,raw,{n}")
    c2s, s2c = [], []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or any(k in ln for k in ("====", "Follow:", "Filter:", "Node ")):
            continue
        (s2c if ln.startswith("\t") else c2s).append(s)
    mk = lambda xs: bytes.fromhex("".join(x.replace(" ", "") for x in xs))
    return mk(c2s), mk(s2c)


def read_len(buf, off, size, little):
    fmt = ("<" if little else ">") + ("H" if size == 2 else "I")
    return struct.unpack_from(fmt, buf, off)[0]


def chain(buf, magic, alt_magics, H, L, S, little, bias):
    """Chain-parse; returns (frames, ok, end_pos, fail_pos, alts_used).

    ok=True iff the whole buffer is covered exactly (zero resync).
    alt_magics: set of additional acceptable frame magics (ACK frames).
    """
    pos, frames = 0, []
    while pos < len(buf):
        if magic and buf[pos:pos + len(magic)] not in (magic, *alt_magics):
            return frames, False, pos, pos, alt_magics
        if pos + H > len(buf):
            return frames, False, pos, pos, alt_magics
        plen = read_len(buf, pos + L, S, little)
        end = pos + H + plen + bias
        if plen > len(buf) or end > len(buf) or end <= pos:
            return frames, False, pos, pos, alt_magics
        frames.append((pos, end - pos))
        pos = end
    return frames, True, len(buf), None, alt_magics


def fit_stream(buf, label):
    """Brute-force framing params. Returns best confirmed hypothesis or None."""
    tried = 0
    for msize in (2, 4, 0):
        magic = buf[:msize] if msize else b""
        for bias in (0, 2, 4, -2, -4):            # negative: length field covers header too (TPKT/RFC1006)
            for H in range(4, 65, 2):               # from 4: short carriers exist (MBAP=6)
                for S in (4, 2):
                    for little in (True, False):
                        for L in range(0, max(1, H - S + 1), 1):
                            tried += 1
                            alt = b""
                            frames, ok, end, fail, alts = chain(
                                buf, magic, (), H, L, S, little, bias)
                            if not ok and frames:
                                # alternate-magic discovery: resume with a
                                # new magic taken from the failure position
                                alt = buf[fail:fail + (msize or 2)]
                                if len(alt) == (msize or 2) and alt != magic:
                                    frames2, ok, end, fail, _ = chain(
                                        buf, magic, (alt,), H, L, S, little, bias)
                                    if ok:
                                        frames = frames2
                                if not ok:
                                    continue
                            if ok and len(frames) >= 3:
                                # degenerate-fit guard (M4 pitfall #15):
                                # reject when average frame size is absurd
                                avg = len(buf) / len(frames)
                                if avg > 1024:
                                    continue
                                plens = [sz - H - bias for _, sz in frames[:50]]
                                return {
                                    "stream": label, "grade": "traffic",
                                    "magic": magic.hex() if magic else None,
                                    "alt_magic": alt.hex() if alt else None,
                                    "header_size": H, "len_offset": L,
                                    "len_size": S, "endian": "le" if little else "be",
                                    "len_bias": bias, "frames": len(frames),
                                    "bytes": len(buf), "params_tried": tried,
                                    "sample_payload_lens": plens[:10],
                                }
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--tshark", default=TSHARK)
    ap.add_argument("--max-streams", type=int, default=8)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    globals()["TSHARK"] = args.tshark

    data = F.load(args.out)
    confirmed, unresolved = [], []
    for n in list_streams(args.pcap)[:args.max_streams]:
        c2s, s2c = follow_raw(args.pcap, n)
        for label, buf in ((f"{n}/c2s", c2s), (f"{n}/s2c", s2c)):
            if len(buf) < 32:
                continue
            hyp = fit_stream(buf, label)
            if hyp:
                # fill alt magic actually used (from discovery pass)
                confirmed.append(hyp)
                F.add(data, "frame_formats", hyp)
                print(f"[CONFIRMED] stream {label}: magic={hyp['magic']} "
                      f"H={hyp['header_size']} len@{hyp['len_offset']}x{hyp['len_size']}"
                      f"{hyp['endian']} frames={hyp['frames']} bytes={hyp['bytes']}")
            else:
                unresolved.append(label)
                print(f"[unresolved] stream {label} ({len(buf)}B) "
                      f"first-bytes={buf[:8].hex(' ')}")
    F.add(data, "phases", {"phase": "P3", "status": "done" if not unresolved else "partial",
                           "confirmed": len(confirmed), "unresolved": unresolved})
    F.save(args.out, data)
    print(f"\n{len(confirmed)} confirmed, {len(unresolved)} unresolved -> {args.out}")


if __name__ == "__main__":
    main()
