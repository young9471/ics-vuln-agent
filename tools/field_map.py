#!/usr/bin/env python3
"""P3b field-map extractor: byte-level field division from traffic variance.

Groups captured frames by protocol key (Modbus FC; private FCs sub-keyed by
the next two payload bytes), aligns samples of one group, and classifies
every byte window by its variance behaviour:

    mbap-len    u16@4 == frame_len-6 in all samples (carrier length field)
    txn-echo    u16@0 == paired request's MBAP txn (response direction)
    seq         monotonically increasing in send order (counter/address)
    constant    same value in all samples
    ascii       printable run
    data        varying bytes (payload)

Discipline (PLAYBOOK §P3): a field division is only as good as its variance
proof - every emitted field carries its evidence rule, nothing is eyeballed.
Frames are chain-parsed with zero-resync; streams that do not chain cleanly
as MBAP are skipped.

Usage:
  python field_map.py --pcap s1.pcapng --tshark "C:/Program Files/Wireshark/tshark.exe" \
      [--min-samples 3] [--semantics sem.json] --out findings.json
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F  # noqa: E402

TSHARK = os.environ.get("PROTOCOL_AGENT_TSHARK", "tshark")
PRIVATE_FC_MIN = 0x41  # fc >= this -> sub-key by next two payload bytes


def follow(pcap, n):
    # M0-2: same loud-failure rule as frame_hypothesis.sh — a failing tshark
    # used to look like "no streams / no frames found".
    try:
        p = subprocess.run([TSHARK, "-r", pcap, "-q", "-z", f"follow,tcp,raw,{n}"],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise SystemExit(f"tshark not found: {TSHARK} "
                         "(set PROTOCOL_AGENT_TSHARK or add Wireshark to PATH)")
    if p.returncode != 0 or (not p.stdout.strip() and p.stderr.strip()):
        raise SystemExit(f"tshark failed (exit {p.returncode}): {p.stderr.strip()[:500]}")
    out = p.stdout
    c2s, s2c = [], []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or any(k in ln for k in ("====", "Follow:", "Filter:", "Node ")):
            continue
        (s2c if ln.startswith("\t") else c2s).append(s)
    mk = lambda xs: bytes.fromhex("".join(x.replace(" ", "") for x in xs))
    return mk(c2s), mk(s2c)


def mbap_chain(buf):
    """Zero-resync MBAP chain; returns frames or None when the stream breaks."""
    frames, pos = [], 0
    while pos + 6 <= len(buf):
        ln = int.from_bytes(buf[pos + 4:pos + 6], "big")
        end = pos + 6 + ln
        if ln < 2 or end > len(buf):
            return None
        frames.append(buf[pos:end])
        pos = end
    return frames if len(frames) >= 3 and pos == len(buf) else None


def tpkt_chain(buf):
    """Zero-resync TPKT chain (4B header, u16be total length incl header)."""
    frames, pos = [], 0
    while pos + 4 <= len(buf):
        ln = int.from_bytes(buf[pos + 2:pos + 4], "big")
        end = pos + ln
        if ln < 4 or end > len(buf):
            return None
        frames.append(buf[pos:end])
        pos = end
    return frames if len(frames) >= 3 and pos == len(buf) else None


def group_key(pdu):
    """pdu = bytes after unit id. Private FCs get a 2-byte sub-key."""
    if not pdu:
        return None
    key = (pdu[0],)
    if pdu[0] >= PRIVATE_FC_MIN and len(pdu) >= 3:
        key = (pdu[0], pdu[1], pdu[2])
    return key


def key_str(key, sub=None):
    if key and key[0] == "rsp":
        key = key[1:]
        pre = "resp "
    else:
        pre = ""
    s = f"{pre}FC=0x{key[0]:02x}"
    if len(key) > 1:
        s += f" chan=0x{key[1]:02x} cmd=0x{key[2]:02x}"
    if sub:
        s += f" sub={sub[0]:02x} {sub[1]:02x}"
    return s


def u_at(frame, off, size, be):
    return int.from_bytes(frame[off:off + size], "big" if be else "little")


def classify(frames, paired_txn=None):
    """Byte-align full wire frames; merge offsets into evidence-backed fields.

    Returns (fields, tail) - fields cover the region present in ALL samples;
    the variable-length remainder is reported as `tail`.
    """
    common = min(len(f) for f in frames)
    txn_of = [int.from_bytes(f[0:2], "big") for f in frames]

    def window_class(off, size, be):
        """Return (class, note) if all samples match a variance rule, else None."""
        try:
            vals = [u_at(f, off, size, be) for f in frames]
        except Exception:
            return None
        if off == 4 and size == 2 and be and \
                all(v == len(f) - 6 for v, f in zip(vals, frames)):
            return "mbap-len", "u16be@4 == frame_len-6 in all"
        if off == 2 and size == 2 and be and \
                all(v == len(f) for v, f in zip(vals, frames)):
            return "tpkt-len", "u16be@2 == frame_len (total incl header) in all"
        if paired_txn is not None and off == 0 and size == 2 and be and \
                all(v == t for v, t in zip(vals, paired_txn)):
            return "txn-echo", "u16be@0 == paired request txn in all"
        if all(vals[i] < vals[i + 1] for i in range(len(vals) - 1)):
            delta = "const" if len({vals[i + 1] - vals[i]
                                    for i in range(len(vals) - 1)}) == 1 else "varies"
            return "seq", f"monotonic increase (delta {delta})"
        return None

    fields, i = [], 0
    while i < common:
        hit = None
        for size in (2, 4):
            for be in (True, False):
                c = window_class(i, size, be)
                if c:
                    hit = (size, be, c)
                    break
            if hit:
                break
        if hit:
            size, be, (cls, note) = hit
            fields.append({"off": i, "size": size, "class": cls,
                           "type": f"u{size * 8}{'be' if be else 'le'}",
                           "note": note, "evidence": f"{len(frames)}/{len(frames)}"})
            i += size
            continue
        vals = {f[i] for f in frames}
        if len(vals) == 1:
            j = i
            while j < common and len({f[j] for f in frames}) == 1:
                # an evidence rule at j outranks absorbing j into the const run
                if j > i and any(window_class(j, s, be)
                                for s in (2, 4) for be in (True, False)):
                    break
                j += 1
            fields.append({"off": i, "size": j - i, "class": "constant",
                           "type": f"const[{i}:{j}]", "value": frames[0][i:j].hex(" "),
                           "evidence": f"{len(frames)}/{len(frames)}"})
            i = j
            continue
        j = i
        while j < common and len({f[j] for f in frames}) > 1:
            j += 1
        run = (frames[0][i:j], )
        is_ascii = all(0x20 <= b <= 0x7e for f in frames for b in f[i:j]) and j - i >= 2
        fields.append({"off": i, "size": j - i,
                       "class": "ascii" if is_ascii else "data",
                       "type": "bytes",
                       "values": sorted({f[i:j].hex() for f in frames})[:4],
                       "evidence": f"{len(frames)}/{len(frames)} varying"})
        i = j
    lens = [len(f) for f in frames]
    tail = None
    if max(lens) > common:
        tail = {"from_off": common, "len_range": [min(lens) - common, max(lens) - common]}
    return fields, tail


def subsplit(frames):
    """Split a group by its first two arg bytes when that yields clean clusters."""
    pdu = lambda f: f[7:]
    args0 = {(pdu(f)[3], pdu(f)[4]) for f in frames if len(pdu(f)) >= 5}
    if not (2 <= len(args0) <= 8):
        return None
    buckets = {}
    for f in frames:
        p = pdu(f)
        if len(p) < 5:
            return None
        buckets.setdefault((p[3], p[4]), []).append(f)
    if min(len(v) for v in buckets.values()) >= 3:
        return buckets
    return None


def read_pcapng_udp(path, port):
    """Minimal pcapng reader: yield (src_ip, dst_ip, udp_payload) for UDP datagrams
    to/from the given port. No external deps."""
    import struct as _s
    buf = []
    with open(path, "rb") as f:
        while True:
            b = f.read(8)
            if len(b) < 8:
                break
            btype, blen = _s.unpack("<II", b)
            if blen < 12 or blen % 4:
                break
            body = f.read(blen - 12)
            f.read(4)  # trailing length
            if btype == 6:  # Enhanced Packet Block: iface, ts_hi, ts_lo, caplen, origlen
                caplen = _s.unpack("<I", body[12:16])[0]
                buf.append(body[20:20 + caplen])
    datagrams = []
    for pkt in buf:
        if len(pkt) < 14 + 20 + 8 or pkt[12:14] != b"\x08\x00":
            continue
        ip = pkt[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0xF) * 4
        sport, dport = _s.unpack("!HH", ip[ihl:ihl + 4])
        if port not in (sport, dport):
            continue
        udplen = _s.unpack("!H", ip[ihl + 4:ihl + 6])[0]
        payload = ip[ihl + 8: ihl + udplen]
        datagrams.append((".".join(str(c) for c in ip[12:16]),
                          ".".join(str(c) for c in ip[16:20]), payload))
    return datagrams


def main():
    global TSHARK
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--tshark", default=TSHARK)
    ap.add_argument("--mode", choices=("mbtcp", "tpkt", "chain", "udp"), default="mbtcp",
                    help="mbtcp: MBAP carrier (Modbus FC keying); tpkt: RFC1006 carrier; "
                         "chain: generic [magic][len] framing (--magic-hex/--header/--len-*)")
    ap.add_argument("--key-off", type=int, default=11,
                    help="[tpkt/chain] absolute frame offset of the grouping key")
    ap.add_argument("--key-len", type=int, default=2)
    ap.add_argument("--magic-hex", default="", help="[chain] frame magic to enforce (hex)")
    ap.add_argument("--header", type=int, default=6, help="[chain] header size incl magic")
    ap.add_argument("--len-off", type=int, default=4)
    ap.add_argument("--len-size", type=int, default=2, choices=(2, 4))
    ap.add_argument("--len-endian", choices=("be", "le"), default="be")
    ap.add_argument("--len-bias", type=int, default=0,
                    help="[chain] bytes after payload not covered by the length field")
    ap.add_argument("--udp-port", type=int, default=9600, help="[udp] UDP port to analyze")
    ap.add_argument("--min-samples", type=int, default=3)
    ap.add_argument("--semantics", default=None,
                    help="JSON {key: {'offset': 'name'}} to rename fields")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    TSHARK = args.tshark
    sem = {}
    if args.semantics:
        with open(args.semantics, encoding="utf-8") as fh:
            sem = json.load(fh)

    # M0-2: loud failure on tshark errors (see follow()).
    try:
        p = subprocess.run([TSHARK, "-r", args.pcap, "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                            "-T", "fields", "-e", "tcp.stream"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise SystemExit(f"tshark not found: {TSHARK} "
                         "(set PROTOCOL_AGENT_TSHARK or add Wireshark to PATH)")
    if p.returncode != 0 or (not p.stdout.strip() and p.stderr.strip()):
        raise SystemExit(f"tshark failed (exit {p.returncode}): {p.stderr.strip()[:500]}")
    out = p.stdout
    streams = sorted({int(x) for x in out.split() if x.strip().isdigit()})

    data = F.load(args.out)
    n_maps = 0
    if args.mode == "udp":
        dgrams = read_pcapng_udp(args.pcap, args.udp_port)
        groups = {"request": {}, "response": {}}
        dev_ip = dgrams[0][1] if dgrams else None   # first datagram's destination = device
        for src, dst, payload in dgrams:
            direction = "response" if src == dev_ip else "request"
            groups[direction].setdefault(payload[args.key_off:args.key_off + args.key_len], []).append(payload)
        for direction in ("request", "response"):
            for key, gframes in sorted(groups[direction].items()):
                if len(gframes) < args.min_samples:
                    continue
                kstr = f"udp key={key.hex(' ')} @{args.key_off}"
                n_maps += emit(data, key, gframes, direction, None, sem, kstr)
        F.add(data, "phases", {"phase": "P3b", "status": "done", "field_maps": n_maps,
                               "mode": "udp"})
        F.save(args.out, data)
        print(f"\n{n_maps} field maps -> {args.out}")
        return

    if args.mode == "chain":
        magic = bytes.fromhex(args.magic_hex) if args.magic_hex else b""

        def chain_frames(buf):
            frames, pos = [], 0
            while pos < len(buf):
                if magic and buf[pos:pos + len(magic)] != magic:
                    return None
                end = pos + args.header + args.len_bias
                if end + args.len_size > len(buf):
                    return None
                fmt = (">" if args.len_endian == "be" else "<") + ("H" if args.len_size == 2 else "I")
                import struct
                end += struct.unpack_from(fmt, buf, pos + args.len_off)[0]
                if end <= pos or end > len(buf):
                    return None
                frames.append(buf[pos:end])
                pos = end
            return frames if len(frames) >= 3 else None

        for n in streams:
            c2s, s2c = follow(args.pcap, n)
            for buf, direction in ((c2s, "request"), (s2c, "response")):
                frames = chain_frames(buf)
                if not frames:
                    continue
                groups = {}
                for f in frames:
                    if len(f) < args.key_off + args.key_len:
                        groups.setdefault(b"", []).append(f)
                        continue
                    groups.setdefault(f[args.key_off:args.key_off + args.key_len], []).append(f)
                for key, gframes in sorted(groups.items()):
                    if len(gframes) < args.min_samples:
                        continue
                    kstr = f"chain key={key.hex(' ')} @{args.key_off}"
                    n_maps += emit(data, key, gframes, direction, None, sem, kstr)
        F.add(data, "phases", {"phase": "P3b", "status": "done", "field_maps": n_maps,
                               "mode": "chain"})
        F.save(args.out, data)
        print(f"\n{n_maps} field maps -> {args.out}")
        return

    if args.mode == "tpkt":
        for n in streams:
            c2s, s2c = follow(args.pcap, n)
            for buf, direction in ((c2s, "request"), (s2c, "response")):
                frames = tpkt_chain(buf)
                if not frames:
                    continue
                groups = {}
                for f in frames:
                    if len(f) < args.key_off + args.key_len:
                        # frames shorter than the key (e.g. 7B empty COTP-DT heartbeats)
                        groups.setdefault(b"", []).append(f)
                        continue
                    groups.setdefault(f[args.key_off:args.key_off + args.key_len], []).append(f)
                for key, gframes in sorted(groups.items()):
                    if len(gframes) < args.min_samples:
                        continue
                    kstr = f"tpkt key={key.hex(' ')} @{args.key_off}"
                    n_maps += emit(data, key, gframes, direction, None, sem, kstr)
        F.add(data, "phases", {"phase": "P3b", "status": "done", "field_maps": n_maps,
                               "mode": "tpkt"})
        F.save(args.out, data)
        print(f"\n{n_maps} field maps -> {args.out}")
        return

    req_groups, txn_key = {}, {}
    rsp_by_key = {}
    for n in streams:
        c2s, s2c = follow(args.pcap, n)
        for buf, direction in ((c2s, "request"), (s2c, "response")):
            frames = mbap_chain(buf)
            if not frames:
                continue
            if direction == "request":
                for f in frames:
                    key = group_key(f[7:])
                    if key:
                        req_groups.setdefault(key, []).append(f)
                        txn_key[int.from_bytes(f[0:2], "big")] = key
            else:
                for f in frames:
                    rsp_by_key.setdefault(f, None)  # placeholder, paired below

    # pair responses to request keys via MBAP txn
    rsp_groups = {}
    for f in list(rsp_by_key):
        t = int.from_bytes(f[0:2], "big")
        key = txn_key.get(t)
        if key:
            rsp_groups.setdefault(("rsp",) + key, []).append(f)

    data = F.load(args.out)
    n_maps = 0
    for tag, groups, direction, pairing in (
            ("req", req_groups, "request", None),
            ("rsp", rsp_groups, "response", "pair")):
        for key, frames in sorted(groups.items()):
            if len(frames) < args.min_samples:
                continue
            buckets = subsplit(frames) if direction == "request" else None
            if buckets:
                for sub, sub_frames in sorted(buckets.items()):
                    n_maps += emit(data, key, sub_frames, direction, pairing, sem,
                                   key_str(key, sub))
            else:
                n_maps += emit(data, key, frames, direction, pairing, sem, key_str(key))
    F.add(data, "phases", {"phase": "P3b", "status": "done", "field_maps": n_maps})
    F.save(args.out, data)
    print(f"\n{n_maps} field maps -> {args.out}")


def emit(data, key, frames, direction, pairing, sem, kstr):
    paired_txn = None
    if pairing:
        paired_txn = [int.from_bytes(f[0:2], "big") for f in frames]
    fields, tail = classify(frames, paired_txn)
    sem_map = sem.get(kstr, {})
    for fld in fields:
        if str(fld["off"]) in sem_map:
            fld["name"] = sem_map[str(fld["off"])]
    real_key = key[1:] if key and key[0] == "rsp" else key
    item = {"kind": "field-map", "key": kstr, "direction": direction,
            "samples": len(frames), "grade": "traffic",
            "frame_len": [min(len(f) for f in frames), max(len(f) for f in frames)],
            "fields": fields}
    if tail:
        item["tail"] = tail
    if len(real_key) > 2:
        item["channel"] = f"0x{real_key[1]:02x}"
        item["cmd"] = f"0x{real_key[2]:02x}"
    # idempotent: a re-run replaces the previous map for the same key+direction
    data["field_maps"] = [m for m in data.get("field_maps", [])
                          if not (m.get("key") == kstr and m.get("direction") == direction)]
    F.add(data, "field_maps", item)
    print(f"[{direction:8s}] {kstr}: {len(frames)} samples, {len(fields)} fields"
          + (f", tail@{tail['from_off']}" if tail else ""))
    return 1


if __name__ == "__main__":
    main()
