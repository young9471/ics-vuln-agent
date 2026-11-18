#!/usr/bin/env python3
"""P5 declarative protocol client harness.

A protocol is described by a SPEC dict (transport + framing + handshake +
request layout); the harness builds/frames/sends/receives generically.
Two battle-tested specs are built in (both verified against a live
WAGO 750-8202): the CODESYS-V2 gateway protocol (TCP 2455) and the
WAGO service protocol (TCP 6626). New cases: add a spec, reuse the engine.

Usage (live):
  python client_harness.py --spec wago --host 192.168.1.20 identify
  python client_harness.py --spec wago --host 192.168.1.20 code 0x0106
  python client_harness.py --spec codesys --host 192.168.1.20 session
"""
import argparse
import socket
import struct
import sys

SPECS = {
    "fins": {
        "name": "OMRON FINS/UDP (CX-Programmer, UDP 9600)",
        "port": 9600,
        "frame": {
            "carrier": "fins",                      # one FINS frame per UDP datagram
            "transport": "udp",                     # [ICF][RSV][GCT][DNA DA1 DA2][SNA SA1 SA2][SID][MRC][SRC]
            "checksum": None,
        },
        "handshake": None,
        "services": {                                # golden CP1L-E session (runs/cxprog)
            "ctrl": "80 00 07 00 00 00 00 66 00 01 06 01",       # controller data read
            "status": "80 00 07 00 00 00 00 66 00 02 05 01",     # CPU unit status
            "read": "80 00 07 00 00 00 00 66 00 0d 01 01 06 00 00 00 00 20",  # memory read
        },
    },
    "enip": {
        "name": "Rockwell PCCC over EtherNet/IP (MicroLogix/SLC, TCP 44818)",
        "port": 44818,
        "frame": {
            "carrier": "enip",                      # 24B hdr: cmd u16le len u16le session
            "checksum": None,                       #  status u32le context u64 options u32le
        },
        "handshake": "01 00 00 00",                 # RegisterSession(0x65): ver=1 flags=0
        "services": {                               # golden 1766-L32BWA session (runs/rslogix)
            # full SendRRData(0x6F) payload, verbatim replay; inner PCCC = 0x06 small read
            "read6": "00 00 00 00 0a 00 02 00 00 00 00 00 b2 00 12 00"
                     " 4b 02 20 67 24 01 07 4d 00 9e 62 a3 1e 06 00 f0 00 03",
        },
    },
    "napro": {
        "name": "Nandaauto NAPro engineering protocol (NA series, TCP 5555)",
        "port": 5555,
        "frame": {
            "carrier": "chain",                      # magic 00 00 55 55 + u16be body len
            "magic": "00005555",
            "checksum": None,
        },
        "handshake": None,
        "services": {                                # golden NA300 session (runs/napro)
            "hello": "01 02 00 00 00 00 00 00 00 00",   # identity probe (flag@14 = 00)
            "hello2": "01 02 00 00 00 00 00 00 01 00",   # variant flag = 01
            "open": "01 41 00 00 00 00 00 00 00 00 00 00 00 00 01 01",
            "op09": "01 09 0e 00 05 00 01 00 00 00",
        },
    },
    "s7smart": {
        "name": "Siemens S7-200 SMART PPI over TPKT/COTP (TCP 102)",
        "port": 102,
        "frame": {
            "carrier": "tpkt",                       # 03 00 + u16be total len; COTP DT 02 f0 80
            "cotp_dt": "02f080",
            "checksum": None,
        },
        "handshake": "03 00 00 16 11 e0 00 00 00 01 00 c1 02 01 01 c2 02 01 01 c0 01 0a",
        "services": {                                 # golden CPU SR20 session (runs/s7200smart)
            "poll": "32 01 00 00 cc c1 00 08 00 00 f0 00 00 01 00 01 03 c0",
            "readinfo": "32 01 00 00 00 01 00 1a 00 00 04 02 12 0a 10 02 00 10 00 00 03 00 00"
                        " 00 12 0a 10 02 00 06 00 00 05 00 20 80",
            "szl": "32 07 00 00 00 02 00 0c 00 04 00 01 12 08 12 48 12 00 00 00 00 00 0a 00 00 00",
            "varread": "32 07 00 00 00 05 00 08 00 0c 00 01 12 04 11 43 03 00 ff 09 00 08"
                       " 30 38 30 30 30 30 31 41",
        },
    },
    "umas": {
        "name": "Schneider UMAS over Modbus TCP (M340/M580, TCP 502)",
        "port": 502,
        "frame": {
            "carrier": "mbap",                       # [txn u16be][proto=0][len u16be][unit]
            "unit": 0,
            "checksum": None,
        },
        "handshake": None,
        "services": {                                 # golden M580 session (runs/ce153 pcap)
            "probe": "00 5a 00 02",                   # session pre-open probe
            "info": "00 5a 00 01 00",                 # info family
            "login": "LOGIN_T",                       # 00 5a 00 0a 00 + 'T'*1019 (fixed 1024B buffer)
            "info2": "00 5a 00 03 00",
            "info3": "00 5a 00 03 04",
            "beat": "00 5a 00 04",                    # heartbeat / poll beat
            "host": "00 5a 00 10 46 46 00 00 0f 44 45 53 4b 54 4f 50 2d 31 51 35 4a 32 36 34",
            "chanbeat": "00 5a 24 04",                # beat on app channel 0x24
            "read50": "00 5a 24 50 15 00 01 0b",      # chan-0x24 cmd 0x50 (observed poll loop)
        },
    },
    "fx5u": {
        # MELSOFT engineering tunnel (GX Works3 <-> FX5U, TCP 5562); SLMP/MC 3E rides
        # TCP 5000 on real CPUs. Frames below are verbatim replays of the live-verified
        # case-19 probes (FX5U-32MR/ES): tunnel responses carry 0xd7xx/0xdaxx magic,
        # 21B header with u16le payload length at offset 19, lock-step seq at offset 2.
        "name": "Mitsubishi FX5U MELSOFT tunnel (GX Works3, TCP 5562)",
        "port": 5562,
        "frame": {
            "carrier": "melsec",
            "open_channel": "5a0000ff",              # bare greeting -> da0000ff+24B ack
            "resp_magic": ("d701", "da00"),
            "header_size": 21,
            "len_offset": 19,
            "checksum": None,
        },
        "handshake": "1c0a161400000000000000000000000000000000000000000121010000000001",
        "services": {                                 # golden FX5U-32MR/ES live session
            "identify": "1c0a161400000000000000000000000000000000000000000121010000000001",
            "auth": "1c0a1614000000000000000000000000000000000000000001a0020000000349df69fc",
            "session": "1c0a16140000000000000000000000000000000000000000016203000000",
        },
    },
    "wago": {
        "name": "WAGO service protocol (750-8xx/PFC200, TCP 6626)",
        "port": 6626,
        "frame": {
            "header_fmt": "<9H",                      # proto,seq,frag,total,0,0,0,flags,len
            "proto_id": 0x1288,                        # constant first u16 (pitfall #2)
            "len_field_index": 8,                      # which u16 is the length
            "len_covers": "payload",                   # payload bytes only
            "checksum": None,                          # additive u16 exists in lib but TCP uses none
        },
        "handshake": "01 01 fe af",                     # 0xAFFE magic
        "request_prefix_fmt": "<H",                     # payload starts with u16 function code
        "recv_exact": "len_field",                      # payload length from header
    },
    "codesys": {
        "name": "CODESYS V2 gateway (TCP 2455)",
        "port": 2455,
        "frame": {
            "header_fmt": "<HHIIIII",                   # magic,ver,plen,0,origin,dest,d4
            "magic": 0xCCCC,
            "ack_magic": 0x6666,                        # side-channel ACK (pitfall #1)
            "ack_d4": 6, "ack_reply_d4": 4,
            "d4_from_service": lambda svc: (svc << 8) | 0x23,
            "len_covers": "payload",
            "checksum": None,
        },
        "handshake": None,
        "services": {                                   # canned exchanges (from golden case)
            "hello": (0x05, "42 3c 00 34 36"),
            "identify": (0x0F, "01 04 00 00 00 06 00 00 00 00 00 00 00 00 00 cd"),
            "login": (0x15, "01 04 00 00 00 06 00 00 00 06 00 00 00 31 31 31 31"
                             " 31 31 00 cd"),
            "poll": (0x02, "50 05"),
            "taskinfo": (0x02, "51 10"),
            "logout": (0x02, "50 15"),
            "close": (0x02, "50 21"),
        },
    },
}


class FrameEngine:
    """Build/parse frames per spec; seq auto-increment."""

    def __init__(self, spec):
        self.spec = spec
        self.f = spec["frame"]
        self.seq = 1
        self.session = 0                            # ENIP session handle from handshake

    def _header(self, payload, d4=0, magic_override=None):
        f = self.f
        if f.get("carrier") in ("fins", "melsec"):        # payload is the whole frame
            return b""
        if f.get("carrier") == "enip":                 # ENIP 24B header, d4 = command
            self.seq += 1
            return struct.pack("<HHII", d4, len(payload), self.session, 0) \
                + struct.pack("<Q", self.seq) + struct.pack("<I", 0)
        if f.get("carrier") == "chain":                 # generic [magic][len] framing
            self.seq += 1
            return bytes.fromhex(f.get("magic", "")) + struct.pack(">H", len(payload))
        if f.get("carrier") == "tpkt":                  # s7smart-style RFC1006 + COTP DT
            self.seq += 1
            total = 7 + len(payload)
            return b"\x03\x00" + struct.pack(">H", total) \
                + bytes.fromhex(f.get("cotp_dt", "02f080"))
        if f.get("carrier") == "mbap":                 # umas-style MBAP wrapper
            self.seq += 1
            # payload already starts with the unit byte (canned PDUs include it)
            return struct.pack(">HHH", self.seq & 0xFFFF, 0, len(payload))
        if "proto_id" in f:                              # wago-style 9xu16
            vals = [f["proto_id"], self.seq, 1, 1, 0, 0, 0, 0, len(payload)]
            hdr = struct.pack(f["header_fmt"], *vals)
        else:                                            # codesys-style
            magic = magic_override or f["magic"]
            d4 = d4 or f["d4_from_service"](0)
            hdr = struct.pack(f["header_fmt"], magic, 1, len(payload), 0, 0, 1, d4)
        self.seq += 1
        return hdr

    def build(self, payload: bytes, d4=0, magic_override=None) -> bytes:
        hdr = self._header(payload, d4, magic_override)
        body = hdr + payload
        if self.f.get("checksum") == "add16":
            body += struct.pack("<H", sum(body) & 0xFFFF)
        return body

    def ack_frame(self) -> bytes:
        f = self.f
        return struct.pack(f["header_fmt"], f["ack_magic"], 1, 0, 0, 0, 0, f["ack_d4"])


class Client:
    def __init__(self, spec, host, timeout=4.0):
        self.spec, self.engine = spec, FrameEngine(spec)
        if spec["frame"].get("transport") == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((host, spec["port"]))
        else:
            self.sock = socket.create_connection((host, spec["port"]), timeout=timeout)
        self.sock.settimeout(timeout)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            d = self.sock.recv(n - len(buf))
            if not d:
                raise ConnectionError("peer closed")
            buf += d
        return buf

    def recv_frame(self):
        if self.spec["frame"].get("carrier") in ("fins", "melsec"):
            # melsec: responses carry 0xd7xx/0xdaxx magic, 21B header, u16le len@19
            if self.spec["frame"].get("carrier") == "melsec":
                first2 = self._recv_exact(2)
                hs = int(self.spec["frame"].get("header_size", 21))
                hdr = first2 + self._recv_exact(hs - 2)
                plen = struct.unpack_from(
                    "<H", hdr, int(self.spec["frame"].get("len_offset", 19)))[0]
                payload = self._recv_exact(plen) if plen else b""
                return hdr, payload
            data = self.sock.recv(4096)                  # datagram = whole FINS frame
            return b"", data
        if self.spec["frame"].get("carrier") == "enip":
            hdr = self._recv_exact(24)
            plen = struct.unpack_from("<H", hdr, 2)[0]
            payload = self._recv_exact(plen) if plen else b""
            return hdr, payload
        if self.spec["frame"].get("carrier") == "chain":
            hdr = self._recv_exact(6)
            magic = bytes.fromhex(self.spec["frame"].get("magic", ""))
            if magic and hdr[:len(magic)] != magic:
                raise ConnectionError(f"bad magic {hdr.hex(' ')}")
            plen = struct.unpack_from(">H", hdr, 4)[0]
            payload = self._recv_exact(plen) if plen else b""
            return hdr, payload
        if self.spec["frame"].get("carrier") == "tpkt":
            hdr = self._recv_exact(4)
            total = struct.unpack_from(">H", hdr, 2)[0]      # includes the 4-byte header
            payload = self._recv_exact(total - 4) if total > 4 else b""
            if payload[:2] == b"\x02\xf0":                   # strip COTP DT header
                payload = payload[3:]
            return hdr, payload
        if self.spec["frame"].get("carrier") == "mbap":
            hdr = self._recv_exact(6)                        # MBAP head (no unit byte)
            plen = struct.unpack_from(">H", hdr, 4)[0]       # covers unit + PDU
            payload = self._recv_exact(plen) if plen > 0 else b""
            return hdr, payload
        hs = struct.calcsize(self.spec["frame"]["header_fmt"])
        hdr = self._recv_exact(hs)
        plen = struct.unpack_from("<H" if "proto_id" in self.spec["frame"] else "<I",
                                  hdr, 16 if "proto_id" in self.spec["frame"] else 4)[0]
        payload = self._recv_exact(plen) if plen else b""
        return hdr, payload

    def post_ack(self):
        """CODESYS-style side-channel ACK after each exchange (pitfall #1)."""
        if "ack_magic" in self.spec["frame"]:
            # M0-3: restore the caller's timeout instead of pinning 4.0s.
            saved = self.sock.gettimeout()
            self.sock.sendall(self.engine.ack_frame())
            try:
                self.sock.settimeout(0.6)
                self.sock.recv(4096)
            except socket.timeout:
                pass
            finally:
                self.sock.settimeout(saved)

    def exchange(self, payload: bytes, d4=0):
        self.sock.sendall(self.engine.build(payload, d4=d4))
        hdr, pl = self.recv_frame()
        self.post_ack()
        return pl

    def handshake(self):
        hx = self.spec.get("handshake")
        if hx:
            if self.spec["frame"].get("carrier") == "melsec":
                # open-channel greeting first (bare frame, response starts da0000ff)
                if self.spec["frame"].get("open_channel"):
                    self.sock.sendall(bytes.fromhex(self.spec["frame"]["open_channel"]))
                    hdr, _ = self.recv_frame()
                return self.exchange(bytes.fromhex(hx))
            if self.spec["frame"].get("carrier") == "enip":
                self.sock.sendall(self.engine.build(bytes.fromhex(hx), d4=0x65))
                hdr, pl = self.recv_frame()             # RegisterSession reply
                self.engine.session = struct.unpack_from("<I", hdr, 4)[0]
                return pl
            if self.spec["frame"].get("carrier") == "tpkt":
                self.sock.sendall(bytes.fromhex(hx))    # raw COTP CR (already TPKT-framed)
                hdr, pl = self.recv_frame()             # COTP CC
                return pl
            return self.exchange(bytes.fromhex(hx))
        return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class ShortResponse(Exception):
    """Device replied with a frame too short or malformed for the flow to parse.

    Fuzzing and differential probes deliberately produce such replies; the
    flows must raise this instead of IndexError/struct.error (M0-3).
    """


def _need(pl: bytes, n: int, ctx: str) -> bytes:
    if len(pl) < n:
        raise ShortResponse(f"{ctx}: 响应过短（{len(pl)}B，需要 {n}B）：{pl.hex(' ')}")
    return pl


def wago_flow(c, code=None):
    print("handshake:", (c.handshake() or b"").hex(" "))
    if code:
        pl = c.exchange(struct.pack("<H", code))
        _need(pl, 4, f"code 0x{code:04x}")
        echo, status = struct.unpack_from("<HH", pl)
        print(f"code=0x{code:04x} -> echo=0x{echo:04x} status=0x{status:04x} "
              f"data={pl[4:52].hex(' ')}{' ...' if len(pl) > 56 else ''}")
        return pl
    for name, cd in [("GetDeviceState", 0x0106), ("IdentifyDevice", 0x0108),
                     ("GetNetworkID", 0x010C)]:
        pl = c.exchange(struct.pack("<H", cd))
        _need(pl, 4, name)
        echo, status = struct.unpack_from("<HH", pl)
        print(f"{name:16s} echo=0x{echo:04x} status=0x{status:04x} len={len(pl) - 4}")


def codesys_flow(c, service):
    svc_map = c.spec["services"]
    seq = [("hello", "hello"), ("identify", "identify"), ("poll", "poll")]
    if service in svc_map:
        seq = [(service, service)]
    for tag, key in seq:
        svc, payload_hex = svc_map[key]
        pl = c.exchange(bytes.fromhex(payload_hex),
                        d4=c.spec["frame"]["d4_from_service"](svc))
        print(f"{tag:10s} svc=0x{svc:02x} -> {pl[:48].hex(' ')}")


def fins_flow(c, action):
    svc = c.spec["services"]
    for tag in ("ctrl", "status", "read", "ctrl"):
        pl = c.exchange(bytes.fromhex(svc[tag]))
        _need(pl, 14, tag)  # icf at [0], cmd at [10:12], mres at [12:14]
        icf, cmd, mres = pl[0], pl[10:12].hex(" "), pl[12:14].hex(" ")
        ok = "OK" if mres == "00 00" else f"err={mres}"
        print(f"{tag:7s} icf=0x{icf:02x} cmd={cmd} {ok:11s} len={len(pl):3d} "
              f"data={pl[14:46].hex(' ')}{' ...' if len(pl) > 46 else ''}")


def enip_flow(c, action):
    svc = c.spec["services"]
    print("RegisterSession:", (c.handshake() or b"").hex(" "),
          "| session handle =", hex(c.engine.session))
    for tag in ["read6", "read6"]:
        pl = c.exchange(bytes.fromhex(svc[tag]), d4=0x6F)   # SendRRData
        # reply CIP service 0xCB + PCCC [cmd|0x80][status][data]
        idx = pl.find(b"\xcb")
        tail = pl[idx:] if idx >= 0 else pl
        print(f"{tag:6s} len={len(pl):4d} cip-reply={tail[:40].hex(' ')}"
              f"{' ...' if len(pl) > 40 else ''}")


def napro_flow(c, action):
    svc = c.spec["services"]
    seq = {"info": ["hello", "hello2", "op09"],
           "session": ["hello", "hello2", "op09", "hello"]}.get(action, ["hello"])
    for tag in seq:
        pl = c.exchange(bytes.fromhex(svc[tag]))
        cmd = f"{pl[0]:02x} {pl[1]:02x}" if len(pl) >= 2 else "??"
        print(f"{tag:7s} rsp-cmd={cmd} len={len(pl):6d} data={pl[:44].hex(' ')}"
              f"{' ...' if len(pl) > 44 else ''}")


def s7smart_flow(c, action):
    svc = c.spec["services"]
    print("COTP CR/CC:", (c.handshake() or b"").hex(" "))
    seq = {"info": ["poll", "readinfo", "szl", "varread"],
           "session": ["poll", "readinfo", "szl", "varread", "poll"]}.get(action,
           [action] if action in svc else ["poll"])
    for tag in seq:
        pl = c.exchange(bytes.fromhex(svc[tag]))
        if len(pl) < 8 or pl[0] != 0x32:
            print(f"{tag:9s} UNEXPECTED: {pl[:24].hex(' ')}")
            continue
        ver, msg_cls = pl[1], pl[6:8].hex(" ")
        ret = "OK" if b"\xff" in pl[10:14] or ver in (0x03,) else "check"
        print(f"{tag:9s} ver={ver:02x} class={msg_cls} {ret:5s} len={len(pl):3d} "
              f"data={pl[10:42].hex(' ')}{' ...' if len(pl) > 42 else ''}")


def umas_flow(c, action):
    svc = c.spec["services"]

    def pdu(name):
        h = svc[name]
        if h == "LOGIN_T":                              # fixed 1024B password buffer
            return bytes.fromhex("00 5a 00 0a 00") + b"T" * 1019
        return bytes.fromhex(h)

    seqs = {
        "info": ["probe", "info", "info2", "info3", "beat"],
        "session": ["probe", "login", "info2", "info3", "beat", "host",
                    "chanbeat", "read50", "beat"],
    }
    for tag in seqs[action]:
        pl = c.exchange(pdu(tag))
        # payload = [unit][5A][chan][status][data]
        _need(pl, 4, tag)
        chan, b1 = pl[2], pl[3]
        status = "OK" if b1 == 0xFE else f"err=0x{b1:02x}"
        print(f"{tag:9s} chan=0x{chan:02x} {status:9s} len={len(pl) - 4:4d} "
              f"data={pl[4:40].hex(' ')}{' ...' if len(pl) > 43 else ''}")


def fx5u_flow(c, action):
    svc = c.spec["services"]
    seq = {"info": ["identify"],
           "session": ["identify", "auth", "session"]}.get(action, ["identify"])
    for tag in seq:
        pl = c.exchange(bytes.fromhex(svc[tag]))
        model = ""
        idx = pl.find(b"FX5")
        if idx >= 0:
            model = pl[idx:idx + 18].decode("ascii", "replace").strip("\x00 ")
        print(f"{tag:9s} len={len(pl):4d} model={model:18s} data={pl[:32].hex(' ')}"
              f"{' ...' if len(pl) > 32 else ''}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", choices=SPECS, required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("action", nargs="?", default="session",
                    help="wago: session|identify|code 0xNNNN / codesys: hello|identify|poll")
    ap.add_argument("value", nargs="?", default=None)
    args = ap.parse_args()
    spec = dict(SPECS[args.spec])
    if args.port:
        spec["port"] = args.port
    c = Client(spec, args.host)
    try:
        if args.spec == "wago":
            code = int(args.value, 0) if args.action == "code" and args.value else None
            wago_flow(c, code)
        elif args.spec == "fins":
            fins_flow(c, args.action)
        elif args.spec == "enip":
            enip_flow(c, args.action)
        elif args.spec == "napro":
            napro_flow(c, args.action if args.action in ("info", "session") else "info")
        elif args.spec == "s7smart":
            s7smart_flow(c, args.action if args.action in ("info", "session") else "info")
        elif args.spec == "umas":
            umas_flow(c, args.action if args.action in ("info", "session") else "info")
        elif args.spec == "fx5u":
            fx5u_flow(c, args.action if args.action in ("info", "session") else "info")
        else:
            codesys_flow(c, args.action)
    except ShortResponse as exc:
        print(f"short/malformed response: {exc}", file=sys.stderr)
        return 1
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
