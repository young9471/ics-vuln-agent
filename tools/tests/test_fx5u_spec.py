"""fx5u spec 测试：帧透传构造、melsec 载体响应解析、spec 完整性。"""
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import client_harness as CH


def _norm(h):
    return h.replace(" ", "")


class FX5USpecTests(unittest.TestCase):
    def test_spec_shape(self):
        spec = CH.SPECS["fx5u"]
        self.assertEqual(spec["frame"]["carrier"], "melsec")
        self.assertEqual(spec["port"], 5562)
        for key in ("handshake", "identify", "auth", "session"):
            hexs = _norm(spec["services"].get(key, "") if key != "handshake"
                         else spec["handshake"])
            bytes.fromhex(hexs)                       # 帧字节有效
        # case-19 实测帧原样回放：identify 应含 0x2101 命令字
        self.assertIn("2101", _norm(spec["services"]["identify"]))

    def test_build_is_verbatim_replay(self):
        spec = dict(CH.SPECS["fx5u"])
        eng = CH.FrameEngine(spec)
        frame = eng.build(bytes.fromhex(_norm(spec["handshake"])))
        self.assertEqual(frame.hex(), _norm(spec["handshake"]))

    def test_recv_melsec_frame(self):
        spec = dict(CH.SPECS["fx5u"])
        a, b = socket.socketpair()
        payload = bytes.fromhex("deadbeef01")
        head = b"\xd7\x01" + b"\x00" * 17 + struct.pack("<H", len(payload))
        self.assertEqual(len(head), 21)

        threading.Thread(target=lambda: b.sendall(head + payload),
                         daemon=True).start()
        with mock.patch.object(CH.socket, "create_connection", return_value=a):
            c = CH.Client(spec, "127.0.0.1")
        hdr, pl = c.recv_frame()
        self.assertEqual(hdr[:2], b"\xd7\x01")
        self.assertEqual(pl, payload)
        a.close()
        b.close()


if __name__ == "__main__":
    unittest.main()
