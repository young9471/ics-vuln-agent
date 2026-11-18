import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import analyzer_cache
import binary_survey
import capture
import elf_analyze
import ghidra_analyze
import probe_dsl
import session_model
import traffic_insights as ti


class CrcTests(unittest.TestCase):
    def test_known_crc_values(self):
        data = b"123456789"
        self.assertEqual(ti.crc8(data), 0xF4)
        self.assertEqual(ti.crc16(data, 0x1021, 0xFFFF), 0x29B1)
        self.assertEqual(ti.crc16_modbus(data), 0x4B37)
        self.assertEqual(ti.crc32(data), 0xCBF43926)

    def test_infer_crc(self):
        msgs = []
        for i in range(4):
            payload = bytes([0x01, i, 0x02])
            body = b"\xaa" + payload
            msgs.append(body + struct.pack("<H", ti.crc16_modbus(payload)))
        hits = ti.infer_crc(msgs)
        self.assertTrue(any(h["algorithm"] == "crc16-modbus" for h in hits), hits)


class EntropyTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(ti.entropy(b"\x00" * 32), 0.0)
        high = ti.entropy(bytes(range(256)))
        self.assertGreater(high, 7.9)


class BinarySurveyTests(unittest.TestCase):
    def test_keyword_score(self):
        data = b"connect socket tcp port 192.168. device"
        score, reasons, hits, _ = binary_survey.score_for("a.exe", data, ("PE", "x86", False))
        self.assertGreater(score, 0)
        self.assertIn("socket", hits)
        self.assertTrue(reasons)


class ElfTests(unittest.TestCase):
    def test_header(self):
        data = bytearray(64)
        data[:4] = b"\x7fELF"
        data[4] = 2  # 64-bit
        data[5] = 1  # little endian
        data[18:20] = (62).to_bytes(2, "little")  # x86-64
        info = elf_analyze.elf_header(bytes(data))
        self.assertIsNotNone(info)
        self.assertEqual(info["arch"], "x64")



class TrafficInsightTests(unittest.TestCase):
    def test_crc_parameter_sets(self):
        self.assertEqual(ti.crc_with("crc16-modbus", b"123456789"), 0x4B37)
        self.assertEqual(ti.crc_with("crc32-ieee", b"123456789"), 0xCBF43926)
        self.assertEqual(ti.crc_with("crc16-ccitt", b"123456789"), 0x29B1)

    def test_compression_candidate(self):
        zipped = zlib.compress(b"protocol-agent" * 20)
        hits = ti.compression_candidates([zipped])
        self.assertTrue(any(h["method"] == "zlib" for h in hits), hits)

    def test_differential_fields(self):
        msgs = [bytes([0xAA, 0x01, i]) + b"tail" for i in range(4)]
        hits = ti.differential_fields(msgs)
        self.assertEqual(len(hits), 1)
        self.assertIn(2, hits[0]["varying_offsets"])
        self.assertIn(0, [x["offset"] for x in hits[0]["constant_offsets"]])


class SessionModelTests(unittest.TestCase):
    @staticmethod
    def row(frame, ts, src, dst, stream, sport, dport, seq, payload):
        return [str(frame), str(ts), src, dst, str(stream), str(sport), str(dport),
                str(seq), "0", "0x18", str(len(bytes.fromhex(payload))), payload,
                "", "", ""]

    def test_pairing_retry_timeout(self):
        rows = [
            self.row(1, 1.0, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 100, "aa01"),
            self.row(2, 1.1, "10.0.0.2", "10.0.0.1", 0, 502, 1234, 200, "bb01"),
            self.row(3, 2.0, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 102, "aa01"),
            self.row(4, 2.1, "10.0.0.2", "10.0.0.1", 0, 502, 1234, 202, "bb01"),
            self.row(5, 3.0, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 104, "aa02"),
        ]
        models = session_model.build_models(rows, timeout_s=0.5, type_offset=0, type_size=1)
        self.assertEqual(len(models), 1)
        m = models[0]
        self.assertEqual((m["requests"], m["responses"], m["paired"]), (3, 2, 2))
        self.assertEqual(m["unmatched_requests"], 1)
        self.assertEqual(len(m["retries"]), 1)
        self.assertEqual(len(m["timeouts"]), 1)
        self.assertEqual(m["transitions"][0]["count"], 2)

    def test_tcp_reassembly(self):
        rows = [
            self.row(1, 1.0, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 100, "aa"),
            self.row(2, 1.01, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 101, "bb"),
            self.row(3, 1.1, "10.0.0.2", "10.0.0.1", 0, 502, 1234, 200, "cc"),
        ]
        streams = session_model.group_packets(rows)
        stream = next(iter(streams.values()))
        messages, frag = session_model.reassemble_tcp([p for p in stream["packets"] if p["tcp"]])
        self.assertEqual(frag["gaps"], 0)
        self.assertIn(bytes([0xAA, 0xBB]), [m["payload"] for m in messages])


    def test_large_session_performance(self):
        rows = []
        for i in range(10000):
            t = float(i) * 0.01
            rows.append(self.row(2 * i + 1, t, "10.0.0.1", "10.0.0.2", 0, 1234, 502, 100 + 2 * i, "aa01"))
            rows.append(self.row(2 * i + 2, t + 0.005, "10.0.0.2", "10.0.0.1", 0, 502, 1234, 500 + 2 * i, "bb01"))
        started = time.monotonic()
        models = session_model.build_models(rows, timeout_s=1, type_offset=0, type_size=1)
        elapsed = time.monotonic() - started
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["paired"], 10000)
        self.assertLess(elapsed, 5.0, f"session model too slow: {elapsed:.3f}s")

class ProbeDslTests(unittest.TestCase):
    def test_build_request_fields_sequence_checksum(self):
        req = {
            "hex": "01 02",
            "fields": [{"offset": 0, "size": 1, "value": 0x07}],
            "sequence": {"offset": 1, "size": 1, "start": 9},
            "checksum": {"type": "sum8", "coverage": [0, 2]},
        }
        frame = probe_dsl.build_request(req)
        self.assertEqual(frame, bytes([0x07, 0x09, 0x10]))

    def test_expect(self):
        ok, _ = probe_dsl.check_expect(bytes.fromhex("aabbcc"), {"contains_hex": "bbcc", "min_bytes": 3})
        self.assertTrue(ok)
        bad, _ = probe_dsl.check_expect(b"x", {"min_bytes": 2})
        self.assertFalse(bad)


class AnalyzerCacheTests(unittest.TestCase):
    def test_sha256_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = os.path.join(tmp, "sample.bin")
            with open(sample, "wb") as fh:
                fh.write(b"v1")
            with mock.patch.dict(os.environ, {"PROTOCOL_AGENT_ANALYZER_CACHE": tmp}):
                self.assertTrue(analyzer_cache.store(sample, "ghidra", "12.2", {"value": 1}))
                self.assertEqual(analyzer_cache.load(sample, "ghidra", "12.2"), {"value": 1})
                with open(sample, "wb") as fh:
                    fh.write(b"v2")
                self.assertIsNone(analyzer_cache.load(sample, "ghidra", "12.2"))



class CaptureInterfaceTests(unittest.TestCase):
    def test_parse_tshark_interfaces(self):
        items = capture.parse_tshark_interfaces("1. dev0 (Ethernet1)" + chr(10) + "2. dev1 (Loopback)")
        self.assertEqual(items[0]["id"], "1")
        self.assertIn("Ethernet1", items[0]["name"])
        self.assertEqual(items[1]["id"], "2")

    def test_default_interfaces_excludes_loopback(self):
        original = capture.list_interfaces
        capture.list_interfaces = lambda ts=None: [
            {"id": "1", "name": "Ethernet1"}, {"id": "2", "name": "Loopback"}]
        try:
            items = capture.default_interfaces("tshark")
            self.assertEqual([x["id"] for x in items], ["1"])
        finally:
            capture.list_interfaces = original

class GhidraTimeoutTests(unittest.TestCase):
    def test_timeout_writes_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "findings.json")
            argv = ["ghidra_analyze.py", "--path", "sample.dll", "--out", out,
                    "--append", "--timeout", "1"]
            with mock.patch.object(ghidra_analyze, "find_headless", return_value="analyzeHeadless"), \
                    mock.patch.object(ghidra_analyze.subprocess, "run",
                                      side_effect=subprocess.TimeoutExpired("analyzeHeadless", 1)), \
                    mock.patch.object(sys, "argv", argv):
                rc = ghidra_analyze.main()
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            notes = [n for n in data["notes"] if n.get("kind") == "ghidra-timeout"]
            self.assertEqual(len(notes), 1)
            self.assertIn("exceeded", notes[0]["reason"])


if __name__ == "__main__":
    unittest.main()
