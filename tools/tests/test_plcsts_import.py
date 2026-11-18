"""plcsts_import 单测：分类器、hex 帧提取、厂商/型号路径解析。"""
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import plcsts_import as P  # noqa: E402

SAMPLE = '''
from plcsts import exploits, validators
import binascii

stop_payload = "000000000006015a0041ff00"
start_payload = "000000000006015a0040ff00"
keep_alive = binascii.a2b_hex("000000000004015a")

class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'Schneider M221 PLC start/stop',
        'description': 'Control schneider M221 start or stop',
        'devices': ['Schneider M221 programmable logic controllers (PLCs)'],
    }
    target = exploits.Option('', 'Target address', validators=validators.ipv4)
    port = exploits.Option(502, 'Target Port', validators=validators.integer)
'''


class ClassifyTests(unittest.TestCase):
    def test_start_stop_destructive(self):
        self.assertEqual(P.classify("M221_CPU_start_stop", "attacking"), (3, "destructive"))

    def test_dos(self):
        self.assertEqual(P.classify("na300_dos", "attacking"), (7, "destructive"))

    def test_write_memory(self):
        self.assertEqual(P.classify("na300_write_memory", "attacking"), (4, "destructive"))

    def test_set_io(self):
        self.assertEqual(P.classify("micrologix_1100_set_io", "attacking"), (13, "write"))

    def test_modify_program(self):
        self.assertEqual(P.classify("MAC1100_overwrite_program", "attacking"), (5, "destructive"))

    def test_password_crack(self):
        self.assertEqual(P.classify("micrologix_1100_cancel_password", "attacking"), (6, "write"))

    def test_get_info(self):
        self.assertEqual(P.classify("M221_get_info", "attacking"), (1, "read"))

    def test_spreading_default(self):
        self.assertEqual(P.classify("na300_ftp_default", "spreading"), (2, "read"))

    def test_rce(self):
        self.assertEqual(P.classify("na300_rce", "spreading"), (8, "destructive"))


class ParseTests(unittest.TestCase):
    def _parse(self, rel="attacking/schneider/M221/M221_CPU_start_stop.py"):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(SAMPLE, encoding="utf-8")
            return P.parse_module(p, root)

    def test_hex_string_and_a2b_frames(self):
        it = self._parse()
        self.assertEqual(it["refs"]["frames"]["stop_payload"], "000000000006015a0041ff00")
        self.assertEqual(it["refs"]["frames"]["keep_alive"], "000000000004015a")
        self.assertEqual(it["refs"]["port"], 502)

    def test_vendor_model_from_path(self):
        it = self._parse()
        self.assertEqual(it["vendor"], "schneider-electric")
        self.assertEqual(it["refs"]["model"], "M221")
        self.assertEqual(it["protocol"], "modbus")
        self.assertEqual(it["vclass"], 3)
        self.assertTrue(it["cve_id"].startswith("PLCSTS:"))

    def test_scanning_skipped(self):
        self.assertIsNone(self._parse("scanning/Proprietary_protocol/Schneider/M221_scanning.py"))

    def test_persistence_skipped(self):
        self.assertIsNone(self._parse("persistence/malware_io.py"))

    def test_na300_vendor(self):
        it = self._parse("attacking/Nandaauto/NA300/na300_dos.py")
        self.assertEqual(it["vendor"], "nandaauto")
        self.assertEqual(it["refs"]["model"], "NA300")
        self.assertEqual(it["vclass"], 7)


if __name__ == "__main__":
    unittest.main()
