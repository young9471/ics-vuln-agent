"""icssploit_import 单测：分类器、AST 解析（帧/端口/设备）、SQL 转义。"""
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import icssploit_import as I  # noqa: E402

SAMPLE = '''
from icssploit import exploits, validators
import socket

stop_packet = bytearray.fromhex('0300004302f080')

class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'S7-1200 PLC Control',
        'description': 'Use S7comm plus command to start/stop/reset plc.',
        'devices': ['Siemens S7-1200 programmable logic controllers (PLCs)'],
        'references': ['https://example.com/ref'],
    }
    target = exploits.Option('', 'Target address', validators=validators.ipv4)
    port = exploits.Option(102, 'Target Port', validators=validators.integer)
    command = exploits.Option(1, 'Command 0:start 1:stop')
'''


class ClassifyTests(unittest.TestCase):
    def test_plc_control_is_runstop_destructive(self):
        self.assertEqual(I.classify("S7-1200 PLC Control", "start/stop/reset plc", "exploits", "plcs/siemens/x"),
                         (3, "destructive"))

    def test_dos_and_exec(self):
        self.assertEqual(I.classify("Crash QNX Inetd", "crash the tcp service", "exploits", "qnx/x")[0], 7)
        self.assertEqual(I.classify("QCONN Remote Command Execution", "remote exec", "exploits", "qnx/x")[0], 8)

    def test_creds_are_auth_read(self):
        self.assertEqual(I.classify("FTP Default Creds", "dictionary attack", "creds", "creds/ftp_default"),
                         (2, "read"))

    def test_profinet_setip(self):
        self.assertEqual(I.classify("profinet device ip setup", "setup ip with dcp", "exploits", "siemens/profinet_set_ip")[0], 12)


class ParseTests(unittest.TestCase):
    def _parse(self, rel="exploits/plcs/siemens/s7_1200_plc_control.py"):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(SAMPLE, encoding="utf-8")
            return I.parse_module(p, root)

    def test_extracts_info_port_frames(self):
        it = self._parse()
        self.assertEqual(it["vclass"], 3)
        self.assertEqual(it["vendor"], "siemens")
        self.assertEqual(it["protocol"], "s7comm")
        self.assertEqual(it["refs"]["port"], 102)
        self.assertEqual(it["refs"]["frames"]["stop_packet"], "0300004302f080")
        self.assertEqual(it["refs"]["risk"], "destructive")
        self.assertTrue(it["cve_id"].startswith("ICSSPLOIT:"))
        self.assertIn("S7-1200", it["product"])

    def test_scanners_skipped(self):
        self.assertIsNone(self._parse("scanners/s7comm_scan.py"))

    def test_init_skipped(self):
        self.assertIsNone(self._parse("exploits/__init__.py"))


class SqlTests(unittest.TestCase):
    def test_upsert_escapes_quotes(self):
        it = {"cve_id": "ICSSPLOIT:x", "source": "icssploit", "vclass": 3,
              "vendor": "siemens", "product": "it's", "protocol": "s7comm",
              "summary": "a'b", "refs": {"k": "v"}, "confidence": "high",
              "class_basis": "icssploit-module"}
        sql = I.upsert_sql(it)
        self.assertIn("'it''s'", sql)
        self.assertIn("ON CONFLICT (cve_id, source) DO UPDATE", sql)


if __name__ == "__main__":
    unittest.main()
