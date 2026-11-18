"""surface_probe 测试：本地 HTTP 服务探测、ENIP 头解析、findings 写回。"""
import http.server
import json
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import surface_probe as SP


class WebProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            server_version = "WAGO-Web/2.0"
            sys_version = ""

            def do_GET(self):
                if self.path == "/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(
                        b"<html><title>PFC200 Management</title>"
                        b"<body>password admin config</body></html>")
                elif "passwd" in self.path and "%2e%2e" in self.path:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"root:x:0:0")
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass

        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_web_probe(self):
        out = SP.probe_web("127.0.0.1", self.port, timeout=3)
        self.assertTrue(out["open"])
        self.assertEqual(out["banner"]["server"], "WAGO-Web/2.0")
        self.assertIn("PFC200", out["banner"]["title"])
        kws = {f["keyword"] for f in out["findings"] if "keyword" in f}
        self.assertTrue({"password", "admin"} & kws)
        # 服务器对 %2e%2e 路径返回 200+passwd 特征 → 穿越 finding
        self.assertTrue(any(f.get("severity") == "high" and "穿越" in f["note"]
                            for f in out["findings"]))


class EnipProbeTests(unittest.TestCase):
    def test_enip_header_parse(self):
        a, b = socket.socketpair()
        body = b"\xfd\x00" + b"WAGO750-8202" + b"\x00" * 8
        hdr = (0x63).to_bytes(2, "little") + struct.pack("<H", len(body)) \
            + b"\x00" * 20

        threading.Thread(target=lambda: b.sendall(hdr + body),
                         daemon=True).start()
        with mock.patch.object(SP.socket, "create_connection", return_value=a):
            out = SP.probe_enip("127.0.0.1", timeout=3)
        self.assertTrue(out["open"])
        self.assertIn("750-8202", out.get("device_hint", ""))
        a.close()
        b.close()

    def test_closed_port(self):
        out = SP.probe_enip("127.0.0.1", 1, timeout=0.5)
        self.assertFalse(out["open"])


class FindingsWriteTests(unittest.TestCase):
    def test_write_back(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "f.json"
            result = {"surface": "enip", "host": "h1", "open": False,
                      "findings": [], "ts": "t"}
            fp.write_text(json.dumps({"vuln_surface": {"secondary_scan": []}}),
                          encoding="utf-8")
            import findings as F
            data = F.load(str(fp))
            surface = data.get("vuln_surface") or {}
            scan = surface.setdefault("secondary_scan", [])
            scan.append(result)
            surface["secondary_scan"] = scan
            data["vuln_surface"] = surface
            F.save(str(fp), data)
            back = json.loads(fp.read_text(encoding="utf-8"))
            self.assertEqual(back["vuln_surface"]["secondary_scan"][0]["surface"],
                             "enip")


if __name__ == "__main__":
    unittest.main()
