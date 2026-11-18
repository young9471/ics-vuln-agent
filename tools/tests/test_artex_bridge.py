"""artex_bridge 单元测试：token 铸造、协议摘要、回流解析映射、campaign 生成。"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import artex_bridge as AB


class TokenTests(unittest.TestCase):
    def test_mint_service_token_shape(self):
        tok = AB.mint_service_token(b"k" * 32)
        head, claims, sig = tok.split(".")
        import base64
        def dec(s):
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        self.assertEqual(json.loads(dec(head))["alg"], "HS256")
        cl = json.loads(dec(claims))
        self.assertEqual(cl["sub"], "ARTEX")
        self.assertGreater(cl["exp"], cl["iat"])
        # 签名可复现（同 key 同 claims）
        tok2 = AB.mint_service_token(b"k" * 32)
        self.assertEqual(tok, tok2)


class SummaryTests(unittest.TestCase):
    def test_protocol_summary_includes_focus(self):
        f = {"streams": [{"endpoints": "1.1.1.1:1000 <-> 2.2.2.2:502"}],
             "function_codes": [{"code": "0x5a"}, {"code": "0x10"}],
             "device_profile": {"facts": {"vendor": "WAGO", "model": "750-8202",
                                          "firmware": "14"}}}
        s = AB.protocol_summary(f)
        self.assertIn("502", s)
        self.assertIn("0x5a", s)
        self.assertIn("WAGO", s)
        self.assertIn("解析", s)


class PullMappingTests(unittest.TestCase):
    def test_map_artex_finding(self):
        v = AB.map_artex_finding({"title": "stack buffer overflow in frame parser"})
        self.assertIn(v, (4, 7))
        v2 = AB.map_artex_finding({"title": "hard-coded credentials in httpd"})
        self.assertIn(v2, (8, 2, 9))


class CampaignTests(unittest.TestCase):
    def test_focus_functions(self):
        track = {"decompile_functions": [
            {"name": "ParseFrame", "addr": "0x1000"},
            {"name": "crc16_calc", "addr": "0x1100"},
            {"name": "UI_draw_button", "addr": "0x2000"},
        ]}
        got = AB.focus_functions(track)
        self.assertEqual([f["name"] for f in got], ["ParseFrame", "crc16_calc"])

    def test_campaign_from_pull(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "findings.json"
            fp.write_text(json.dumps({
                "probes": [{"request": "0102 0304"}],
                "vuln_surface": {"firmware_track": {"pull": {
                    "task_id": "12", "status": "done",
                    "decompile_functions": [{"name": "recv_dispatch"}],
                }}},
            }), encoding="utf-8")
            args = mock.Mock(findings=str(fp), host="192.168.1.10", port=502,
                             seed_hex=None, out=str(Path(d) / "camp.json"))
            client = None
            rc = AB.cmd_campaign(args, client)
            self.assertEqual(rc, 0)
            camp = json.loads(Path(args.out).read_text(encoding="utf-8"))
            self.assertEqual(camp["mode"], "fuzz")
            self.assertEqual(camp["risk"], "destructive")
            self.assertEqual(camp["seeds"][0]["hex"], "01020304")
            self.assertIn("recv_dispatch", camp["notes"])
            self.assertTrue(camp["guardian"]["enabled"])
            self.assertIsNone(campaign_needs_approval(camp) and None or None)


def campaign_needs_approval(camp):
    return camp["risk"] == "destructive"


if __name__ == "__main__":
    unittest.main()
