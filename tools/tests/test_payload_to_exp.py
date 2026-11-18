"""payload_to_exp 单测：独立脚本渲染（零框架/帧嵌入/端口/风险）。"""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import payload_to_exp as P  # noqa: E402

ITEM = {
    "id": 1, "cve_id": "PLCSTS:attacking/schneider/M221/M221_CPU_start_stop",
    "source": "plcsts", "vendor": "schneider-electric", "protocol": "modbus",
    "refs": {
        "module": "attacking/schneider/M221/M221_CPU_start_stop.py",
        "model": "M221", "risk": "destructive", "port": 502,
        "frames": {"stop_payload": "000000000006015a0041ff00",
                   "start_payload": "000000000006015a0040ff00"},
    },
}


class RenderTests(unittest.TestCase):
    def test_zero_framework_imports(self):
        fname, body = P.render(ITEM)
        self.assertNotIn("from plcsts", body)
        self.assertNotIn("from icssploit", body)
        self.assertNotIn("import exploits", body)
        for std in ("import argparse", "import socket", "import json"):
            self.assertIn(std, body)

    def test_frames_and_port_embedded(self):
        fname, body = P.render(ITEM)
        self.assertIn("000000000006015a0041ff00", body)
        self.assertIn("stop_payload", body)
        self.assertIn("PORT = 502", body)
        self.assertEqual(fname, "M221_CPU_start_stop")  # 无 .py.py

    def test_risk_banner_and_dryrun(self):
        _, body = P.render(ITEM)
        self.assertIn("破坏性操作", body)
        self.assertIn("--dry-run", body)
        self.assertIn("--frame", body)
        self.assertIn("--list", body)

    def test_no_frames_returns_none(self):
        it = dict(ITEM, refs={"module": "x.py", "frames": {}})
        self.assertIsNone(P.render(it))

    def test_sha_placeholder_filled(self):
        _, body = P.render(ITEM, "abcd1234abcd1234")
        self.assertIn("sha16: abcd1234abcd1234", body)

    def test_slug(self):
        self.assertEqual(P.slug("a/b c.py"), "a_b_c.py")
        self.assertEqual(P.slug(""), "payload")


if __name__ == "__main__":
    unittest.main()
