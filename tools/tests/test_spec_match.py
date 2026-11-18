import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import spec_match


class SpecMatchTests(unittest.TestCase):
    def test_ports_and_magic_rank_codesys_and_wago(self):
        findings = {
            "streams": [
                {"protocol": "tcp", "sport": 40000, "dport": 2455},
            ],
            "frame_formats": [
                {"magic": "0300", "carrier": "tpkt", "inner_layout": "s7"},
            ],
        }
        result = spec_match.rank(findings, [])
        scores = {item["spec"]: item["score"] for item in result["ranked"]}
        self.assertGreaterEqual(scores.get("codesys", 0), 50)
        self.assertEqual(result["recommended"], "codesys")

    def test_unknown_hints_recommend_nothing(self):
        result = spec_match.rank({"streams": [{"dport": 9999}]}, [])
        self.assertIsNone(result["recommended"])
        self.assertEqual(result["ranked"], [])

    def test_extra_ports_and_fins_udp(self):
        result = spec_match.rank({}, [9600])
        scores = {item["spec"]: item["score"] for item in result["ranked"]}
        self.assertGreaterEqual(scores.get("fins", 0), 50)
        self.assertEqual(result["recommended"], "fins")

    def test_magic_only_match(self):
        findings = {"frame_formats": [{"magic": "6666", "carrier": "chain"}]}
        result = spec_match.rank(findings, [])
        self.assertTrue(any(item["reasons"] for item in result["ranked"]))


if __name__ == "__main__":
    unittest.main()