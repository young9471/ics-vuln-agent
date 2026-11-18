"""p769_offline 纯函数单测：裁决应用、门判定、厂商线索。"""
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import p769_offline as P  # noqa: E402


def mk_findings(hyps=None, items=None):
    return {
        "device_profile": {"matrix": {"identity_query": {"protocol": [{"ref": "x"}]}}},
        "vuln_surface": {"applicability": {"items": items or [], "summary": {}}},
        "vuln_hypotheses": hyps or [],
    }


class ApplyAdjudicationTests(unittest.TestCase):
    def test_unknown_settled_and_summary_recomputed(self):
        data = mk_findings(
            items=[{"template_id": "V9A", "state": "unknown", "missing_caps": ["web_service"]}],
            hyps=[{"id": "H-V9A", "template_id": "V9A", "state": "pending",
                   "detection": "deterministic"}],
        )
        out = P.apply_adjudication(data, {
            "applicability": [{"template_id": "V9A", "state": "not_applicable",
                               "reason": "抓包范围内未见 web"}],
            "hypotheses": [],
        })
        it = out["vuln_surface"]["applicability"]["items"][0]
        self.assertEqual(it["state"], "not_applicable")
        s = out["vuln_surface"]["applicability"]["summary"]
        self.assertEqual((s["applicable"], s["not_applicable"], s["unknown"]), (0, 1, 0))
        # 前置能力不适用 → 假设连带 not_applicable
        self.assertEqual(out["vuln_hypotheses"][0]["state"], "not_applicable")

    def test_verdict_frames_attached_for_exp_gen(self):
        data = mk_findings(
            hyps=[{"id": "H-V1", "state": "pending", "detection": "deterministic",
                   "risk": "write", "evidence": ["pcap frame 3"]}],
        )
        out = P.apply_adjudication(data, {
            "applicability": [],
            "hypotheses": [{"id": "H-V1", "state": "confirmed",
                            "verdict": "confirmed-by-traffic", "reason": "r",
                            "evidence": ["pcap frame 3"], "frames": ["01aabb"]}],
        })
        h = out["vuln_hypotheses"][0]
        self.assertEqual(h["state"], "confirmed")
        frames_ev = [e for e in h["evidence"] if isinstance(e, dict) and e.get("frames")]
        self.assertEqual(frames_ev[0]["frames"], ["01aabb"])

    def test_fuzz_deferred_live(self):
        data = mk_findings(
            hyps=[{"id": "H-V4C", "state": "pending", "detection": "fuzz"}],
        )
        out = P.apply_adjudication(data, {"applicability": [], "hypotheses": []})
        h = out["vuln_hypotheses"][0]
        self.assertEqual((h["state"], h["verdict"]), ("inconclusive", "fuzz-deferred-live"))


class GateTests(unittest.TestCase):
    def test_gate_g_requires_no_unknown_and_no_pending(self):
        base = {
            "device_profile": {"matrix": {"mem_read": {"protocol": [{"ref": "x"}]}}},
            "vuln_surface": {"applicability": {"summary": {
                "applicable": 5, "not_applicable": 2, "unknown": 0}}},
            "vuln_hypotheses": [{"id": "H-1", "state": "confirmed", "detection": "deterministic"}],
        }
        ok, _ = P.gate_g(json.loads(json.dumps(base)))
        self.assertTrue(ok)
        bad = json.loads(json.dumps(base))
        bad["vuln_surface"]["applicability"]["summary"]["unknown"] = 3
        self.assertFalse(P.gate_g(bad)[0])
        pending = json.loads(json.dumps(base))
        pending["vuln_hypotheses"][0]["state"] = "pending"
        self.assertFalse(P.gate_g(pending)[0])

    def test_gate_i_needs_exploit_for_write_confirmed(self):
        data = {
            "vuln_hypotheses": [
                {"id": "H-1", "state": "confirmed", "risk": "write"},
                {"id": "H-2", "state": "confirmed", "risk": "read"},
            ],
            "exploit_assets": [{"hypothesis": "H-1"}],
        }
        P.REPORT_GENERATED[99] = "report"
        ok, _ = P.gate_i(data, 99)
        self.assertTrue(ok)
        data["exploit_assets"] = []
        self.assertFalse(P.gate_i(data, 99)[0])


class VendorHintTests(unittest.TestCase):
    def test_guess_vendor(self):
        self.assertEqual(
            P.guess_vendor_product({"comm_assets": [{"path": "C:/Somachine Basic/bin.exe"}]}),
            ("schneider", ""))
        self.assertEqual(
            P.guess_vendor_product({"comm_assets": [{"path": "C:/Wago/io.dll"}]}),
            ("wago", ""))
        self.assertEqual(P.guess_vendor_product({"comm_assets": []}), ("", ""))


if __name__ == "__main__":
    unittest.main()
