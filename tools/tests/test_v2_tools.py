"""V2 工具链单元测试：模板库/画像/适用性/campaign 引擎/Guardian SNMP/EXP 生成。"""
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import applicability
import campaign_runner as CR
import device_profile
import exp_gen
import guardian
import vuln_templates as VT


class TemplateTests(unittest.TestCase):
    def test_library_shape(self):
        self.assertGreaterEqual(len(VT.TEMPLATES), 35)
        ids = [t["id"] for t in VT.TEMPLATES]
        self.assertEqual(len(ids), len(set(ids)), "template ids must be unique")
        for t in VT.TEMPLATES:
            self.assertIn(t["risk"], ("read", "write", "destructive"))
            self.assertIn(t["detection"], ("deterministic", "fuzz"))
            self.assertIn(1, [1])  # vclass in range
            self.assertTrue(t["name"])

    def test_eval_node_three_states(self):
        matrix = {
            "memory_read": {"protocol": [{"ref": "x", "grade": "live"}],
                            "service": [], "physical": []},
            "auth": {"protocol": [], "service": [], "physical": []},  # 已探测不存在
            # run_stop 键缺失 → unknown
        }
        self.assertIs(VT.eval_node({"cap": "memory_read", "via": "any"}, matrix), True)
        self.assertIs(VT.eval_node({"cap": "auth", "via": "any"}, matrix), False)
        self.assertEqual(VT.eval_node({"cap": "run_stop", "via": "any"}, matrix), "unknown")
        self.assertIs(VT.eval_node(None, matrix), True)
        # any: True 短路 unknown
        self.assertIs(VT.eval_node(
            {"any": [{"cap": "memory_read"}, {"cap": "run_stop"}]}, matrix), True)
        # all: unknown 不被 False 之外的确定值遮蔽
        self.assertEqual(VT.eval_node(
            {"all": [{"cap": "memory_read"}, {"cap": "run_stop"}]}, matrix), "unknown")
        self.assertIs(VT.eval_node(
            {"all": [{"cap": "memory_read"}, {"cap": "auth"}]}, matrix), False)

    def test_classify_and_missing(self):
        matrix = {}                                   # 全 unknown
        t = VT.BY_ID["V3A-unauth-runstop"]
        self.assertEqual(VT.classify(t, matrix), "unknown")
        self.assertIn("run_stop", VT.missing_caps(t["requires"], matrix))
        t11 = VT.BY_ID["V11A-no-encryption"]
        self.assertEqual(VT.classify(t11, matrix), "applicable")   # requires None


class ProfileTests(unittest.TestCase):
    def test_build_from_traffic_and_scan(self):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "findings.json"
            fp.write_text(json.dumps({
                "schema": "protocol-agent/findings/v1",
                "comm_assets": [{"dst_port": 80, "device_ip": "10.0.0.9"},
                                {"dst_port": 502}],
                "function_codes": [{"fc": 0x10, "name": "write registers"}],
                "notes": [{"note": "工程软件发现固件更新功能"}],
            }), encoding="utf-8")
            prof = device_profile.build(str(fp))
            m = prof["matrix"]
            self.assertTrue(m["web_service"]["service"])          # traffic:port:80
            self.assertTrue(any("traffic" in e["ref"]
                                for e in m["web_service"]["service"]))
            self.assertTrue(m["memory_write"]["protocol"])        # 关键词 inferred
            self.assertIn("protocol", prof["tracks"])
            self.assertEqual(prof["facts"]["device_ip"], "10.0.0.9")

    def test_offline_no_scan(self):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "f.json"
            fp.write_text("{}", encoding="utf-8")
            prof = device_profile.build(str(fp))
            self.assertEqual(prof["firmware_obtainable"], "none")
            self.assertEqual(prof["tracks"], ["protocol"])


class ApplicabilityTests(unittest.TestCase):
    def test_full_flow_states_and_hypotheses(self):
        profile = {"matrix": {
            "identity_query": {"protocol": [{"ref": "r", "grade": "live"}],
                               "service": [], "physical": []},
            "memory_read": {"protocol": [{"ref": "r", "grade": "live"}],
                            "service": [], "physical": []},
            "memory_write": {"protocol": [], "service": [], "physical": []},
            "auth": {"protocol": [], "service": [], "physical": []},
        }}
        result, hyps = applicability.evaluate(profile)
        s = result["summary"]
        self.assertEqual(s["total"], len(VT.TEMPLATES))
        self.assertEqual(s["applicable"] + s["not_applicable"] + s["unknown"], s["total"])
        # V1A 需要 identity_query → applicable 且生成假设
        v1a = next(i for i in result["items"] if i["template_id"] == "V1A-anon-identity")
        self.assertEqual(v1a["state"], "applicable")
        self.assertIn("H-V1A-anon-identity", [h["id"] for h in hyps])
        # V4B 需要 memory_write（已探测不存在）→ not_applicable
        v4b = next(i for i in result["items"] if i["template_id"] == "V4B-anon-memory-write")
        self.assertEqual(v4b["state"], "not_applicable")
        # V3A 需要 run_stop（键缺失）→ unknown + 探测任务
        v3a = next(i for i in result["items"] if i["template_id"] == "V3A-unauth-runstop")
        self.assertEqual(v3a["state"], "unknown")
        self.assertTrue(any(t["capability"] == "run_stop"
                            for t in result["posture_tasks"]))
        # destructive 假设带审批标记
        h3 = next((h for h in hyps if h["template_id"] == "V3A-unauth-runstop"), None)
        self.assertIsNone(h3)                                    # unknown 不生成假设
        hv = next(h for h in hyps if h["risk"] == "destructive")
        self.assertTrue(hv["requires_approval"])


class CampaignEngineTests(unittest.TestCase):
    def test_blacklist(self):
        hits = CR.blacklist_violation([bytes.fromhex("01025a00")], ["025a"])
        self.assertEqual(hits, ["025a"])
        self.assertEqual(CR.blacklist_violation([b"\x01\x02\x03"], ["abcd"]), [])

    def test_classify(self):
        self.assertEqual(CR.classify(b"", "timed out"), "timeout")
        self.assertEqual(CR.classify(b"", "Connection reset"), "reset")
        self.assertEqual(CR.classify(b"\x01", ""), "short1:01")
        r = CR.classify(bytes.fromhex("01020304") * 16, "")     # 64B → 桶 64
        self.assertTrue(r.startswith("len64:"))
        r16 = CR.classify(bytes.fromhex("01020304") * 4, "")     # 16B → 桶 16
        self.assertTrue(r16.startswith("len16:"))

    def test_approval_offline(self):
        camp = {"risk": "destructive", "approval": {}}
        ok, _ = CR.check_approval(camp, None, None, None)
        self.assertFalse(ok)
        ok, _ = CR.check_approval(camp, None, None, "APPROVED:zhang:lab-test")
        self.assertTrue(ok)
        ok, _ = CR.check_approval({"risk": "read"}, None, None, None)
        self.assertTrue(ok)

    def test_ops_and_structural(self):
        self.assertIn(0xFFFF, CR.op_values("boundary", 2, 3, []))
        req = {"hex": "0102", "fields": [{"name": "fc", "offset": 0, "size": 1, "value": 5}]}
        rep = CR.make_structural(req, "repeat")
        self.assertEqual(rep["hex"], "01020102")
        tr = CR.make_structural(req, "truncate")
        self.assertEqual(tr["hex"], "01")

    def test_verify_mode_against_echo_server(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        port = server.getsockname()[1]

        def echo():
            try:
                while True:
                    c, _ = server.accept()
                    with c:
                        data = c.recv(1024)
                        c.sendall(b"OK" + data[:2])
            except OSError:
                pass

        th = threading.Thread(target=echo, daemon=True)
        th.start()
        camp = {
            "target": {"host": "127.0.0.1", "port": port, "timeout_ms": 800},
            "verify": [
                {"label": "probe1",
                 "request": {"hex": "0102", "fields": []},
                 "expect": {"contains_hex": "4f4b", "min_bytes": 3}},
                {"label": "probe-reject",
                 "request": {"hex": "0304"},
                 "expect": {"reject_hex": ["4f4b"]}},
            ],
        }
        report = {}
        verdicts = CR.run_verify(camp, report)
        self.assertEqual(verdicts[0]["verdict"], "confirmed")
        self.assertEqual(verdicts[1]["verdict"], "rejected")
        server.close()

    def test_dry_run_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            camp = {
                "id": "t1", "mode": "verify", "risk": "read",
                "target": {"host": "127.0.0.1", "port": 1},
                "blacklist": ["dead"],
                "verify": [{"label": "x", "request": {"hex": "0102"}, "expect": {}}],
            }
            p = Path(d) / "c.json"
            p.write_text(json.dumps(camp), encoding="utf-8")
            import subprocess
            r = subprocess.run([sys.executable, str(TOOLS / "campaign_runner.py"),
                                "--campaign", str(p), "--dry-run"],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("dry_run", r.stdout)


class GuardianTests(unittest.TestCase):
    def test_snmp_ber_roundtrip(self):
        msg = guardian._ber(0x30, guardian._ber(0x02, b"\x00") +
                            guardian._ber(0x04, b"public") +
                            guardian._ber(0xA0, guardian._ber(0x02, b"\x01\x00")))
        tag, body, nxt = guardian._parse_asn1(msg, 0)
        self.assertEqual(tag, 0x30)
        self.assertEqual(nxt, len(msg))
        # OID 编码：1.3.6.1.2.1.1.3.0 → 2B 06 01 02 01 01 03 00
        self.assertEqual(guardian._encode_oid("1.3.6.1.2.1.1.3.0"),
                         bytes([0x2B, 6, 1, 2, 1, 1, 3, 0]))

    def test_snapshot_local(self):
        snap = guardian.snapshot("127.0.0.1")
        self.assertIn("reachable", snap)
        self.assertTrue(snap["reachable"])


class ExpGenTests(unittest.TestCase):
    def test_gen_replay_script(self):
        hyp = {"id": "H-V1A-x", "template_id": "V1A-anon-identity", "risk": "read",
               "name": "匿名身份读取", "verdict_rule": "返回版本即 confirmed",
               "state": "confirmed",
               "evidence": [{"frames": ["0102030001"], "expect": {"min_bytes": 4}}]}
        with tempfile.TemporaryDirectory() as d:
            path, err = exp_gen.gen_script(hyp, "replay", d, 502)
            self.assertIsNone(err)
            self.assertTrue(path.exists())
            body = path.read_text(encoding="utf-8")
            self.assertIn("FRAMES", body)
            self.assertIn("--target", body)
            self.assertIn("授权", body)
            # 生成的脚本语法有效
            compile(body, str(path), "exec")


if __name__ == "__main__":
    unittest.main()
