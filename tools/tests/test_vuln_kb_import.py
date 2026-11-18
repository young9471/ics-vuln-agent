"""vuln_kb_import 单元测试：CWE/关键词分类器、SQL 生成与转义、批量提示词与 LLM 解析。"""
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import vuln_kb_import as VK


class ItVendorFilterTests(unittest.TestCase):
    def test_it_vendors_excluded(self):
        for vendor in ("microsoft", " Google ", "ORACLE", "python", "openbsd"):
            self.assertTrue(
                VK.it_vendor_excluded({"vendor": vendor}),
                f"{vendor} 应被剔除",
            )

    def test_ics_and_component_vendors_kept(self):
        # 组件库（V8 固件与组件匹配目标）、网络边界厂商、工控厂商、空 vendor 都保留。
        for vendor in ("siemens", "linux", "openssl", "haxx", "busybox",
                       "cisco", "fortinet", "wago", ""):
            self.assertFalse(
                VK.it_vendor_excluded({"vendor": vendor}),
                f"{vendor} 不应被剔除",
            )


class ClassifierTests(unittest.TestCase):
    def test_cwe_high_confidence(self):
        for cwes, want in [
            ("['CWE-200']", 1),
            ("CWE-287", 2),
            ("CWE-400", 7),
            ("['CWE-798']", 8),          # 硬编码 → 固件与组件（优先于认证）
            ("['CWE-319']", 11),
            ("['CWE-125', 'CWE-200']", 4),   # 4 在优先级表先于 1
            ("['CWE-494']", 5),
        ]:
            item = {"cve_id": "CVE-1", "summary": "x", "cwes": cwes}
            v, conf, basis = VK.classify(item)
            self.assertEqual((v, conf), (want, "high"), f"{cwes} -> {v}/{conf}/{basis}")

    def test_keyword_fallback(self):
        v, conf, basis = VK.classify({"summary": "hard-coded credentials allow login",
                                      "cwes": ""})
        self.assertEqual(v, 8)
        self.assertIn(conf, ("medium", "low"))
        v2, _, _ = VK.classify({"summary": "device can be remotely stopped by "
                                           "unauthenticated user sending a packet", "cwes": ""})
        self.assertEqual(v2, 3)

    def test_unclassified(self):
        v, conf, basis = VK.classify({"summary": "something odd", "cwes": ""})
        self.assertIsNone(v)
        self.assertEqual(basis, "unclassified")

    def test_parse_cwes(self):
        self.assertEqual(VK.parse_cwes("['CWE-200', 'CWE-319']"), ["CWE-200", "CWE-319"])
        self.assertEqual(VK.parse_cwes(""), [])


class SqlTests(unittest.TestCase):
    def test_upsert_escapes_quotes(self):
        item = {"cve_id": "CVE-2020-7525", "summary": "password 'leak' in config",
                "vendor": "Schneider", "product": "M221", "protocol": "Modbus"}
        sql = VK.upsert_sql(item, 2, "high", "cwe:CWE-200", "icsvuln")
        self.assertIn("'password ''leak'' in config'", sql)
        self.assertIn("ON CONFLICT (cve_id, source)", sql)
        self.assertIn("'icsvuln'", sql)
        self.assertIn("vclass=EXCLUDED.vclass", sql)

    def test_refine_update(self):
        sql = VK.refine_update_sql("CVE-1", "plc-intel", 7)
        self.assertIn("vclass=7", sql)
        self.assertIn("confidence='llm'", sql)


class LLMTests(unittest.TestCase):
    def test_batch_prompt_shape(self):
        items = [{"cve_id": "CVE-1", "summary": "plaintext password"}]
        p = VK.build_batch_prompt(items)
        self.assertIn("CVE-1: plaintext password", p)
        self.assertIn("14", p)

    def test_parse_llm_json(self):
        self.assertEqual(VK.parse_llm_json('{"CVE-1": 2}'), {"CVE-1": 2})
        self.assertEqual(VK.parse_llm_json('说明\n{"CVE-1": 3}\n尾注'), {"CVE-1": 3})
        self.assertEqual(VK.parse_llm_json("no json"), {})
        self.assertEqual(VK.parse_llm_json('{"broken'), {})


if __name__ == "__main__":
    unittest.main()
