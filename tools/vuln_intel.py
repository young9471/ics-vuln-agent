#!/usr/bin/env python3
"""P7 情报桥：本地双库查询（plc-intel API + icsvuln SQLite），PLAN-V2 §6⑤。

三级查询的第一二级（第三级联网检索由 Agent 的 web 工具承担，结果沉淀回 plc-intel）。
- plc-intel（活库）：POST /api/match 离线资产匹配（vendor/product/version/CPE），
  失败自动降级 GET /api/inventory 关键词过滤。
- icsvuln（大库）：SQLite 直查，protocols 字段精确匹配 + 型号 LIKE。

用法：
  python vuln_intel.py --vendor wago --product 750-8202 [--version fw14]
      [--protocol modbus] [--max 30] [--findings <findings.json>]
环境变量：PROTOCOL_AGENT_PLC_INTEL（默认 http://127.0.0.1:4320）
          PROTOCOL_AGENT_ICSVULN_DB（默认 C:\科研\工控漏洞库\data\icsvuln.db）
"""
import argparse
import datetime
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F                     # noqa: E402

DEFAULT_PLC_INTEL = os.environ.get("PROTOCOL_AGENT_PLC_INTEL", "http://127.0.0.1:4320")
DEFAULT_ICSVULN = os.environ.get(
    "PROTOCOL_AGENT_ICSVULN_DB", r"C:\科研\工控漏洞库\data\icsvuln.db")
DEFAULT_PSQL = os.environ.get(
    "PROTOCOL_AGENT_PSQL", r"C:\科研\114项目\protocol-agent\runtime\pgsql\bin\psql.exe")
DEFAULT_PG = os.environ.get(
    "PROTOCOL_AGENT_PG", "127.0.0.1:5433:protocol_platform:pagent")

# 14 类分类的关键词先验（LLM 语义层建库前的粗分类，供假设排序；正式标注入库走 vuln_knowledge）
CLASS_KEYWORDS = [
    (3, ("stop", "start", "run", "启停")),
    (2, ("password", "credential", "authentication", "login", "口令", "认证")),
    (8, ("hard-coded", "hardcoded", "firmware", "固件", "update")),
    (5, ("program", "logic", "project", "工程", "逻辑")),
    (7, ("denial", "crash", "reboot", "dos", "拒绝服务")),
    (1, ("information", "disclosure", "version", "泄露", "信息")),
    (9, ("web", "http", "ftp", "snmp", "telnet")),
    (10, ("replay", "spoof", "重放", "欺骗")),
    (11, ("encrypt", "cleartext", "tls", "加密", "明文")),
    (6, ("protection", "bypass", "保护")),
    (4, ("memory", "register", "read", "write", "内存")),
]


def guess_vclass(text):
    t = (text or "").lower()
    best, score = None, 0
    for vc, kws in CLASS_KEYWORDS:
        s = sum(1 for k in kws if k in t)
        if s > score:
            best, score = vc, s
    return best


def query_plc_intel(base, vendor, product, version, protocol, max_n, timeout=8.0):
    """活库匹配。POST /api/match 失败则 GET /api/inventory 过滤兜底。"""
    base = base.rstrip("/")
    hits = []
    try:
        body = json.dumps({"assets": [{
            "vendor": vendor or "", "product": product or "", "version": version or "",
        }]}).encode()
        req = urllib.request.Request(base + "/api/match", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
        # 兼容 {assets:[{matches:[...]}]} / {matches:[...]} / [ ... ] 多种返回形态
        rows = payload if isinstance(payload, list) else (
            payload.get("matches") or payload.get("results") or [])
        if not rows and isinstance(payload, dict):
            for a in payload.get("assets", []):
                if isinstance(a, dict):
                    rows.extend(a.get("matches") or [])
        for row in rows:
            if isinstance(row, dict):
                hits.append({
                    "cve_id": row.get("cve") or row.get("id") or row.get("cve_id"),
                    "summary": (row.get("description") or row.get("summary") or "")[:300],
                    "cvss": row.get("cvss") or row.get("cvss_score"),
                    "source": "plc-intel",
                    "raw": row,
                })
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # 降级：完整清单关键词过滤
        try:
            with urllib.request.urlopen(base + "/api/inventory", timeout=timeout) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
            rows = payload.get("vulnerabilities") if isinstance(payload, dict) else payload
            kws = [k.lower() for k in (vendor, product, protocol) if k]
            for row in rows or []:
                blob = json.dumps(row, ensure_ascii=False).lower()
                if kws and any(k in blob for k in kws):
                    hits.append({
                        "cve_id": row.get("id") or row.get("cve_id"),
                        "summary": (row.get("description") or "")[:300],
                        "cvss": row.get("cvss"),
                        "source": "plc-intel(fallback)",
                        "raw": row,
                    })
                    if len(hits) >= max_n:
                        break
        except Exception:
            return {"ok": False, "error": f"plc-intel unreachable: {exc}", "hits": []}
    return {"ok": True, "hits": hits[:max_n]}


def query_icsvuln(db_path, vendor, product, version, protocol, max_n):
    if not Path(db_path).exists():
        return {"ok": False, "error": f"icsvuln db not found: {db_path}", "hits": []}
    hits = []
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = db.cursor()
        kws = [k for k in (vendor, product, protocol, version) if k]
        where = " OR ".join(
            ["lower(coalesce(p.product,'')) LIKE ?"] * 2 +
            ["lower(coalesce(p.vendor,'')) LIKE ?", "lower(coalesce(v.description,'')) LIKE ?",
             "lower(coalesce(v.protocols,'')) LIKE ?"])
        params = []
        for k in kws:
            params += [f"%{k.lower()}%"] * 5
        rows = cur.execute(
            "select distinct v.cve_id, v.description, v.cvss_score, v.cvss_severity, "
            "v.protocols, v.cwes from vulnerabilities v "
            "left join products p on p.cve_id=v.cve_id where " + where +
            " limit ?", (*params, max_n)).fetchall()
        for cve, desc, score, sev, protos, cwes in rows:
            hits.append({
                "cve_id": cve, "summary": (desc or "")[:300],
                "cvss": score, "severity": sev,
                "protocols": json.loads(protos) if protos and protos.startswith("[") else protos,
                "cwes": cwes, "source": "icsvuln",
            })
        db.close()
    except sqlite3.Error as exc:
        return {"ok": False, "error": f"icsvuln query failed: {exc}", "hits": []}
    return {"ok": True, "hits": hits}


def query_kb(vendor, product, protocol, vclass, max_n, psql_path=DEFAULT_PSQL,
             pg=DEFAULT_PG):
    """查询平台侧 vuln_knowledge 语义层（vuln_kb_import.py 富化后的 14 类库）。"""
    import subprocess

    def esc(s):
        return "'" + str(s).replace("'", "''") + "'"

    conds = []
    if vendor:
        conds.append(f"lower(vendor) LIKE {esc('%' + vendor.lower() + '%')}")
    if product:
        conds.append(f"(lower(product) LIKE {esc('%' + product.lower() + '%')} "
                     f"OR lower(summary) LIKE {esc('%' + product.lower() + '%')})")
    if protocol:
        conds.append(f"lower(protocol) LIKE {esc('%' + protocol.lower() + '%')}")
    if vclass:
        conds.append(f"vclass = {int(vclass)}")
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    # 载荷库（icssploit：带真实帧的已验证利用原语）优先于 CVE 先验返回，
    # 否则按 cve_id 排序时 ICSSPLOIT: 前缀永远排在 CVE- 之后被 LIMIT 截掉。
    sql = ("SELECT coalesce(json_agg(t), '[]'::json) FROM ("
           "SELECT cve_id, source, vclass, vendor, product, protocol, "
           "left(summary, 200) AS summary, confidence FROM vuln_knowledge"
           + where + " ORDER BY (source='icssploit') DESC, cve_id LIMIT " + str(int(max_n)) + ") t")
    pgp = pg.split(":")
    host, port, dbn, user = (pgp + ["127.0.0.1", "5433", "protocol_platform", "pagent"])[:4]
    p = subprocess.run([psql_path, "-h", host, "-p", port, "-U", user, "-d", dbn,
                        "-At", "-c", sql], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode != 0:
        return {"ok": False, "error": p.stderr.strip()[:300], "hits": []}
    try:
        return {"ok": True, "hits": json.loads(p.stdout or "[]")}
    except ValueError:
        return {"ok": False, "error": "kb json decode failed", "hits": []}


def main():
    ap = argparse.ArgumentParser(description="漏洞情报双库查询（P7 ②步）")
    ap.add_argument("--vendor")
    ap.add_argument("--product")
    ap.add_argument("--version")
    ap.add_argument("--protocol", help="协议名（modbus/s7comm/umas/...）→ icsvuln protocols 精确匹配")
    ap.add_argument("--max", type=int, default=30)
    ap.add_argument("--plc-intel-url", default=DEFAULT_PLC_INTEL)
    ap.add_argument("--icsvuln-db", default=DEFAULT_ICSVULN)
    ap.add_argument("--skip-plc-intel", action="store_true")
    ap.add_argument("--skip-icsvuln", action="store_true")
    ap.add_argument("--kb-only", action="store_true",
                    help="只查平台 vuln_knowledge 语义层（vuln_kb_import 富化后的 14 类库）")
    ap.add_argument("--vclass", type=int, default=None, help="按 14 类编号过滤 kb 查询")
    ap.add_argument("--psql", default=DEFAULT_PSQL)
    ap.add_argument("--pg", default=DEFAULT_PG)
    ap.add_argument("--findings", help="结果合并进 vuln_surface.intel_matches")
    args = ap.parse_args()
    if not any((args.vendor, args.product, args.protocol, args.version, args.vclass)):
        print("error: 至少给一个 --vendor/--product/--version/--protocol/--vclass",
              file=sys.stderr)
        return 1

    out = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "query": {k: getattr(args, k) for k in ("vendor", "product", "version", "protocol")}}
    if not args.kb_only and not args.skip_plc_intel:
        out["plc_intel"] = query_plc_intel(args.plc_intel_url, args.vendor, args.product,
                                           args.version, args.protocol, args.max)
    if not args.skip_icsvuln:
        out["icsvuln"] = query_icsvuln(args.icsvuln_db, args.vendor, args.product,
                                       args.version, args.protocol, args.max)
    out["kb"] = query_kb(args.vendor, args.product, args.protocol, args.vclass,
                         args.max, args.psql, args.pg)
    all_hits = (out.get("plc_intel", {}).get("hits", [])
                + out.get("icsvuln", {}).get("hits", [])
                + out.get("kb", {}).get("hits", []))
    seen, merged = set(), []
    for h in all_hits:
        key = (h.get("cve_id") or "") + "|" + h["summary"][:60] if h.get("summary") \
            else (h.get("cve_id") or "") + "|" + h.get("source", "")
        if key in seen:
            continue
        seen.add(key)
        h.setdefault("vclass_guess", guess_vclass(
            (h.get("summary") or "") + " " + str(h.get("protocols") or "")))
        merged.append(h)
    out["merged"] = merged
    out["sources_ok"] = {"plc_intel": out.get("plc_intel", {}).get("ok"),
                         "icsvuln": out.get("icsvuln", {}).get("ok"),
                         "kb": out.get("kb", {}).get("ok")}

    if args.findings:
        data = F.load(args.findings)
        surface = data.get("vuln_surface") or {}
        surface["intel_matches"] = out
        data["vuln_surface"] = surface
        F.save(args.findings, data)
    print(json.dumps({"count": len(merged), "sources_ok": out["sources_ok"],
                      "hits": merged}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
