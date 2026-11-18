#!/usr/bin/env python3
"""vuln_knowledge 存量标注导入（M1 收尾，PLAN-V2 §6⑤）。

流程：
  1) 提取 icsvuln（is_ics 或 protocols 非空）与 plc-intel（inventory.sqlite 全量）；
  2) 确定性归类：CWE→14 类映射（高置信）→ 关键词规则（中/低置信），全部离线零成本；
  3) 生成幂等 upsert SQL（ON CONFLICT (cve_id, source)）→ 经 psql 入库；
  4) 可选 --refine：把非高置信条目分批（默认 20 条/批）送平台
     POST /api/llm/complete（admin，key 不出平台）做 LLM 归类并回写。

用法：
  python vuln_kb_import.py --out vk.sql --execute            # 确定性全量导入
  python vuln_kb_import.py --refine --execute \
      --api-base http://localhost:8790 --api-user protocol --api-pass <pw> \
      [--profile-id 2] [--limit 2000]                        # LLM 精修歧义项
"""
import argparse
import datetime
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_ICSVULN = os.environ.get(
    "PROTOCOL_AGENT_ICSVULN_DB", r"C:\科研\工控漏洞库\data\icsvuln.db")
DEFAULT_PLC_INTEL = os.environ.get(
    "PROTOCOL_AGENT_PLC_INTEL_DB",
    r"C:\Users\admin\Documents\ChatGPT\AI漏洞挖掘智能体\plc-intel\data\inventory.sqlite")
DEFAULT_PSQL = r"C:\科研\114项目\protocol-agent\runtime\pgsql\bin\psql.exe"

# ---------------------------------------------------------------------------
# 确定性分类器：CWE → 14 类（有序，特殊优先），关键词兜底
# ---------------------------------------------------------------------------
CWE_VCLASS = [
    # (类, CWE 前缀列表) —— 顺序即优先级：更特殊的类在前
    (5, ("CWE-494", "CWE-345", "CWE-284")),            # 逻辑篡改/完整性
    (8, ("CWE-798", "CWE-1104", "CWE-489", "CWE-912")),  # 固件与组件
    (11, ("CWE-319", "CWE-327", "CWE-326", "CWE-295", "CWE-757", "CWE-331")),  # 加密
    (10, ("CWE-294", "CWE-290", "CWE-346")),           # 重放/欺骗
    (9, ("CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-352", "CWE-98")),  # Web/服务面
    (2, ("CWE-287", "CWE-306", "CWE-307", "CWE-521", "CWE-384", "CWE-613", "CWE-798")),
    (6, ("CWE-863",)),                                  # 保护破解（授权缺失败给 3/4 之外的）
    (3, ("CWE-862",)),                                  # 远程启停/越权控制
    (4, ("CWE-125", "CWE-787", "CWE-120", "CWE-121", "CWE-122", "CWE-190", "CWE-191", "CWE-789")),
    (7, ("CWE-400", "CWE-476", "CWE-835", "CWE-770")),  # DoS
    (1, ("CWE-200", "CWE-532", "CWE-209", "CWE-916", "CWE-522")),
    (14, ("CWE-502", "CWE-427", "CWE-223")),            # 工程侧客户端
]

KEYWORD_VCLASS = [
    (3, (r"remote(ly)? (stop|start)", r"unauthenticated .{0,40}(stop|start)",
         r"(stop|start) (the )?plc", "remote stop", "remote start", "启停")),
    (2, ("authentication bypass", "weak authentication", "brute force", "default credential",
         "plaintext password", "password", "credentials", "login", "认证", "口令")),
    (8, ("hard-coded", "hardcoded", "backdoor", "outdated", "firmware update",
         "firmware", "固件", "后门")),
    (5, ("project file", "program download", "logic", "工程", "逻辑")),
    (7, ("denial of service", "denial-of-service", "crash", "reboot", "dos", "拒绝服务")),
    (1, ("information disclosure", "information exposure", "sensitive information",
         "version", "泄露", "信息")),
    (9, ("web server", "web interface", "http", "ftp", "snmp", "telnet", "cross-site")),
    (10, ("replay", "spoofing", "man-in-the-middle", "重放", "欺骗")),
    (11, ("cleartext", "plaintext transmission", "encryption", "tls", "加密", "明文")),
    (6, ("protection bypass", "write protection", "read protection", "保护")),
    (4, ("out-of-bounds", "buffer overflow", "memory", "register", "越界", "内存")),
    (13, ("physical output", "i/o", "force", "watchdog", "time sync")),
    (12, ("discovery", "broadcast", "amplification")),
]

CLASS_NAMES = {1: "信息泄露", 2: "协议认证", 3: "远程启停", 4: "内存读写", 5: "逻辑篡改",
               6: "保护破解", 7: "拒绝服务", 8: "固件与组件", 9: "次要攻击面",
               10: "重放与欺骗", 11: "加密与降级", 12: "发现协议滥用", 13: "物理IO操纵",
               14: "工程侧客户端"}


def parse_cwes(raw):
    if not raw:
        return []
    out = []
    for m in re.finditer(r"CWE-\d+", str(raw)):
        out.append(m.group(0))
    return out


def classify_by_cwe(cwes):
    """按 CWE_VCLASS 的优先级顺序返回首个命中的 (vclass, cwe)。"""
    cwe_set = set(cwes)
    for vclass, prefixes in CWE_VCLASS:
        for p in prefixes:
            if p in cwe_set:
                return vclass, p
    return None, ""


def classify_by_keywords(text):
    t = (text or "").lower()
    if not t:
        return None, 0
    scores = {}
    for idx, (vclass, kws) in enumerate(KEYWORD_VCLASS):
        s = 0
        for kw in kws:
            if re.search(kw, t):
                # 多词短语（含空格/连字符）更具体，权重更高
                s += 4 if (" " in kw or "-" in kw) else (2 if len(kw) > 8 else 1)
        if s:
            scores[vclass] = (s, idx)
    if not scores:
        return None, 0
    vclass, (_, _) = sorted(scores.items(), key=lambda kv: (-kv[1][0], kv[1][1]))[0]
    top = max(v[0] for v in scores.values())
    ties = sum(1 for v in scores.values() if v[0] == top)
    return vclass, (top if ties == 1 else max(1, top - 1))   # 平票降一档置信


def classify(item):
    """→ (vclass|None, confidence high/medium/low/None, basis)"""
    hit = classify_by_cwe(parse_cwes(item.get("cwes")))
    if hit[0] is not None:
        return hit[0], "high", f"cwe:{hit[1]}"
    v, score = classify_by_keywords(item.get("summary", ""))
    if v and score >= 3:
        return v, "medium", f"kw:{score}"
    if v:
        return v, "low", f"kw:{score}"
    return None, None, "unclassified"


# ---------------------------------------------------------------------------
# 提取
# ---------------------------------------------------------------------------
# 纯办公/端侧 IT 厂商：与 PLC/DCS/HMI/工控固件、SCADA 均无关联，导入时剔除。
# 刻意保留的灰色地带：组件库（linux/openssl/curl/busybox/…，V8 固件与组件
# 类的匹配目标）、网络边界厂商（cisco/fortinet/…，OT 常见）、医疗设备商。
IT_VENDOR_EXCLUDE = {
    "microsoft", "google", "apple", "oracle", "intel", "amd", "ibm", "samsung",
    "vmware", "citrix", "adobe", "mozilla", "debian", "redhat", "canonical",
    "att", "netapp", "gnome", "videolan", "golang", "python", "mongodb",
    "isc", "openldap", "openbsd", "wordpress", "drupal", "zoom", "android",
    "chromium", "firefox", "suse", "ubuntu",
}


def it_vendor_excluded(item):
    return (item.get("vendor") or "").strip().lower() in IT_VENDOR_EXCLUDE


def extract_icsvuln(db_path):
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = db.cursor()
    products = {}
    for cve, vendor, product in cur.execute(
            "SELECT cve_id, vendor, product FROM products WHERE cve_id IS NOT NULL"):
        if cve not in products and (vendor or product):
            products[cve] = f"{vendor or ''}/{product or ''}"
    rows = cur.execute(
        "SELECT cve_id, description, protocols, cwes, is_ics FROM vulnerabilities "
        "WHERE is_ics = 1 OR (protocols IS NOT NULL AND protocols NOT IN ('', '[]'))").fetchall()
    db.close()
    out = []
    for cve, desc, protos, cwes, _ in rows:
        if not cve:
            continue
        proto = ""
        try:
            pl = json.loads(protos) if protos and protos.startswith("[") else []
            proto = pl[0] if pl else ""
        except ValueError:
            pass
        vendor_product = products.get(cve, "/")
        out.append({"cve_id": cve, "summary": (desc or "")[:400], "protocol": proto,
                    "cwes": cwes or "", "vendor": vendor_product.split("/")[0],
                    "product": vendor_product.split("/")[-1]})
    return out


def extract_plcintel(db_path):
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = db.cursor()
    out = []
    for (payload,) in cur.execute("SELECT payload FROM vulnerabilities"):
        try:
            p = json.loads(payload)
        except ValueError:
            continue
        cve = p.get("id") or p.get("cve") or p.get("cve_id")
        if not cve or not str(cve).startswith("CVE"):
            continue
        out.append({"cve_id": str(cve), "summary": (p.get("description") or "")[:400],
                    "protocol": "", "cwes": "", "vendor": "", "product": ""})
    db.close()
    return out


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------
def q(s):
    return "'" + str(s or "").replace("'", "''") + "'"


def upsert_sql(item, vclass, confidence, basis, source):
    return ("INSERT INTO vuln_knowledge(cve_id, source, vclass, vendor, product, protocol, "
            "summary, refs, confidence, class_basis) VALUES ("
            f"{q(item['cve_id'])}, {q(source)}, "
            + ("NULL" if vclass is None else str(int(vclass))) + ", "
            + f"{q(item['vendor'])}, {q(item['product'])}, {q(item['protocol'])}, "
            + f"{q(item['summary'])}, '[]'::jsonb, {q(confidence)}, {q(basis)}) "
            "ON CONFLICT (cve_id, source) DO UPDATE SET vclass=EXCLUDED.vclass, "
            "vendor=EXCLUDED.vendor, product=EXCLUDED.product, protocol=EXCLUDED.protocol, "
            "summary=EXCLUDED.summary, confidence=EXCLUDED.confidence, "
            "class_basis=EXCLUDED.class_basis;")


def refine_update_sql(cve, source, vclass):
    return (f"UPDATE vuln_knowledge SET vclass={int(vclass)}, confidence='llm', "
            f"class_basis='llm-refine' WHERE cve_id={q(cve)} AND source={q(source)};")


def run_psql(sql_file, args):
    pg = args.pg.split(":")
    host, port, dbn, user = (pg + ["127.0.0.1", "5433", "protocol_platform", "pagent"])[:4] \
        if len(pg) < 4 else pg
    cmd = [args.psql, "-h", host, "-p", port, "-U", user, "-d", dbn,
           "-v", "ON_ERROR_STOP=1", "-f", sql_file]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        print(p.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"psql 导入失败 (exit {p.returncode})")
    return p.stdout


# ---------------------------------------------------------------------------
# LLM 精修（经平台 /api/llm/complete，key 不出平台）
# ---------------------------------------------------------------------------
REFINE_SYSTEM = ("你是工控 PLC 漏洞分类器。只输出一个 JSON 对象，键是 CVE 编号、值是 1-14 的"
                 "整数，不要输出任何解释或其他文本。")


def build_batch_prompt(items):
    lines = ["把每条 CVE 归入以下 14 类之一（整数）：",
             "1信息泄露 2协议认证 3远程启停 4内存读写 5控制逻辑篡改 6读写保护破解 "
             "7拒绝服务 8固件与组件(硬编码/过时组件/后门/更新无校验) "
             "9次要攻击面(Web/FTP/SNMP/telnet) 10重放与欺骗 11加密与降级 "
             "12发现协议滥用 13物理I/O操纵 14工程软件客户端。无法判断用 0。", ""]
    for it in items:
        desc = (it.get("summary") or "").replace("\n", " ")[:180]
        lines.append(f"{it['cve_id']}: {desc}")
    lines.append("")
    lines.append('输出形如 {"CVE-2020-7525": 2, ...} 的 JSON。')
    return "\n".join(lines)


def parse_llm_json(text):
    if not text:
        return {}
    m = re.search(r"\{[^{}]*\}", text, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except ValueError:
        return {}


def api_login(base, user, password):
    req = urllib.request.Request(
        base.rstrip("/") + "/api/auth/login",
        data=json.dumps({"username": user, "password": password}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())["token"]


def api_complete(base, token, prompt, profile_id=None, max_tokens=8192, timeout=180):
    body = {"prompt": prompt, "system": REFINE_SYSTEM, "max_tokens": max_tokens,
            # 分类是轻任务：关闭思考，防止推理模型烧光预算返回空正文
            "thinking_type": "disabled", "reasoning_effort": "low"}
    if profile_id:
        body["profile_id"] = profile_id
    req = urllib.request.Request(
        base.rstrip("/") + "/api/llm/complete",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read().decode())
    if not out.get("ok"):
        raise RuntimeError(out.get("error", "llm complete failed"))
    return out["text"]


def refine(items, args, sql_path):
    """对 items 分批 LLM 归类，逐批增量写 UPDATE SQL（防中断丢进度）。

    返回 (refined_count, batch_failures)。
    """
    token = api_login(args.api_base, args.api_user, args.api_pass)
    refined, fails = 0, 0
    todo = items[:args.limit] if args.limit else items
    with open(sql_path, "w", encoding="utf-8", newline="\n") as fh:
        for i in range(0, len(todo), args.batch_size):
            batch = todo[i:i + args.batch_size]
            try:
                text = api_complete(args.api_base, token,
                                    build_batch_prompt(batch), args.profile_id)
                got = {k.strip().upper(): v for k, v in parse_llm_json(text).items()}
            except Exception as exc:                    # noqa: BLE001 - 逐批容错
                print(f"batch {i // args.batch_size}: {exc}", file=sys.stderr)
                fails += 1
                time.sleep(2)
                continue
            n_ok = 0
            for it in batch:
                v = got.get(it["cve_id"])
                if isinstance(v, str) and v.lstrip("-").isdigit():
                    v = int(v)
                if isinstance(v, int) and 1 <= v <= 14:
                    fh.write(refine_update_sql(it["cve_id"], it["_source"], v) + "\n")
                    n_ok += 1
            fh.flush()
            refined += n_ok
            print(f"  refined {min(i + args.batch_size, len(todo))}/{len(todo)} "
                  f"(+{n_ok} this batch)", file=sys.stderr)
            time.sleep(args.interval)
    return refined, fails


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="vuln_knowledge 存量标注导入")
    ap.add_argument("--icsvuln-db", default=DEFAULT_ICSVULN)
    ap.add_argument("--plc-intel-db", default=DEFAULT_PLC_INTEL)
    ap.add_argument("--source", choices=("both", "icsvuln", "plc-intel"), default="both")
    ap.add_argument("--out", default=None, help="SQL 输出文件（默认 vk_import_<ts>.sql 于临时目录）")
    ap.add_argument("--execute", action="store_true", help="生成后经 psql 执行入库")
    ap.add_argument("--psql", default=DEFAULT_PSQL)
    ap.add_argument("--pg", default="127.0.0.1:5433:protocol_platform:pagent",
                    help="host:port:db:user")
    ap.add_argument("--refine", action="store_true", help="LLM 精修非高置信条目")
    ap.add_argument("--refine-only", action="store_true", help="跳过确定性导入，只精修")
    ap.add_argument("--api-base", default="http://localhost:8790")
    ap.add_argument("--api-user", default="protocol")
    ap.add_argument("--api-pass", required=False)
    ap.add_argument("--profile-id", type=int, default=None)
    ap.add_argument("--refine-confidence", default="None,low",
                    help="refine 哪些置信级：逗号分隔 None/low/medium/high（默认 None,low）")
    ap.add_argument("--batch-size", type=int, default=20)
    ap.add_argument("--limit", type=int, default=0, help="refine 条数上限（0=不限）")
    ap.add_argument("--keep-it-vendors", action="store_true",
                    help="不过滤纯 IT 厂商（默认剔除 IT_VENDOR_EXCLUDE 名单）")
    ap.add_argument("--interval", type=float, default=1.0, help="批间间隔秒")
    args = ap.parse_args()

    corpus = []
    src_items = {}
    if args.source in ("both", "icsvuln") and Path(args.icsvuln_db).exists():
        src_items["icsvuln"] = extract_icsvuln(args.icsvuln_db)
    if args.source in ("both", "plc-intel") and Path(args.plc_intel_db).exists():
        src_items["plc-intel"] = extract_plcintel(args.plc_intel_db)
    for src, items in src_items.items():
        print(f"extracted {len(items)} from {src}", file=sys.stderr)

    stats = {"high": 0, "medium": 0, "low": 0, "unclassified": 0}
    excluded = 0
    results = []                                        # (item, source, vclass, conf, basis)
    for src, items in src_items.items():
        for it in items:
            if not args.keep_it_vendors and it_vendor_excluded(it):
                excluded += 1
                continue
            v, conf, basis = classify(it)
            stats[conf or "unclassified"] += 1
            results.append((it, src, v, conf, basis))
    if excluded:
        print(f"excluded {excluded} non-ICS vendor rows (IT_VENDOR_EXCLUDE)", file=sys.stderr)

    out_path = args.out or str(Path(tempfile_dir()) /
                               f"vk_import_{datetime.datetime.now():%Y%m%d_%H%M%S}.sql")
    if not args.refine_only:
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("-- vuln_knowledge bulk import (idempotent upsert)\n")
            for it, src, v, conf, basis in results:
                fh.write(upsert_sql(it, v, conf, basis, src) + "\n")
        print(json.dumps({"sql": out_path, "statements": len(results), "confidence": stats},
                         ensure_ascii=False))
        if args.execute:
            run_psql(out_path, args)
            print("imported via psql", file=sys.stderr)

    if args.refine:
        if not args.api_pass:
            raise SystemExit("--refine 需要 --api-pass（平台管理员密码）")
        want = {c.strip() for c in args.refine_confidence.split(",") if c.strip()}
        ambiguous = [dict(it, _source=src) for it, src, v, conf, basis in results
                     if (conf or "None") in want and it["cve_id"]]
        sql_path = out_path.replace(".sql", "_refine.sql") if out_path.endswith(".sql") \
            else out_path + ".refine.sql"
        refined, fails = refine(ambiguous, args, sql_path)
        print(json.dumps({"refine_sql": sql_path, "refined": refined,
                          "batches_failed": fails}, ensure_ascii=False))
        if args.execute and refined:
            run_psql(sql_path, args)
            print("refine written via psql", file=sys.stderr)
    return 0


def tempfile_dir():
    import tempfile
    return tempfile.gettempdir()


if __name__ == "__main__":
    sys.exit(main())
