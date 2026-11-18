#!/usr/bin/env python3
"""P7-P9 离线补齐：对已过门 F 的老案例批量执行离线可完成的漏洞挖掘阶段。

流程（无设备、无子代理；确定性工具 + 单次 LLM 批量裁决）：
  P7  device_profile.py → applicability.py → vuln_intel.py →
      LLM 批量裁决（未知子模板按证据落定 + deterministic 假设定终态）
  P8  static：fuzz 假设 → inconclusive/fuzz-deferred-live（离线不执行 campaign）
  P9  exp_gen.py（confirmed 且带帧）→ 05 号报告（工具生成）→ 登记 protocol_reports
回写：findings 同步 DB、config.vuln_enabled=true、P7/P8/P9 阶段行与门事件。
live 模式老案例只做 P7（门 H 离线过不了 campaign≥1）。

用法：
  python p769_offline.py --case 7 [--case 12 ...] | --static-old
      [--api-base http://localhost:8790] [--user protocol --pass xxx]
      [--dry-run]
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
PY = sys.executable
PSQL = ROOT / "runtime" / "pgsql" / "bin" / "psql.exe"
CASES = ROOT / "platform" / "data" / "protocol_cases"

# vendor 线索：comm_assets 路径关键词 → 情报查询厂商名
VENDOR_HINTS = [
    ("schneider", "schneider"), ("somachine", "schneider"), ("ecostruxure", "schneider"),
    ("siemens", "siemens"), ("step7", "siemens"), ("tia", "siemens"),
    ("moxa", "moxa"), ("wago", "wago"), ("codesys", "codesys"),
    ("mitsubishi", "mitsubishielectric"), ("gx works", "mitsubishielectric"),
    ("delta", "deltaww"), ("omron", "omron"), ("beckhoff", "beckhoff"),
    ("ab ", "rockwellautomation"), ("rslogix", "rockwellautomation"),
    ("advantech", "advantech"), ("fx5u", "mitsubishielectric"),
]

VCLASS_NAMES = {1: "信息泄露", 2: "协议认证", 3: "远程启停", 4: "内存读写", 5: "逻辑篡改",
                6: "保护破解", 7: "拒绝服务", 8: "固件与组件", 9: "次要攻击面",
                10: "重放与欺骗", 11: "加密与降级", 12: "发现协议滥用", 13: "物理I/O操纵",
                14: "工程侧客户端"}


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", **kw)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed({r.returncode}): {' '.join(map(str, cmd))}\n{r.stderr[:800]}")
    return r.stdout


def psql(sql):
    tmp = Path(tempfile.gettempdir()) / f"p769_{datetime.datetime.now():%H%M%S%f}.sql"
    tmp.write_text(sql, encoding="utf-8")
    env = dict(os.environ)
    env["PGPASSWORD"] = "pagent"
    r = subprocess.run([str(PSQL), "-h", "127.0.0.1", "-p", "5433", "-U", "pagent",
                        "-d", "protocol_platform", "-t", "-A", "-f", str(tmp)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env=env)
    tmp.unlink(missing_ok=True)
    if r.returncode != 0:
        raise RuntimeError(f"psql failed: {r.stderr[:500]}")
    return r.stdout


def load_case_meta(case_id):
    out = psql(f"SELECT id, mode, name, COALESCE(config::text,'{{}}'), "
               f"COALESCE((SELECT status FROM protocol_phases WHERE case_id={case_id} AND phase='P6'),'') "
               f"FROM protocol_cases WHERE id={case_id};")
    row = [l for l in out.splitlines() if "|" in l]
    if not row:
        raise RuntimeError(f"case {case_id} not found")
    parts = row[0].split("|")
    return {"id": int(parts[0]), "mode": parts[1].strip(), "name": parts[2].strip(),
            "config": parts[3].strip(), "p6": parts[4].strip()}


# ------------------------------------------------------------------ P7 tools
def run_p7_tools(fjson):
    for tool in ("device_profile.py", "applicability.py"):
        run([PY, str(TOOLS / tool), "--findings", str(fjson)], cwd=str(TOOLS))


def guess_vendor_product(data):
    text = json.dumps(data.get("comm_assets", []) + data.get("notes", []), ensure_ascii=False).lower()
    for needle, vendor in VENDOR_HINTS:
        if needle in text:
            return vendor, ""
    return "", ""


def run_intel(fjson, data):
    vendor, product = guess_vendor_product(data)
    proto = ""
    for s in data.get("streams", []):
        if isinstance(s, dict) and s.get("protocol"):
            proto = str(s["protocol"]).lower()
            break
    args = [PY, str(TOOLS / "vuln_intel.py"), "--findings", str(fjson),
            "--skip-plc-intel", "--max", "10"]
    if vendor:
        args += ["--vendor", vendor]
    if proto:
        args += ["--protocol", proto]
    if not vendor and not proto:
        return  # 无线索时跳过（vuln_intel 要求至少一个查询维度）
    run(args, cwd=str(TOOLS))


# ------------------------------------------------------------------ LLM 裁决
def api_login(base, user, password):
    req = urllib.request.Request(base + "/api/auth/login", method="POST",
                                 data=json.dumps({"username": user, "password": password}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read()).get("token")


def api_complete(base, token, prompt):
    body = {"prompt": prompt, "max_tokens": 8192,
            # 裁决是证据对照任务：关闭思考，防推理模型烧光预算返回空正文
            "thinking_type": "disabled", "reasoning_effort": "low"}
    req = urllib.request.Request(base + "/api/llm/complete", method="POST",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=600) as r:
        out = json.loads(r.read())
    if not out.get("ok"):
        raise RuntimeError(out.get("error", "llm complete failed"))
    return out.get("text", "")


def digest_findings(data):
    """压缩案例证据给裁决用：资产指纹 + 功能码 + 帧格式 + 会话/探针线索。"""
    d = {}
    assets = [a.get("path", "") or a.get("name", "") for a in data.get("comm_assets", [])][:12]
    d["comm_assets"] = assets
    codes = [{"code": c.get("code") or c.get("code_key"), "label": c.get("label", ""),
              "source": c.get("source", ""), "evidence": str(c.get("evidence", ""))[:80]}
             for c in data.get("function_codes", [])][:40]
    d["function_codes"] = codes
    frames = [{"magic": f.get("magic"), "carrier": f.get("carrier"),
               "commands": f.get("commands_observed")} for f in data.get("frame_formats", [])][:8]
    d["frame_formats"] = frames
    notes = [str(n.get("payload") or n.get("summary") or n.get("kind"))[:120]
             for n in data.get("notes", [])
             if n.get("kind") in ("session-model", "code-reconciliation",
                                  "session-model-final", "pitfall")][:12]
    d["notes"] = notes
    probes = [{"kind": p.get("kind"), "status": p.get("status"), "grade": p.get("grade")}
              for p in data.get("probes", [])][:10]
    d["probes"] = probes
    d["device_profile"] = data.get("device_profile", {}).get("matrix")
    return d


def build_adjudication_prompt(data, unknown_items, pending_hyps):
    parts = [
        "你是工控协议漏洞直判裁决器。基于案例 P1-P6 的离线证据，对两批条目做裁决。",
        "证据等级 traffic > live > static > inferred；只能引用下述证据，不得臆造。",
        "",
        "## 案例证据摘要",
        json.dumps(digest_findings(data), ensure_ascii=False, indent=1)[:6000],
        "",
        "## 任务一：未知能力子模板落定（当前 unknown，需要 applicable 或 not_applicable）",
        "规则：pcap 抓包覆盖的会话里未见对应服务/能力帧，且静态结论也无该能力 → "
        "not_applicable（reason 注明“抓包范围内未见…，如 pcap 未覆盖该面可 live 复核”）；"
        "证据里存在该能力的任何迹象 → applicable。给不出把握就 applicable（宁多勿漏）。",
    ]
    for it in unknown_items:
        parts.append(f"- {it['template_id']}（缺能力: {', '.join(it.get('missing_caps', []))}）{it['name']}")
    parts += [
        "",
        "## 任务二：deterministic 假设裁决（三选一终态）",
        "confirmed：证据足以成立（verdict=confirmed-by-traffic 或 confirmed-by-static；"
        "evidence 给证据引用数组）；**write/destructive 风险类只有当证据里有可回放帧时才可"
        "confirmed（frames 字段给 hex 数组，从 frame_formats.commands_observed 或 "
        "function_codes.evidence 摘录），否则 inconclusive（reason 写“缺可回放帧”）**；",
        "falsified：证据明确反证（verdict=refuted-by-traffic/static）；",
        "inconclusive：离线证据不足以定论（verdict=inconclusive-offline，reason 写缺什么）。",
    ]
    for h in pending_hyps:
        parts.append(f"- {h['id']} [{h.get('risk')}] {h['name']} 判定规则: {h.get('verdict_rule') or h.get('plan') or '-'}")
    parts += [
        "",
        "## 输出（严格 JSON，无其它文字）",
        '{"applicability": [{"template_id":"...","state":"applicable|not_applicable","reason":"..."}],',
        '"hypotheses": [{"id":"H-...","state":"confirmed|falsified|inconclusive",'
        '"verdict":"...","reason":"...","evidence":["..."],"frames":["hex..."]}]}',
    ]
    return "\n".join(parts)


def parse_llm_json(text):
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON in reply")
    return json.loads(m.group(0))


def adjudicate(base, token, data):
    surface = data.get("vuln_surface", {})
    items = surface.get("applicability", {}).get("items", [])
    unknown = [i for i in items if i.get("state") == "unknown"]
    hyps = data.get("vuln_hypotheses", [])
    pending = [h for h in hyps if h.get("detection") == "deterministic" and h.get("state") == "pending"]
    # 上一轮遗留：write/destructive confirmed 但没有可回放帧（exp_gen 生成不了 EXP，
    # 门 I 会如实 fail）——重置为 pending 让本轮按强化规则重裁。
    for h in hyps:
        if (h.get("state") == "confirmed" and h.get("risk") in ("write", "destructive")
                and h.get("detection") == "deterministic"):
            has_frames = any(isinstance(e, dict) and e.get("frames") for e in (h.get("evidence") or []))
            if not has_frames:
                h["state"] = "pending"
                pending.append(h)
    if not unknown and not pending:
        return {"applicability": [], "hypotheses": []}
    prompt = build_adjudication_prompt(data, unknown, pending)
    raw = api_complete(base, token, prompt)
    try:
        out = parse_llm_json(raw)
    except (ValueError, json.JSONDecodeError):
        raw = api_complete(base, token, prompt)  # 坏 JSON 重试一次
        out = parse_llm_json(raw)
    # 校验 id 合法性，防 LLM 编造
    valid_t = {i["template_id"] for i in unknown}
    valid_h = {h["id"] for h in pending}
    out["applicability"] = [a for a in out.get("applicability", []) if a.get("template_id") in valid_t]
    out["hypotheses"] = [h for h in out.get("hypotheses", []) if h.get("id") in valid_h]
    return out


def apply_adjudication(data, verdict):
    surface = data.setdefault("vuln_surface", {})
    applic = surface.setdefault("applicability", {})
    items = applic.get("items", [])
    by_t = {a["template_id"]: a for a in verdict.get("applicability", [])}
    for it in items:
        v = by_t.get(it["template_id"])
        if v and it.get("state") == "unknown":
            it["state"] = v["state"]
            it["reason"] = v.get("reason", "")
            if v["state"] == "not_applicable":
                it.pop("missing_caps", None)
    # 重算 summary
    states = [i.get("state") for i in items]
    applic["summary"] = {
        "total": len(items),
        "applicable": states.count("applicable"),
        "not_applicable": states.count("not_applicable"),
        "unknown": states.count("unknown"),
    }
    # 未知落定为 not_applicable 的假设 → not_applicable
    na_templates = {i["template_id"] for i in items if i.get("state") == "not_applicable"}
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    for h in data.get("vuln_hypotheses", []):
        if h.get("template_id") in na_templates and h.get("state") == "pending":
            h["state"] = "not_applicable"
            h["verdict"] = "not_applicable"
            h["verdict_reason"] = "前置能力不适用（离线证据落定）"
        v = next((x for x in verdict.get("hypotheses", []) if x["id"] == h["id"]), None)
        if v and h.get("state") == "pending":
            h["state"] = v["state"]
            h["verdict"] = v.get("verdict", "")
            h["verdict_reason"] = v.get("reason", "")
            ev = h.get("evidence") if isinstance(h.get("evidence"), list) else []
            ev = ev + (v.get("evidence") or [])
            if v.get("frames") and not any(isinstance(e, dict) and e.get("frames") for e in ev):
                grade = "traffic" if "traffic" in v.get("verdict", "") else "static"
                ev.append({"frames": v["frames"], "ref": "offline-adjudication", "grade": grade})
            h["evidence"] = ev
        h.setdefault("ts", ts)
    # fuzz → deferred-live（P8 离线）
    for h in data.get("vuln_hypotheses", []):
        if h.get("detection") == "fuzz" and h.get("state") in ("pending", None):
            h["state"] = "inconclusive"
            h["verdict"] = "fuzz-deferred-live"
            h["verdict_reason"] = "离线模式不执行 fuzz（无设备），需 live 复跑"
    return data


# ------------------------------------------------------------------ gates
def gate_g(data):
    prof = data.get("device_profile", {})
    matrix = prof.get("matrix") or {}
    caps = sum(1 for row in matrix.values()
               if any(row.get(v) for v in ("protocol", "service", "physical")))
    applic = data.get("vuln_surface", {}).get("applicability", {})
    s = applic.get("summary", {})
    pending = sum(1 for h in data.get("vuln_hypotheses", [])
                  if h.get("detection") == "deterministic" and h.get("state") == "pending")
    ok = caps >= 1 and bool(applic) and s.get("unknown", 1) == 0 and \
        (s.get("applicable", 0) + s.get("not_applicable", 0)) > 0 and pending == 0
    detail = (f"能力矩阵 {caps} 项；适用性 applicable={s.get('applicable', 0)} / "
              f"not_applicable={s.get('not_applicable', 0)} / unknown={s.get('unknown', 0)}；"
              f"直判类待裁决 {pending} 条")
    return ok, detail


def gate_h(data):
    terminal = {"confirmed", "falsified", "inconclusive", "enforced", "not_applicable"}
    hyps = data.get("vuln_hypotheses", [])
    t = sum(1 for h in hyps if h.get("state") in terminal)
    c = sum(1 for h in hyps if h.get("state") == "confirmed")
    return (len(hyps) > 0 and t == len(hyps),
            f"假设终态 {t}/{len(hyps)}（confirmed={c}；离线模式不执行 campaign，fuzz 类 deferred-live）")


def gate_i(data, case_id):
    hyps = data.get("vuln_hypotheses", [])
    exps = data.get("exploit_assets", [])
    have = {e.get("hypothesis") for e in exps}
    need = covered = 0
    for h in hyps:
        if h.get("state") == "confirmed" and h.get("risk") in ("write", "destructive"):
            need += 1
            if h["id"] in have:
                covered += 1
    rep_ok = bool(REPORT_GENERATED.get(case_id))
    return (need == covered and rep_ok and len(exps) + len(hyps) > 0,
            f"EXP 登记 {len(exps)} 条；write/destructive 确认项 {covered}/{need} 有 EXP；漏洞报告 {rep_ok}")


REPORT_GENERATED = {}


# ------------------------------------------------------------------ P9 report
def build_report(case_id, name, data):
    hyps = data.get("vuln_hypotheses", [])
    conf = [h for h in hyps if h.get("state") == "confirmed"]
    s = data.get("vuln_surface", {}).get("applicability", {}).get("summary", {})
    lines = [
        f"# 05 漏洞利用与验证报告（离线工具生成）",
        "",
        f"- 案例：#{case_id} «{name}»",
        f"- 生成：p769_offline 工具链（device_profile / applicability / vuln_intel / LLM 批量直判 / exp_gen）",
        f"- 范围声明：本报告基于 P1-P6 离线证据（traffic/static），未做真机 live 验证；",
        f"  fuzz 类假设因离线模式未执行（fuzz-deferred-live），需 live 复跑。",
        "",
        "## 1. 适用性总览",
        f"- 47 子模板：适用 {s.get('applicable', 0)} · 不适用 {s.get('not_applicable', 0)} · 未知 {s.get('unknown', 0)}",
        "",
        "## 2. 已确认漏洞",
    ]
    if not conf:
        lines.append("- 无（离线证据不足以确认任何假设）")
    for h in conf:
        lines += [f"### {h['id']} {h.get('name', '')}",
                  f"- 类别：{h.get('vclass')}·{VCLASS_NAMES.get(h.get('vclass'), '?')}　风险：{h.get('risk')}",
                  f"- 结论：{h.get('verdict', '')} —— {h.get('verdict_reason', '')}",
                  f"- 证据：{'；'.join(str(e)[:100] for e in (h.get('evidence') or [])[:3])}"]
    exps = data.get("exploit_assets", [])
    lines += ["", "## 3. EXP 资产"]
    if not exps:
        lines.append("- 无")
    for e in exps:
        lines.append(f"- {e.get('id')}（{e.get('tier')}，sha16 {e.get('sha256_16')}）")
    others = [h for h in hyps if h.get("state") not in ("confirmed",)]
    lines += ["", "## 4. 其余假设", f"- 共 {len(others)} 条（inconclusive/falsified/not_applicable），明细见 findings。"]
    return "\n".join(lines)


# ------------------------------------------------------------------ DB 回写
def sql_literal(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"


def sync_db(case_id, data, name, phases, mode):
    fjson = json.dumps(data, ensure_ascii=False)
    tag = f"$p769c{case_id}$"
    stmts = [
        f"UPDATE protocol_cases SET findings={tag}\n{fjson}\n{tag}::jsonb, updated_at=now() WHERE id={case_id};",
        f"UPDATE protocol_cases SET config=jsonb_set(COALESCE(config,'{{}}'::jsonb), '{{vuln_enabled}}', 'true') WHERE id={case_id};",
    ]
    for ph, gate, ok, detail in phases:
        status = "pass" if ok else "fail"
        ev = json.dumps({"offline_batch": True, "gate": gate}, ensure_ascii=False)
        stmts.append(
            f"INSERT INTO protocol_phases (case_id, phase, gate, status, detail, evidence, started_at, finished_at, updated_at) "
            f"VALUES ({case_id}, '{ph}', '{gate}', '{status}', "
            f"{sql_literal(detail[:500])}, '{ev}', now(), now(), now()) "
            f"ON CONFLICT (case_id, phase) DO UPDATE SET status='{status}', "
            f"detail={sql_literal(detail[:500])}, evidence='{ev}', updated_at=now();")
        stmts.append(
            f"INSERT INTO protocol_events (case_id, phase, kind, message, payload) "
            f"VALUES ({case_id}, '{ph}', 'gate', {sql_literal(f'[门 {gate}] ' + ('PASS' if ok else 'FAIL') + ' ' + detail[:200])}, "
            f"'{{\"offline_batch\": true}}'::jsonb);")
    report = REPORT_GENERATED.get(case_id)
    if report:
        stmts.append(
            f"INSERT INTO protocol_reports (case_id, doc_type, title, content, version) "
            f"VALUES ({case_id}, '05_漏洞利用与验证报告', '05 漏洞利用与验证报告（离线）', "
            f"{sql_literal(report)}, 1) ON CONFLICT DO NOTHING;")
    stmts.append(
        f"INSERT INTO protocol_events (case_id, phase, kind, message, payload) "
        f"VALUES ({case_id}, '', 'status', {sql_literal('P7-P9 离线补齐完成（工具链批量，无设备模式）')}, "
        f"'{{\"offline_batch\": true}}'::jsonb);")
    psql("\n".join(stmts))


# ------------------------------------------------------------------ main
def process_case(case_id, base, token, dry=False):
    meta = load_case_meta(case_id)
    if meta["p6"] != "pass":
        return {"case": case_id, "skip": f"P6 未通过（{meta['p6'] or '未跑'}），P7 前置不满足"}
    wd = CASES / f"case-{case_id}"
    fjson = wd / "findings.json"
    if not fjson.exists():
        return {"case": case_id, "skip": "findings.json 不存在"}
    data = json.loads(fjson.read_text(encoding="utf-8"))

    # P7 三工具
    run_p7_tools(fjson)
    data = json.loads(fjson.read_text(encoding="utf-8"))
    run_intel(fjson, data)
    data = json.loads(fjson.read_text(encoding="utf-8"))

    # LLM 批量裁决 + P8 离线终态
    verdict = adjudicate(base, token, data)
    data = apply_adjudication(data, verdict)
    fjson.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    g_ok, g_detail = gate_g(data)
    phases = [("P7", "G", g_ok, g_detail)]
    result = {"case": case_id, "name": meta["name"], "mode": meta["mode"],
              "P7": "pass" if g_ok else f"fail ({g_detail})",
              "applicability": data.get("vuln_surface", {}).get("applicability", {}).get("summary", {})}

    if meta["mode"] == "static" and g_ok:
        # P9: exp_gen（confirmed 全部 replay 级）
        out = run([PY, str(TOOLS / "exp_gen.py"), "--findings", str(fjson),
                   "--tier", "replay"], cwd=str(TOOLS))
        data = json.loads(fjson.read_text(encoding="utf-8"))
        h_ok, h_detail = gate_h(data)
        rep = build_report(case_id, meta["name"], data)
        REPORT_GENERATED[case_id] = rep
        (wd / "docs").mkdir(exist_ok=True)
        (wd / "docs" / "05_漏洞利用与验证报告.md").write_text(rep, encoding="utf-8")
        i_ok, i_detail = gate_i(data, case_id)
        phases += [("P8", "H", h_ok, h_detail), ("P9", "I", i_ok, i_detail)]
        result.update({
            "P8": "pass" if h_ok else f"fail ({h_detail})",
            "P9": "pass" if i_ok else f"fail ({i_detail})",
            "confirmed": sum(1 for h in data.get("vuln_hypotheses", []) if h.get("state") == "confirmed"),
            "hypotheses": len(data.get("vuln_hypotheses", [])),
            "exploits": len(data.get("exploit_assets", [])),
        })
    else:
        result["P8"] = "skipped（live 模式离线过不了门 H 的 campaign≥1；或 P7 未过）"
        result["P9"] = "skipped"

    if not dry:
        sync_db(case_id, data, meta["name"], phases, meta["mode"])
    return result


def main():
    ap = argparse.ArgumentParser(description="P7-P9 离线补齐（老案例批量）")
    ap.add_argument("--case", type=int, action="append", default=[])
    ap.add_argument("--static-old", action="store_true", help="所有 P6 已过的 static 老案例")
    ap.add_argument("--api-base", default="http://localhost:8790")
    ap.add_argument("--user", default="protocol")
    ap.add_argument("--pass", dest="password",
                    default=os.environ.get("ICS_AGENT_API_PASS", ""),
                    help="平台管理员密码（或环境变量 ICS_AGENT_API_PASS）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    ids = list(args.case)
    if args.static_old:
        out = psql("SELECT id FROM protocol_cases WHERE mode='static' AND id NOT IN "
                   "(SELECT case_id FROM protocol_phases WHERE phase='P7') "
                   "AND id IN (SELECT case_id FROM protocol_phases WHERE phase='P6' AND status='pass') ORDER BY id;")
        ids += [int(x) for x in out.split() if x.strip().isdigit()]
    if not ids:
        ap.error("需要 --case 或 --static-old")
    if not args.password:
        ap.error("需要 --pass 或环境变量 ICS_AGENT_API_PASS（平台管理员密码）")
    token = api_login(args.api_base, args.user, args.password)
    results = []
    for cid in sorted(set(ids)):
        try:
            results.append(process_case(cid, args.api_base, token, args.dry_run))
        except Exception as e:  # noqa: BLE001
            results.append({"case": cid, "error": str(e)[:300]})
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
