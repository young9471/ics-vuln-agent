#!/usr/bin/env python3
"""ARTEX-IOT 固件轨 API 桥（PLAN-V2 §3.7，M2）。

三个子命令：
  handoff  移交：从 findings 生成协议侧摘要 → 建 ARTEX 任务（goal 聚焦协议解析组件）
           → multipart 上传固件 → 落 handoff 登记文件
  pull     回流：拉任务状态/组件清单/发现/反编译函数 → 写 findings 的
           vuln_surface.firmware_track + 生成/更新 vuln_hypotheses（组件→V8B，
           ARTEX finding→带 artex 引用的假设）
  campaign 定向 campaign 生成：协议侧种子（frame_formats/probes/wago spec）×
           ARTEX 反编译候选（parse/recv/crc 类函数）→ campaign_runner JSON

鉴权：--key-file 指向 ARTEX 的 jwt.key（本机联调用，自签 7 天服务 token，
不改用户密码）；或 --token 直接给。

用法示例：
  python artex_bridge.py handoff --findings <f.json> --firmware fw.bin \
      --api-base http://localhost:8787 --key-file C:\科研\project\ARTEX-IOT\jwt.key
  python artex_bridge.py pull --task 12 --findings <f.json> --key-file ...
  python artex_bridge.py campaign --task 12 --findings <f.json> --host 192.168.1.10 \
      --port 502 --out campaigns/artex-12.json
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F                      # noqa: E402

DEFAULT_API = os.environ.get("PROTOCOL_AGENT_ARTEX_API", "http://localhost:8787")
DEFAULT_KEY = os.environ.get(
    "PROTOCOL_AGENT_ARTEX_KEY", r"C:\科研\project\ARTEX-IOT\jwt.key")

# ARTEX 反编译函数名/字符串中值得定向 fuzz 的候选特征
FOCUS_HINTS = ("parse", "recv", "dispatch", "crc", "checksum", "decode",
               "frame", "packet", "length", "memcpy", "strcpy")


# ---------------------------------------------------------------- 鉴权与 HTTP
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint_service_token(key: bytes, subject="ARTEX", ttl_days=7) -> str:
    """按 ARTEX signJWT 的 claims（sub/iat/exp，HS256）自签服务 token。"""
    now = int(time.time())
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = b64url(json.dumps(
        {"sub": subject, "iat": now, "exp": now + ttl_days * 86400}).encode())
    signing = f"{head}.{claims}".encode()
    sig = b64url(hmac.new(key, signing, hashlib.sha256).digest())
    return f"{head}.{claims}.{sig}"


class ArtexClient:
    def __init__(self, base, token, timeout=30):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.h = {"Authorization": f"Bearer {token}"}

    def _req(self, method, path, body=None, headers=None, data=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=data)
        for k, v in {**self.h, **(headers or {})}.items():
            req.add_header(k, v)
        if body is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(body).encode()
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "null")

    def get(self, path):
        return self._req("GET", path)

    def post_json(self, path, body):
        return self._req("POST", path, body=body)

    def upload_firmware(self, task_id, fw_path):
        """multipart/form-data，字段名 file（ARTEX taskFirmwareUpload 契约）。"""
        boundary = uuid.uuid4().hex
        fw = Path(fw_path)
        part = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{fw.name}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        body = part + fw.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        return self._req("POST", f"/api/tasks/{task_id}/firmware", data=body,
                         headers={"Content-Type":
                                  f"multipart/form-data; boundary={boundary}"})


# ---------------------------------------------------------------- handoff
def protocol_summary(findings):
    """从 findings 提炼协议侧摘要，聚焦 ARTEX 审计范围到协议解析组件。"""
    protos, ports, fcs = set(), set(), []
    for s in findings.get("streams", []):
        ep = str(s.get("endpoints", ""))
        for tok in ep.replace("<->", " ").split():
            if ":" in tok:
                p = tok.rsplit(":", 1)[-1]
                if p.isdigit():
                    ports.add(int(p))
        proto = str(s.get("protocol", "") or "")
        if proto:
            protos.add(proto)
    for fc in findings.get("function_codes", [])[:40]:
        fcs.append(str(fc.get("code", "")))
    profile = findings.get("device_profile") or {}
    facts = profile.get("facts") or {}
    lines = [
        "固件审计聚焦指令：优先分析承担工业协议解析的组件与函数",
        f"（协议线索：{', '.join(sorted(protos)) or '未知'}；"
        f"端口：{', '.join(str(p) for p in sorted(ports)) or '未知'}）。",
        "重点：帧解析/长度字段处理/校验和计算/命令分发函数中的边界检查缺失，",
        "即 memcpy/strcpy 无长度约束、长度字段未验证、整数溢出。",
        f"已知功能码（用于函数对齐锚点）：{' '.join(fcs[:30]) or '无'}。",
        f"设备：{facts.get('vendor') or '?'} {facts.get('model') or '?'} "
        f"固件 {facts.get('firmware') or '?'}。",
    ]
    return "\n".join(lines)


def cmd_handoff(args, client):
    data = F.load(args.findings)
    goal = protocol_summary(data)
    desc = (f"protocol-agent 固件轨移交 {args.vendor or ''} {args.product or ''}").strip()
    st, task = client.post_json("/api/tasks", {
        "description": desc, "goal": goal,
        "firmware_vendor": args.vendor or "", "firmware_version": args.version or "",
    })
    if st != 201:
        print(json.dumps({"error": f"create task -> {st}", "resp": task},
                         ensure_ascii=False))
        return 1
    task_id = str(task.get("id"))
    st2, up = client.upload_firmware(task_id, args.firmware)
    if st2 not in (200, 201):
        print(json.dumps({"error": f"firmware upload -> {st2}", "resp": up},
                         ensure_ascii=False))
        return 1
    sha = hashlib.sha256(Path(args.firmware).read_bytes()).hexdigest()
    handoff = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
               "artex_task_id": task_id, "firmware_sha256": sha,
               "firmware": str(Path(args.firmware).resolve()),
               "vendor": args.vendor, "product": args.product,
               "upload": up}
    surface = data.get("vuln_surface") or {}
    surface["firmware_track"] = surface.get("firmware_track") or {}
    surface["firmware_track"]["handoff"] = handoff
    data["vuln_surface"] = surface
    F.save(args.findings, data)
    if args.out:
        Path(args.out).write_text(json.dumps(handoff, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    print(json.dumps({"ok": True, **handoff}, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- pull
def map_artex_finding(f):
    """ARTEX finding → 14 类猜测（vuln_intel 先验 + vuln_kb_import 关键词分类兜底）。"""
    from vuln_intel import guess_vclass
    from vuln_kb_import import classify_by_keywords
    text = " ".join(str(f.get(k, "")) for k in ("title", "description", "summary"))
    v = guess_vclass(text)
    if v is None:
        v, _ = classify_by_keywords(text)
    return v


def cmd_pull(args, client):
    st, task = client.get(f"/api/tasks/{args.task}")
    if st != 200:
        print(json.dumps({"error": f"get task -> {st}", "resp": task}, ensure_ascii=False))
        return 1
    sha = (task.get("firmware") or {}).get("sha256") if isinstance(task.get("firmware"), dict) \
        else task.get("firmware_sha256")
    sha = sha or (args.sha or "")
    components, finds, functions = [], [], []
    if sha:
        st, comp = client.get(f"/api/components?firmware={sha}&limit=200")
        components = (comp.get("components") or comp.get("items") or []) \
            if isinstance(comp, dict) else comp or []
    st, fl = client.get(f"/api/exploration/findings?task={args.task}&limit=200")
    finds = fl if isinstance(fl, list) else (fl or {}).get("items", [])
    st, jobs = client.get(f"/api/tasks/{args.task}/decompile/jobs")
    if isinstance(jobs, list):
        job_list = jobs
    elif isinstance(jobs, dict):
        job_list = jobs.get("items") or jobs.get("jobs") or []
    else:
        job_list = []
    job_list = [j for j in job_list if isinstance(j, dict)]
    for job in job_list:
        jid = job.get("id") or job.get("job_id")
        if not jid:
            continue
        st, funcs = client.get(f"/api/decompile/jobs/{jid}/functions?limit=500")
        rows = funcs if isinstance(funcs, list) else (funcs or {}).get("items", []) \
            or (funcs or {}).get("functions", [])
        for fn in rows:
            functions.append({"job": jid, "name": fn.get("name") or fn.get("func"),
                              "addr": fn.get("addr") or fn.get("address")})

    track = {"task_id": str(args.task), "status": task.get("status"),
             "firmware_sha256": sha, "ts": datetime.datetime.now().isoformat(timespec="seconds"),
             "components": [
                 {"name": c.get("component_name") or c.get("name"),
                  "type": c.get("type"), "version": c.get("version"),
                  "vendor": c.get("vendor"), "binary": c.get("binary_path")}
                 for c in components],
             "findings": [
                 {"id": f.get("id"), "title": f.get("title"),
                  "severity": f.get("severity") or f.get("level"),
                  "vclass_guess": map_artex_finding(f)}
                 for f in finds],
             "decompile_functions": functions}

    data = F.load(args.findings)
    surface = data.get("vuln_surface") or {}
    surface["firmware_track"] = surface.get("firmware_track") or {}
    surface["firmware_track"]["pull"] = track
    data["vuln_surface"] = surface

    # 组件 → V8B 假设；ARTEX finding → 带 artex 引用的假设
    existing = {h["id"] for h in data.get("vuln_hypotheses", [])}
    for c in track["components"]:
        hid = f"H-V8B-{(c['name'] or 'comp').replace(' ', '_')}"
        if hid not in existing and c["name"]:
            data.setdefault("vuln_hypotheses", []).append({
                "id": hid, "template_id": "V8B-outdated-components", "vclass": 8,
                "name": f"组件 CVE 匹配：{c['name']} {c['version'] or ''}".strip(),
                "risk": "read", "detection": "deterministic", "state": "pending",
                "requires_approval": False,
                "plan": f"vuln_intel --kb --product {c['name']} 比对已知组件 CVE",
                "evidence": [{"artex_component": c["name"], "version": c["version"]}],
                "ts": track["ts"]})
            existing.add(hid)
    for f in track["findings"]:
        hid = f"H-ARTX-{f['id']}"
        if hid not in existing:
            data.setdefault("vuln_hypotheses", []).append({
                "id": hid, "template_id": "-", "vclass": f["vclass_guess"] or 4,
                "name": f"ARTEX 固件审计发现：{f['title']}",
                "risk": "destructive", "detection": "deterministic", "state": "pending",
                "requires_approval": True,
                "plan": "按 ARTEX finding 定位协议解析函数，生成定向 campaign 真机验证",
                "evidence": [{"artex_finding": f["id"]}],
                "ts": track["ts"]})
            existing.add(hid)
    F.save(args.findings, data)
    print(json.dumps({"ok": True, "task": track["status"],
                      "components": len(track["components"]),
                      "findings": len(track["findings"]),
                      "decompile_functions": len(functions),
                      "findings_path": args.findings}, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- campaign
def focus_functions(track):
    """从反编译函数清单挑解析类候选。"""
    out = []
    for fn in track.get("decompile_functions", []):
        name = str(fn.get("name") or "").lower()
        if any(k in name for k in FOCUS_HINTS):
            out.append(fn)
    return out[:20]


def cmd_campaign(args, client):
    data = F.load(args.findings)
    track = ((data.get("vuln_surface") or {}).get("firmware_track") or {}).get("pull")
    if not track:
        print("error: findings 里没有 firmware_track.pull（先跑 pull）", file=sys.stderr)
        return 1
    focus = focus_functions(track)
    # 协议侧种子：findings 的 probes 请求帧优先，其次 frame_formats 魔数首帧；
    # 都没有时退回最小种子（由 --seed-hex 提供或空）。
    seeds = []
    for pr in data.get("probes", [])[:3]:
        req = str(pr.get("request") or "")
        hexs = req.replace(" ", "").replace(":", "")
        try:
            bytes.fromhex(hexs)
        except ValueError:
            continue
        if hexs:
            seeds.append({"hex": hexs, "fields": []})
    if not seeds and args.seed_hex:
        seeds.append({"hex": args.seed_hex.replace(" ", ""), "fields": []})
    if not seeds:
        print("error: 没有可用种子（findings.probes 或 --seed-hex）", file=sys.stderr)
        return 1
    campaign = {
        "id": f"artex-{track['task_id']}-targeted",
        "mode": "fuzz", "risk": "destructive",
        "target": {"host": args.host, "port": args.port, "timeout_ms": 2000},
        "session": {"prefix": []},
        "seeds": seeds,
        "fuzz": {"mutate_fields": [], "ops": ["boundary", "bitflip", "arith", "repeat",
                                              "truncate", "longpad"]},
        "budget": {"max_packets": 200, "rate_per_sec": 1.0,
                   "max_duration_sec": 600, "no_reply_break": 8},
        "blacklist": [],
        "guardian": {"enabled": True},
        "approval": {"id": None},
        "notes": "ARTEX 固件轨定向 campaign：" +
                 (f"焦点函数 {', '.join(f['name'] for f in focus)}"
                  if focus else "无反编译焦点（全字段变异）") +
                 "。执行前需平台审批并填 approval.id。",
    }
    # 种子里的字段变异目标：把种子 hex 的长度位交给算子（若知道结构可加 fields）
    out = Path(args.out or Path(args.findings).parent /
               f"campaigns/artex-{track['task_id']}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(campaign, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "campaign": str(out), "seeds": len(seeds),
                      "focus_functions": [f["name"] for f in focus][:8],
                      "risk": "destructive（执行需审批）"}, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="ARTEX-IOT 固件轨 API 桥")
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api-base", default=DEFAULT_API)
    common.add_argument("--key-file", default=DEFAULT_KEY)
    common.add_argument("--token", default=None)

    p1 = sub.add_parser("handoff", parents=[common])
    p1.add_argument("--findings", required=True)
    p1.add_argument("--firmware", required=True)
    p1.add_argument("--vendor", default="")
    p1.add_argument("--product", default="")
    p1.add_argument("--version", default="")
    p1.add_argument("--out", default=None)

    p2 = sub.add_parser("pull", parents=[common])
    p2.add_argument("--task", required=True)
    p2.add_argument("--findings", required=True)
    p2.add_argument("--sha", default=None, help="任务未带固件 sha 时手工指定")

    p3 = sub.add_parser("campaign", parents=[common])
    p3.add_argument("--task", default=None, help="仅用于校验；实际取 findings 的 pull")
    p3.add_argument("--findings", required=True)
    p3.add_argument("--host", required=True)
    p3.add_argument("--port", type=int, default=502)
    p3.add_argument("--seed-hex", default=None)
    p3.add_argument("--out", default=None)

    args = ap.parse_args()
    token = args.token
    if not token:
        key = Path(args.key_file).read_bytes().strip()
        token = mint_service_token(key)
    client = ArtexClient(args.api_base, token, timeout=120)

    if args.cmd == "handoff":
        return cmd_handoff(args, client)
    if args.cmd == "pull":
        return cmd_pull(args, client)
    return cmd_campaign(args, client)


if __name__ == "__main__":
    sys.exit(main())
