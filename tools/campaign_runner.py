#!/usr/bin/env python3
"""P8 campaign 执行引擎：verify（确定性验证）与 fuzz（灰盒变异）两种模式。

设计（PLAN-V2 §4/§3.8）：
- 种子为 probe_dsl request 字典（hex 模板 + fields 覆写 + checksum 自动重算），
  变异 = 修改 fields[].value / 结构操作，校验和始终修复，保证畸形帧"能到达解析器"。
- 响应分类器：把每个响应归入有限状态类；新类 = 新解析深度 = 伪覆盖率信号。
- 调度：字段×算子的 UCB1 多臂老虎机，reward = 新响应类(1.0)/reset 类(3.0)。
- 安全：黑名单静态校验（载入即拒绝）、速率预算、无响应熔断、Guardian 子进程监护、
  destructive 必须携带审批（平台 API 校验或显式离线批准）。

退出码：0 正常 / 2 Guardian 红线 / 4 黑名单拒绝 / 5 缺审批 / 6 预算耗尽未完成（信息性）
"""
import argparse
import datetime
import itertools
import json
import math
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import probe_dsl as PD                     # noqa: E402

FORBIDDEN_FIELD_NAMES = ("flash", "firmware", "update", "factory", "boot")
BOUNDARY_VALUES = (0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
                   0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)
EXIT_REDLINE, EXIT_BLACKLIST, EXIT_NO_APPROVAL, EXIT_BUDGET = 2, 4, 5, 6


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------- 黑名单与审批
def frame_hex(frame: bytes) -> str:
    return frame.hex()


def blacklist_violation(frames, blacklist):
    """blacklist 为 hex 片段列表（子串匹配）。返回命中的片段。"""
    hits = []
    for f in frames:
        h = f.hex()
        for pat in blacklist:
            p = pat.replace(" ", "").replace(":", "").lower()
            if p and p in h:
                hits.append(pat)
    return hits


def check_approval(camp, api_base, api_token, i_approve):
    """destructive campaign 的硬闸：平台审批 API 或显式离线批准，二选一。"""
    if camp.get("risk") != "destructive":
        return True, ""
    approval = camp.get("approval") or {}
    if api_base and approval.get("id"):
        import urllib.request
        url = f"{api_base.rstrip('/')}/api/protocol/approvals/{int(approval['id'])}"
        req = urllib.request.Request(url)
        if api_token:
            req.add_header("Authorization", f"Bearer {api_token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                st = json.loads(r.read().decode("utf-8", "replace")).get("status")
            if st == "approved":
                return True, ""
            return False, f"approval #{approval['id']} status={st}"
        except Exception as exc:
            return False, f"approval check failed: {exc}"
    if i_approve and i_approve.startswith("APPROVED:"):
        return True, f"offline approval: {i_approve}"
    return False, "destructive campaign 需要审批（--api-base + approval.id，或 --i-approve 'APPROVED:<操作者>:<说明>'）"


# ---------------------------------------------------------------- 变异算子
def field_size(req, name):
    for f in req.get("fields", []) or []:
        if f.get("name") == name:
            return int(f.get("size", 1)), int(f.get("offset", 0))
    return None, None


def base_value(req, name):
    for f in req.get("fields", []) or []:
        if f.get("name") == name:
            return int(f.get("value", 0))
    return 0


def make_mutated(req, name, value):
    """返回修改了字段 value 的 request 深拷贝（checksum 由 build_request 修复）。"""
    import copy
    out = copy.deepcopy(req)
    for f in out.get("fields", []) or []:
        if f.get("name") == name:
            f["value"] = int(value)
    return out


def make_structural(req, op):
    import copy
    out = copy.deepcopy(req)
    h = (out.get("hex") or "").replace(" ", "")
    raw = bytes.fromhex(h) if h else b""
    if op == "repeat":
        raw = raw + raw
    elif op == "truncate":
        raw = raw[: max(1, len(raw) // 2)]
    elif op == "longpad":
        raw = raw + b"\x41" * 256
    out["hex"] = raw.hex()
    return out


def op_values(op, size, base, dictionary):
    if op == "boundary":
        return [v for v in BOUNDARY_VALUES if v < (1 << (8 * size))]
    if op == "arith":
        return [base + d for d in (1, -1, 2, -2, 16, -16) if base + d >= 0]
    if op == "bitflip":
        bits = min(8 * size, 16)
        step = max(1, bits // 4)
        return [base ^ (1 << b) for b in range(0, bits, step)]
    if op == "dict":
        return [int(str(d), 0) for d in dictionary][:8]
    return []


# ---------------------------------------------------------------- 响应分类器
def classify(resp, err):
    if err:
        e = err.lower()
        if "refused" in e or "reset" in e or "aborted" in e:
            return "reset"
        if "timed out" in e or "timeout" in e:
            return "timeout"
        return f"net:{e[:24]}"
    if not resp:
        return "empty"
    if len(resp) < 4:
        return f"short{len(resp)}:{resp.hex()}"
    return f"len{len(resp) // 16 * 16}:hdr{resp[:4].hex()}"


# ---------------------------------------------------------------- 会话管理
class Session:
    """TCP 会话：前缀回放 + 断连自动重连。"""

    def __init__(self, target, prefix):
        self.target = target
        self.prefix = prefix or []
        self.sock = None
        self.reconnects = 0

    def connect(self):
        if self.sock is not None:
            return
        self.sock = socket.create_connection(
            (self.target["host"], int(self.target["port"])),
            timeout=float(self.target.get("timeout_ms", 2000)) / 1000)
        for req in self.prefix:
            self.sock.sendall(PD.build_request(req))
            try:
                self.sock.recv(65535)
            except OSError:
                break

    def send(self, frame):
        self.connect()
        timeout = float(self.target.get("timeout_ms", 2000)) / 1000
        self.sock.settimeout(timeout)
        self.sock.sendall(frame)
        try:
            resp = self.sock.recv(65535)
            return resp, ""
        except OSError as exc:
            err = str(exc)
            if "refused" in err.lower() or "reset" in err.lower() or "aborted" in err.lower():
                self.close()                     # 连接已死，下次重连
            return b"", err

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None
        self.reconnects += 1


# ---------------------------------------------------------------- 调度与执行
def run_fuzz(camp, report):
    t = camp["target"]
    seeds = camp.get("seeds") or []
    if not seeds:
        raise SystemExit("fuzz campaign 缺少 seeds")
    fuzz = camp.get("fuzz", {})
    fields = fuzz.get("mutate_fields") or [
        f.get("name") for s in seeds for f in (s.get("fields") or []) if f.get("name")]
    ops = fuzz.get("ops") or ["boundary", "bitflip", "arith", "dict"]
    dictionary = fuzz.get("dictionary") or []
    budget = camp.get("budget", {})
    max_packets = int(budget.get("max_packets", 200))
    rate = float(budget.get("rate_per_sec", 2.0))
    max_dur = float(budget.get("max_duration_sec", 600))
    breaker_n = int(budget.get("no_reply_break", 10))

    # 臂 = (seed_i, field, op) 与结构臂 (seed_i, op)
    arms = []
    for si, seed in enumerate(seeds):
        for f in fields:
            for op in ops:
                arms.append({"kind": "field", "seed": si, "field": f, "op": op,
                             "n": 0, "reward": 0.0, "cursor": 0, "values": None})
        for op in ("repeat", "truncate", "longpad"):
            arms.append({"kind": "struct", "seed": si, "op": op,
                         "n": 0, "reward": 0.0})

    session = Session(t, camp.get("session", {}).get("prefix"))
    classes, hist = {}, {}
    new_classes, crashes = [], []
    consecutive_bad = 0
    t0 = time.monotonic()
    it = 0
    rng = random.Random(1234 + hash(camp.get("id", "")) % 1000)
    try:
        while it < max_packets and time.monotonic() - t0 < max_dur:
            if report.get("_redline"):
                break
            arm = pick_arm(arms, it)
            seed = seeds[arm["seed"]]
            if arm["kind"] == "field":
                if arm["values"] is None:
                    size, _ = field_size(seed, arm["field"])
                    if size is None:
                        arm["n"] += 1
                        continue
                    arm["values"] = op_values(arm["op"], size,
                                              base_value(seed, arm["field"]), dictionary) or [0]
                v = arm["values"][arm["cursor"] % len(arm["values"])]
                arm["cursor"] += 1
                req = make_mutated(seed, arm["field"], v)
            else:
                req = make_structural(seed, arm["op"])
            frame = PD.build_request(req)
            it += 1
            resp, err = session.send(frame)
            cls = classify(resp, err)
            hist[cls] = hist.get(cls, 0) + 1
            reward = 0.05
            if cls not in classes:
                classes[cls] = now()
                new_classes.append({"class": cls, "arm": arm_label(arm), "ts": now(),
                                    "frame": frame_hex(frame), "resp": (resp or b"")[:64].hex()})
                reward = 1.0
            if cls in ("reset", "timeout"):
                reward = 3.0
                consecutive_bad += 1
                crashes.append({"class": cls, "arm": arm_label(arm),
                                "frame": frame_hex(frame), "ts": now(), "repro": None})
            else:
                consecutive_bad = 0
            arm["n"] += 1
            arm["reward"] += reward
            if consecutive_bad >= breaker_n:
                report["circuit_breaker"] = f"连续 {consecutive_bad} 次无响应/复位，熔断停止"
                break
            time.sleep(max(0.0, 1.0 / rate - 0.01))
    finally:
        session.close()
    report["packets_sent"] = it
    report["duration_sec"] = round(time.monotonic() - t0, 1)
    report["response_histogram"] = hist
    report["new_classes"] = new_classes
    report["reconnects"] = session.reconnects
    # 崩溃去重 + 复现 + 最小化（每签名取一个代表）
    report["crashes"] = triage(crashes, t, camp, rate)


def arm_label(arm):
    return f"s{arm['seed']}:{arm['field'] if arm['kind'] == 'field' else ''}{arm['op']}"


def pick_arm(arms, i):
    for a in arms:
        if a["n"] == 0:
            return a
    total = sum(a["n"] for a in arms)
    c = 0.7
    best, score = None, -1
    for a in arms:
        ucb = a["reward"] / a["n"] + c * math.sqrt(math.log(total + 1) / a["n"])
        if ucb > score:
            best, score = a, ucb
    return best


def triage(crashes, target, camp, rate):
    """崩溃去重（arm+class 签名）、复现 ×3、尾部截断最小化。"""
    seen, out = set(), []
    for c in crashes:
        sig = (c["arm"], c["class"])
        if sig in seen:
            continue
        seen.add(sig)
        time.sleep(2.0)                       # 冷却
        ok = 0
        for _ in range(3):
            resp, err = one_shot(target, bytes.fromhex(c["frame"]),
                                 camp.get("session", {}).get("prefix"))
            if classify(resp, err) == c["class"]:
                ok += 1
            time.sleep(max(0.5, 1.0 / rate))
        c["repro"] = f"{ok}/3"
        if ok >= 2:
            c["minimized_hex"] = ddmin(bytes.fromhex(c["frame"]), target,
                                       camp.get("session", {}).get("prefix"), c["class"])
        out.append(c)
    return out


def one_shot(target, frame, prefix):
    s = Session(target, prefix)
    try:
        return s.send(frame)
    finally:
        s.close()


def ddmin(frame, target, prefix, want_class, max_rounds=6):
    """尾部截断式最小化：保住崩溃类的前提下尽量短。"""
    cur = frame
    step = max(1, len(cur) // 4)
    rounds = 0
    while len(cur) > 8 and step >= 1 and rounds < max_rounds:
        cand = cur[: len(cur) - step]
        try:
            resp, err = one_shot(target, cand, prefix)
            if classify(resp, err) == want_class:
                cur = cand
            else:
                step = step // 2
        except OSError:
            break
        rounds += 1
        time.sleep(0.4)
    return cur.hex()


def run_verify(camp, report):
    t = camp["target"]
    items = camp.get("verify") or []
    verdicts = []
    for v in items:
        frame = PD.build_request(v["request"])
        resp, err = one_shot(t, frame, camp.get("session", {}).get("prefix"))
        expect = v.get("expect") or {}
        ok, why = PD.check_expect(resp, expect)
        reject_hex = [x.replace(" ", "").lower() for x in expect.get("reject_hex", [])]
        if err:
            verdict = "no_response"
        elif any(bytes.fromhex(r) in resp for r in reject_hex if r):
            verdict = "rejected"
        elif ok:
            verdict = "confirmed" if expect.get("state_assert") is None else "claimed_only"
        else:
            verdict = "claimed_only" if resp else "no_response"
        verdicts.append({"label": v.get("label", "?"), "verdict": verdict,
                         "expect_fail": why, "resp_hex": (resp or b"")[:96].hex()})
        report.setdefault("verify_verdicts", []).append(verdicts[-1])
        time.sleep(0.5)
    report["packets_sent"] = len(items)
    return verdicts


# ---------------------------------------------------------------- Guardian
def start_guardian(camp, report_dir):
    if not (camp.get("guardian", {}) or {}).get("enabled"):
        return None, None
    out = Path(tempfile.gettempdir()) / f"guardian-{camp.get('id', 'x')}-{int(time.time())}.json"
    budget = float(camp.get("budget", {}).get("max_duration_sec", 600))
    cmd = [sys.executable, str(Path(__file__).parent / "guardian.py"), "watch",
           "--host", camp["target"]["host"], "--duration", str(budget + 30),
           "--interval", "3", "--json-out", str(out)]
    if camp["guardian"].get("community"):
        cmd += ["--community", camp["guardian"]["community"]]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, out


def main():
    ap = argparse.ArgumentParser(description="P8 campaign 执行引擎")
    ap.add_argument("--campaign", required=True, help="campaign JSON 文件")
    ap.add_argument("--report", default=None, help="报告输出 JSON 路径")
    ap.add_argument("--dry-run", action="store_true", help="只做静态校验（黑名单/审批/构造），不发包")
    ap.add_argument("--api-base", default=None, help="平台 API（审批校验）")
    ap.add_argument("--api-token", default=None)
    ap.add_argument("--i-approve", default=None,
                    help="离线审批：'APPROVED:操作者:说明'（destructive 必须）")
    args = ap.parse_args()

    with open(args.campaign, encoding="utf-8") as fh:
        camp = json.load(fh)
    camp.setdefault("id", Path(args.campaign).stem)

    # 静态黑名单：种子/前缀/verify 帧不得命中
    pre_frames = [PD.build_request(r) for r in (camp.get("session", {}) or {}).get("prefix", [])]
    seed_frames = [PD.build_request(r) for r in camp.get("seeds", [])]
    verify_frames = [PD.build_request(v["request"]) for v in camp.get("verify", [])]
    hits = blacklist_violation(pre_frames + seed_frames + verify_frames,
                               camp.get("blacklist", []))
    if hits:
        print(json.dumps({"error": "blacklist", "hits": hits}, ensure_ascii=False))
        return EXIT_BLACKLIST
    # 变异字段名黑名单（flash/firmware/update/factory/boot）
    bad_fields = [f for f in camp.get("fuzz", {}).get("mutate_fields", [])
                  if any(k in f.lower() for k in FORBIDDEN_FIELD_NAMES)]
    if bad_fields and camp.get("risk") == "destructive" and not (args.i_approve or "").startswith("APPROVED"):
        print(json.dumps({"error": "forbidden_mutation_fields", "fields": bad_fields}, ensure_ascii=False))
        return EXIT_BLACKLIST
    ok, why = check_approval(camp, args.api_base, args.api_token, args.i_approve)
    if not ok:
        print(json.dumps({"error": "approval", "detail": why}, ensure_ascii=False))
        return EXIT_NO_APPROVAL

    report = {"campaign_id": camp["id"], "mode": camp.get("mode"), "risk": camp.get("risk"),
              "started": now(), "approval": why or "-", "_redline": False}
    if args.dry_run:
        report["dry_run"] = "static checks passed; frames built"
        report["frames_preview"] = [f.hex()[:80] for f in (pre_frames + seed_frames + verify_frames)[:6]]
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    gproc, gout = start_guardian(camp, None)
    exit_code = 0
    try:
        if camp.get("mode") == "verify":
            run_verify(camp, report)
        else:
            camp.setdefault("mode", "fuzz")
            run_fuzz(camp, report)
    finally:
        report["finished"] = now()
        if gproc is not None:
            gproc.terminate()
            try:
                gproc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gproc.kill()
            if gout and gout.exists():
                try:
                    g = json.loads(gout.read_text(encoding="utf-8"))
                    report["guardian"] = g
                    if g.get("red_line"):
                        report["_redline"] = True
                        exit_code = EXIT_REDLINE
                except ValueError:
                    pass
    report.pop("_redline", None)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
