#!/usr/bin/env python3
"""P9 EXP 工程：把 confirmed 假设编译成独立参数化复现脚本（PLAN-V2 §5）。

三级产物：replay（确定性回放）默认 / poc（--tier poc，同 replay，参数化说明更全）/
chain（多阶段，frames 按 stages 组织）。

输入：findings.json 中 state=confirmed 的 vuln_hypotheses（evidence 里带 frames 数组，
P7 verify / P8 campaign 在落库时写入），或 --frames-json 显式给帧。

输出：<outdir>/<假设id>.py 独立脚本 + findings.exploit_assets 登记。
生成的脚本零依赖（纯标准库），带授权声明横幅与目标参数。
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F                     # noqa: E402

SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""EXP: {title}  [{tier}]

假设: {hid}  模板: {tid}  风险级: {risk}  生成: {ts}
判定规则: {verdict}

!! 仅用于授权测试环境与科研目的。运行前确认目标在实验室隔离网段内。
!! {risk_note}
用法: python {fname}.py --target 192.168.x.x [--port {port}] [--dry-run]
"""
import argparse
import json
import socket
import sys
import time

FRAMES = {frames}
EXPECT = {expect}
PREFIX = {prefix}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, default={port})
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dry_run:
        for i, f in enumerate(FRAMES):
            print(f"[dry] frame{{i}} {{len(bytes.fromhex(f))}}B: {{f[:60]}}")
        return 0
    results = []
    for i, hexf in enumerate(FRAMES):
        frame = bytes.fromhex(hexf)
        try:
            with socket.create_connection((args.target, args.port), timeout=args.timeout) as s:
                for p in PREFIX:
                    s.sendall(bytes.fromhex(p))
                    try:
                        s.recv(65535)
                    except OSError:
                        pass
                s.settimeout(args.timeout)
                s.sendall(frame)
                resp = s.recv(65535)
            ok, why = expect_ok(resp, EXPECT)
            results.append({{"i": i, "resp_len": len(resp), "resp_hex": resp[:96].hex(),
                             "verdict": "executed" if ok else ("rejected" if why == "reject" else "claimed")}})
        except OSError as exc:
            results.append({{"i": i, "verdict": "no_response", "error": str(exc)}})
        time.sleep(0.5)
    print(json.dumps({{"exp": "{hid}", "target": args.target, "results": results,
                       "confirmed": all(r.get("verdict") == "executed" for r in results)}},
                     ensure_ascii=False, indent=2))
    return 0 if all(r.get("verdict") == "executed" for r in results) else 1


def expect_ok(resp, expect):
    if not expect:
        return bool(resp), ""
    if expect.get("reject_hex") and any(bytes.fromhex(r) in resp for r in expect["reject_hex"]):
        return False, "reject"
    if expect.get("contains_hex") and bytes.fromhex(expect["contains_hex"]) not in resp:
        return False, "missing"
    if expect.get("min_bytes") and len(resp) < expect["min_bytes"]:
        return False, "short"
    return True, ""


if __name__ == "__main__":
    sys.exit(main())
'''

RISK_NOTES = {
    "read": "只读操作：读取设备信息/内存。",
    "write": "写操作：仅作用于实验室标记区，可能影响设备状态。",
    "destructive": "破坏性操作：可能停机/改变控制逻辑/触发重启，必须有人值守并准备恢复。",
}


def gen_script(hyp, tier, outdir, default_port):
    frames = []
    for ev in hyp.get("evidence", []):
        if isinstance(ev, dict) and ev.get("frames"):
            frames.extend(ev["frames"])
        elif isinstance(ev, str) and ev.startswith("frame:"):
            frames.append(ev.split("frame:", 1)[1].replace(" ", ""))
    if not frames:
        return None, "evidence 中没有可回放帧（需要 P7/P8 落库时附带 frames）"
    expect = {}
    for ev in hyp.get("evidence", []):
        if isinstance(ev, dict) and ev.get("expect"):
            expect = ev["expect"]
            break
    prefix = []
    for ev in hyp.get("evidence", []):
        if isinstance(ev, dict) and ev.get("prefix_frames"):
            prefix = ev["prefix_frames"]
            break
    fname = f"{hyp['id']}.py"
    body = SCRIPT_TEMPLATE.format(
        title=hyp.get("name", hyp["id"]), tier=tier, hid=hyp["id"],
        tid=hyp.get("template_id", "-"), risk=hyp.get("risk", "?"),
        ts=datetime.datetime.now().isoformat(timespec="seconds"),
        verdict=hyp.get("verdict_rule", "-"), risk_note=RISK_NOTES.get(hyp.get("risk"), ""),
        frames=json.dumps(frames, ensure_ascii=False), expect=json.dumps(expect),
        prefix=json.dumps(prefix), port=default_port, fname=hyp["id"],
    )
    path = Path(outdir) / fname
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path, None


def main():
    ap = argparse.ArgumentParser(description="EXP 生成器（P9）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--hypothesis", default=None, help="假设 id（H-V..），缺省处理全部 confirmed")
    ap.add_argument("--tier", choices=("replay", "poc", "chain"), default="replay")
    ap.add_argument("--outdir", default=None, help="缺省 <findings 目录>/exploits")
    ap.add_argument("--port", type=int, default=502)
    args = ap.parse_args()

    data = F.load(args.findings)
    outdir = args.outdir or str(Path(args.findings).parent / "exploits")
    hyps = [h for h in data.get("vuln_hypotheses", [])
            if h.get("state") == "confirmed" and
            (args.hypothesis in (None, h["id"]))]
    if not hyps:
        print("error: 没有 state=confirmed 的假设（或指定 id 不存在）", file=sys.stderr)
        return 1
    generated = []
    for hyp in hyps:
        path, err = gen_script(hyp, args.tier, outdir, args.port)
        if err:
            generated.append({"id": hyp["id"], "error": err})
            continue
        sha = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        asset = {"id": f"EXP-{hyp['id']}", "hypothesis": hyp["id"],
                 "tier": args.tier, "path": str(path), "sha256_16": sha,
                 "risk": hyp.get("risk"), "ts": datetime.datetime.now().isoformat(timespec="seconds")}
        data.setdefault("exploit_assets", [])
        if not any(a["id"] == asset["id"] for a in data["exploit_assets"]):
            data["exploit_assets"].append(asset)
        generated.append({"id": hyp["id"], "script": str(path), "sha256_16": sha})
    F.save(args.findings, data)
    print(json.dumps({"generated": generated, "outdir": outdir}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
