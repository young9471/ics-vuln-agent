#!/usr/bin/env python3
"""载荷脱框架：把 KB 里的 plcsts/icssploit 载荷转成零依赖独立 EXP 脚本。

原模块依赖 `from plcsts import exploits, ...` 框架运行时；本工具抽取其
硬编码协议帧，编译成纯标准库脚本（argparse + socket），存入智能体 EXP 库
platform/data/exp_library/<source>/<vendor>/<slug>.py，并把独立脚本路径与
sha16 回写 vuln_knowledge.refs（standalone / standalone_sha16）。

脚本特性：--target/--port/--timeout/--dry-run/--list；命名帧用 --frame 选择
（如 stop_payload），--all 顺序发全部。不 import 任何原框架代码。

用法：
  python payload_to_exp.py [--execute] [--source plcsts|icssploit|all]
      [--psql ...] [--pg host:port:db:user] [--out-dir <exp_library>]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PSQL = str(ROOT / "runtime" / "pgsql" / "bin" / "psql.exe")
DEFAULT_PG = "127.0.0.1:5433:protocol_platform:pagent"
DEFAULT_OUT = ROOT / "platform" / "data" / "exp_library"

RISK_NOTES = {
    "read": "只读操作：读取设备信息/内存。",
    "write": "写操作：仅作用于实验室标记区，可能影响设备状态。",
    "destructive": "破坏性操作：可能停机/改变控制逻辑/触发重启，必须有人值守并准备恢复。",
}

TEMPLATE = '''#!/usr/bin/env python3
"""EXP: {title}  [{source}]

厂商/型号: {vendor} {model}  协议: {proto}  风险级: {risk}
来源载荷: {module}  脱框架生成: {ts}  sha16: {sha}

!! 仅用于授权测试环境与科研目的。运行前确认目标在实验室隔离网段内。
!! {risk_note}
!! 本脚本零依赖（纯标准库），不依赖原 ICSsploit/plcsts 框架。
用法:
  python {fname}.py --target 192.168.x.x [--port {port}] --list
  python {fname}.py --target 192.168.x.x --frame {first_frame} [--dry-run]
  python {fname}.py --target 192.168.x.x --all
"""
import argparse
import json
import socket
import sys
import time

# 命名协议帧（从原载荷硬编码帧抽取）
FRAMES = {frames}
PORT = {port}


def send_frame(target, port, name, hexf, timeout):
    frame = bytes.fromhex(hexf)
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(frame)
            try:
                resp = s.recv(65535)
            except OSError:
                resp = b""
        return {{"frame": name, "sent_bytes": len(frame), "resp_len": len(resp),
                 "resp_hex": resp[:128].hex(), "verdict": "executed" if resp else "no_response"}}
    except OSError as exc:
        return {{"frame": name, "verdict": "error", "error": str(exc)}}


def main():
    ap = argparse.ArgumentParser(description="Standalone EXP (framework-free)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--frame", default=None, help="要发送的命名帧（缺省第一个）")
    ap.add_argument("--all", action="store_true", help="顺序发送全部帧")
    ap.add_argument("--list", action="store_true", help="列出可用帧")
    ap.add_argument("--dry-run", action="store_true", help="只打印不发包")
    args = ap.parse_args()

    if args.list:
        for name, hexf in FRAMES.items():
            print(f"{{name}}: {{len(bytes.fromhex(hexf))}}B  {{hexf[:60]}}")
        return 0

    names = list(FRAMES.keys())
    if args.all:
        selected = names
    else:
        pick = args.frame or names[0]
        if pick not in FRAMES:
            print(f"unknown frame: {{pick}}; available: {{', '.join(names)}}", file=sys.stderr)
            return 2
        selected = [pick]

    if args.dry_run:
        for n in selected:
            print(f"[dry] {{n}} {{len(bytes.fromhex(FRAMES[n]))}}B: {{FRAMES[n][:60]}}")
        return 0

    results = []
    for n in selected:
        results.append(send_frame(args.target, args.port, n, FRAMES[n], args.timeout))
        time.sleep(0.5)
    print(json.dumps({{"exp": "{fname}", "target": args.target, "risk": "{risk}",
                       "results": results}}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def slug(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_") or "payload"


def fetch_payloads(psql, pg, source):
    host, port, dbn, user = pg.split(":")
    cond = "source IN ('plcsts','icssploit')" if source == "all" else f"source = '{source}'"
    sql = (f"SELECT coalesce(json_agg(t),'[]'::json) FROM (SELECT id, cve_id, source, "
           f"COALESCE(vendor,'') vendor, COALESCE(protocol,'') protocol, refs "
           f"FROM vuln_knowledge WHERE {cond} AND refs ? 'frames') t")
    env = dict(os.environ)
    env["PGPASSWORD"] = env.get("PGPASSWORD", "pagent")
    r = subprocess.run([psql, "-h", host, "-p", port, "-U", user, "-d", dbn, "-At", "-c", sql],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:400])
    return json.loads(r.stdout.strip() or "[]")


def render(item, sha_placeholder=""):
    refs = item.get("refs") or {}
    frames = refs.get("frames") or {}
    if not frames:
        return None
    risk = refs.get("risk", "write")
    port = refs.get("port") or 502
    if not isinstance(port, int):
        port = 502
    vendor = item.get("vendor") or refs.get("vendor") or ""
    model = refs.get("model") or ""
    module = refs.get("module") or item.get("cve_id", "")
    title = module.split("/")[-1]
    if title.endswith(".py"):
        title = title[:-3]
    fname = slug(title)
    first = next(iter(frames))
    body = TEMPLATE.format(
        title=title, source=item["source"], vendor=vendor, model=model,
        proto=item.get("protocol") or "-", risk=risk, module=module,
        ts=datetime.datetime.now().isoformat(timespec="seconds"), sha=sha_placeholder,
        risk_note=RISK_NOTES.get(risk, ""), fname=fname, port=port,
        first_frame=first, frames=json.dumps(frames, ensure_ascii=False, indent=4),
    )
    return fname, body


def main():
    ap = argparse.ArgumentParser(description="载荷脱框架 → 独立 EXP 脚本")
    ap.add_argument("--execute", action="store_true", help="回写 KB refs（standalone 路径/sha）")
    ap.add_argument("--source", default="all", choices=("all", "plcsts", "icssploit"))
    ap.add_argument("--psql", default=DEFAULT_PSQL)
    ap.add_argument("--pg", default=DEFAULT_PG)
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    out_root = Path(args.out_dir)
    items = fetch_payloads(args.psql, args.pg, args.source)
    generated, skipped, updates = [], 0, []
    for it in items:
        refs = it.get("refs") or {}
        rendered = render(it)
        if not rendered:
            skipped += 1
            continue
        fname, body = rendered
        vendor = slug(it.get("vendor") or refs.get("vendor") or "misc")
        model = slug(refs.get("model") or "")
        sub = Path(it["source"]) / vendor
        if model:
            sub = sub / model
        rel_path = (sub / f"{fname}.py").as_posix()
        abs_path = out_root / rel_path
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(body, encoding="utf-8")
        sha = hashlib.sha256(abs_path.read_bytes()).hexdigest()[:16]
        # 回填真实 sha 到脚本头
        _, body = render(it, sha)
        abs_path.write_text(body, encoding="utf-8")
        sha = hashlib.sha256(abs_path.read_bytes()).hexdigest()[:16]
        generated.append({"id": it["id"], "cve_id": it["cve_id"], "path": rel_path, "sha16": sha})
        updates.append((it["id"], rel_path, sha))
    print(json.dumps({"generated": len(generated), "skipped": skipped,
                      "out_dir": str(out_root)}, ensure_ascii=False))
    if args.execute and updates:
        host, port, dbn, user = args.pg.split(":")
        sqls = []
        for kid, rel_path, sha in updates:
            patch = json.dumps({"standalone": rel_path, "standalone_sha16": sha}, ensure_ascii=False)
            sqls.append(f"UPDATE vuln_knowledge SET refs = refs || '{patch}'::jsonb WHERE id = {kid};")
        tmp = Path(tempfile.gettempdir()) / f"exp_lib_{datetime.datetime.now():%H%M%S%f}.sql"
        tmp.write_text("\n".join(sqls), encoding="utf-8")
        env = dict(os.environ)
        env["PGPASSWORD"] = env.get("PGPASSWORD", "pagent")
        r = subprocess.run([args.psql, "-h", host, "-p", port, "-U", user, "-d", dbn, "-f", str(tmp)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
        tmp.unlink(missing_ok=True)
        if r.returncode != 0:
            print(r.stderr[:400], file=sys.stderr)
            return 1
        print("KB refs updated OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
