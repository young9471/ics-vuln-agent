#!/usr/bin/env python3
"""ICSsploit 载荷知识库导入：把 PLC 利用框架的模块解析为 vuln_knowledge 条目。

载荷 = 带真实协议帧的已验证利用原语，是 P7 直判与 P9 EXP 生成的高价值先验。
AST 静态解析（不执行框架代码）：__info__（设备/描述/参考）、Option 端口、
bytearray.fromhex 硬编码帧。scanners 是侦察工具不是漏洞，不入库。

用法：
  python icssploit_import.py --framework <icssploit-master 目录> [--execute]
      [--psql <psql.exe>] [--pg host:port:db:user]
条目 cve_id 用稳定伪 id "ICSSPLOIT:<模块路径>"（非 CVE，是载荷引用），
真实帧/端口/选项存 refs JSONB；source='icssploit' 与 CVE 源区分。
"""
import argparse
import ast
import datetime
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_PSQL = r"C:\科研\114项目\protocol-agent\runtime\pgsql\bin\psql.exe"
DEFAULT_PG = "127.0.0.1:5433:protocol_platform:pagent"

# 模块路径/名称 → (vendor, protocol)
VENDOR_PROTO = {
    "siemens": ("siemens", "s7comm"),
    "schneider": ("schneider-electric", "modbus"),
    "qnx": ("qnx", "qconn"),
    "vxworks": ("vxworks", "rpc"),
    "advantech": ("advantech", ""),
}
CREDS_PROTO = {
    "ftp": "ftp", "http": "http", "snmp": "snmp", "ssh": "ssh",
    "telnet": "telnet", "s7": "s7comm",
}


def classify(name, desc, kind, path):
    """→ (vclass, risk)。载荷语义映射到 14 类。"""
    text = (name + " " + desc + " " + path).lower()
    if kind == "creds":
        return 2, "read"                      # 默认/弱凭据与暴破 → 协议认证
    if any(k in text for k in ("start/stop", "plc control", "stop plc", "start plc",
                               "reset plc", "cpu control", "start/stop/reset")):
        return 3, "destructive"               # 远程启停
    if any(k in text for k in ("crash", "dos", "denial", "kill", "inetd")):
        return 7, "destructive"               # 拒绝服务
    if any(k in text for k in ("remote_exec", "qconn", "backdoor", "exec")):
        return 8, "destructive"               # 调试后门/远程执行 → 固件与组件
    if any(k in text for k in ("set_ip", "profinet", "dcp")):
        return 12, "write"                    # 发现/配置协议滥用
    return 9, "write"                         # 其余次要攻击面


def lit(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def parse_module(py_path, modules_root):
    rel = py_path.relative_to(modules_root).as_posix()
    parts = rel.split("/")
    kind = parts[0]                            # exploits / creds / scanners
    if kind == "scanners" or py_path.name == "__init__.py":
        return None
    tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"))
    info, options, frames = {}, {}, {}
    for node in ast.walk(tree):
        # __info__ = {...}
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "__info__":
                    v = lit(node.value)
                    if isinstance(v, dict):
                        info = v
                # name = bytearray.fromhex('...')  /  name = Exploit.Option(...)
                if isinstance(t, ast.Name):
                    if isinstance(node.value, ast.Call):
                        f = node.value.func
                        fname = ""
                        if isinstance(f, ast.Attribute):
                            fname = f.attr
                        if fname == "fromhex" and node.value.args:
                            hx = lit(node.value.args[0])
                            if isinstance(hx, str) and re.fullmatch(r"[0-9a-fA-F]+", hx or ""):
                                frames[t.id] = hx.lower()
                        elif fname == "Option" and node.value.args:
                            default = lit(node.value.args[0])
                            options[t.id] = default
    if not info:
        return None
    name = str(info.get("name", py_path.stem))
    desc = str(info.get("description", ""))
    devices = info.get("devices") or []
    product = str(devices[0]) if devices else ""
    # vendor/protocol：优先路径，其次 creds 名
    vendor = proto = ""
    for key, (v, p) in VENDOR_PROTO.items():
        if key in rel.lower():
            vendor, proto = v, p
            break
    if kind == "creds":
        for key, p in CREDS_PROTO.items():
            if py_path.stem.startswith(key):
                proto = p
                break
    if "s7comm_plus" in rel:
        proto = "s7comm+"
    if "profinet" in rel or "profinet" in name.lower():
        proto = "profinet-dcp"
    port = options.get("port")
    if not isinstance(port, int):
        port = None
    vclass, risk = classify(name, desc, kind, rel)
    return {
        "cve_id": "ICSSPLOIT:" + rel[:-3],
        "source": "icssploit",
        "vclass": vclass,
        "vendor": vendor,
        "product": product[:200],
        "protocol": proto,
        "summary": (name + " — " + desc)[:400],
        "refs": {
            "module": rel, "kind": kind, "risk": risk, "port": port,
            "frames": frames, "options": {k: v for k, v in options.items()
                                          if isinstance(v, (int, str, bool))},
            "references": [r for r in (info.get("references") or []) if r],
            "authors": info.get("authors") or [],
        },
        "confidence": "high",
        "class_basis": "icssploit-module",
    }


def q(s):
    if s is None:
        return "NULL"
    return "'" + str(s).replace("\\", "\\\\").replace("'", "''") + "'"


def upsert_sql(item):
    refs = json.dumps(item["refs"], ensure_ascii=False)
    return (
        "INSERT INTO vuln_knowledge(cve_id, source, vclass, vendor, product, protocol, "
        "summary, refs, confidence, class_basis) VALUES ("
        f"{q(item['cve_id'])}, {q(item['source'])}, {item['vclass']}, {q(item['vendor'])}, "
        f"{q(item['product'])}, {q(item['protocol'])}, {q(item['summary'])}, "
        f"{q(refs)}::jsonb, {q(item['confidence'])}, {q(item['class_basis'])}) "
        "ON CONFLICT (cve_id, source) DO UPDATE SET vclass=EXCLUDED.vclass, "
        "vendor=EXCLUDED.vendor, product=EXCLUDED.product, protocol=EXCLUDED.protocol, "
        "summary=EXCLUDED.summary, refs=EXCLUDED.refs, confidence=EXCLUDED.confidence, "
        "class_basis=EXCLUDED.class_basis;"
    )


def main():
    ap = argparse.ArgumentParser(description="ICSsploit 载荷 → vuln_knowledge")
    ap.add_argument("--framework", required=True, help="icssploit-master 目录")
    ap.add_argument("--execute", action="store_true", help="生成后经 psql 入库")
    ap.add_argument("--out", default=None)
    ap.add_argument("--psql", default=DEFAULT_PSQL)
    ap.add_argument("--pg", default=DEFAULT_PG)
    args = ap.parse_args()
    root = Path(args.framework)
    modules = root / "icssploit" / "modules"
    if not modules.exists():
        print(f"error: {modules} 不存在", file=sys.stderr)
        return 1
    items, skipped = [], 0
    for py in sorted(modules.rglob("*.py")):
        try:
            it = parse_module(py, modules)
        except SyntaxError as e:
            print(f"skip(parse) {py.name}: {e}", file=sys.stderr)
            skipped += 1
            continue
        if it:
            items.append(it)
        else:
            skipped += 1
    out_path = args.out or str(Path(tempfile.gettempdir()) /
                               f"icssploit_kb_{datetime.datetime.now():%Y%m%d_%H%M%S}.sql")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("-- ICSsploit payload knowledge import (idempotent upsert)\n")
        for it in items:
            fh.write(upsert_sql(it) + "\n")
    print(json.dumps({"parsed": len(items), "skipped": skipped, "sql": out_path},
                     ensure_ascii=False))
    if args.execute:
        host, port, db, user = args.pg.split(":")
        import os
        env = dict(os.environ)
        env["PGPASSWORD"] = env.get("PGPASSWORD", "pagent")
        r = subprocess.run([args.psql, "-h", host, "-p", port, "-U", user, "-d", db,
                            "-f", out_path], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env=env)
        if r.returncode != 0:
            print(r.stderr[:800], file=sys.stderr)
            return 1
        print("executed OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
