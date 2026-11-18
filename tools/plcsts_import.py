#!/usr/bin/env python3
"""plcsts 设备专属载荷知识库导入（用户自研 PLC 攻击框架，按厂商/型号组织）。

与 icssploit_import 同源框架（__info__ + exploits.Option），但载荷多为 hex
字符串赋值 / binascii.a2b_hex，且目录直接给出厂商/型号/类别。覆盖约 25 家
厂商（含全部五基准设备 + 和利时/海为/四方/南大傲拓/DCCE 等国产）。

只导入 attacking / cleaning / spreading（漏洞利用原语）；scanning 是侦察、
persistence 是恶意代码，不进漏洞知识库。AST 静态解析，不执行框架代码。

用法：
  python plcsts_import.py --modules <plcsts/modules 目录> [--execute]
"""
import argparse
import ast
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from icssploit_import import q, upsert_sql  # noqa: E402  复用 SQL 生成

DEFAULT_PSQL = r"C:\科研\114项目\protocol-agent\runtime\pgsql\bin\psql.exe"
DEFAULT_PG = "127.0.0.1:5433:protocol_platform:pagent"

VENDOR_MAP = {
    "schneider": "schneider-electric", "siemens": "siemens", "rockwell": "rockwellautomation",
    "nandaauto": "nandaauto", "nadaauto": "nandaauto", "wago": "wago",
    "mitsubishi": "mitsubishielectric", "sanling": "mitsubishielectric", "omron": "omron",
    "ge": "ge", "hollysys": "hollysys", "haiwell": "haiwell", "sifang": "sifang",
    "dcce": "dcce", "abb": "abb", "beckhoff": "beckhoff", "moxa": "moxa",
    "phoenix": "phoenixcontact", "tenkong": "tenkong", "uwin": "uwin", "xinjie": "xinjie",
}
VENDOR_PROTO = {
    "schneider-electric": "modbus", "siemens": "s7comm", "rockwellautomation": "enip",
    "mitsubishielectric": "melsec", "omron": "fins", "ge": "srtp", "wago": "modbus",
    "abb": "modbus", "beckhoff": "ads", "phoenixcontact": "pcworx",
}
IMPORT_CATEGORIES = {"attacking", "cleaning", "spreading"}


def classify(filename, category):
    """→ (vclass, risk)。按文件名关键词 + 类别映射 14 类。"""
    f = filename.lower()
    if "dos" in f:
        return 7, "destructive"
    if any(k in f for k in ("start_stop", "start_and_stop", "cpu_control", "reboot",
                            "restart", "remote_control", "cpu_start")):
        return 3, "destructive"
    if any(k in f for k in ("wipe_memory", "memory_destruction", "write_mem", "read_mem",
                            "read_and_write", "read_write")):
        return 4, "destructive"
    if any(k in f for k in ("set_io", "write_io", "set_io", "read_write_io", "io_value",
                            "force_cpu", "clear_cpu_fault")):
        return 13, "write"
    if any(k in f for k in ("modify_program", "overwrite_program", "upload_program",
                            "clear_program", "delete_progrom", "delete_program", "clear_db",
                            "clear_ob", "clear_sdb", "clear_all", "get_program", "modify_program",
                            "clear_conf", "delete_cfg", "delete_log", "trace_clear")):
        return 5, "destructive"
    if any(k in f for k in ("modify_ip", "set_ip")):
        return 12, "write"
    if any(k in f for k in ("password_blasting", "read_ftp_username", "read_password")):
        return 2, "read"
    if "password" in f:
        return 6, "write"
    if any(k in f for k in ("get_info", "read_plc_type", "get_cpu_info")):
        return 1, "read"
    if any(k in f for k in ("_sh", "rce")):
        return 8, "destructive"
    if category == "spreading" and "default" in f:
        return 2, "read"
    if category == "cleaning":
        return 5, "destructive"
    return 9, "write"


def is_hex(s):
    return isinstance(s, str) and len(s) >= 8 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s)


def lit(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def parse_module(py_path, modules_root):
    rel = py_path.relative_to(modules_root).as_posix()
    parts = rel.split("/")
    category = parts[0]
    if category not in IMPORT_CATEGORIES or py_path.name == "__init__.py":
        return None
    if py_path.name == "template.py":
        return None
    tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"))
    info, options, frames = {}, {}, {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if not isinstance(t, ast.Name):
                continue
            if t.id == "__info__":
                v = lit(node.value)
                if isinstance(v, dict):
                    info = v
                continue
            val = node.value
            # name = "hexstring"
            if isinstance(val, ast.Constant) and is_hex(val.value):
                frames[t.id] = val.value.lower()
            # name = bytearray.fromhex / binascii.a2b_hex / unhexlify("...")
            elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                if val.func.attr in ("fromhex", "a2b_hex", "unhexlify") and val.args:
                    hx = lit(val.args[0])
                    if is_hex(hx):
                        frames[t.id] = hx.lower()
                elif val.func.attr == "Option" and val.args:
                    options[t.id] = lit(val.args[0])
    # 厂商/型号取自路径段
    vendor = model = ""
    for seg in parts[1:]:
        low = seg.lower()
        if low in VENDOR_MAP and not vendor:
            vendor = VENDOR_MAP[low]
        elif vendor and not model and seg not in ("__init__.py",):
            if not seg.endswith(".py"):
                model = seg
    if not vendor:
        # 文件名前缀兜底（如 schneider_TM221...）
        for key, v in VENDOR_MAP.items():
            if py_path.stem.lower().startswith(key):
                vendor = v
                break
    if not model:
        m = re.search(r"(TM\d+\w+|S7\d+\w*|Micro\d+|micrologix_?\d+|NA\d+|MAC\d+|CSC\d+|"
                      r"LE\d+\w*|LK\d+|CP\d+\w*|CS\d+\w*|Q\d+\w*|R\d+|PM\d+|750[-_]?\d+|"
                      r"C\d+S\d+\w*|T\d+S\d+\w*|UW\d+|T920|RX3i|CK\d+)", rel, re.I)
        if m:
            model = m.group(1)
    name = str(info.get("name", py_path.stem))
    desc = str(info.get("description", ""))
    devices = info.get("devices") or []
    product = (str(devices[0]) if devices else (vendor + " " + model)).strip()[:200]
    port = options.get("port")
    if not isinstance(port, int):
        port = None
    proto = VENDOR_PROTO.get(vendor, "")
    vclass, risk = classify(py_path.stem, category)
    return {
        "cve_id": "PLCSTS:" + rel[:-3],
        "source": "plcsts",
        "vclass": vclass,
        "vendor": vendor,
        "product": product,
        "protocol": proto,
        "summary": (name + " — " + desc)[:400] if desc else name[:400],
        "refs": {
            "module": rel, "category": category, "vendor": vendor, "model": model,
            "risk": risk, "port": port, "frames": frames,
            "options": {k: v for k, v in options.items() if isinstance(v, (int, str, bool))},
            "references": [r for r in (info.get("references") or []) if r],
        },
        "confidence": "high",
        "class_basis": "plcsts-module",
    }


def main():
    ap = argparse.ArgumentParser(description="plcsts 设备载荷 → vuln_knowledge")
    ap.add_argument("--modules", required=True, help="plcsts/modules 目录")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--psql", default=DEFAULT_PSQL)
    ap.add_argument("--pg", default=DEFAULT_PG)
    args = ap.parse_args()
    root = Path(args.modules)
    if not root.exists():
        print(f"error: {root} 不存在", file=sys.stderr)
        return 1
    items, skipped = [], 0
    for py in sorted(root.rglob("*.py")):
        try:
            it = parse_module(py, root)
        except SyntaxError as e:
            print(f"skip(parse) {py.name}: {e}", file=sys.stderr)
            skipped += 1
            continue
        if it:
            items.append(it)
        else:
            skipped += 1
    out_path = args.out or str(Path(tempfile.gettempdir()) /
                               f"plcsts_kb_{datetime.datetime.now():%Y%m%d_%H%M%S}.sql")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("-- plcsts device payload knowledge import (idempotent upsert)\n")
        for it in items:
            fh.write(upsert_sql(it) + "\n")
    # 统计
    by_vendor, by_class = {}, {}
    for it in items:
        by_vendor[it["vendor"] or "?"] = by_vendor.get(it["vendor"] or "?", 0) + 1
        by_class[it["vclass"]] = by_class.get(it["vclass"], 0) + 1
    print(json.dumps({"parsed": len(items), "skipped": skipped,
                      "by_vendor": by_vendor, "by_vclass": by_class, "sql": out_path},
                     ensure_ascii=False))
    if args.execute:
        host, port, dbn, user = args.pg.split(":")
        env = dict(os.environ)
        env["PGPASSWORD"] = env.get("PGPASSWORD", "pagent")
        r = subprocess.run([args.psql, "-h", host, "-p", port, "-U", user, "-d", dbn,
                            "-f", out_path], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env=env)
        if r.returncode != 0:
            print(r.stderr[:800], file=sys.stderr)
            return 1
        print("executed OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
