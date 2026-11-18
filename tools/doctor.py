#!/usr/bin/env python3
"""Check Python dependencies and optional reverse-engineering backends."""
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import analyzer_bundle
except Exception:
    analyzer_bundle = None

def has(mod):
    return importlib.util.find_spec(mod) is not None


def tshark_path():
    candidates = [
        os.environ.get("PROTOCOL_AGENT_TSHARK", ""),
        shutil.which("tshark") or "",
        "C:/Program Files/Wireshark/tshark.exe",
        "C:/Program Files (x86)/Wireshark/tshark.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return ""


report = {
    "python": sys.version.split()[0],
    "python_deps": {m: has(m) for m in ("pefile", "capstone")},
    "tshark": tshark_path(),
    "bundle": str(analyzer_bundle.find_bundle()) if analyzer_bundle and analyzer_bundle.find_bundle() else "",
    "ilspycmd": analyzer_bundle.find_ilspy() if analyzer_bundle else "",
    "ghidra": analyzer_bundle.find_ghidra() if analyzer_bundle else "",
    "ida": shutil.which("idat64") or shutil.which("idat") or "",
    "readelf": shutil.which("readelf") or "",
    "objdump": shutil.which("objdump") or "",
}
print(json.dumps(report, ensure_ascii=False, indent=2))
