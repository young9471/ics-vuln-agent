#!/usr/bin/env python3
"""P4 static function-code extractor.

Anchors: exported symbol addresses (authoritative function boundaries) or
debug-string entry logs ("Class::method" pushed at function start).
Patterns (request-builder idioms, x86 32-bit):
    mov eax, imm32 ; ... ; mov word ptr [reg], ax      (u16 code store)
    mov e??, imm32 ; push e??                           (code as arg)
    push imm32                                          (direct arg)

Anti-bleed rules (pitfall #7): scan is bounded by the next export start;
only the FIRST match per function is kept; string labels attach only when
the xref lies inside that same function.

Usage:
  python extract_codes.py --dll comm.dll --anchor exports \
      [--label-regex 'API::'] --out findings.json
"""
import argparse
import os
import re
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F  # noqa: E402

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    sys.exit("pip install pefile capstone")


def u16_store_codes(md, body_bytes, base, start, end):
    """First `mov eax,imm` + `mov word ptr [..], ax` in [start,end)."""
    code = body_bytes
    pending, age = None, 0
    for ins in md.disasm(code, base + start):
        if ins.address >= base + end:
            break
        if ins.mnemonic == "mov" and ins.op_str.startswith("eax, 0x"):
            pending, age = int(ins.op_str.split(", ")[1], 16), 0
            continue
        if pending is not None:
            if ins.mnemonic == "mov" and ins.op_str.startswith("word ptr [") \
                    and ins.op_str.endswith(", ax"):
                return pending, ins.address
            age += 1
            if age > 4:
                pending = None
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--anchor", choices=("exports", "strings"), default="exports")
    ap.add_argument("--label-regex", default=r"::", help="regex for debug-string labels")
    ap.add_argument("--symbol-filter", default="", help="substring filter on symbol names")
    ap.add_argument("--min-code", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--max-code", type=lambda x: int(x, 0), default=0xFFFF)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    pe = pefile.PE(args.dll)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    tsec = next(s for s in pe.sections if b".text" in s.Name)
    trva = tsec.VirtualAddress
    text = img[trva:trva + tsec.Misc_VirtualSize]

    funcs = []  # (start_rva, label)
    if args.anchor == "exports":
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not e.name:
                continue
            name = e.name.decode(errors="replace")
            if args.symbol_filter and args.symbol_filter not in name:
                continue
            if name.startswith("??0") or name.startswith("??1") or name.startswith("??4"):
                continue  # ctor/dtor/assign
            funcs.append((e.address, name))
    funcs.sort()
    if not funcs:
        sys.exit("no anchor functions found")

    label_re = re.compile(args.label_regex.encode() + rb"\w+")
    rows, dup_guard = [], {}
    for i, (start, label) in enumerate(funcs):
        end = funcs[i + 1][0] if i + 1 < len(funcs) else start + 0x600
        end = min(end, start + 0x600)
        body = img[start:end]
        if trva <= start < trva + len(text):
            code, ev = u16_store_codes(md, body, base, start, end)
            if code is not None and args.min_code <= code <= args.max_code \
                    and code not in dup_guard:
                dup_guard[code] = label
                rows.append((code, label, ev))

    rows.sort()
    data = F.load(args.out)
    for code, label, ev in rows:
        F.add(data, "function_codes", {
            "code": f"0x{code:04x}", "label": label[:120],
            "evidence": f"{os.path.basename(args.dll)}@{ev:08x}",
            "grade": "static", "layer": "static-extract"})
    F.add(data, "phases", {"phase": "P4", "status": "done",
                           "codes_extracted": len(rows)})
    F.save(args.out, data)

    print(f"{'code':>8}  {'evidence':>10}  label")
    for code, label, ev in rows:
        print(f"0x{code:04x}   {ev:08x}   {label[:100]}")
    print(f"\n{len(rows)} codes -> {args.out}")


if __name__ == "__main__":
    main()
