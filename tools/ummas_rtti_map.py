#!/usr/bin/env python3
"""UMAS command <-> CUmas* class mapping via MSVC RTTI chain.

For each CUmas* class:
    name string -> TypeDescriptor (name-8)
    TypeDescriptor RVA -> RTTI Complete Object Locator (COL+0x0C == TD RVA)
    COL VA -> vftable (dword at vftable-4)
Then per class vtable, disassemble slot functions hunting the command byte:
    virtual getter:  mov al, imm8 ; ret        (B0 xx C3)
    or               mov eax, imm32 ; ret
Fallback: constructor stores vftable VA into [this]; nearby
    mov byte ptr [reg+disp8], imm8   (C6 4x xx NN) is the command byte.
"""
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"C:\Program Files (x86)\Schneider Electric\EcoStruxure Machine Expert - Basic\MbComms.dll"

pe = pefile.PE(DLL)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
md = Cs(CS_ARCH_X86, CS_MODE_32)
tsec = next(s for s in pe.sections if b'.text' in s.Name)
TEXT_LO, TEXT_HI = base + tsec.VirtualAddress, base + tsec.VirtualAddress + tsec.Misc_VirtualSize


def rva(va):
    return va - base


# 1) type descriptors
classes = []
for m in re.finditer(rb'\.\?AV(CUmas\w*)@@\x00', img):
    td_va = base + m.start() - 8
    classes.append((m.group(1).decode(), td_va))

# 2) COLs (pTypeDescriptor at COL+0x0C is image-relative in PE32)
name_to_vftables = {}
for name, td_va in classes:
    td_rva = struct.pack('<I', td_va - base)
    vftables = []
    for cm in re.finditer(re.escape(td_rva), img):
        col_rva = cm.start() - 0x0C
        if col_rva < 0:
            continue
        col_va = base + col_rva
        # 3) vftable: dword == VA(COL); vftable starts right after
        colp = struct.pack('<I', col_va)
        for vm in re.finditer(re.escape(colp), img):
            vft = vm.start() + 4
            if TEXT_LO <= base + vft:
                continue
            # read first vtable entry to sanity-check it points into .text
            first, = struct.unpack_from('<I', img, vft)
            if TEXT_LO <= first < TEXT_HI:
                vftables.append(vft)
    name_to_vftables[name] = vftables

print(f"{len(classes)} classes, vftables found for {sum(1 for v in name_to_vftables.values() if v)}")


def scan_fn_for_code(va, max_bytes=48):
    """mov al,imm8; ret  or  mov eax,imm32; ret -> imm ; else None"""
    rva_ = va - base
    saw_al, saw_eax = None, None
    for ins in md.disasm(img[rva_:rva_ + max_bytes], va):
        if ins.mnemonic == 'mov' and ins.op_str.startswith('al, 0x'):
            saw_al = int(ins.op_str.split(', ')[1], 16)
        elif ins.mnemonic == 'mov' and ins.op_str.startswith('eax, 0x'):
            saw_eax = int(ins.op_str.split(', ')[1], 16)
        elif ins.mnemonic == 'ret':
            if saw_al is not None and saw_al < 0x80:
                return saw_al
            if saw_eax is not None and saw_eax < 0x100:
                return saw_eax
            return None
    return None


results = {}
for name, vfts in sorted(name_to_vftables.items()):
    codes = set()
    for vft in vfts:
        # a) virtual getters in the first 12 slots
        for slot in range(12):
            fn, = struct.unpack_from('<I', img, vft + 4 * slot)
            if not (TEXT_LO <= fn < TEXT_HI):
                break
            c = scan_fn_for_code(fn)
            if c is not None:
                codes.add(c)
        # b) constructor: find vftable VA stored in .text, look for byte stores after
        pat = struct.pack('<I', base + vft)
        for tm in list(re.finditer(re.escape(pat), img[tsec.VirtualAddress:tsec.VirtualAddress + tsec.Misc_VirtualSize]))[:3]:
            site = tsec.VirtualAddress + tm.start()
            for ins in md.disasm(img[site:site + 200], base + site):
                if ins.mnemonic == 'mov' and ins.op_str.startswith('byte ptr [') and ins.op_str.endswith(']') \
                        and '0x' in ins.op_str.split(', ')[-1]:
                    imm = int(ins.op_str.split(', ')[-1], 16)
                    if 1 <= imm <= 0x7F:
                        codes.add(imm)
                if ins.mnemonic == 'ret':
                    break
    if codes:
        results[name] = sorted(codes)

traffic = {0x01: "会话初始化", 0x02: "读设备身份", 0x03: "读工程信息", 0x04: "状态轮询",
           0x10: "停止类", 0x11: "登出", 0x24: "变量轮询", 0x28: "心跳",
           0x72: "参数", 0x71: "会话层通道"}
print(f"\n{'class':28s} {'code(s)':24s} traffic-match")
for name, codes in sorted(results.items()):
    tags = ", ".join(f"0x{c:02x}" + (f"({traffic[c]})" if c in traffic else "") for c in codes)
    print(f"CUmas{name[4:]:24s} {tags}")
print(f"\nmapped: {len(results)}/{len(classes)}")
