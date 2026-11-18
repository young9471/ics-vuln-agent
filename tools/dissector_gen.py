#!/usr/bin/env python3
"""M5-2: Wireshark Lua dissector generator.

Single source of truth = findings.json:
  - frame_formats  -> header layout (magic / len offset+size+endian / bias)
  - function_codes -> name tables, routed by layer tag

Protocol wiring via --proto NAME:PORT:LAYER:SHAPE where SHAPE is one of
  codesys     24B header, magic CCCC/6666, service byte at +0x15;
              svc 0x02 tunnels inner [0x50|0x51|0x38][fn]; inner names come
              from layer 'runtime-fn' merged at 0xFF00+fn
  wago        18B header 9xu16 (proto-id 0x1288), payload [u16 code][args];
              response payload = [code echo][u16 status][data]
  modbus-umas MBAP carrier; only FC 0x5A decoded, other FCs fall through to
              the previously registered dissector on that port
  generic     findings-driven split, raw hex payload

Usage:
  python dissector_gen.py --findings runs/combined_demo/findings.json \
      --proto codesysgw:2455:gateway-svc:codesys \
      --proto wago:6626:wago-svc:wago \
      --proto umas:502:umas-cmd:modbus-umas \
      --out runs/combined_demo/dissector.lua
Test:
  tshark -X lua_script:dissector.lua -r capture.pcapng -V
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F  # noqa: E402


def collect_arg_fields(data):
    """field_maps (request direction) -> {chan,cmd,a0,a1 4-byte key: [(off,size,name)]}.

    off is relative to the args region (frame offset 10 = first arg byte).
    Args-prefix bytes come from constant fields; unknown bytes -> 0.
    """
    out = {}
    for m in data.get("field_maps", []):
        if m.get("direction") != "request" or "channel" not in m:
            continue
        chan, cmd = int(m["channel"], 16), int(m["cmd"], 16)
        args = [0, 0]
        for f in m.get("fields", []):
            if f.get("class") != "constant":
                continue
            for i, b in enumerate(bytes.fromhex(f["value"].replace(" ", ""))):
                pos = f["off"] - 10 + i
                if 0 <= pos < 2:
                    args[pos] = b
        key = (chan << 24) | (cmd << 16) | (args[0] << 8) | args[1]
        flds = [(f["off"] - 10, f["size"],
                 f.get("name") or f'{f.get("class","?")}@{f["off"] - 10}')
                for f in m.get("fields", []) if f["off"] >= 10]
        if flds:
            out[key] = flds
    return out


def collect_tpkt_fields(data):
    """tpkt-mode field_maps (@13 keys = message class K1) -> {K1: [(off,size,name)]}.

    off is relative to the args region (frame offset 16).
    """
    out = {}
    for m in data.get("field_maps", []):
        if m.get("direction") != "request" or "@13" not in m.get("key", ""):
            continue
        kstr = m["key"]
        try:
            hexpart = kstr.split("key=")[1].split(" @")[0].replace(" ", "")
            k1 = int(hexpart, 16)
        except (IndexError, ValueError):
            continue
        flds = [(f["off"] - 16, f["size"],
                 f.get("name") or f'{f.get("class", "?")}@{f["off"] - 16}')
                for f in m.get("fields", []) if f["off"] >= 16]
        if flds:
            out.setdefault(k1, flds)
    return out


def collect_chain_fields(data):
    """chain-mode field_maps (keys = cmd bytes @6) -> {cmd: [(off,size,name)]}, args base 8."""
    out = {}
    for m in data.get("field_maps", []):
        kstr = m.get("key", "")
        if m.get("direction") != "request" or not kstr.startswith("chain key="):
            continue
        try:
            hexpart = kstr.split("key=")[1].split(" @")[0].replace(" ", "")
            cmd = int(hexpart, 16)
        except (IndexError, ValueError):
            continue
        flds = [(f["off"] - 8, f["size"],
                 f.get("name") or f'{f.get("class", "?")}@{f["off"] - 8}')
                for f in m.get("fields", []) if f["off"] >= 8]
        if flds:
            out.setdefault(cmd, flds)
    return out


def _ff_name(f):
    """Display name for one field-map entry (sem.json names win; class-based fallback)."""
    if f.get("name"):
        return f["name"]
    c = f.get("class", "?")
    if c == "constant":
        return f"const {f.get('value', '')}".strip()
    if c in ("seq",):
        return "seq/counter"
    if c == "txn-echo":
        return "txn echo"
    if c in ("mbap-len", "tpkt-len"):
        return "length field"
    if c == "ascii":
        return "ascii"
    return "data"


def _ff_list(m):
    """field-map item -> [(off, size(-1=to-end), name)] covering the WHOLE frame."""
    flds = [(f["off"], f["size"], _ff_name(f)) for f in m.get("fields", [])]
    if m.get("tail"):
        flds.append((m["tail"]["from_off"], -1, "变长数据尾部"))
    return flds


def collect_full_fields(data, shape):
    """field_maps -> per-shape {req: {key: flds}, rsp: {key: flds}}.

    Keys are computed exactly like the Lua side reads them from the wire:
      modbus-umas  chan*256+cmd (2B)   [+4B variant for sub-keyed requests]
      s7-smart     bytes@13 as u16 (message class K1); short frames -> key -1
      na           bytes@6 as u16
      enip         bytes@0 as u16
      fins         bytes@10 as u16 (MRC/SRC)
    """
    req, rsp = {}, {}
    req4 = {}
    for m in data.get("field_maps", []):
        kstr = m.get("key", "")
        flds = _ff_list(m)
        if not flds:
            continue
        if "channel" in m:  # mbtcp
            chan, cmd = int(m["channel"], 16), int(m["cmd"], 16)
            k2 = chan * 256 + cmd
            tbl = req if m.get("direction") == "request" else rsp
            if m.get("direction") == "request" and "sub" in kstr:
                # sub-keyed request: disambiguate by first two arg bytes from constants
                args = [0, 0]
                for f in m.get("fields", []):
                    if f.get("class") != "constant":
                        continue
                    for i, by in enumerate(bytes.fromhex(f["value"].replace(" ", ""))):
                        pos = f["off"] - 10 + i
                        if 0 <= pos < 2:
                            args[pos] = by
                req4[(k2 << 16) | (args[0] << 8) | args[1]] = flds
            else:
                tbl[k2] = flds
        elif shape == "s7-smart" and kstr.startswith("tpkt key=") and "@13" in kstr:
            hexpart = kstr.split("key=")[1].split(" @")[0].replace(" ", "")
            k = int(hexpart, 16) if hexpart else -1
            (req if m.get("direction") == "request" else rsp)[k] = flds
        elif shape in ("na", "enip") and kstr.startswith("chain key="):
            k = int(kstr.split("key=")[1].split(" @")[0].replace(" ", ""), 16)
            (req if m.get("direction") == "request" else rsp)[k] = flds
        elif shape == "fins" and kstr.startswith("udp key="):
            k = int(kstr.split("key=")[1].split(" @")[0].replace(" ", ""), 16)
            (req if m.get("direction") == "request" else rsp)[k] = flds
    return {"req": req, "req4": req4, "rsp": rsp}


def _lua_ff_table(d):
    if not d:
        return "nil"
    items = []
    for k, flds in sorted(d.items()):
        entries = ", ".join(f"{{o={o},s={s},n={lua_str(n)}}}" for o, s, n in flds)
        items.append(f"[{k}]={{{entries}}}")
    return "{" + ", ".join(items) + "}"


def lua_str(s):
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def collect_codes(data, layer, offset=0):
    out = {}
    for c in data.get("function_codes", []):
        if c.get("layer") == layer:
            try:
                out[int(c["code"], 0) + offset] = c.get("label", "?")
            except (ValueError, KeyError):
                continue
    return out


def emit(name, port, shape, codes, af_table=None, full_fields=None):
    p = f"p_{name}"
    lines = [f"-- ======== {name} [{shape}] on tcp/{port} ========",
             f"local {p} = Proto('{name}', {lua_str(name)})"]
    for fid, ftype, disp in [("magic", "string", "Magic"),
                             ("len", "uint32", "PayloadLen"),
                             ("svc", "uint16", "Service"),
                             ("svcname", "string", "ServiceName"),
                             ("code", "uint16", "FuncCode"),
                             ("codename", "string", "CodeName"),
                             ("status", "uint16", "Status"),
                             ("data", "bytes", "Data")]:
        lines.append(f"{p}.fields.{fid} = ProtoField.{ftype}('{name}.{fid}', '{disp}')")
    tbl = "{" + ", ".join(f"[{k}]={lua_str(v)}" for k, v in sorted(codes.items())) + "}"
    lines.append(f"local {p}_names = {tbl}")
    fx = ", ".join(f"{p}.fields.{f}" for f in
                   ("magic", "len", "svc", "svcname", "code", "codename", "status", "data"))
    lines.append(f"local {p}_fx = {{{fx}}}")
    if shape in ("modbus-umas", "s7-smart", "na") and af_table:
        entries = ", ".join(
            f"[{k}]={{{', '.join(f'{{o={o},s={s},n={lua_str(n)}}}' for o, s, n in v)}}}"
            for k, v in sorted(af_table.items()))
        lines.append(f"local {p}_af = {{{entries}}}")
    if full_fields:
        lines.append(f"local {p}_ff_req = {_lua_ff_table(full_fields['req'])}")
        lines.append(f"local {p}_ff_req4 = {_lua_ff_table(full_fields.get('req4'))}")
        lines.append(f"local {p}_ff_rsp = {_lua_ff_table(full_fields['rsp'])}")
        lines.append(f"""local {p}_last = {{}}
local function {p}_ff_add(st, tvb, base, ff, endoff)
    if not ff then return end
    for _, fd in ipairs(ff) do
        local sz = fd.s
        if sz < 0 then sz = endoff - (base + fd.o) end
        if sz > 0 and base + fd.o + sz <= endoff then
            local rng = tvb(base + fd.o, sz)
            local it = st:add({p}_fx[8], rng)
            local val = ''
            if sz <= 4 then val = string.format(' = 0x%X', rng:uint()) end
            it:prepend_text(fd.n .. val .. ' ')
        end
    end
end""")
        lines.append(f"local function {p}_isreq(pinfo) return pinfo.dst_port == {port} end")
    if shape == "modbus-umas":
        lines.append(f"_G.UMAS_ORIG_{port} = DissectorTable.get('tcp.port'):get_dissector({port})")
    body = {
        "codesys": f"""        if remaining < 24 then pinfo.desegment_len = 24 - remaining; pinfo.desegment_offset = off; return end
        local plen = tvb(off + 4, 4):le_uint()
        if remaining < 24 + plen then pinfo.desegment_len = 24 + plen - remaining; pinfo.desegment_offset = off; return end
        local magic = tvb(off, 2):uint()
        local st = tree:add({p}, tvb(off, 24 + plen), '{name}')
        st:add({p}_fx[1], tvb(off, 2), string.format('magic 0x%04X', magic))
        st:add({p}_fx[2], tvb(off + 4, 4), plen)
        if magic == 0xCCCC then
            local svc = bit.band(bit.rshift(tvb(off + 20, 4):le_uint(), 8), 0xFF)
            st:add({p}_fx[3], tvb(off + 21, 1), svc)
            st:add({p}_fx[4], {p}_names[svc] or '?')
            if plen > 0 then
                local payload = tvb(off + 24, plen)
                if svc == 0x02 and plen >= 2 then
                    local fn = payload(1, 1):uint()
                    st:add({p}_fx[5], payload(1, 1), fn)
                    st:add({p}_fx[6], {p}_names[0xFF00 + fn] or '')
                    if plen > 2 then st:add({p}_fx[8], payload(2, plen - 2)) end
                else
                    st:add({p}_fx[8], payload)
                end
            end
        end
        off = off + 24 + plen""",
        "wago": f"""        if remaining < 18 then pinfo.desegment_len = 18 - remaining; pinfo.desegment_offset = off; return end
        local plen = tvb(off + 16, 2):le_uint()
        if remaining < 18 + plen then pinfo.desegment_len = 18 + plen - remaining; pinfo.desegment_offset = off; return end
        local st = tree:add({p}, tvb(off, 18 + plen), '{name}')
        st:add({p}_fx[1], tvb(off, 2), string.format('proto-id 0x%04X', tvb(off, 2):le_uint()))
        st:add({p}_fx[2], tvb(off + 16, 2), plen)
        if plen >= 2 then
            local payload = tvb(off + 18, plen)
            st:add({p}_fx[5], payload(0, 2), payload(0, 2):le_uint())
            st:add({p}_fx[6], {p}_names[payload(0, 2):le_uint()] or '?')
            if plen >= 4 then st:add({p}_fx[7], payload(2, 2), payload(2, 2):le_uint()) end
            if plen > 4 then st:add({p}_fx[8], payload(4, plen - 4)) end
        end
        off = off + 18 + plen""",
        "fins": f"""        local plen = tvb:len() - off
        if plen < 12 then break end
        local st = tree:add({p}, tvb(off, plen), '{name} (FINS/UDP)')
        st:add({p}_fx[1], tvb(off, 1), string.format('ICF 0x%02X', tvb(off, 1):uint()))
        st:add({p}_fx[3], tvb(off + 2, 1), tvb(off + 2, 1):uint())
        st:add({p}_fx[4], string.format('dst %d.%d.%d src %d.%d.%d',
            tvb(off + 3, 1):uint(), tvb(off + 4, 1):uint(), tvb(off + 5, 1):uint(),
            tvb(off + 6, 1):uint(), tvb(off + 7, 1):uint(), tvb(off + 8, 1):uint()))
        local cmd = tvb(off + 10, 2):uint()
        st:add({p}_fx[5], tvb(off + 10, 2), cmd)
        st:add({p}_fx[6], {p}_names[cmd] or string.format('MRC/SRC 0x%04X', cmd))
        if {p}_ff_req then
            local k = tvb(off + 10, 1):uint() * 256 + tvb(off + 11, 1):uint()
            local ff = {p}_ff_rsp
            if {p}_isreq(pinfo) then ff = {p}_ff_req end
            {p}_ff_add(st, tvb, off, ff[k], off + plen)
        end
        if plen > 12 then st:add({p}_fx[8], tvb(off + 12, plen - 12)) end
        off = off + plen""",
        "enip": f"""        if remaining < 24 then break end
        local plen = tvb(off + 2, 2):le_uint()
        if remaining < 24 + plen then pinfo.desegment_len = 24 + plen - remaining; pinfo.desegment_offset = off; return end
        local cmd = tvb(off, 2):le_uint()
        local st = tree:add({p}, tvb(off, 24 + plen), '{name}')
        st:add({p}_fx[5], tvb(off, 2), cmd)
        st:add({p}_fx[6], {p}_names[cmd] or string.format('cmd 0x%04X', cmd))
        st:add({p}_fx[2], tvb(off + 2, 2), plen)
        st:add({p}_fx[3], tvb(off + 4, 4), tvb(off + 4, 4):le_uint())
        if {p}_ff_req then
            local k = tvb(off, 1):uint() * 256 + tvb(off + 1, 1):uint()
            local ff = {p}_ff_rsp
            if {p}_isreq(pinfo) then ff = {p}_ff_req end
            {p}_ff_add(st, tvb, off, ff[k], off + 24 + plen)
        end
        if plen > 0 then st:add({p}_fx[8], tvb(off + 24, plen)) end
        off = off + 24 + plen""",
        "na": f"""        if remaining < 6 then break end
        local plen = tvb(off + 4, 2):uint()
        if remaining < 6 + plen then pinfo.desegment_len = 6 + plen - remaining; pinfo.desegment_offset = off; return end
        local st = tree:add({p}, tvb(off, 6 + plen), '{name}')
        st:add({p}_fx[1], tvb(off, 4), string.format('magic %s', tvb(off, 4):string()))
        st:add({p}_fx[2], tvb(off + 4, 2), plen)
        if plen >= 2 then
            local cmd = tvb(off + 6, 2):uint()
            st:add({p}_fx[5], tvb(off + 6, 2), cmd)
            st:add({p}_fx[6], {p}_names[cmd] or string.format('cmd 0x%04X', cmd))
            if {p}_ff_req then
                local ff = {p}_ff_rsp
                if {p}_isreq(pinfo) then ff = {p}_ff_req end
                {p}_ff_add(st, tvb, off, ff[cmd], off + 6 + plen)
            end
            if {p}_af then
                local af = {p}_af[cmd]
                if af then
                    for _, fd in ipairs(af) do
                        if off + 8 + fd.o + fd.s <= off + 6 + plen then
                            local it = st:add({p}_fx[8], tvb(off + 8 + fd.o, fd.s))
                            it:prepend_text(fd.n .. ': ')
                        end
                    end
                end
            end
            if plen > 2 then st:add({p}_fx[8], tvb(off + 8, plen - 2)) end
        end
        off = off + 6 + plen""",
        "s7-smart": f"""        if remaining < 4 then break end
        local total = tvb(off + 2, 2):uint()
        if remaining < total then pinfo.desegment_len = total - remaining; pinfo.desegment_offset = off; return end
        local st = tree:add({p}, tvb(off, total), '{name} (S7-200 SMART PPI)')
        st:add({p}_fx[2], tvb(off + 2, 2), total)
        if tvb(off + 4, 1):uint() == 0x02 and tvb(off + 5, 1):uint() == 0xf0 and total >= 15 then
            local ver = tvb(off + 8, 1):uint()
            local seq = tvb(off + 11, 2):uint()
            local k1 = tvb(off + 13, 2):uint()
            st:add({p}_fx[1], tvb(off + 7, 1), string.format('magic 0x%02X', tvb(off + 7, 1):uint()))
            st:add({p}_fx[3], tvb(off + 8, 1), ver)
            st:add({p}_fx[5], tvb(off + 13, 2), k1)
            st:add({p}_fx[6], {p}_names[k1] or string.format('class 0x%04X', k1))
            if {p}_ff_req then
                local ff = {p}_ff_rsp
                if {p}_isreq(pinfo) then ff = {p}_ff_req end
                {p}_ff_add(st, tvb, off, ff[k1], off + total)
            end
            if {p}_af then
                local af = {p}_af[k1]
                if af then
                    for _, fd in ipairs(af) do
                        if off + 16 + fd.o + fd.s <= off + total then
                            local it = st:add({p}_fx[8], tvb(off + 16 + fd.o, fd.s))
                            it:prepend_text(fd.n .. ': ')
                        end
                    end
                end
            end
            if total > 15 then st:add({p}_fx[8], tvb(off + 15, total - 15)) end
        else
            if {p}_ff_req and {p}_ff_req[-1] then
                {p}_ff_add(st, tvb, off, {p}_ff_req[-1], off + total)
            end
            st:add({p}_fx[8], tvb(off + 4, total - 4))
        end
        off = off + total""",
        "modbus-umas": f"""        if remaining < 8 then break end
        local ln = tvb(off + 4, 2):uint()
        if remaining < 6 + ln then pinfo.desegment_len = 6 + ln - remaining; pinfo.desegment_offset = off; return end
        local fc = tvb(off + 7, 1):uint()
        if fc ~= 0x5A then
            if _G.UMAS_ORIG_{port} then _G.UMAS_ORIG_{port}:call(tvb(off, 6 + ln), pinfo, tree) end
            off = off + 6 + ln
            goto cont
        end
        local st = tree:add({p}, tvb(off, 6 + ln), '{name} (UMAS/FC90)')
        local a, b = pinfo.src_port, pinfo.dst_port
        if a > b then a, b = b, a end
        local conv = a .. '-' .. b
        if ln >= 4 then
            local pdu = tvb(off + 8, ln - 2)
            local b1 = pdu(1, 1):uint()
            if b1 == 0xFE or b1 == 0xFD then
                st:add({p}_fx[7], pdu(1, 1), b1)
                {p}_ff_add(st, tvb, off, {p}_ff_rsp and {p}_ff_rsp[{p}_last[conv]], off + 6 + ln)
                st:add({p}_fx[8], pdu(2, pdu:len() - 2))
            else
                st:add({p}_fx[5], pdu(1, 1), b1)
                st:add({p}_fx[6], {p}_names[b1] or '?')
                if {p}_ff_req then
                    {p}_last[conv] = pdu(0, 1):uint() * 256 + b1
                    local ff = {p}_ff_req[{p}_last[conv]]
                    if not ff and pdu:len() >= 4 and {p}_ff_req4 then
                        ff = {p}_ff_req4[{p}_last[conv] * 65536 + pdu(2, 1):uint() * 256 + pdu(3, 1):uint()]
                    end
                    {p}_ff_add(st, tvb, off, ff, off + 6 + ln)
                end
                if pdu:len() > 2 then
                    local af = nil
                    if pdu:len() >= 4 and {p}_af then
                        af = {p}_af[pdu(0, 1):uint() * 16777216 + b1 * 65536
                                    + pdu(2, 1):uint() * 256 + pdu(3, 1):uint()]
                    end
                    if af then
                        for _, fd in ipairs(af) do
                            if 2 + fd.o + fd.s <= pdu:len() then
                                local it = st:add({p}_fx[8], pdu(2 + fd.o, fd.s))
                                it:prepend_text(fd.n .. ': ')
                            end
                        end
                    else
                        st:add({p}_fx[8], pdu(2, pdu:len() - 2))
                    end
                end
            end
        end
        off = off + 6 + ln""",
        "generic": """        if remaining < 24 then break end
        local st = tree:add(%s, tvb(off, 24), '%s')
        st:add(%s_fx[8], tvb(off, 24))
        off = off + 24""" % (p, name, p),
    }[shape]
    lines.append(f"""local function dissect_{name}(tvb, pinfo, tree)
    local off, total = 0, tvb:len()
    while off < total do
        local remaining = total - off
{body}
        ::cont::
    end
    pinfo.cols.protocol = '{name}'
end
{p}.dissector = dissect_{name}
DissectorTable.get('{"udp.port" if shape == "fins" else "tcp.port"}'):add({port}, {p})""")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True, action="append")
    ap.add_argument("--proto", required=True, action="append", help="NAME:PORT:LAYER:SHAPE")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    data = F.load(args.findings[0])
    for extra in args.findings[1:]:
        other = F.load(extra)
        for k in ("function_codes", "frame_formats"):
            data.setdefault(k, []).extend(other.get(k, []))

    out = ["-- AUTO-GENERATED by dissector_gen.py -- test: tshark -X lua_script:this.lua -r x.pcapng\n"]
    for spec in args.proto:
        name, port, layer, shape = spec.split(":")
        codes = collect_codes(data, layer)
        if shape == "codesys":
            codes.update(collect_codes(data, "runtime-fn", offset=0xFF00))
        ff = collect_full_fields(data, shape) if shape in (
            "modbus-umas", "s7-smart", "na", "enip", "fins") else None
        if ff and not (ff["req"] or ff["rsp"] or ff.get("req4")):
            ff = None
        af = collect_arg_fields(data) if shape == "modbus-umas" else \
            (collect_tpkt_fields(data) if shape == "s7-smart" else
             (collect_chain_fields(data) if shape == "na" else None))
        out.append(emit(name, int(port), shape, codes, af, ff))
        out.append("")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    lua = "\n".join(out)
    open(args.out, "w", encoding="utf-8").write(lua)
    print(f"wrote {args.out} ({len(lua)}B, {len(args.proto)} protocols)")


if __name__ == "__main__":
    main()
