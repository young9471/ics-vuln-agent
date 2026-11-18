# IDAPython post-script used by ida_analyze.py. Prints TSV records.
import idautils
import idc
import idaapi

def main():
    import sys
    out = idc.ARGV[1] if len(idc.ARGV) > 1 else "ida-export.tsv"
    with open(out, "w", encoding="utf-8") as f:
        for ea in idautils.Functions():
            f.write("FUNC\t0x%x\t%s\n" % (ea, idc.get_func_name(ea)))
        for name in idautils.Names():
            ea, nm = name
            f.write("NAME\t0x%x\t%s\n" % (ea, nm))
        for s in idautils.Strings():
            try:
                f.write("STRING\t0x%x\t%s\n" % (s.ea, str(s).replace("\t", " ").replace("\n", " ")))
            except Exception:
                pass
        for imp in idautils.Entries():
            f.write("ENTRY\t0x%x\t%s\n" % (imp[0], imp[1]))
    idc.qexit(0)

main()
