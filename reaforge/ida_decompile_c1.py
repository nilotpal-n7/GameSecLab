# Headless Hex-Rays decompile anchored on strings (for stripped/obfuscated binaries).
# Finds the function(s) referencing license strings, decompiles them + one level of
# callees, writes capstone/ida_decompile_c1.txt. Run:
#   idat.exe -A -S"...ida_decompile_c1.py" license_app_c1.exe
import ida_auto, ida_hexrays, idautils, ida_funcs, ida_pro, idc, os

ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

# C1 encrypts strings (-irobf-cse), so string anchors are gone. Anchor on main.
import ida_name
roots = set()
for nm in ("main", "_main", "wmain", "_wmain"):
    ea = ida_name.get_name_ea(idc.BADADDR, nm)
    if ea != idc.BADADDR:
        f = ida_funcs.get_func(ea)
        if f:
            roots.add(f.start_ea)
# Fallback: if IDA didn't label main, take non-library functions (skip CRT via FUNC_LIB).
if not roots:
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f and not (f.flags & ida_funcs.FUNC_LIB):
            roots.add(ea)

# expand one level: include functions the roots call
targets = set(roots)
for ea in list(roots):
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    for item in idautils.FuncItems(ea):
        for xref in idautils.CodeRefsFrom(item, 0):
            cf = ida_funcs.get_func(xref)
            if cf and cf.start_ea != ea:
                targets.add(cf.start_ea)

def decomp(ea):
    try:
        return str(ida_hexrays.decompile(ea))
    except Exception as e:
        return "// decompile failed @ 0x%x: %s" % (ea, e)

lines = []
for ea in sorted(targets):
    name = idc.get_func_name(ea)
    lines.append("// ===== function %s @ 0x%x =====" % (name, ea))
    lines.append(decomp(ea))
    lines.append("")

out = os.path.join(os.path.dirname(idc.get_idb_path()), "ida_decompile_c1.txt")
with open(out, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

ida_pro.qexit(0)
