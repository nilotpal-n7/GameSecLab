#!/usr/bin/env python3
r"""REAForge quick smoke tests — verify the pipeline across the arch x format matrix.

Fast (default, no emulation):
  * every core/category/title module imports cleanly;
  * the arch-agnostic engine builds register tables for BOTH x86-32 and x86-64;
  * the reference keygens (license_app clean build, HashLink hl_hash_utf8) match known ground truth,
    including the signed-char / signed-modulo edge cases.

Slow (opt-in: set RUN_CAMPAIGNS=1; needs vmp-lazy-unpack + the authorized binaries present):
  * x64 EXE case — license_app check_license validate battery -> ALL PASS;
  * x86 DLL case — Dead Cells libhl.dll hl_hash_utf8 validate battery -> ALL PASS.

Run:  python -m reaforge.tests.test_smoke       (or: pytest reaforge/tests/test_smoke.py)
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
for _p in (str(ROOT), VMP_LAZY):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def test_core_imports():
    """engine/peel import with no emulation deps; build_canon covers both bitnesses."""
    from reaforge.core import engine, peel  # noqa: F401
    c64, _, _ = engine.build_canon(64)      # (canon, ucreg, full)
    c32, _, _ = engine.build_canon(32)
    assert c64["al"] == ("rax", 1, 0) and c64["rax"] == ("rax", 8, 0)
    assert c32["al"] == ("eax", 1, 0) and "rax" not in c32          # 32-bit has no 64-bit regs
    assert c32["ax"] == ("eax", 2, 0)


def test_category_and_title_modules_import():
    """Category engines (EXE + DLL paths) and both title configs import and expose CONFIG/run."""
    from categories.hashlink import campaign as hashlink  # x86 DLL mechanism
    from categories.native_license import campaign as native  # x64 EXE mechanism
    assert hasattr(native, "Config") and hasattr(native, "run")
    assert hasattr(hashlink, "Config") and hasattr(hashlink, "run")
    from targets.dead_cells import config as dc
    from targets.license_app import config as la
    assert la.CONFIG.check_rva == 0x1000 and callable(la.CONFIG.expected)
    assert dc.CONFIG.export == "hl_hash_utf8"


def test_protector_tools_wired():
    """Themida from-dump tools import and the protector exposes unwrap/reconstruct/lift_vm."""
    from reaforge.tools import pe_reconstruct, themida_unwrap, vm_lift  # noqa: F401
    assert callable(themida_unwrap.unwrap) and callable(pe_reconstruct.reconstruct)
    assert callable(vm_lift.lift) and callable(vm_lift.emulate)
    from reaforge.core.protectors import for_name
    t = for_name("themida")
    assert t.available()
    assert all(hasattr(t, m) for m in ("unwrap_iat", "reconstruct", "lift_vm"))


def test_license_app_keygen():
    """Clean-build keygen matches the VM-validated ground truth (5 serials)."""
    from targets.license_app.config import expected_key
    known = {
        0x12345678: 0x7A3B3935, 0xAABBCCDD: 0x3E988000, 0xDEADBEEF: 0x593BA6C6,
        0x00000000: 0xB8BF23C9, 0xFFFFFFFF: 0x4E25F1B6,
    }
    for serial, key in known.items():
        assert expected_key(serial) == key, f"expected_key({serial:#x}) != {key:#x}"


def test_hashlink_ref_hash_edges():
    """hl_hash_utf8 reference: empty, ascii, and the signed-char sign-extension edge."""
    from categories.hashlink.campaign import ref_hash
    assert ref_hash(b"") == 0
    assert ref_hash(b"a") == 97                      # 223*0 + 97
    assert ref_hash(b"ab") == 223 * 97 + 98          # 21729
    assert ref_hash(b"\xff") == 0xFFFFFFFF           # (unsigned)(signed char)-1, signed modulo keeps -1


def _run_validate(mod, title):
    from reaforge.core.__main__ import _check_authorized
    _check_authorized(mod.CONFIG.packed)
    assert Path(mod.CONFIG.packed).exists(), f"{title}: packed binary missing"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        mod.run(modes=("validate",))
    out = buf.getvalue()
    assert "ALL PASS" in out, f"{title} validate did not pass:\n{out[-600:]}"
    return out


def test_campaign_x64_exe():
    """x64 EXE case: license_app check_license validate battery (opt-in)."""
    if not os.environ.get("RUN_CAMPAIGNS"):
        print("  [skip] set RUN_CAMPAIGNS=1 to run the x64 EXE campaign"); return
    from targets.license_app import config as la
    _run_validate(la, "license_app (x64 EXE)")


def test_campaign_x86_dll():
    """x86 DLL case: Dead Cells libhl.dll hl_hash_utf8 validate battery (opt-in)."""
    if not os.environ.get("RUN_CAMPAIGNS"):
        print("  [skip] set RUN_CAMPAIGNS=1 to run the x86 DLL campaign"); return
    from targets.dead_cells import config as dc
    _run_validate(dc, "dead_cells (x86 DLL)")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    fails = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except Exception as e:
            fails += 1; print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - fails}/{len(tests)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
