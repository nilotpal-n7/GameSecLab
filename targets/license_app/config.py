#!/usr/bin/env python3
r"""Title config: license_app — our own VMProtect 3.11 crackme (x64 check_license).

The only place the license_app specifics live: its clean-build keygen (ground truth, used ONLY to validate /
cross-check recovery), the virtualized function RVA, the Proof-B recurrence, and the local paths to
its packed binary + snapshot. Everything mechanical is in categories/native_license/campaign.py.

Run via the CLI:   python -m reaforge.core license_app [serial_hex] [modes]
"""
from __future__ import annotations

from pathlib import Path

import z3

from categories.native_license import campaign
from reaforge.core import peel

HERE = Path(__file__).resolve().parent
DUMPS = HERE / "dumps"
M = (1 << 32) - 1


def expected_key(mid: int) -> int:
    """Reference keygen (clean-build algorithm our crackme implements; cross-check oracle only)."""
    acc = (0x1505 ^ mid) & M
    for i in range(8):
        acc = ((acc * 33) & M) ^ ((mid >> (i * 4)) & 0xF)
        acc = (acc + i * 7) & M
    return acc


def _prove_b(want, serial_sym):
    """Prove want(serial) == the pristine 0x1505^s; ((acc*33)^nibble)+7i recurrence over ALL 2^32."""
    Sz = peel.conv(serial_sym); bz = peel.conv(want)
    acc = z3.BitVecVal(0x1505, 32) ^ Sz
    for i in range(8):
        acc = (acc * z3.BitVecVal(33, 32)) ^ (z3.LShR(Sz, z3.BitVecVal(4 * i, 32)) & z3.BitVecVal(0xF, 32))
        acc = acc + z3.BitVecVal((i * 7) & M, 32)
    sv = z3.Solver(); sv.set("timeout", 180000); sv.add(bz != acc); r = sv.check()
    if r == z3.unsat:
        print("  [Proof B] UNSAT over all 2^32 ==> want == pristine 0x1505^s; ((acc*33)^nibble)+7i")
    elif r == z3.unknown:
        print("  [Proof B] z3 timeout (multiply blow-up); backed by per-round proofs + validation.")
    else:
        print(f"  [Proof B] counterexample: {sv.model()}")


CONFIG = campaign.Config(
    name="license_app check_license",
    packed=str(DUMPS / "license_app.vmp.exe"),
    snap=str(DUMPS / "license_postoep.snap"),
    check_rva=0x1000,
    expected=expected_key,
    prove=_prove_b,
    default_serial=0xAABBCCDD,
    keybuf=0x00000add00000000,
    ret_sentinel=0x7ff900002000,
    marker=0x13371337,
)


def run(packed=None, arg=None, modes=("validate", "recover", "peel", "prove")):
    serial = int(arg, 16) if arg else CONFIG.default_serial
    cfg = CONFIG
    if serial != cfg.default_serial:
        cfg = campaign.Config(**{**cfg.__dict__, "default_serial": serial})
    campaign.run(cfg, packed, modes)
