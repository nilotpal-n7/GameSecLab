#!/usr/bin/env python3
r"""Apply Denuvo's GAMBA (published general-MBA simplifier) to our VMProtect 3.11 hash.

Purpose: demonstrate, with a real published tool, the intra-round vs inter-round split from
knowledge/vmprotect_3.11/mba_deobfuscation.md:
  * GAMBA (linear-isolation + SiMBA + variable substitution) DOES collapse intra-round MBA, e.g.
    the shift-encoded multiply (acc<<5)+acc -> 33*acc.
  * GAMBA alone does NOT roll the 8-round loop (no inductive recurrence synthesis) -> the unrolled
    hash stays a large nested expression. That inter-round layer is what our peel.py adds
    (cut-point slicing + Plotkin anti-unification).

Since Proof B (peel.py) proves want(serial) == the clean-build recurrence for ALL 2^32 serials, the
clean-build unrolled form below IS the recovered VMProtect expression up to proven equivalence.

Own-code driver that imports GAMBA as a library (external repo is not executed directly).
Run:  python -I reaforge/devirt/demba_gamba.py
"""
import os
import sys

GAMBA_SRC = os.environ.get("GAMBA_SRC", r"C:\Tools\_downloads\research\mba-tools\GAMBA\src")
sys.path.insert(0, GAMBA_SRC)
import simplify_general as G  # exposes simplify_mba(expr, bitCount, useZ3, modRed, verifBitCount)

BITS = 32

def run(label, expr, useZ3=True):
    print(f"\n=== {label} ===")
    print(f"  in : {expr if len(expr)<160 else expr[:157]+'...'}  (len={len(expr)})")
    try:
        out = G.simplify_mba(expr, BITS, useZ3=useZ3, modRed=True)
        print(f"  out: {out if len(str(out))<220 else str(out)[:217]+'...'}  (len={len(str(out))})")
    except Exception as e:
        print(f"  GAMBA error: {e!r}")

def one_round(acc_term, i):
    nib = f"((s >> {4*i}) & 15)"
    return f"((((({acc_term}) << 5) + ({acc_term})) ^ {nib}) + {7*i})"

if __name__ == "__main__":
    # 1) intra-round: shift-encoded *33 inside the round (x = accumulator, s = serial)
    run("single round, shift-encoded *33  (((x<<5)+x) ^ ((s>>28)&15)) + 49", one_round("x", 7))

    # 2) intra-round, pure multiply form for comparison
    run("single round, explicit *33  ((x*33) ^ ((s>>28)&15)) + 49",
        "(((x * 33) ^ ((s >> 28) & 15)) + 49)")

    # 3) full 8-round unrolled hash over serial s (== want, by Proof B). Watch GAMBA NOT roll the loop.
    acc = "(5381 ^ s)"                       # acc_0 = 0x1505 ^ serial
    for i in range(8):
        acc = one_round(acc, i)
    run("full 8-round unrolled hash (expect: simplified but NOT re-rolled to a loop)", acc, useZ3=False)
