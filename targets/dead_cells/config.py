#!/usr/bin/env python3
r"""Title config: dead_cells — our own VMProtect 3.11-protected copy of Dead Cells' libhl.dll.

Dead Cells is a HashLink game, so all the hashing ground truth (hl_hash_utf8) is category-level in
categories/hashlink/campaign.py. This title only names its packed binary + snapshot.

Run via the CLI:   python -m reaforge.core dead_cells [N] [modes]
"""
from __future__ import annotations

from pathlib import Path

from categories.hashlink import campaign

HERE = Path(__file__).resolve().parent
DUMPS = HERE / "dumps"

CONFIG = campaign.Config(
    name="Dead Cells libhl.dll",
    packed=str(DUMPS / "libhl.vmp.dll"),
    snap=str(DUMPS / "dll32_postunpack.snap"),
    export="hl_hash_utf8",
    N=4,
)


def run(packed=None, arg=None, modes=("validate", "recover", "peel", "prove")):
    cfg = CONFIG
    if arg:
        cfg = campaign.Config(**{**cfg.__dict__, "N": int(arg)})
    campaign.run(cfg, packed, modes)
