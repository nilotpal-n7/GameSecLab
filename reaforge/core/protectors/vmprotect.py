#!/usr/bin/env python3
r"""VMProtect protector — reaches OEP by emulation-unpack (vmp-lazy-unpack), version-aware.

We do not hardcode VMProtect's VM: the real handlers run on Unicorn and the generic x86 SymEngine
shadows them, so this works across VM sub-versions unchanged. What IS VMProtect-specific is the
*unpack* (packer, rolling-key string decode, CRT-init handlers, OEP detection) — that lives in
`VmpLoader` on top of vmp-lazy-unpack, and this class is the seam around it.
"""
from __future__ import annotations

import os
import re

from reaforge.core.loader import VMP_LAZY, VmpLoader
from reaforge.core.protectors.base import Protector


class VMProtect(Protector):
    name = "vmprotect"
    aliases = ("vmprotect",)
    # Acquire-or-fallback per version: a static devirtualizer if one reaches that version, else our own
    # emulation-unpack. (Public static devirtualizers lag the protector by years — hence the fallback.)
    strategy = {
        "<=3.5": "NoVmp/VTIL devirtualizes statically (if built); else emulation-unpack",
        "3.6":   "NoVmpy fork (if built); else emulation-unpack",
        ">=3.7": "emulation-unpack (vmp-lazy-unpack) — no public static devirtualizer; our own path",
    }

    def available(self) -> bool:
        return os.path.isdir(VMP_LAZY)

    def required_tools(self) -> list[str]:
        return ["vmp-lazy-unpack (emulation-unpack env; set $VMP_LAZY_UNPACK)",
                "optional: NoVmp/VTIL for VMProtect <= 3.6 (static)"]

    def classify_version(self, facts) -> str:
        die = facts if isinstance(facts, str) else (facts.get("tools", {}).get("die") or "")
        m = re.search(r"vmprotect[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", die, re.I)
        return m.group(1) if m else "unknown"

    def unpack(self, packed, snap=None, progress=lambda m: None):
        if not self.available():
            raise NotImplementedError(
                f"vmp-lazy-unpack not found at {VMP_LAZY}; set $VMP_LAZY_UNPACK or install it.")
        ld = VmpLoader(packed, progress=progress)
        ld.reach_unpacked(snap)
        return ld

    def vm_model(self):
        return None   # emulated, not hardcoded — see module docstring
