#!/usr/bin/env python3
r"""Themida / WinLicense (Oreans SecureEngine) protector — not automated here.

Our emulation-unpack is VMProtect-specific; Themida is a different packer + VM family, with no public
automated unpacker for modern builds. So `unpack()` is a NotImplementedError that routes to the manual
plan, and `required_tools()` names what to acquire. The devirt engine + bypass mode remain
protector-agnostic once a target is unpacked.
"""
from __future__ import annotations

from reaforge.core.protectors.base import Protector


class Themida(Protector):
    name = "themida"
    aliases = ("winlicense", "oreans")
    strategy = {
        "2.x": "older builds: magicmida / Themidie sometimes auto-unpack; else manual OEP + Scylla",
        "3.x": "manual: x64dbg + ScyllaHide past anti-debug -> find OEP -> Scylla dump + IAT rebuild",
    }

    def available(self) -> bool:
        return False

    def required_tools(self) -> list[str]:
        return ["x64dbg + ScyllaHide", "Scylla (OEP dump + IAT rebuild)",
                "magicmida / Themidie (older builds)"]

    def unpack(self, packed, snap=None, progress=lambda m: None):
        raise NotImplementedError(
            "Themida (Oreans SecureEngine) has no automated unpacker here — our emulation-unpack is "
            "VMProtect-specific. See targets/license_app/themida_plan.md for the manual unpack + the "
            "protector-agnostic dynamic bypass. Tools to get: " + ", ".join(self.required_tools()))
