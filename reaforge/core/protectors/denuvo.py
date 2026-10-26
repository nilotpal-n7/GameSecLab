#!/usr/bin/env python3
r"""Denuvo Anti-Tamper — out of scope as a static-devirt target (and legally, on shipping titles).

Denuvo is online/anti-tamper DRM, not a self-contained VM you statically devirtualize; and defeating
it on a third-party title is DMCA §1201 territory. This class exists so the registry can *recognize*
Denuvo and refuse it cleanly, pointing at the only in-scope path: your OWN protected analog.
"""
from __future__ import annotations

from reaforge.core.protectors.base import Protector


class Denuvo(Protector):
    name = "denuvo"
    aliases = ()

    def available(self) -> bool:
        return False

    def required_tools(self) -> list[str]:
        return ["(live, dynamic analysis only — not a static-devirt target)"]

    def unpack(self, packed, snap=None, progress=lambda m: None):
        raise NotImplementedError(
            "Denuvo is anti-tamper / online DRM, not a static VM to devirtualize, and breaking it on a "
            "shipping game is out of scope (DMCA §1201). Only your own Denuvo-free analog is in scope.")
