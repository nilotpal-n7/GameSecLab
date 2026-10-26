"""Protector registry — pick the right protector for a target, or refuse cleanly.

`classify(facts)` is cheap (string match, no heavy imports). `for_name` / `for_facts` lazily import the
concrete subclass (VMProtect pulls the loader; Themida/Denuvo don't), so you can classify without
loading the emulation stack.
"""
from __future__ import annotations

from reaforge.core.protectors.base import ALIASES, Protector, classify

KNOWN = tuple(ALIASES)   # ("vmprotect", "themida", "denuvo")


def for_name(name: str) -> Protector:
    key = (name or "vmprotect").lower()
    if key == "vmprotect":
        from reaforge.core.protectors.vmprotect import VMProtect
        return VMProtect()
    if key == "themida":
        from reaforge.core.protectors.themida import Themida
        return Themida()
    if key == "denuvo":
        from reaforge.core.protectors.denuvo import Denuvo
        return Denuvo()
    raise KeyError(f"unknown protector {name!r}; known: {', '.join(KNOWN)}")


def for_facts(facts):
    name = classify(facts)
    return for_name(name) if name != "unknown" else None


__all__ = ["Protector", "classify", "for_name", "for_facts", "KNOWN"]
