#!/usr/bin/env python3
r"""Protector abstraction — one seam for every packer/DRM, so nothing is hardcoded to VMProtect.

A `Protector` subclass owns everything that is specific to one protector *family* (VMProtect, Themida,
Denuvo, ...): how to recognize it, its versions, which tools reaching its unpacked state needs, whether
we have those means, and the unpack itself. Versions are handled inside the subclass (a strategy per
range), so a new sub-version is a data change, not a new fork.

Design note — we do NOT hardcode a protector's VM bytecode/opcode handlers. The devirt engine EMULATES
the real VM on Unicorn and shadows it with generic x86 semantics (`engine.py`), so `vm_model()` is
`None` for an emulated protector. A subclass only overrides it if it genuinely ships a handler model.

The contract for `unpack()`'s return value (the "environment") is what the campaigns use:
`uc`, `arch`, `mapped_start`/`mapped_end`, `resolve_export(name)`, `resolve_rva(rva)`,
`add_handler(symbol, fn, argc)`, `restore_snapshot(path)`, `close()`.
"""
from __future__ import annotations

# Lightweight identification table (DIE/recon substrings). Kept here so classify() needs no heavy import.
ALIASES = {
    "vmprotect": ("vmprotect",),
    "themida": ("themida", "winlicense", "oreans"),
    "denuvo": ("denuvo",),
}


def _die_text(facts) -> str:
    if isinstance(facts, str):
        return facts.lower()
    if isinstance(facts, dict):
        return (facts.get("tools", {}).get("die") or "").lower()
    return ""


def classify(facts) -> str:
    """Name of the protector recon points to, or 'unknown'. Pure string match — no loader import."""
    die = _die_text(facts)
    for name, subs in ALIASES.items():
        if any(s in die for s in subs):
            return name
    return "unknown"


class Protector:
    name = "protector"
    aliases: tuple[str, ...] = ()
    #: version-range -> how we reach its unpacked state (use a tool if available, else our own)
    strategy: dict[str, str] = {}

    @classmethod
    def matches(cls, die_text: str) -> bool:
        t = die_text.lower()
        return any(a in t for a in (cls.name, *cls.aliases))

    def available(self) -> bool:
        """True when we have the means (a tool, or our own unpacker) to reach this protector's OEP."""
        return False

    def required_tools(self) -> list[str]:
        """What reaching this protector's unpacked state needs (so missing means can be acquired)."""
        return []

    def classify_version(self, facts) -> str:
        return "unknown"

    def unpack(self, packed, snap=None, progress=lambda m: None):
        """Reach the unpacked/OEP state and return the environment (see module docstring for its contract).

        Raise NotImplementedError when we have no means — `required_tools()` then says what to get.
        """
        raise NotImplementedError(
            f"{self.name}: no unpacker available here. Tools to get: {', '.join(self.required_tools()) or '(none known)'}")

    def vm_model(self):
        """Protector VM opcode/handler model, if one is shipped. None = the VM is emulated concretely
        (no hardcoded bytecode); the arch-agnostic SymEngine shadows the real handlers as they run."""
        return None

    def unavailable_message(self) -> str:
        return (f"{self.name}: reaching its unpacked state is not automated here "
                f"(tools to get: {', '.join(self.required_tools()) or 'n/a'}).")
