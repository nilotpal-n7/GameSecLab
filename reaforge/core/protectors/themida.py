#!/usr/bin/env python3
r"""Themida / WinLicense (Oreans SecureEngine) protector.

No public automated unpacker exists for modern builds, so reaching the dumped state still needs a
manual GUI step (x64dbg + ScyllaHide past the anti-debug, then a full-memory dump) — `unpack()`
without a dump raises NotImplementedError and routes to the manual plan. But from a dump onward the
path is wired to our own reaforge tools, no reference binary:

  * `unwrap_iat()`  — reaforge.tools.themida_unwrap: emulate each Advanced-API-Wrapping stub to its
                      real API (oracle-free), so the dump's IAT can be rebuilt.
  * `reconstruct()` — reaforge.tools.pe_reconstruct: rebuild a runnable PE from the dump.

  * `lift_vm()`    — reaforge.tools.vm_lift: emulate a VM'd function's SecureEngine VM from the dump
                      and recover what it computes (the constant the input is checked against),
                      self-validated — oracle-free devirt of the Falcon VM region.

`unpack(packed, dump=...)` runs unwrap -> reconstruct and returns a ThemidaUnpacked result; `lift_vm()`
devirtualizes the VM'd regions (EPV entry + VM_START/VM_END body). `vm_model()` stays None — the VM is
emulated, never hardcoded.
"""
from __future__ import annotations

from dataclasses import dataclass

from reaforge.core.protectors.base import Protector


@dataclass
class ThemidaUnpacked:
    """What a from-dump unpack yields: the rebuilt exe, the resolved IAT, and whether VM'd code remains."""
    exe: str | None
    imports: list              # [(rva, slot_val, tag, api), ...] from themida_unwrap
    vm_regions_pending: bool = True   # the EPV entry + VM_START/END body still need vm_lift

    @property
    def resolved(self) -> int:
        return sum(1 for _r, _v, tag, _a in self.imports if tag in ("direct", "UNWRAPPED"))


class Themida(Protector):
    name = "themida"
    aliases = ("winlicense", "oreans")
    strategy = {
        "2.x": "older builds: magicmida / Themidie sometimes auto-unpack; else manual OEP + Scylla",
        "3.x": "manual: x64dbg + ScyllaHide past anti-debug -> full-memory dump -> unwrap_iat + reconstruct",
    }

    def available(self) -> bool:
        # the from-dump tools are pure-python (unicorn/pefile); the only non-automated step is the dump.
        try:
            import pefile  # noqa: F401
            import unicorn  # noqa: F401
            return True
        except ImportError:
            return False

    def required_tools(self) -> list[str]:
        return ["x64dbg + ScyllaHide (past anti-debug, to reach OEP)",
                "a full-memory process dump (Task Manager -> Create dump file)",
                "reaforge.tools.themida_unwrap + pe_reconstruct (ours; from the dump on)"]

    def unwrap_iat(self, dump, main_module_substr, iat_rva, iat_size, show=print):
        """Resolve the API-wrapped IAT from a full-memory dump (oracle-free). -> list of (rva,val,tag,api)."""
        from reaforge.tools.themida_unwrap import unwrap
        return unwrap(dump, main_module_substr, iat_rva, iat_size, show=show)

    def reconstruct(self, dump_exe, out, orig=None, oep=None, base=None, show=print):
        """Rebuild a runnable PE from the dump (orig = your own clean binary oracle, optional)."""
        from reaforge.tools.pe_reconstruct import reconstruct
        return reconstruct(dump_exe, out, orig=orig, oep=oep, base=base, show=show)

    def lift_vm(self, dump, main_module_substr, func_rva, serial=0x75685AB2,
                expected_key=None, show=print):
        """De-virtualize a VM'd function from a full-memory dump: emulate the SecureEngine VM and
        recover the constant the input is checked against, self-validated (oracle-free)."""
        from reaforge.tools.vm_lift import lift
        return lift(dump, main_module_substr, func_rva, serial=serial,
                    expected_key=expected_key, show=show)

    def unpack(self, packed, snap=None, progress=lambda m: None, *,
               dump=None, main_module_substr=None, iat_rva=None, iat_size=None,
               dump_exe=None, out=None, orig=None, oep=None, base=None):
        """From a full-memory `dump`: unwrap the IAT, then (if `dump_exe`/`out` given) reconstruct.

        Without a dump we can't reach the unpacked state automatically (Themida anti-debug) — raise and
        point at the manual plan. `packed` is kept for the Protector contract / recon symmetry.
        """
        if dump is None:
            raise NotImplementedError(
                "Themida: no automated unpack from the packed file — our emulation-unpack is VMProtect-"
                "specific and Themida's anti-debug blocks it. Reach the dump manually (see "
                "targets/license_app/recovery/recovery_themida.md), then call unpack(dump=..., "
                "main_module_substr=..., iat_rva=..., iat_size=...). Tools: " + ", ".join(self.required_tools()))
        imports = self.unwrap_iat(dump, main_module_substr, iat_rva, iat_size, show=progress)
        exe = None
        if dump_exe and out:
            exe = self.reconstruct(dump_exe, out, orig=orig, oep=oep, base=base, show=progress)
        return ThemidaUnpacked(exe=exe, imports=imports)

    def vm_model(self):
        return None   # SecureEngine VM is emulated by vm_lift, not hardcoded — see module docstring
