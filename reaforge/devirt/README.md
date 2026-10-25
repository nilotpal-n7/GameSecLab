# REAForge devirt — building our own VMProtect 3.11 devirtualizer

No public tool devirtualizes VMProtect 3.11 (see `docs/devirt_tooling_availability_2026.md`), so we build one.
Approach: **concolic emulation along a single concrete path** — emulate the VM'd function directly (no path
explosion, unlike angr on the whole VM; no debugger, unlike Pin which 3.11 detects by timing).

## What works (`emulate_checklicense.py`)
- Maps the unpacked dump's PE headers + all sections into **Unicorn**, sets up stack / key buffer /
  `KUSER_SHARED_DATA` / a TEB via GS, stubs `GetVolumeInformationA`, lazy-maps stray pages.
- **The VM interpreter executes end-to-end with no divergence** (mapping the PE headers fixed the rolling-key
  self-checksum reads — that was the key insight). We can drive `check_license`'s VM at will.

## The wall we hit
`check_license` → `machine_id()` → `GetVolumeInformationA`, but **VMProtect import protection resolves APIs by
walking `PEB→Ldr`**, not via the rebuilt `.idata` (our IAT hook fired 0 times). With no Windows loader
environment, the VM's resolver walks a zeroed PEB → null → execution derails → garbage return.

**Root cause:** faithfully emulating a VMProtect function needs a real **Windows process environment**
(PEB/LDR, loaded-module list with export tables, `GetProcAddress`, API stubs). That subsystem is precisely what
`vmp-lazy-unpack` already implements (it ships `ntdll.dll` + `catalog.json` of exports).

## Options to finish
1. **Build the loader env into our harness** — PEB/LDR + a minimal kernel32/ntdll export table + resolver +
   API stubs. Most educational; a real subsystem (several iterations).
2. **Reuse `vmp-lazy-unpack`'s harness** — it already sets up the env + API hooks; extend it to keep emulating
   *past OEP* into `check_license`, feed a key, and read the result / trace the compare. Faster path.
3. **Add the symbolic layer** once emulation is faithful: symbolize the serial (and/or key), run the single
   concrete path, and read off the formula / solve for the valid key (angr is now installed for the SMT step;
   or Triton-style taint on the Unicorn trace).

## Status
Milestone 1 (emulate the VM) is ~80% — the VM runs; only the API-resolution environment is missing. The C2
break itself is already complete (unpack + `main` recovered; algorithm known from C0). This devirtualizer is
the "pure recovery" stretch goal.
