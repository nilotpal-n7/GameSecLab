# Themida / WinLicense layer — plan + honest tooling reality

The next protect-and-break layer after VMProtect: re-protect the same `license_app` with **Themida**
(Oreans). The algorithm is unchanged (we already have the clean-build keygen / `expected_key`), so the
teaching value here is the **unpack fight** and a **protector-agnostic dynamic bypass** — not another
devirtualization of the math.

## Protect step — your GUI hands (I can't run Themida)

1. Build the marker source the same way as the VMProtect target (`src/license_app_hardened.c`), or reuse
   `dumps/license_app_hardened.exe`.
2. In the **Themida** GUI (Demo is fine): open the exe, and under **Protection Options** enable a
   representative set — **Virtualize** the `check_license` region (SecureEngine VM: Tiger/Dolphin/Fish),
   **Anti-Debugger (advanced)**, **Memory Guard**, **Entry Point Virtualization**, **Metamorphic engine**.
3. **Protect** → save as `dumps/license_app.themida.exe`.
4. Authorize it so the tooling will touch it:
   ```bash
   python -m reaforge.orchestrator authorize "C:\Tools\GameSecLab\targets\license_app\dumps\license_app.themida.exe" "my own license_app, Themida-packed by me"
   ```

## Why reaforge/core does NOT apply here (honest)

`reaforge/core` (loader + engine) and the `vmp-lazy-unpack` env it builds on are **VMProtect-specific**:
they model VMProtect's packer, rolling-key self-checksums, import protection and VM. Themida is a
**different protector** (Oreans' own packer + SecureEngine VMs), so:

- our emulation-unpack will not reach a Themida OEP, and
- our devirtualizer cannot read SecureEngine bytecode.

`python -m reaforge.orchestrator run license_app` detects this (recon classifies the protector) and
**refuses the VMProtect path** on a Themida binary rather than crashing — pointing here instead.

Public Themida tooling lags the protector the same way NoVmp lags VMProtect: unpackers like *magicmida*,
*Themidie*, and *unlicense* target older/!3.x builds and specific options; modern Themida is largely a
**manual** unpack + manual VM analysis job.

## Break route (recommended order)

1. **Unpack to OEP (your hands, I guide).** x64dbg + ScyllaHide (Themida profile) through the anti-debug;
   find OEP (tail-jump / section hop); **Scylla** dump + IAT rebuild. This is the real, version-independent
   skill and the bulk of the Themida fight.
2. **Protector-agnostic dynamic bypass (already built).** The verdict is one branch regardless of protector.
   The `bypass` mode we added for VMProtect is the same idea live: trace a correct vs wrong key, find the one
   diverging branch (the LICENSED/INVALID decision), and invert/NOP it in x64dbg. It needs no devirtualization
   and works on Themida too. Verify the forced result against the `expected_key` oracle.
3. **Manual VM analysis (stretch).** If you want the SecureEngine VM itself: locate the VM entry, dispatcher
   and handler table in the dump — the same method as manual VMProtect VM recovery, different opcode set.

## Cross-check oracle

Whatever the layer, the ground truth stays `expected_key(serial)` in `config.py` — the clean-build algorithm
(key for this machine: `75685AB2`). A successful bypass = the VM accepts a wrong key, or accepts the key
`expected_key` predicts, exactly as on the clean and VMProtect builds.

## Status

Awaiting the Themida-packed binary (your GUI protect step). Once it exists and is authorized, drop it in
`dumps/` and we drive the unpack + dynamic bypass from there.
