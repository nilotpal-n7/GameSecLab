# Capstone — build a real protected target with pro tools, then break it

Goal: the closest **legal** analog to the Denuvo experience. Take a small program **you wrote**, protect it
with the **actual industry tools** (the same virtualizers shipped on real games/software), then reverse your
own protected binary with the professional RE toolchain. No toy layers — real VMProtect/Themida output.

**Legality:** using a commercial protector on your own code, and reverse-engineering your own protected
binary, is fully legal — it's literally what evaluation licenses are for. The line we never cross is doing
this to **someone else's** DRM-protected product.

**Honest ceiling:** even done perfectly this is not "cracking Denuvo" (scale: thousands of triggers woven
into real game code, a team iterating for years). But VMProtect/Themida are genuine commercial-grade
virtualization + anti-tamper, and unpacking/devirtualizing them is a real, in-demand RE discipline.

---

## The BUILD stack (protect your own program) — all professional, mostly free

| Your wishlist item | Professional tool that provides it |
| --- | --- |
| Custom emulated CPU (virtualization) | **VMProtect** (demo, vmpsoft.com) and/or **Themida/WinLicense** (demo, oreans.com) — real commercial VMs |
| Mutation / JIT-ish code | VMProtect "Mutation", Themida mutation engine; (research-grade extra: Tigress `Jit`, already installed) |
| Encryption + packing | VMProtect/Themida pack + encrypt the binary |
| Debugger checks | VMProtect/Themida built-in multi-layer anti-debug |
| Integrity / tamper checks | VMProtect/Themida memory-integrity + section checksums |
| Timing checks | built into the protectors; can also add `rdtsc` deltas in source |
| Hardware binding + OS fingerprinting | **WinLicense** / VMProtect licensing (hardware-locked serials) — or hand-roll `cpuid`/MAC/MachineGuid |
| Compile-time obfuscation (extra layer) | **OLLVM fork for x64**: **Hikari** or **Pluto** (CFG flattening, bogus flow, instr. substitution, string enc.). Note: O-MVLL is iOS/Android only — not for this. |

**Platform shift:** this capstone is **Windows x64 PE** (not WSL/ELF) — VMProtect/Themida protect PE files.
That's good: it matches your real target (Unreal games are Windows PE) and uses tools you already have
(Visual Studio 2026, x64dbg at `C:\Tools\x96dbg`).

## The BREAK stack (reverse your own protected binary) — the real skill set

| Step | Tool (status) |
| --- | --- |
| Run + observe, defeat anti-debug | **x64dbg** (have: `C:\Tools\x96dbg`) + **ScyllaHide** plugin (to install) |
| Dump the unpacked image from memory | **Scylla** (ships with x64dbg) |
| Static analysis / decompile | **Ghidra** (have: `C:\Tools\ghidra`) |
| Devirtualize VMProtect x64 (3.0–3.5) | **NoVmp** (GPL, built on **VTIL**) + **vmpfix** |
| Symbolic devirtualization (engine-agnostic) | **Triton** or **angr** |
| Themida/CodeVirtualizer devirt | HWBP on `VirtualProtect` → dump at OEP; CodeVirtualizer static-devirt writeups |

---

## Phased plan (each phase is build-one-layer then break-it)

**Phase C0 — the target (you write it).** A small Windows C "licensed app": reads a serial, derives an
expected value from a **hardware ID** (`cpuid` + volume serial + MachineGuid), accepts/rejects. Compile
clean in VS2026. This is our `check_key`, grown up and hardware-bound. Reverse it clean first (baseline).

**Phase C1 — compile-time obfuscation (Hikari/Pluto OLLVM).** Rebuild with CFG flattening + string
encryption. Reverse it in Ghidra: learn to see through flattening (recover the real control flow).

**Phase C2 — VMProtect (the big one).** Protect the C1 binary with VMProtect demo: virtualize the license
check, enable packing + anti-debug + integrity. Then **break it**: x64dbg+ScyllaHide to run past anti-debug,
Scylla to dump, NoVmp/VTIL to devirtualize the protected function, recover the logic.

**Phase C3 — Themida + hardware licensing (WinLicense).** Re-protect with Themida, add a hardware-locked
serial. Break: HWBP-on-VirtualProtect unpack, dump, devirtualize; and study how the hardware check is done.

**Phase C4 — write it up.** A per-layer report: what each protection does, how you defeated it, what was
easy vs. what needed symbolic execution. That document is the portfolio centerpiece.

**Then → the external test:** a **Tigress Challenge** level or a **FLARE-On** VM challenge — pro-made targets
to prove the skills transfer.

## Install list (fetch when we reach each phase; all into `C:\Tools\`)

- VMProtect demo — vmpsoft.com → Get Demo (Windows)
- Themida/WinLicense demo — oreans.com (your name/email; eval license)
- Hikari or Pluto (prebuilt clang, or build) — for the OLLVM layer
- ScyllaHide — x64dbg plugin (github)
- NoVmp + VTIL (build in VS2026); Triton/angr (pip) when needed

---

## C5 — full "RE-like" bypass chain on our own target

See `phases/re_techniques_reference.md` for the technique->tool map. Make `license_app` resemble
RE, then reproduce the whole bypass chain legally on our own binary:

1. **Make the target RE-like:** bind the license to **multiple HWID sources** (CPUID + C: volume serial +
   PEB + KUserSharedData), add an **anti-tamper CRC** of its own `.text`, then **protect with VMProtect**
   (virtualize `check_license`). Now it mirrors the 3 RE layers.
2. **Build the reusable harness** (our own, in C — becomes part of REAForge):
   proxy-DLL hijack + `DllMain`, IAT hook framework, VEH, shadow-page patch (UD2 trick),
   VirtualProtect/VirtualQuery hooks, RDTSC-timing hook, HWID record/replay.
3. **Find the checks** with Intel Pin (CPUID/RDTSC trace, incl. JIT'd regions via VirtualAlloc hook).
4. **Devirtualize** the VMProtect'd `check_license` with NoVmp/VTIL + our capstone deobfuscator.
5. **Record HWIDs on this machine, replay** to make the check pass as if on another machine — the exact
   "get past the popup" goal from the video, on our own app.

This is the capstone's capstone: a from-scratch, legal reproduction of the modern DRM-analysis workflow.

---
