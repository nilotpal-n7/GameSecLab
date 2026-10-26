# RE-crack techniques

Source: From several official commercial websites' free educational docs.

## How that RE works (3 layers)

1. **Hardware-ID binding + token file.** RE pulls constants out of protected functions, server encrypts
   them with a key derived from **hardware IDs**, returns a **token file**. At runtime the game decrypts
   constants using the local HWIDs; wrong machine -> wrong constants -> crash. A startup check compares HWIDs
   to the token and re-requests if they changed. **Bypassing that startup check = identifying every HWID the
   game uses.** HWID sources seen: **CPUID**, **system-DLL headers** (ntdll/kernel32/kernelbase),
   **KUserSharedData** (fixed address `0x7FFE0000`), **PEB**.
2. **Anti-tamper.** Continuous **CRC checksums** of its own code (run inside the VM) -> any byte patch = death.
3. **Virtualization (VMProtect VMP2).** Stack VM: virtual IP = RSI, virtual SP = RBP, virtual regs = offsets
   from RDI. **Encrypted handler table + instructions (rolling encryption), obfuscated handlers**, plus
   **jump obfuscation** (code split into chunks stitched by jumps, interleaved) and **dead-store obfuscation**
   (valid junk instructions adding noise).

## The attacker technique stack → our tool, our legal target

| # | Our legal reproduction (own binary + VMProtect) | Tool (have/need) |
| --- | --- | --- | --- |
| 1 | DIE recon (RE v2 + Steam, packed .sdata) | DIE on our VMProtect'd `license_app` | DIE ✓ |
| 2 | Run + dump after self-unpack | Scylla dump of our packed binary at OEP | x64dbg+Scylla ✓ |
| 3 | Ghidra: garbage outside protected section | Ghidra/IDA on the dump | Ghidra ✓, IDA ✓ |
| 4 | **Deobfuscate**: flatten jumps ("all roads to Rome") + remove dead stores (read/write liveness) with **libcapstone** | Build our own capstone deobfuscator on VMProtect output | capstone ✓ (build the pass) |
| 5 | **VMP2 recovery**: find VM entry (`lea r12,[table]`), decrypt handler table (xor/not/rotate), pattern-match handlers->JSON, emulate VM (rolling enc, bidirectional VIP) | Devirtualize our VMProtect fn — use **NoVmp/VTIL** (the "back.engineering" tooling the video cites) and/or our emulator | NoVmp+VTIL (build), unicorn ✓ |
| 6 | Key insight: VM lacks **CPUID/RDTSC** -> full VM-exit -> findable native instr | Same holds for VMProtect; find native CPUID/RDTSC in our target | — |
| 7 | **DLL hijacking** (own DLL w/ `DllMain`, same exports) to run first | Drop a proxy DLL next to our own app | write in C |
| 8 | **IAT hooking** (overwrite import pointers) + keep original = hook framework | Our own hook framework vs our own app | write in C |
| 9 | **VEH** (vectored exception handler) to catch access violations + edit registers | Our VEH harness | write in C |
| 10 | **Patch w/o tripping CRC**: `UD2` 2-byte -> invalid-opcode exception -> VEH redirects to **shadow page** (copy code, patch, mark real page read-only, redirect execution) | Shadow-page patch our own app | write in C |
| 11 | **Hook VirtualProtect/VirtualQuery** so the target can't reset page protection (report success, don't change) | Our hooks | write in C |
| 12 | **Intel PIN** (DBI) to trace CPUID/RDTSC, incl. **JIT'd** CPUID in heap (hook VirtualAlloc, shadow the big region) | PIN tracer on our app | **Intel Pin 4.0** (install) |
| 13 | **HWID record/replay**: struct of CPUID + DLL-header reads + KUserSharedData + PEB; record on A, replay on B | Our app binds to these; build the record/replay lib | write in C |
| 14 | **Timing defeat**: RE RDTSC timing checks -> hook RDTSC to a small consistent delta | Our RDTSC hook | write in C |
| 15 | **VEH ordering**: register our handler first | Handler-chain ordering | write in C |

## What to install (when we reach each step)

- **Intel Pin 4.4** (free DBI) — INSTALLED at `C:\Tools\PIN\...\pin.exe`. Starter tool
  `reaforge/pintools/recon_trace.cpp`; build/run guide `phases/pin_lab.md` (Windows kit uses LLVM clang-cl;
  build at step #12).
- **NoVmp + VTIL** — build in VS2026 for step #5 (VMProtect devirtualization).
- Everything else (#7–#15) we **write ourselves** in C — that's the point: our own VEH/IAT/DLL-hijack/shadow-page/
  HWID-record-replay harness becomes a reusable part of REAForge.
