# Themida layer — recovery (license_app.themida.exe)

Target: `license_app.themida.exe` — **Themida x64 3.2.4 (2026, demo)** protecting `license_app_vm.exe`
(the clean check with `check_license`'s body wrapped in `VM_START/VM_END`). DIE: `Themida/Winlicense(3.XX)`.

## What the protection did

- **Entry Point Virtualization:** the first 18 bytes of the entry (`0x1490–0x14A2`) are virtualized.
- **check_license virtualized:** macro region `0x14FB–0x158E` (our `VM_START/VM_END`) runs in a SecureEngine VM.
- **Demo restriction:** *all* virtualization macros are forced to **Falcon Tiny** (the weakest VM) regardless
  of the EAGLE64 Black selection — true EAGLE64 needs a licensed Themida.
- Full-strength otherwise: packing (112 KB → 1.8 MB), anti-debug, Advanced API-Wrapping, string encryption,
  Detect File/Registry Monitors, Anti-File-patching, Anti-Sandbox.

## Break notes (x64dbg)

- **Anti-debug beaten** by ScyllaHide's `Themida x86/x64` profile — the demo nag appeared under the debugger
  with no "debugger found".
- **Hardware breakpoints are detected** (Themida reads the DR registers → "debugger found"). Enabling
  ScyllaHide **DRx Protection** hides them, but then it also blocks x64dbg from *installing* its own HW BPs.
- **Clean OEP capture resisted** (HW BP neutralized; memory-access BPs fire on SecureEngine's decrypt reads).
  Modern Themida resists public unpacking the same way VMProtect 3.11 resists NoVmp — that version lag IS the
  lesson. A full clean dump (with the wrapped IAT rebuilt) is the hard, licensed-tool / manual frontier.
- **Clean dump — DONE (code-complete).** Scylla targeting the exe (imagebase `0x140000000`, OEP `base+0x1490`):
  Dump + Fix Dump → `dumps/license_app.themida_dump_SCY.exe`. The dump holds the original code at the original
  RVAs — `main @0x2490`, `check_license @0x14E0` (prologue then `jmp` into the SecureEngine VM), the verdict
  branch `test eax,eax / jnz` at `0x24AE/0x24B0`, strings intact. **IDA Hex-Rays decompiles `main` cleanly** —
  the full licence-check control flow recovered from the protected binary.
  Gotcha that cost us several tries: at the `GetVolumeInformationA` break RIP is inside kernel32, so the
  integrated Scylla first dumped **kernel32** (imagebase `0x7FFE35320000`, our code absent). Fix: **Pick DLL →
  the exe** so the target base is `0x140000000`.
- **IAT caveat:** `Get Imports` = **8 valid / 28 wrapped** of 36 (Advanced API-Wrapping; `DIRECT IMPORTS = 0`).
  Scylla can't resolve modern Themida wrappers, so the dump is **analyzable but not directly runnable** —
  unwrapping the 28 stubs is the dedicated-unwrapper frontier. (A runnable crack = the live branch-flip bypass.)

## The bypass (no unpack, no devirt)

`main` is **native** — only `check_license`'s body is in the VM. IDA Hex-Rays / objdump of the clean build:

```
1400024a9  call  check_license
1400024ae  test  eax, eax
1400024b0  jnz   loc_1400024CA     ; taken → "LICENSED", fall-through → "INVALID LICENSE"
```

**Patch `0x1400024b0`: `75` → `EB`** (jnz → jmp) ⇒ any key prints `LICENSED`. If Themida's Memory-Guard reverts
the byte edit, force the register instead (make `eax = 1` right after `call check_license`) so nothing on the
code page is modified.

## Ground truth (Hex-Rays of the clean build — confirms our keygen)

```c
check_license: acc = serial ^ 0x1505;
               do { acc = (33*acc ^ ((serial >> (4*i)) & 0xF)) + 7*i; } for i in 0..7;
               return strtoul(key,16) == acc;   // == expected_key() in config.py
```

## Takeaway

Commercial VM protectors move the cost to **understanding** the code (unpack + devirt), not to **defeating the
check** — the native verdict branch falls to a one-byte patch regardless of VM strength. The demo additionally
caps the VM to Falcon Tiny, so even the devirt here would be easy; a licensed EAGLE64 build is the real frontier.
