# Intel Pin lab — dynamic binary instrumentation (DBI)

**Installed:** Pin **4.4** at
`C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows\pin.exe` (REAForge detects it as `pin`).
The reference `../binary_protection_instrumentation_reference.txt` §6 and `re_techniques_reference.md`
step #12 both point here.

**Scope:** authorized targets only — your own `license_app.exe`, CTF/crackmes, owned games you may mod.
Pin injects analysis code into a live process; never attach it to someone else's protected product.

## Why Pin, next to the tools we already have

- **Ghidra/IDA** = static (the on-disk bytes). **x64dbg** = interactive single-stepping.
- **Pin** = programmatic observation of *every executed instruction* with almost no manual driving. It sees
  **JIT'd / self-generated code** that never exists on disk — exactly what VM-protectors emit. That's why it
  is the right tool for C5 step 3 ("find the native CPUID/RDTSC a VM can't virtualize").

## The starter tool: `reaforge/pintools/recon_trace.cpp`

Counts instructions and logs the runtime address of every `cpuid` / `rdtsc` / `rdtscp`. Those are the
hardware-fingerprint and timing anchors in a protected binary.

## Build — one command (WORKING, validated 2026-10-26)

`reaforge/pintools/build.bat <tool.cpp>` builds any pintool. No VS ClangCL component needed — it drives
**Pin's own `make`** (whose `pin-clang-cl++` / `pin-ld` wrappers are bash scripts) with our **Hikari clang-cl**
+ **msys64 make** on PATH, inside a VS2026 env (for the Windows SDK libs). Source stays in the repo; it stages
into `%PIN%\source\tools\REAForge\`, builds, and copies the `.dll` back here.

```bat
cmd /c "C:\Tools\GameSecLab\reaforge\pintools\build.bat recon_trace.cpp"
REM -> reaforge\pintools\recon_trace.dll
```

Prereqs (all already installed): Pin 4.4, Hikari clang-cl (`C:\Tools\ollvm\install\bin`), msys64 make
(`C:\Tools\msys64\usr\bin`), VS2026 (vcvars64). The vcxproj/MSBuild route does **not** work (VS has no ClangCL
toolset) — use `build.bat`.

> Why the kit's wrappers matter: `pin-clang-cl++` and `pin-ld` are `#!/bin/bash` scripts that add the PIN_CRT /
> XED include+lib flags. That's why we build through `make` (run under msys sh), not by calling cl/clang-cl
> directly from cmd.

## Run (once built)

```bash
C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows\pin.exe ^
  -t C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows\source\tools\MyPinTool\obj-intel64\recon_trace.dll ^
  -o C:\Tools\GameSecLab\capstone\pin_recon.log ^
  -- C:\Tools\GameSecLab\capstone\license_app.exe 75685AB2
```

Read `capstone\pin_recon.log`: each `cpuid/rdtsc @ 0xADDR` line is a place to breakpoint in x64dbg or mark in
IDA. On the **clean C0** build you'll see `GetVolumeInformationA`'s path, not raw cpuid; after VMProtect (C2)
the native cpuid/rdtsc the VM can't hide is what this surfaces.

## Safe warm-up exercises (from the reference, §6)

1. Instruction count on clean `license_app.exe` → baseline.
2. Same after the C1/C2 protections → watch the count explode (DBI makes the obfuscation cost visible).
3. Compare `-O0` vs `-O2` builds on a deterministic input.

## Next Pin tools to add (later phases)

- `callTrace` — log calls to a named routine (C5: watch the license check fire).
- `virtualloc_shadow` — hook `VirtualAlloc`/`VirtualProtect` to catch JIT'd regions, then instrument them
  (C5 step 3, the "JIT'd CPUID in heap" case).
