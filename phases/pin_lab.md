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

## Build (Windows — needs VS2026 / clang-cl, the kit's documented path)

The kit ships a template under `source\tools\MyPinTool\`. Easiest route: drop our source in and reuse its
build files.

```bash
set PIN=C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows
copy C:\Tools\GameSecLab\reaforge\pintools\recon_trace.cpp %PIN%\source\tools\MyPinTool\
```

Then either:
- **Visual Studio:** open `%PIN%\source\tools\MyPinTool\MyPinTool-clang.vcxproj`, set the source to
  `recon_trace.cpp`, build **Release x64** → produces `obj-intel64\recon_trace.dll`; or
- **Command line (VS "x64 Native Tools" prompt):** from that folder,
  `make obj-intel64/recon_trace.dll` using the kit's `makefile` (clang-cl toolchain).

> We build this **when we reach C5 step 3** — it needs your VS hands and we're currently at C0→C1. The source
> is ready and reviewed; no need to build it early.

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
