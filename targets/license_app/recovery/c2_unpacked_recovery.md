# C2 — BREAKTHROUGH: VMProtect 3.11 defeated by emulation-unpacking

After x64dbg, ScyllaHide, and Pin all lost to 3.11's anti-analysis, the **emulation** route won.

## What we did

Ran `vmp-lazy-unpack` (Unicorn emulation; `C:\Tools\_downloads\research\vmp-lazy-unpack`) on
`license_app_c2.vmp.exe`:

```text
emulation reached unpacked entry   (89 s, 122 IAT entries, 126 import resolutions)
-> output/license_app_c2.vmp_unpacked.exe  (+ .imports.json)
```

No debugger, no DBI, no anti-debug fight — under full emulation none of VMProtect's checks
(KUSER_SHARED_DATA reads, CPUID/RDTSC timing, direct syscalls, self-checksumming) can observe us.

## Proof the protection is stripped

| | packed | unpacked |
| --- | --- | --- |
| DIE | `VMProtect[packed]` | `Unknown` (no protector) |
| `.text` | 0 bytes | 88 KB real code (entropy 6.5) |
| strings | encrypted | `LICENSED` / `INVALID LICENSE` / `hex-key` restored |
| imports | 8 (hidden) | `.idata` rebuilt, 122 entries |

## Recovered `main` (IDA Hex-Rays on the dump; `reaforge/ida_unpacked.py`)

```c
sub_140001130(argc, argv):                 // main — fully native, recovered
  if (argc == 2) {
    if (sub_140001000(argv[1])) puts("LICENSED");        // sub_140001000 = check_license
    else                        puts("INVALID LICENSE");
  } else printf("usage: %s <8-hex-key>\n", argv[0]);
```

`sub_140001000` (check_license) = the only still-virtualized function (VM bytecode in `.G#b`); Hex-Rays returns
`None` for it. The **native decision branch** (`call check_license` → `test eax,eax` → `jz`) is now plainly
visible — the runtime-bypass target, no longer behind the packer/anti-debug.

## Status

C2's hard part is **done**: packing + anti-debug + anti-tamper + timing all defeated, `main` recovered, the
virtualized check isolated. Two ways to finish:

1. **Devirtualize `check_license`** with **Pushan** (arXiv:2603.18355) → recover the hash algorithm to C
   pseudocode from the VM bytecode alone (the "pure" recovery).
2. We already recovered that algorithm at **C0** (keygen prints `75685AB2`), so the key is known; the native
   branch flip would force LICENSED on any key.

## The lesson

Against modern VMProtect anti-analysis, **don't fight the runtime — emulate it.** Debuggers and DBI are
observable (flags, timing, syscalls); a controlled CPU emulator is not.
