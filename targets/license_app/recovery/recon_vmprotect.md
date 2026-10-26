# RECON — VMProtect-protected binary (`license_app.vmp.exe`)

Static recon of your VMProtect build, static-recon style: **command → key output → what it means.** Evidence from
DIE + pefile run 2026-10-26. Compared against the unprotected marker build `license_app_hardened.exe`.

## 1. Sections & entropy — `diec -e license_app.vmp.exe`

```txt
Total 7.78: packed
  .text   0 bytes        .rdata 0 bytes      .data 0 bytes     (original code/data EMPTIED)
  .fptable/.'FI 0 bytes
  .D1u    512 bytes  0.56 (loader metadata)
  .G#b    1,505,280 bytes  7.79  packed   <-- the VM + packed image
  .reloc  512 bytes  0.59
```

**Means:** VMProtect moved your real `.text/.rdata/.data` *into* the big encrypted section `.G#b` (randomized,
unreadable section name, entropy 7.79 ≈ encrypted). Static tools now see almost nothing — the code only exists
in cleartext in memory, after the stub unpacks it. This is why the break is **dynamic** (run it, then look).

## 2. Imports — pefile, clean vs protected

```txt
license_app_hardened.exe      : 74 imports  (VMProtectSDK64.dll + KERNEL32.dll)
license_app.vmp.exe  :  8 imports  (KERNEL32 only — minimal loader set)
```

**Means:** **Import Protection** collapsed the import table from 74 to 8. The protected binary imports only the
handful of KERNEL32 calls the stub needs to bootstrap (alloc/protect memory, resolve the rest). The real imports
are resolved *by the stub at runtime* and hidden from the on-disk IAT — which is exactly what **Scylla's "Get
Imports / Fix Dump"** rebuilds if you choose to unpack.

## 3. Strings — plaintext scan, clean vs protected

```txt
license_app_hardened.exe      : LICENSED   INVALID LICENSE   (plaintext)
license_app.vmp.exe  : (none)
```

**Means:** the packer encrypts string data too. `"LICENSED"` doesn't exist as plaintext on disk — it's decrypted
into memory at runtime. So the "find `main` via the `LICENSED` string" step **only works live** (x64dbg → Search
for → String references), not on the file.

## Answers

- **Where did the code go?** Into the encrypted `.G#b` section; the named sections are hollow. Only memory has
  the real bytes, post-unpack.
- **Why dynamic, not static?** Code + strings + imports are all encrypted on disk. You must run it to see them.
- **What do the layers I enabled each show here?** Pack → emptied sections + one 7.79-entropy blob; Import
  Protection → 74→8 imports; (Memory Protection + anti-debug don't show statically — they act at runtime, which
  is where the break fights them).
- **Is `check_license`'s algorithm visible?** No — its body is VM bytecode inside `.G#b`. But we don't need it:
  the native branch in `main` that consumes the result is the target (see `vmprotect_break_cheatsheet.md`).
