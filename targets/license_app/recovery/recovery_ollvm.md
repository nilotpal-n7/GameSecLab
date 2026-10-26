# OLLVM layer — compile-time obfuscation and re-recovery

**Layer added:** OLLVM-family compile-time obfuscation on the *same* `license_app.c` source.
**Measurement:** how much harder is it to re-derive the clean-build keygen after this layer?

## Toolchain

- **Hikari/Arkari OLLVM fork** (Ridter/Hikari `Win64-MT-20.1.7-obf1.7.0`), **clang 21.1.0**, target
  `x86_64-pc-windows-msvc`, at `C:\Tools\ollvm\install\bin\clang.exe` (registered in REAForge as `ollvm_clang`).
- MSVC headers/libs auto-detected via VS 2026 (VS "18" Enterprise, MSVC 14.51) + Win11 SDK 10.0.26100.

## Build

```bash
clang license_app.c -O2 -o license_app_clang_clean.exe                       # clean baseline (same compiler)
clang license_app.c -O2 -o license_app_ollvm.exe \
  -mllvm -irobf -mllvm -irobf-cff -mllvm -irobf-cse -mllvm -irobf-cie -mllvm -irobf-indbr
```

Passes: `-irobf-cff` control-flow flattening, `-irobf-cse` string encryption, `-irobf-cie` integer-constant
encryption, `-irobf-indbr` indirect branches. (This fork names flattening `cff`, not the `fla` the README text
shows.)

- **Size:** clean `143,872` → OLLVM `153,600` bytes (+10 KB).
- **Semantics preserved:** `license_app_ollvm.exe 75685AB2` → `LICENSED` (exit 0); junk key → `INVALID LICENSE`.
  **The clean-build keygen still works unchanged** — obfuscation changed the *presentation*, not the algorithm.

## What each pass did to the recovery

### 1. String encryption (`-irobf-cse`) — defeated the recon anchor

Plaintext scan of the two builds:

| string | clean build | OLLVM build |
| --- | --- | --- |
| `LICENSED` / `INVALID LICENSE` / `hex-key` | present | **gone** |

In the clean build we found `check_license` in one step by x-ref'ing the `"LICENSED"` string. In the OLLVM build that anchor is encrypted,
so the first headless pass (anchored on strings) produced an **empty** result — we had to re-anchor on `main`.
Cost: a recon step, not a wall.

### 2. Integer-constant encryption (`-irobf-cie`) — hid the literals, still foldable

Clean `check_license` (Hex-Rays):

```c
acc = volume_serial ^ 0x1505;
for (i=0;i<8;i++){ acc = (33*acc) ^ ((volume_serial>>4*i)&0xF); acc += i*7; }
return strtoul(key,16) == acc;
```

OLLVM `check_license` (= `sub_140001000`) — same shape, every literal replaced by a global ± immediate:

```c
VolumeSerialNumber[0] = ...;
GetVolumeInformationA(RootPathName, 0, ...);
v4 = ... ((VolumeSerialNumber[0] ^ (dword_14002400C - 672300167))   // the 0x1505 seed
          * (dword_140024010 - 576718378))                          // the * 33
          ^ VolumeSerialNumber[0] & (dword_14002407C - 1281108295)  // the & 0xF
          * ...                                                      // (loop unrolled x8 at -O2)
return (unsigned int)sub_140006900(key, 0, ...) == v4;              // strtoul(key,16)
```

The constants `0x1505`, `33`, `0xF`, the shifts and `+i*7` are no longer visible. **But** each `dword_140024XXX`
is a **statically-initialized global**, so the real value folds out by reading `.data`:

| global (@VA) | stored value | `stored + imm` | real constant |
| --- | --- | --- | --- |
| `dword_14002400C` | `0x2812918C` | `672305548 - 672300167` | **5381 = 0x1505** (seed) |
| `dword_140024010` | `0x2260064B` | `576718411 - 576718378` | **33** (multiplier) |
| `dword_14002407C` | `0x4C5C2956` | `1281108310 - 1281108295` | **15 = 0xF** (mask) |

(Folded directly from the on-disk PE — see the `pefile` snippet in NOTES. A constant-propagation pass in
IDA/Ghidra does this automatically.) Cost: one const-fold pass, then the algorithm reads exactly as the clean build.

### 3. Control-flow flattening (`-irobf-cff`) + indirect branches (`-irobf-indbr`) — inflated the graph

- 59 `while(1)` state-dispatchers appear across the binary; `main` is flattened.
- Anchoring on `main` and pulling one level of callees reached **510 functions / 34,585 lines** of pseudocode
  (indirect branches hide the real call targets, so the reachable set explodes) — vs **1 function / ~15 lines**
  in the clean build.
- **Nuance:** flattening barely touched `check_license` itself. At `-O2` the 8-iteration loop is unrolled to
  straight-line arithmetic with no branches, so there is almost no control flow to flatten — `cff` bites
  branchy functions (`main`, the CRT), while `cie`/`cse` are what actually obscured the *check*.

## Cost delta: clean → OLLVM

| | clean | OLLVM |
| --- | --- | --- |
| Find the check | x-ref `"LICENSED"` (instant) | string encrypted → re-anchor on `main` |
| Read the constants | visible in pseudocode | encrypted → read `.data` + const-fold |
| Decompile size | 1 fn / ~15 lines | 510 fns / 34,585 lines reachable |
| Keygen | derived in minutes | **same keygen still valid** (`→ LICENSED`) |

## Honest takeaway

Compile-time obfuscation raised **analysis cost** (hid constants and strings, ballooned the call graph) but
did **not** change what the program computes — the clean-build keygen is unchanged and still prints `75685AB2`. The
literals are recoverable by constant-folding static globals; the flattening is navigable. This is exactly why
**VMProtect virtualization** is the real step up: it replaces the native instructions with bytecode for an
embedded VM, so there is no longer a native arithmetic DAG to fold — you must recover the VM first.

## Artifacts (git-ignored: binaries + the 34k-line dump)

`license_app_ollvm.exe`, `license_app_clang_clean.exe`, `ida_decompile_ollvm.txt`. Rebuild with the command above;
re-dump with `reaforge/ida/decompile.py`.
