# ENVIRONMENTS — which box does what (and what to declutter)

Decided 2026-10-25 from a live probe of every environment. The capstone targets are **Windows x64 PE**
binaries, so Windows-native is the primary workbench and everything else is a supporting role.

## The four environments

| Environment | Role | What lives here |
| --- | --- | --- |
| **Windows 11 (native)** | **PRIMARY workbench** — all Windows-PE work | IDA Pro 9.1, Ghidra, x64dbg + ScyllaHide + Scylla, DIE, VMProtect, Themida, Cheat Engine, ReClass.NET, **Intel Pin 4.4 (Windows DBI)**, Frida 17, MSVC/VS2026, msys64 gcc 16, Python libs (targets/license_app/dumps/unicorn/keystone/lief/pefile/r2pipe) |
| **WSL BlackArch** (`archlinux`) | **Specialized Linux RE arsenal** | radare2, rizin, cutter, gdb, ropper, ROPgadget, clang, nasm, ghidra (headless). Add angr/pwntools/frida here when needed (`pip`/`pacman`). Home for Linux-ELF targets + the external test (Tigress Challenge / FLARE-On Linux levels are ELF). |
| **WSL Ubuntu 24.04** | plain Linux build box | gcc, g++, gdb only. **Nothing unique to this lab** (Tigress is no longer installed — see gap below). |
| **Docker Desktop 29.9** | disposable build & detonation sandboxes | reproducible toolchain builds that would pollute the host (OLLVM/LLVM, NoVmp/VTIL), and isolated no-network detonation of untrusted challenge samples. Not a daily RE box. |

## Why this split

- **Targets are Windows PE** → the disassembler, debugger, protectors, DBI and compiler all want to be on the
  same box as the target. That's Windows. ~90% of the capstone happens here.
- **BlackArch is purpose-built** (you were right): it already carries the whole Linux RE arsenal from the
  `[blackarch]` pacman repo. When a target or challenge is Linux ELF, this is the box — r2/rizin/angr/ROP
  tooling is first-class here and painful to assemble on Ubuntu.
- **Ubuntu is now redundant for the lab.** It only has gcc/gdb, which BlackArch also has. Keep it only if you
  use it for non-lab work; otherwise BlackArch is the single Linux distro.
- **Docker is for reproducibility/isolation, not analysis.** Building OLLVM or NoVmp dirties a host with LLVM
  and VS toolchains; do it in a throwaway container. Detonating a FLARE-On sample belongs in a no-network
  container, never on the host.

## Tool-placement rules (avoid clutter)

1. **One home per Linux RE tool — BlackArch.** Do **not** install radare2/angr/ropper/etc. on Ubuntu too.
2. **Ghidra is duplicated** (Windows `C:\Tools\ghidra` **and** BlackArch `/usr/sbin/ghidra`). Windows is
   canonical (GUI). Keep BlackArch's only for headless Linux-ELF runs; it costs nothing (part of the blackarch group) so no need to remove it.
3. **gcc exists in 3 places** (msys64 / Ubuntu / BlackArch) — not clutter: each builds for a different target
   (Windows PE vs Linux ELF). Leave them.
4. **Intel Pin → Windows only.** The DBI target (`license_app.exe`) is PE, so the Windows Pin kit is correct.
   No Linux Pin needed.
5. **Non-lab tools in `C:\Tools`** (ffmpeg, terraform, scrcpy, platform-tools, nginx, vcpkg, yt-dlp, …) are
   your general toolbox — **out of scope, untouched.** The RE-relevant subset is:
   `{DIE, PIN, ReClass.NET, ThemidaDemo, ghidra, msys64, x96dbg (= x64dbg)}`.

REAForge's `tool_registry.py` now probes **both** WSL distros
correctly (it used to only see Ubuntu and mis-reported "command not found" as installed).
