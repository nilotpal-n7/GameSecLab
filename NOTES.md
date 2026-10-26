# NOTES — running lab log

Newest entries at the bottom. Write in your own words: what you did, what you saw, why it matters.

---

## 2026-10-22 — Setup

### Network note

`download.veloren.net` is intercepted by a **Fortinet FortiGate** TLS-inspection firewall on this
network (cert issuer `CN=FGT37DTK18800193`, not trusted by Windows). Did NOT disable certificate
checks — got the official build from a GitLab/GitHub release mirror instead. That is itself a lesson:
a man-in-the-middle box re-signing TLS is exactly what certificate validation exists to catch.

> The early Veloren memory-analysis work (live scan, server-vs-client proof, ECS struct recovery,
> Frida hooks) now lives as reusable method under `categories/voxel_rust/` and `knowledge/method/`.

---

## 2026-10-23 — Side track: virtualization & anti-tamper (legal Denuvo-technique study)

- Denuvo on a shipping game = DRM circumvention (illegal, DMCA §1201), declined repeatedly across
  reframes. Legal path that teaches the SAME skills: virtualize your OWN C function with **Tigress**
  (WSL), then recover it in **Ghidra**. Answer key available (compile plain + virtualized).
- Built toy `vmlab/keycheck.c` (check_key hashes a 10-char key -> magic 0x32629093; key RELAB-2026).
  Plain build verified (WIN/LOSE). Guide: `knowledge/method/virtualize.md`.

## 2026-10-23 — vmtrack staged end-to-end

- Tigress 3.1-bin installed in WSL. Virtualized check_key -> `keycheck_vm` (Virtualize, magic still
  visible) and `keycheck_vm2` (EncodeLiterals+EncodeArithmetic+Virtualize). Plain ELF = answer key.
- Ghidra project `vmlab/ghidra_proj/KeyCheck.gpr`: all imported + auto-analyzed (headless, jdk-23).
- Deliverable skeleton: `vmlab/recovery_notes.md` (exercises A-D). Guide: `knowledge/method/virtualize.md`.
- Nuance: plain Virtualize hides control flow but NOT literals -> 0x32629093 leaks; the real skill is
  recovering the ALGORITHM (dispatcher + opcode map), not grepping the scalar.

## 2026-10-24 — Capstone decided: pro-tool protect-and-break (legal Denuvo analog)

- Protect OWN program with the real industry tools (VMProtect demo + Themida/WinLicense demo + an
  OLLVM x64 fork), then reverse own output with the pro RE stack (x64dbg+ScyllaHide, Scylla dump,
  NoVmp/VTIL devirt, Triton/angr). Windows x64 PE. Plan: `targets/license_app/protect_and_break.md`.

## 2026-10-24 — REAForge (AI RE orchestrator) + tool install sweep

- Built `reaforge/` (tool_registry, llm_backend[3 modes], orchestrator skeleton, README, scope guard).
- LLM modes: (1) API multi-provider; (2) Bridge = Claude Code auto-answers a file mailbox while
  driving the session; (3) Custom (user's own tool via stdin/stdout). Ollama optional. No API keys set.
- Installed free RE core: capstone, unicorn, keystone, lief, r2pipe (pefile/frida already). ScyllaHide
  v1.4 into x64dbg plugins. Protectors present: VMProtect Demo, Themida. OSS fallback = Tigress.

## 2026-10-24 — Clean build done + bridge mode proven

- clean target `targets/license_app/src/license_app.c`: hardware-bound license (C: volume serial ->
  expected_key -> 8-hex compare). Built + verified LICENSED with keygen's key.
- IDA Professional 9.1 found + registered (`idat.exe` headless).
- **Bridge mode end-to-end:** `REAFORGE_LLM=bridge python reaforge/orchestrator.py recon <exe>` wrote
  facts.json, posted a bridge request, Claude Code answered it automatically, orchestrator printed the
  plan. Automatic while a Claude Code session drives it (the design goal).

## 2026-10-24 — Folded in the RE-crack techniques

- Educational transcript analyzed -> `knowledge/method/re_techniques.md`: 3 RE layers (HWID+token,
  anti-tamper CRC, VMProtect VM) and the attacker stack, each mapped to a LEGAL reproduction on our
  OWN VMProtect-protected binary + the tool for it.
- Added the full bypass chain (full bypass chain): multi-source HWID + anti-tamper CRC + VMProtect, then
  our own DLL-hijack/IAT/VEH/shadow-page/VirtualProtect-hook/RDTSC/HWID record-replay harness + Intel
  Pin tracing + NoVmp devirt. Harness becomes reusable REAForge tooling.

## 2026-10-25 — Intel Pin installed + environment layout decided

- **Intel Pin 4.4** at `C:\Tools\PIN\...\pin.exe`. REAForge detects it. Starter pintool
  `reaforge/pintools/recon_trace.cpp` (instr count + CPUID/RDTSC/RDTSCP address trace). Build needs
  VS2026/clang-cl. Guide: `knowledge/method/pin_lab.md`.
- **Environments mapped** -> `ENVIRONMENTS.md`. Windows-native = primary workbench; **WSL BlackArch**
  = the specialized Linux RE arsenal; **WSL Ubuntu** = plain build box; **Docker** = disposable
  sandboxes. Rule: one home per Linux RE tool (BlackArch), don't duplicate.
- Fixed `reaforge/tool_registry.py`: probes both distros now and validates the path. Added the neutral
  reference `knowledge/binary_protection.txt` (defensive/authorized-lab framing of the same tech).

## 2026-10-25 — OLLVM layer done (OLLVM compile-time obfuscation)

- Installed **Hikari/Arkari OLLVM fork** (clang 21.1.0, x64-windows-msvc) to `C:\Tools\ollvm`.
- Rebuilt `license_app.c` with `-irobf-cff` (flatten), `-irobf-cse` (string-enc), `-irobf-cie`
  (int-const-enc), `-irobf-indbr`. 143,872 -> 153,600 bytes; semantics preserved (keygen still LICENSED).
- Re-reversed via `reaforge/ida/decompile.py` (string anchors gone, so anchor on `main`). Findings in
  `targets/license_app/recovery/recovery_ollvm.md`: strings encrypted, constants became `dwordX±K` but
  FOLD back to 0x1505/33/0xF from static `.data` (proved with pefile), flatten+indbr ballooned the
  reachable set to 510 fns / 34,585 lines vs the clean build's ~15. Honest takeaway: obfuscation raised analysis
  cost, did NOT change the algorithm — same keygen works. That's why VMProtect is the real step up.

## 2026-10-26..27 — VMProtect 3.11 broken + consolidation

- VMProtect target (`targets/license_app/.../license_app.vmp.exe`) and the Dead Cells `libhl.vmp.dll` benchmark
  both devirtualized end-to-end: validated, blind-recovered, round-peeled, and SMT-proven. See
  `targets/license_app/README.md` and `targets/dead_cells/README.md`.
- Repo consolidated into three layers — generic `reaforge/core` engine, reusable `categories/`, and
  per-title `targets/` — with ruff linting and x86/x64×EXE/DLL smoke tests. See the root `README.md`.
