# FIXLIST — defenses to build into my own games

Each item: **what**, **why (which attack it answers)**, **how (UE specifics)**. Status: TODO / DONE.

## Shipping hardening (from static recon setup)

- [ ] **Sign every shipped exe/dll (Authenticode).** Why: proves origin, lets anti-cheat and
      users detect tampered binaries. How: sign in the packaging pipeline (signtool + EV cert).
- [ ] **Never ship .pdb files.** Why: symbols hand attackers every function name. How: keep PDBs
      in a private symbol server for crash reports; exclude from the build output.
- [ ] **Strip embedded debug info and symbol tables too, not just PDBs.** Why: Veloren ships ~160 MB of
      DWARF + 160k symbols -> `Health::change_by` is one search away in Ghidra. How: UE/MSVC: no `.pdb`
      in the package, `/DEBUG` output kept private; Rust/GNU: `strip = true`, `debug = 0`. Verify every release
      with `objdump -h` / DIE (no `.debug_*`, no overlay symbol table).
- [ ] **No dev/override switches in shipping builds.** Why: Veloren's `VELOREN_ASSETS_OVERRIDE` env var
      loads a whole alternate asset folder. How: UE: compile out console commands and `-ini`/override
      arguments in Shipping (`#if !UE_BUILD_SHIPPING`).
- [ ] **Server verifies the client's content.** Why: loose/modified data files. How: server sends an asset
      manifest hash challenge at login; mismatch = kick (multiplayer only — and the server still never trusts client math).
- [ ] **Package as Shipping, test the Shipping build.** Why: Development builds keep the console
      and debug commands. How: Project Launcher / `RunUAT BuildCookRun -clientconfig=Shipping`.
- [ ] **Encrypt and sign paks.** Why: stops casual asset extraction/modding. How: Project Settings
      -> Crypto -> generate AES key + enable pak signing. Caveat: the key must live in the exe to
      decrypt, so it *will* be recovered by a determined attacker — it raises the bar, it is not a wall.
- [ ] **Treat DRM and anti-cheat as speed bumps, not walls.** Why: the Khazan install showed a
      Denuvo-protected AAA game defeated with a hypervisor-level bypass. Anything the client can
      run, the client's owner can eventually change. Real protection = server authority (see anti-cheat synthesis).

## Memory-editing defenses

- [ ] **Obfuscate critical stats in memory.** Why: health was findable as `displayed*256`, a fixed guessable
      transform. How: store `value XOR session_key` + a checksum; recompute on read; rotate the key per
      session. (Veloren's ×256 fixed-point only slows a beginner — don't rely on it.)
- [ ] **Sanity-check every stat mutation.** Why: freezing `current` was never questioned. How: enforce
      `current <= maximum` (Veloren already does in `change_by`), reject health gains without a heal event,
      rate-limit changes. Client-side these only slow cheats; server-side they're real.
- [ ] **Keep mutation authoritative on the server; replicate down.** Why: the client holds a writable copy;
      freezing it is cosmetic online. How: model after `change_by` on the server + a dirty flag that syncs to
      clients (Veloren's `DerefFlaggedStorage`). The client may never be trusted to report its own health.
- [ ] **Integrity-hash stat blocks over FIELDS, not raw bytes.** Why: a direct write bypasses the setter;
      a shadow checksum catches it. How: hash only initialised fields — padding (bytes `0x27`/`0x5F` here)
      holds junk and would cause false mismatches. Client-side detection only (defeatable), not prevention.
- [ ] **Detect foreign handles / known tools / debug registers — as telemetry, not a wall.** Why: attach,
      freezing, and hardware breakpoints are all observable (open handle with VM_WRITE, tool signatures,
      DR0–DR7 set). How: enumerate handles to self, scan drivers/processes, check own CONTEXT. Every one is
      defeatable (renamed tools, kernel reads, DBVM) — treat as cost-raising signals, never as protection.

<!-- Later work adds: server RPC WithValidation, movement/speed-hack correction,
     hook/debugger detection, EAC via Epic Online Services. -->

## Anti-tamper / anti-debug (from the virtualization side-track)

- [ ] **Don't trust libc for anti-debug.** Why: an LD_PRELOAD `ptrace` stub defeated a virtualized check in
      one line. How: call `syscall(SYS_ptrace,...)` directly (no symbol to override), and read `/proc/self/status`
      TracerPid via raw syscalls.
- [ ] **Layer independent anti-debug checks** (TracerPid, rdtsc timing, 0xCC scan, parent-pid, multiple ptrace
      sites), each inside the VM + literal-encoded, so defeating one isn't enough. No single point of failure.
