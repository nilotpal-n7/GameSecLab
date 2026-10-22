# FIXLIST — defenses to build into my own games

Each item: **what**, **why (which attack it answers)**, **how (UE specifics)**. Status: TODO / DONE.

## Shipping hardening (from Phase 0 setup)

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
      run, the client's owner can eventually change. Real protection = server authority (see Phase 5).

<!-- Later phases add: obfuscated stat wrapper, sanity checks, server RPC validation,
     movement correction, hook/debugger detection, EAC via Epic Online Services. -->
