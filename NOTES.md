# NOTES — running learning log

Newest entries at the bottom. Write in your own words: what you did, what you saw, why it matters.

---

## 2026-10-22 — Setup

### Why not the Khazan install?

The first look at `C:\Games\The First Berserker - Khazan` showed it is the commercial game, not
a personal project:

- `KZ.exe` carries a valid Authenticode signature from **Neople Inc.** (DigiCert-issued).
- The UE project name is `BBQ` (`BBQ\Binaries\Win64\BBQ-Win64-Shipping.exe`), Steam app 2829250.
- `Clean_HV_Files.bat` removes FitGirl-repack and Denuvo-bypass files (`DenuvOwO.nfo`,
  `hyperkd.sys`, `SimpleSvm.sys`, a `steamclient64.dll` emulator, a `winmm.dll` proxy loader).

**Recon lesson already learned:** before running a single tool, three things told the whole
story — the code-signing certificate, the folder/project names, and leftover files. Real
analysts always start with "what is this, and where did it come from?"

**Security lesson:** hypervisor-based Denuvo bypasses require turning OFF Virtualization-Based
Security and Memory Integrity (HVCI) and loading a kernel/hypervisor driver from a crack —
that is ring -1 code from an anonymous source. Checked: VBS and HVCI are running again and no
crack drivers are registered.

### Targets chosen

- **Veloren v0.18.0** — open-source (GPL) 3D action RPG: melee, dodge-roll, health, energy
  (stamina). Single-player runs a *real server* inside your process -> perfect for seeing
  server authority overwrite client cheats.
- **Lyra Starter Game** — Epic's free UE5 sample, packaged as Shipping. Used for the
  Unreal-specific lessons (reflection, GObjects/GNames, ProcessEvent).

### Network note

`download.veloren.net` is intercepted by a **Fortinet FortiGate** TLS-inspection firewall on
this network (cert issuer `CN=FGT37DTK18800193`, not trusted by Windows). Did NOT disable
certificate checks. Got the official v0.18.0 build from Veloren's GitLab release instead.
That is itself a lesson: a man-in-the-middle box re-signing TLS is exactly what certificate
validation exists to catch.

### Re-downloading the target (targets/ is git-ignored)

- Source: GitLab release v0.18.0 -> "Windows (x86_64)" asset
  `https://gitlab.com/veloren/veloren/-/jobs/12844032151/artifacts/download`
- Saved as `targets\Veloren\_download\veloren-v0.18.0-windows-x86_64.zip` (464,592,174 bytes)
- SHA256 `71F07893D842F871C63C726095A92AFAEAE77941AF1D7186E54195032E335866`
- Extracted to `targets\Veloren\v0.18.0` (`veloren-voxygen.exe`, `veloren-server-cli.exe`, `assets\`)

---

## 2026-10-22 — Phase 0: static recon of Veloren

Full annotated evidence in `RECON.md`. Key takeaways:

- **Built with:** Rust + MinGW-w64 (GNU). Two proofs: DIE says `Compiler: MinGW` / `Language: Rust`,
  and the bundled `libgcc_s_seh-1.dll` / `libstdc++-6.dll` / `libwinpthread-1.dll`.
- **Not packed.** Total entropy 6.35, `.text` 6.22. DIE's red `Protection: Generic` and
  `Packer: Generic` were **false positives** (24 sections because of DWARF; `.pdata` is a dense address
  table). Lesson: a heuristic is a hint — confirm with entropy + section names.
- **Huge debug leak:** ~160 MB of DWARF `.debug_*` sections + 160,307 symbols (67,559 Rust). The 13 MB
  DIE "overlay" is the COFF symbol table (`PointerToSymbolTable` = overlay offset `0x0ebae800`).
  `veloren_common::comp::health::Health::change_by` is probably where all damage and healing go -> target for Phases 3/4.
- **ASLR + high-entropy ASLR + NX on** -> addresses move every run -> pointer paths in Phase 2.
- **Data:** 2,826 plain-text `.ron` files (abilities, items). E.g. `sword/agile_cascade.ron`:
  `damage: 11`, `energy_cost_per_strike: 5`. Player max health/energy are computed in code, not RON.
- **`VELOREN_ASSETS_OVERRIDE`** env var redirects asset loading -> clean way to test modified data.
- **Embedded server:** single-player runs the same server code locally -> I am the authority offline;
  online, `server.veloren.net` computes everything itself.
- **Re-ran everything myself.** New from that run:
  - Server exe = same build but **no OpenGL** -> headless authority.
  - My `_ZN` count was 91,226 vs 67,559 earlier: mine also matched section/pointer names that *contain*
    Rust names (`.text$_ZN...`). Know what a regex counts before quoting a number.
  - Health is an **ECS component** (`specs::storage::MaskedStorage<Health>`), not a field on a player
    object. Damage flows attack -> `HealthChangeEvent` -> system -> `Health::change_by`.
  - Single-player = two copies of game state in one process (embedded server + client). Phase 2 is about
    finding the server's copy.
## 2026-10-22 — Phase 1-by-hand on Veloren (no UE tools, used debug info + source + disasm)

- `gdb ptype/o Health` fails: build is **line-tables-only DWARF** (`debug=1`) — function names yes,
  Rust struct layouts no (556,850 subprograms, 0 Rust structure_types; the 149 are C runtime).
- Recovered the layout anyway: function symbols + open-source `health.rs`/`energy.rs` (pulled from GitLab
  at tag v0.18.0) + reading `[rcx+off]` in `Health::change_by`. **Claude verified against the binary:**
  - `current` @ **+0x50** (`mov %r15d,0x50(%rcx)`), `maximum` @ **+0x58** (clamp source).
  - **x256 fixed point** (constant `0x43800000` = 256.0): memory = displayed*256; 100 HP -> 25600.
  - `Energy` = 16 bytes: current/base_max/maximum u32 (x256) + regen_rate f32 (raw).
  - Fixed the first-pass guess: `last_change` is at +0x00, not +0x30.
- This is effectively Phase 1 done for Veloren: debug info replaced UE4SS/Dumper-7. On a stripped AAA
  binary you'd get here via Dumper-7 (Phase 1) or breakpoints (Phase 4) instead.
- Phase 2 lesson written using these offsets (`phases/phase2_memory_editing.md`).

## 2026-10-22 — Phase 0: static recon of Veloren (earlier)

- Gotchas: Rust strings aren't null-terminated (junk like `energy_rH3`); PowerShell truncates columns
  (use `-ExpandProperty` / `Format-List`); DIE GUI hides Entropy until **Advanced** is ticked;
  CLI needs `-u` for heuristics.
