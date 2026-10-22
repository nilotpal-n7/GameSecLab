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

## 2026-10-22 — Phase 2: found health, proved which copy is real

- First scan `25600` (100 HP, 4 Bytes, exact) -> filtered with damage -> **3 hits**: two at `8351`
  (= 32.62 HP, HUD showed 33 because it rounds) and one at `0` (noise, ignored).
- Both real hits end in **`...050`** = struct base + `0x50` -> the Phase 1 offset confirmed live.
  This run: **A = `292DED88050`**, **B = `29513580050`** (addresses change every launch: ASLR/heap).
- **B is the client (display) copy:** setting it to 50 changed the HUD instantly; the next server update overwrote it.
- **A is the server (authoritative) copy.** Proof: set A to 100 (25600), HUD stayed 70 (no sync), took a
  hit of **60.2** -> HUD showed **39.84** (`10199`/256) = 100 - 60.2. If A were fake, it would have been
  70.29 - 60.2 = **10.1**. The server computed damage from *my edited value*.
- **Why editing A didn't move the HUD:** Cheat Engine writes memory directly, skipping `change_by` /
  `DerefMut`, so `DerefFlaggedStorage` never marked Health as changed and the server sent nothing. The
  next *real* change (damage) went through the game's code, got flagged, and synced A's value to B.
- Lesson: a client-side edit changes only what you see; an edit to the authority changes reality.
  Online, the authority is on someone else's machine.
- Next: freeze A for god mode, then pointer scan (step 2.5) to survive relaunch.
- **God mode works (froze A at 25600):** each hit, the bar drops to 100 - damage, then the *next* hit
  starts from 100 again. The server computes damage from the frozen 100 and sends the result (flagged
  change); Cheat Engine then silently rewrites the real value to 100 (no flag, no sync), so the bar keeps
  showing the last sent number until the next hit.
- Weakness of freezing: Cheat Engine rewrites on a timer (~every 100 ms). A single hit bigger than 100 HP,
  or two hits in the same frame, lands before the rewrite -> you can still die. A robust god mode patches
  the *code* (`Health::change_by`) instead of the *data*: that's Phase 3.
- **Pointer scan dead end:** two compare scans (plain; then thread stacks as static, offset 65535, level 6)
  both gave **0 paths**. Rust keeps the world on a thread, not in globals; Health is an ECS list slot; and
  the run-1 pointermap had no stack info to compare against. ECS slot paths would be fragile anyway.
- **What writes to this address** (debugger) on the server health: one instruction, 23 writes:
  `7FF7E362D9B3  44 89 79 50  mov [rcx+50],r15d` — the **same** instruction found statically at
  `0x140F4D9B3`. Static analysis and live debugging agree.
- **ASLR measured:** RVA `0xF4D9B3` is fixed; this launch the module base was `0x7FF7E26E0000` instead of the
  preferred `0x140000000`. Code addresses are stable as *module+RVA*; heap data (Health) is not.
- Lesson: when data has no stable pointer path, anchor on the **code** that touches it. That's Phase 3.
  Write-up: `dumps/veloren_health_pointer.md`.
- **ReClass mapped the whole Health struct (96 bytes = 0x60).** `last_change` 0x00–0x27 (time f64 @0x10
  confirmed by it advancing, amount f32 @0x20 = last damage), HashMap 0x28–0x4F (ptr, mask 7, growth 6,
  items 1, seed), current/base_max/maximum @0x50/54/58, bools @0x5C–0x5E. At +0x60 the next NPC's Health
  starts: the ECS VecStorage seen directly in memory. Full table in `dumps/veloren_health_pointer.md`.
- **Recording decoded every byte of `last_change` (0x00–0x27)** against v0.18.0 source:
  attacker = `DamageContributor::Group{entity_uid 1224, group ENEMY=u32::MAX}`; two damage types
  alternating — `Attack(Melee)` hits of -5.4/-10.85 (precise=1) and `Buff(Bleeding)` ticks of -0.271
  (BuffKind #34 = 0x22). Byte 0x27 flips between 00 and 40: padding junk, never initialised.
- Lessons: Rust packs enums as *tag + payload* (and uses spare tag values for `None`); **padding bytes
  hold garbage**, so never fingerprint/compare structs with raw memcmp including padding.
- **Phase 2 closed.** Anti-cheat review in `phases/phase2_anticheat_review.md`: every attack we ran
  (attach, value scan, freeze, pointer scan/code anchor, ReClass) mapped to detection signal + defense,
  split client-side (cost-raising, always defeatable) vs server-side (real). The one proven-real defense:
  server-authoritative state — froze the server copy and it worked; froze the client copy and the next
  sync overwrote it. FIXLIST gained field-hash integrity + handle/tool/DR detection (as telemetry).
- **Phase 3 warm-up (Frida) prepared.** Hook the verified store `veloren-voxygen.exe+0xF4D9B3`
  (`mov [rcx+0x50],r15d`): rcx=Health*, r15d=new current, [rcx+0x50]=old, [rcx+0x58]=max. Chose the store,
  not the function entry, because Rust's ABI + inlining make entry args unreliable. Scripts:
  `change_by_logger.js` (observe all health changes — fires for every ECS entity) and
  `change_by_block_damage.js` (zero damage; all-entities by default, `ONLY_ENTITY` to target the player).
  Driver `run_hook.py` (frida 17 module; frida CLI not on PATH). Lesson preview: shared choke point needs a
  player filter; inline hooks are detectable via prologue-integrity checks. Lesson: `phases/phase3_warmup_veloren.md`.

## 2026-10-22 — Phase 3 warm-up: change_by logger ran (180 events)

- **Hook worked first try.** base `0x7FF7E26E0000` + RVA `0xF4D9B3` = `0x7FF7E362D9B3`; same instruction as
  Phase 0/1 static and Phase 2 debugger. Static analysis, debugger, and Frida all agree on one address.
- **Player = `0x3204EDA8000`** (max 100) — exact match to the ReClass struct base from Phase 2.
- **One function serves ALL entities.** 14+ distinct Health addresses in 180 events (player, several max=50
  trash mobs dying to 0.0, a max=320 boss `...8540`, max=85/65 others). THE reason a hook here needs a filter.
- **ECS stride 0x60 confirmed live:** every entity address = player_base + n*0x60 (slots 0,2,14,17,25,...,149).
  Matches the "+0x60 = next entity" finding from ReClass — now proven across 14 entities.
- **Damage types readable from deltas:** -0.1/-0.2 = DoT (bleed/poison) ticks; -5.4/-14.5/-35.2 = hits;
  +5.0/+7.5/+1.3 = heals/regen; `-0.0` lines = sub-0.05 ticks rounding to 0 but still a write.
- Next: `change_by_block_damage.js` with `ONLY_ENTITY` = this run's player base to block only the player's
  damage (run-specific; a stable player filter is Phase 3 proper).
- **Root cause of the "blocker did nothing" scare: the game was idle, not a broken hook.** A QPC probe
  fired ~46k times in 6s from the same (background) Frida env -> hooks placed here DO fire. change_by fired
  ~0 while on a death/menu screen. A clean 45s block run during active play: calls=35, dmg=16, blocked=16 —
  hook fires, block branch runs, r15 rewritten. Lesson: when a hook shows zero, check the target is actually
  exercising that code before suspecting the hook. (Also: Frida 17 renamed APIs — `Module.findExportByName`
  is gone; use `Module.getGlobalExportByName` / `module.getExportByName`.)
- Fixed run_hook.py timed mode to os._exit instead of session.detach (detach hung on this target).
