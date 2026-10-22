# RECON — Veloren v0.18.0 (Phase 0 deliverable)

Annotated walkthrough of every Phase 0 command: **what it does -> key output -> what it means -> answers.**
Evidence = your pasted output (2026-10-22) plus four follow-up checks Claude ran (marked *[follow-up]*).

Target: `C:\Tools\GameSecLab\targets\Veloren\v0.18.0`

---

## 1. Identity — Step 0.1

### `Get-ChildItem $G | Format-Table Mode,Length,Name`

**Does:** lists the game folder with file sizes. First look at *what ships*.

| File | Size | Role |
| --- | --- | --- |
| `veloren-voxygen.exe` | 260,767,648 | **Game client** ("Voxygen" is Veloren's name for its client/renderer) |
| `veloren-server-cli.exe` | 173,440,230 | **Dedicated server** (command-line, for hosting) |
| `libgcc_s_seh-1.dll`, `libstdc++-6.dll`, `libwinpthread-1.dll` | 0.3–26 MB | GNU/MinGW runtime DLLs |
| `assets\` | — | All game data (models, sounds, stats) |
| `LICENSE` | 35 KB | GPL license (open source) |

### `Get-FileHash ... -Algorithm SHA256`

**Does:** fingerprints each exe. Same hash = byte-identical file. Analysts record hashes so that
notes, offsets and signatures are tied to an exact build — **offsets from one build are wrong for any other.**

- client `D9F6311A46EDFED0FB6EC0E1B6561F468C4B4B9C0C78CFCE2ED84784A8BFDC3C`
- server `39D611BE5473BCC5059AE6580ADEF9093D21ACFA562CF7B5895CE750D5B3A59B`

### `Get-AuthenticodeSignature`

**Does:** checks for a Windows code-signing signature. **Output: all 5 files `NotSigned`.**
**Means:** nothing proves these files came from Veloren or are unmodified. A tampered exe looks
identical to the real one. Compare: Khazan's `KZ.exe` = `Valid`, signed by Neople Inc.

### Answers

- **Which exe is which?** `voxygen` = client, `server-cli` = server.
- **Why does a single-player game ship a server?** Veloren is built client/server from the ground up.
  Single-player starts the *same server code* inside your client process (strings prove it — see §5:
  `Failed to copy map file to singleplayer world`, `userdata/server/server_config/settings.ron`).
  So even offline, game rules run on "a server" — one that **you** own. Critical for Phase 2.
- **What do the 3 DLLs say?** `libgcc_s_seh` + `libstdc++` + `libwinpthread` = **MinGW-w64 (GNU) toolchain**,
  not Microsoft Visual C++ (which would ship `vcruntime140.dll` / `msvcp140.dll`). So: no `.pdb` files —
  GNU tools put debug info *inside* the exe (§4).
- **Signed?** No. Unlike a commercial game, there's no signature for anti-cheat to verify.

---

## 2. Toolchain & engine — Step 0.3 (DIE)

### `diec.exe -d <exe>` (CLI) and the GUI screenshot

**Does:** DIE matches the file against a database of compiler/packer/protector signatures.
`-d` = deep scan. The GUI also runs **heuristics** by default; the CLI needs `-u` for that — which is
why your CLI output showed only 2 lines while the GUI showed 8.

| DIE line | Meaning |
| --- | --- |
| `PE64`, `AMD64`, `64-bit` | 64-bit Windows exe -> 64-bit Cheat Engine/x64dbg later |
| `Compiler: MinGW` | built with the GNU toolchain (matches the DLLs) |
| `(Heur) Language: Rust` + `C++` | Rust game; C++ comes from bundled libraries (e.g. `libstdc++`) |
| `Library: OpenGL` | graphics API import seen. Strings also show **wgpu/naga** (Rust renderer that drives Vulkan/DX12/GL) |
| `Type: Console` | built as a console app — a console window with logs can appear. *[follow-up]* PE header Subsystem = 3 (console) confirms |
| `Operation system: Windows (Server 2003)` | just the minimum-OS field in the PE header (4.0 here, MinGW default). Not meaningful |
| `(Heur) Protection: Generic [Too many sections]` | **false positive** — see §3 |
| `(Heur) Packer: Generic [Recurring import names]` | **false positive** — see §3 |
| `(Heur) Debug data: Contains [.debug_aranges]` | **real** — DWARF debug info inside the exe (§4) |
| `Overlay: Binary [Offset 0x0ebae800, Size 0x00d017a0]` | data after the last section — it's the **symbol table** (§4) |

### Answers

- **Language/compiler:** Rust, compiled with the MinGW-w64 GNU toolchain (`x86_64-pc-windows-gnu`; objdump's
  warnings literally print that target path).
- **Server vs client (your `-d -u` run on `veloren-server-cli.exe`):** same MinGW + same false-positive
  heuristics + debug data, but **no `Library: OpenGL`** — the server has no renderer. Same game rules,
  no graphics: that's what a headless authority looks like.
- **Engine:** custom Rust engine — **not Unreal**. So UE4SS/Dumper-7 don't apply here; we use generic tools
  (Cheat Engine, ReClass, Frida, x64dbg). That's why Lyra exists in this course.

---

## 3. Protection — Step 0.3 (entropy) *[follow-up: `diec.exe -e`]*

**Does:** `-e` computes entropy per region. 0 = all identical bytes, 8 = perfectly random.
Normal code ≈ 5.5–6.5. Compressed/encrypted ≈ 7.5–8.

| Region | Entropy | DIE verdict |
| --- | --- | --- |
| **Total** | **6.35** | not packed |
| `.text` (code, 64.5 MB) | 6.22 | not packed — normal compiled code |
| `.rdata` (constants/strings) | 5.76 | not packed |
| `.pdata` | 7.07 | "packed" — **false positive** |
| all `.debug_*` | 2.3–6.1 | not packed |

### Why the red DIE flags are false positives

- **`.pdata` = 7.07:** `.pdata` is the x64 exception/unwind table — a dense array of code addresses.
  Dense numbers look random to an entropy test. It is not encrypted.
- **"Too many sections":** 24 sections. Protectors add extra sections, so DIE guesses "protected" —
  but 13 of these are standard DWARF `.debug_*` sections. Normal for a GNU debug build.
- **"Recurring import names":** packers often import the same few APIs repeatedly. Here it's an artifact of
  a huge Rust program importing from many DLLs. Real packers also show a tiny `.text`, high `.text`
  entropy, and odd section names — none of which we see.

**Lesson: heuristics are hints, not verdicts.** Confirm with a second signal (entropy, section names,
section sizes) before believing "packed".

### Answers

- **Packer/protector?** None. `.text` is 64.5 MB of plain compiled code at entropy 6.22.
- **What would packed look like?** `.text` small or near-empty, one big section at entropy ~7.9, section names
  like `UPX0/UPX1`, `.vmp0/.vmp1` (VMProtect), `.themida`, or random names (Denuvo).
- **Unusual section names?** None — all standard PE (`.text .data .rdata .pdata .xdata .bss .edata .idata .CRT .tls .reloc`)
  plus standard DWARF (`.debug_*`). Note `.edata` = an **export table** — unusual for a game exe; worth a look in Ghidra later.
- *[follow-up]* PE header `DllCharacteristics=0x160` -> **ASLR on, high-entropy ASLR on, NX/DEP on.**
  ASLR means addresses change every launch — the exact problem pointer paths solve in Phase 2.

---

## 4. Debug leftovers — Step 0.4

### `objdump -h <exe>`

**Does:** prints the section table (name, size, address, flags).

| Section | Size (hex) | Size | What it is |
| --- | --- | --- | --- |
| `.text` | 0x0407cef0 | **64.5 MB** | machine code |
| `.debug_info` | 0x02e61ccd | **46.4 MB** | DWARF: types, structs, variables, functions |
| `.debug_str` | 0x04dddbaa | **77.9 MB** | DWARF: name strings |
| `.debug_line` | 0x010c31dc | 16.8 MB | DWARF: address -> source file/line |
| `.debug_ranges` | 0x011b4900 | 17.7 MB | DWARF: code ranges per function |
| other `.debug_*` | — | ~2 MB | |

All `.debug_*` sections ≈ **160 MB** of the 249 MB file. Each is flagged `DEBUGGING` (not loaded as code).

> **Phase-1-by-hand correction (learner's `objdump --dwarf=info` + `gdb ptype`):** this is **line-tables-only**
> DWARF (`debug = 1`): 556,850 `DW_TAG_subprogram` (function name/file/line, for backtraces) but **zero Rust
> `DW_TAG_structure_type`** — so `gdb ptype/o Health` returns "No symbol". The 149 structs present are C/MinGW
> runtime types. Struct **field offsets are NOT in the binary**; we recovered them by combining the function
> symbols with the open-source `health.rs`/`energy.rs` and reading `[rcx + off]` in the disassembly (below).
> The `Could not find DWO CU /rustc/...` errors are the precompiled std's split-DWARF, never shipped — harmless.

### `objdump -t <exe>` *[follow-up: counted]*

**Does:** dumps the COFF **symbol table** (function/variable names + addresses).

- **160,313 lines / 160,307 symbols.** Your `($sym | Select-String '_ZN').Count` = **91,226**; Claude's first
  count was **67,559**. Both are right — they count different things:
  - **~67.5k** lines where the *symbol itself* is a Rust name (`_ZN...` at the end of the line) — real functions/statics.
  - **~23.3k** extra lines where a Rust name is *embedded* in a section or pointer name
    (`.text$_ZN...`, `.rdata$.refptr._ZN...`). Same functions, listed again by the linker.
  - **61,939 unique** Rust names. Lesson: **know what your regex is counting** before you quote a number.
- Your first 30 lines only showed MinGW startup symbols (`crtexe.c`, `pre_c_init`) — the Rust ones come later.
- The `Unable to load dwo file: /rustc/12eb345e...` warnings: objdump looking for *split* debug files of the
  Rust standard library that exist only on the build machine. Harmless — but they **leak the exact rustc
  commit hash** used to build the game.
- *[follow-up]* PE header `PointerToSymbolTable = 0x0ebae800` = DIE's **overlay offset**. So the 13 MB
  "overlay" is this symbol table + its string table.

Demangled examples *[follow-up, via `c++filt`]*:

```
veloren_common::comp::health::Health::new
veloren_common::comp::health::Health::change_by      <- likely the funnel for ALL damage/healing
veloren_common::combat::Attack::with_damage
veloren_common::combat::DamageKind (deserialize)
```

### What your `health` symbol search revealed (read these closely — they shape Phase 2–4)

| Demangled symbol | What it tells you |
| --- | --- |
| `Health::new`, `Health::change_by` | constructor + the mutation function. Damage and healing both call `change_by` |
| `HealthChange` (+ `Deserialize`, `Debug`) | a health change is its own data type, and it's **serializable** = it travels over the network |
| `drop_in_place<specs::storage::MaskedStorage<...Health>>` | **`specs` is an ECS (Entity-Component-System) library.** Health is a *component* stored in a per-type storage, **not** a field inside a "Player" object |
| `beam::...::AttackEmitters ... EmitExt<HealthChangeEvent>`, `projectile::...::Emitters ...` | beams and projectiles don't change health directly — they **emit `HealthChangeEvent`s**, which a system processes later |
| `...plugin::information::HostEntity>::health` | the WASM plugin API can *read* entity health — the official modding surface |

**Why this matters:**

- **Phase 2 (Cheat Engine):** in Unreal you'd walk `PlayerController -> Pawn -> Health`. Here the path is
  ECS-shaped: `World -> component storage for Health -> slot for your entity`. Pointer scans will end in
  a storage array, and the slot index can change when entities spawn/despawn.
- **Phase 3/4 (hooks, debugger):** damage is event-driven: *attack -> HealthChangeEvent -> system ->
  `Health::change_by`*. Hooking `change_by` catches all damage at one choke point. Hooking
  the event emitter catches it *before* it's applied (and tells you who caused it).
- **Single-player twist:** there are two copies of the game state in one process — the embedded
  server's (authoritative) and the client's (display). Editing the client copy = the server overwrites it.
  Editing the server copy = it sticks. Finding which is which is the core skill of Phase 2.

### Verified struct layout (for Phase 2) — learner's research, Claude-checked against the binary

Disassembly of `Health::change_by` @ `0x140f4c940`, store site `0x140f4d9b3`:

```
mov 0x58(%rcx),%eax        ; eax = self.maximum           -> maximum at +0x58
...mulss <0x43800000=256.0> ; fixed-point x256 scaling
cmp %r15d,%eax
cmovb %eax,%r15d           ; clamp new current to maximum
mov %r15d,0x50(%rcx)       ; self.current = clamped        -> current at +0x50   (rcx = &mut self)
```

```
Health:  +0x00 last_change(HealthChange)  ... damage_contributors(HashMap)
         +0x50 current u32 (x256)  +0x54 base_max u32 (x256)  +0x58 maximum u32 (x256)  +0x5C bools
Energy:  +0x00 current u32 (x256)  +0x04 base_max u32 (x256)  +0x08 maximum u32 (x256)  +0x0C regen_rate f32 (raw)
```

- **x256 fixed point:** memory holds `displayed * 256` (100 HP -> `25600` / `0x6400`) as a 4-byte int.
- **Correction to the first-pass field table:** `last_change` is at **+0x00** (the tail `movdqu %xmm0,(%rcx)`
  stores prove it), not +0x30. `current = +0x50` is confirmed either way.
- Both are `specs` ECS components (`DerefFlaggedStorage<VecStorage<Self>>`): per-type arrays, dirty-flagged
  on `&mut` so the server syncs the change -> see Phase 2 for why a client-side edit gets overwritten.

### Answers

- **Debug sections?** Yes — 13 DWARF sections (line-tables-only), ~160 MB.
- **Symbol table?** Yes — 160k symbols, full Rust paths like `veloren_common::comp::health::Health::change_by`.
- **Why ~260 MB?** About 64% of the file is debug info + symbols. Code itself is 64.5 MB.
- **Why it matters:** in Ghidra you will search `Health::change_by` and land directly in the damage code —
  no guessing. On a commercial game you'd have to *find* that function via strings, breakpoints, or patterns
  (Phase 3/4). Veloren is open source, so shipping symbols costs it nothing; for a closed game this is the
  single most valuable leak.

---

## 5. Interesting strings — Step 0.5

### `strings -n 8 <exe> | Select-String ...`

**Does:** pulls every run of ≥8 printable bytes out of the binary, then filters by keyword.

**Why the health/energy hits look broken** (`energy_rH3`, `damage_eL3`): Rust strings are **not
null-terminated**. `strings` reads into the next bytes, which are machine code (`H3`, `L3` = x64 instruction
bytes). Also many hits are field names inlined into code, not the string table. Lesson: on Rust/modern C++
binaries, search for *exact* names in Ghidra's string view instead of trusting `strings` fragments.

### Important strings found (second search)

| String | Significance |
| --- | --- |
| `VELOREN_ASSETS_OVERRIDE` | **environment variable that redirects asset loading** — load a modified assets folder without touching the original |
| `server.veloren.net`, `https://auth.veloren.net` | official multiplayer server + login/auth server (**never** attach tools while connected) |
| `userdata/server/server_config/settings.ron`, `admins.ron`, `whitelist.ron`, `banlist.ron` | the built-in server's config — single-player has its own admin list |
| `Failed to copy map file to singleplayer world` | confirms an embedded server for single-player |
| `main-login-network_wrong_version`, `main-login-authentication_error` | client/server version + auth checks exist |
| `energy_cost field was added ... merge_requests/1140` | source-code comments/paths leaked; open-source anyway |
| `wasmtime`, `bytecodealliance` | **WASM plugin runtime** — Veloren has an official plugin system (an *intended* mod surface) |
| `wgpu`, `naga`, Vulkan enum dump | renderer = wgpu (Vulkan/DX12). The giant wall of `VK_...` text is Vulkan's type-name table |
| `voxygen/src/session/mod.rs`, `voxygen/src/hud/settings_window/controls.rs` | source file paths (from panic messages) — map binary areas to source files |

### Answers

- **Strings useful in Ghidra:** `Health::change_by`, `HealthChange`, `DamageKind`, `energy_cost`,
  `VELOREN_ASSETS_OVERRIDE` — search them, follow cross-references (XREFs) into code.
- **Network endpoints:** `server.veloren.net` (game), `auth.veloren.net` (accounts), plus wiki/gitlab links.

---

## 6. Data layout — Step 0.6

### `Get-ChildItem assets -Recurse -File | Group-Object Extension`

**Does:** counts asset files by type.

| Type | Count | What |
| --- | --- | --- |
| `.vox` | 4,733 | voxel models (MagicaVoxel) |
| `.ron` | 2,826 | **gameplay data** — items, abilities, NPCs, loot (plain text) |
| `.ftl` | 1,197 | translations (Fluent) |
| `.png` / `.ogg` | 842 / 653 | textures / audio |
| `.glsl` | 67 | shader source code |

**Zero packing, zero encryption.** Everything is a loose, human-readable file.

### `Select-String -Pattern "max_health|health:|energy" -List`

**Does:** finds `.ron` files mentioning those words. **Your output cut off the paths** — use
`| Select-Object -ExpandProperty Path` or `| Format-List` to see them. *[follow-up]*
**1,092 files** match, mostly under `common/abilities/<weapon>/` and `common/items/`.
Your untruncated run starts with `common\material_stats_manifest.ron` (stats per crafting material),
then enemy abilities (`abilities\adlet\...`) and player weapon abilities (`abilities\axe\...`).
**Enemy and player abilities use the same format** — a damage edit can buff enemies as easily as you.

Example — `assets/common/abilities/sword/agile_cascade.ron`:

```ron
kind: Slash(
    damage: 11,                 // damage per hit
    poise: 5,                   // stagger damage
    knockback: 0,
    energy_regen: 0,
),
...
energy_cost_per_strike: 5,      // stamina cost
```

*[follow-up]* No `base_health`/`max_energy` in any `.ron` -> **player max health/energy are computed in code**
(the `veloren_common::comp::health` module), from body type, gear and skills.

### Answers

- **Where do stats live?** Ability/item numbers in plain-text `.ron` under `assets/common/`; base health
  and energy in compiled code.
- **Edit a value, then play single-player?** Single-player's embedded server loads the same local `assets\`,
  so the edit *works* — you are the server.
- **Same edit on a public server?** **No effect** on real outcomes: the remote server loads *its own* assets
  and computes the damage. At most your client shows wrong numbers until the server corrects it.
  -> This is server authority in one sentence.
- **Compared with Unreal:** UE `.pak/.utoc/.ucas` + AES are much harder to tamper with than loose RON.
  But the AES key lives in the exe, so it's a speed bump — and on a server-authoritative game it doesn't matter.

---

## 7. Attacker's summary

Veloren is an unprotected, unsigned 64-bit Rust/MinGW binary with **full debug info and 160k symbols** —
I can open it in Ghidra and jump straight to `Health::change_by` and `combat::Attack`. Gameplay numbers
are plain-text RON files, and `VELOREN_ASSETS_OVERRIDE` lets me load a modified copy cleanly. ASLR is on,
so in Cheat Engine I'll need pointer paths, not fixed addresses. **But** every rule runs in a server: in
single-player that server is mine (anything goes); online, client-side edits can't change real outcomes,
so cheats would be limited to information/input (ESP, aim/auto-dodge), not stat edits.

## 8. Defender's summary (-> FIXLIST.md)

1. Strip debug info and symbols from release builds (`strip=true` / `debug=0`; UE: never ship `.pdb`).
2. Sign binaries.
3. Pack/encrypt/sign assets, and **verify asset hashes server-side** for multiplayer.
4. Don't expose asset-override env vars / dev switches in shipping builds.
5. Keep authority on the server — that's what made Veloren's open assets harmless online.

---

## Self-check (answer without notes before Phase 1)

- [ ] What is Veloren built with, and how do you know (2 independent pieces of evidence)?
- [ ] Is it packed? Why are DIE's two red heuristics wrong here?
- [ ] Why is the client 260 MB?
- [ ] Where do damage values live vs. max health?
- [ ] Why would a RON edit work in single-player but not on `server.veloren.net`?
