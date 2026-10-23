# Lyra setup — build the Unreal target for Phases 1 and 3

Goal: a **packaged Shipping build of Epic's Lyra Starter Game** in `C:\Tools\GameSecLab\targets\Lyra\`,
then treat it as a black box like a store-bought Unreal game. This unlocks the Unreal half of the course:

- **Phase 0 (UE recon):** version, paks, Shipping markers — on a real UE5 exe.
- **Phase 1:** UE4SS + Dumper-7 dump every class and offset automatically (what you did by hand on Veloren).
- **Phase 3 proper:** hook `UObject::ProcessEvent`, Unreal's universal choke point.

**Time: ~4–8 hours, mostly unattended** (downloads, compiling, shader building, packaging).

---

## 0. Your PC (checked 2026-10-22) and what to install

| Item | You have | Verdict |
| --- | --- | --- |
| Free disk on C: | 257 GB | OK — budget ~150 GB (table below) |
| RAM | 15.4 GB | **Tight** (Epic recommends 32). Works, just slower; close browsers/Discord while compiling |
| CPU | Core Ultra 7 155H, 22 threads | Good for compiling |
| GPU | Intel Arc (integrated) | Editor will be slow → set **Engine Scalability → Low** in the editor |
| Visual Studio | 2026 Enterprise 18.8, MSVC 14.51, Win11 SDK 26100 | Compiler + SDK already correct; add one workload (step 1) |
| Epic Games Launcher | not installed | step 2 |

**Disk budget:** engine 50–70 GB · Lyra project + compiled editor + shader cache 25–40 GB ·
packaged Shipping build 5–10 GB · temp headroom ~20 GB.

**Engine version = UE 5.8** (confirmed on Fab: Lyra supports **5.0–5.8**, free, last updated 2026-10-01).
5.8 is the only version that officially supports your VS 2026, and UE4SS's experimental build lists 5.8.

---

## Step 1 — Visual Studio: add the game workload (10 min)
1. Open **Visual Studio Installer** → VS 2026 Enterprise → **Modify**.
2. Tick the workload **Game development with C++**. Keep **Desktop development with C++** (already there).
3. Install. Your MSVC (14.51) and Windows 11 SDK (26100) already meet UE 5.8's requirements.

## Step 2 — Epic Games Launcher + account (20 min + sign-in)
1. Download the **Epic Games Launcher** from <https://www.epicgames.com/store/download> and install it.
2. Sign in (or make a free Epic account). This is *your* account — I won't enter credentials for you.
3. If downloads fail with SSL/certificate errors, the Fortinet firewall that blocked Veloren's download
   server may be interfering — try another network.

## Step 3 — Install Unreal Engine 5.8 (1–3 hr download, big)
1. Launcher → **Unreal Engine** → **Library** → **+** next to Engine Versions → pick **5.8.x** → Install.
2. **Options (click to trim size):** you can untick **Starter Content**, **Templates**, and the
   platform **Target Platforms** you don't need (keep Windows). **Leave "Editor symbols for debugging"
   OFF** — saves ~40 GB and we don't need engine symbols.
3. Install to a drive with room (C: is fine here).

## Step 4 — Get Lyra and create the project (30–60 min)
1. The Fab listing is <https://www.fab.com/listings/93faede1-4434-47c0-85f1-bf27c0820ad0> →
   **Add to My Library** (free; your Epic account).
2. Launcher → **Unreal Engine → Library → Fab Library** → **Lyra Starter Game** → **Create Project**.
   - Lyra only appears here once 5.8 is installed.
   - Choose a project location with space, e.g. `C:\UnrealProjects\LyraStarterGame`.
3. First open compiles C++ and **builds shaders** — this can take 30–90 min on your hardware. Let it finish.
   If VS is set up right, it compiles automatically; if prompted to rebuild modules, click **Yes**.

## Step 5 — Package a Shipping build (30–90 min)
This is the artifact we attack. **Shipping** = release config (no editor, no console by default).
1. In the Lyra editor: **Platforms (toolbar) → Windows → Build Configuration → Shipping**.
2. **Platforms → Windows → Package Project** (pick target **LyraGame** if asked).
3. Output folder: **`C:\Tools\GameSecLab\targets\Lyra\`** (create it). Packaging cooks content + builds the exe.
4. Result: `targets\Lyra\Windows\LyraGame\Binaries\Win64\LyraGame-Win64-Shipping.exe` (name may vary).
   A tiny launcher `LyraGame.exe` sits at the top; the real game is the `...-Shipping.exe` under Binaries.

> Note: Lyra's menus assume Epic Online Services / multiplayer. For a pure offline target, start it and use
> a **single-player / practice or bot match** only. As always in this lab: never attach tools while connected
> to a real online match.

## Step 6 — Phase 0 recon on the packaged build (quick, do with me)
Once packaged, we repeat Phase 0 on Lyra and compare to Veloren:
```powershell
$L = "C:\Tools\GameSecLab\targets\Lyra\Windows\LyraGame"   # adjust to real path
Get-ChildItem $L -Recurse -Filter *.exe | Get-AuthenticodeSignature | Format-Table Status,Path
& C:\Tools\DIE\diec.exe -d -u "$L\Binaries\Win64\LyraGame-Win64-Shipping.exe"
Get-ChildItem "$L\Content\Paks"           # .pak / .utoc / .ucas — FModel checks encryption
Get-ChildItem $L -Recurse -Include *.pdb  # should be NONE in a clean Shipping build
```
Paste that back and we'll write a Lyra RECON section.

---

## After Lyra is built — the Unreal phases

**Phase 1 — map the game live (the big UE payoff):**
- **UE4SS** (experimental build, UE 5.8) → live object/reflection explorer + Lua console. Install into the
  packaged game's `Binaries\Win64\`. Walk `PlayerController → Pawn → find Health/ammo/score by name`.
- **Dumper-7** → inject to dump C++ headers with offsets for every class. Then a Python parser turns the
  dump into `offsets.json` (class → property → offset). This is the automated version of the Veloren
  debug-info + ReClass work you did by hand.
- **FModel** → browse paks, check AES pak encryption/signing.

**Phase 3 proper — hook `ProcessEvent`:**
- Every `UFunction` call in Unreal funnels through `UObject::ProcessEvent(UFunction* fn, void* params)`.
  Hook it once with Frida and you see **every** gameplay call by name — the grown-up version of the Veloren
  `change_by` logger. Then modify args/return (e.g. zero incoming damage in `ApplyDamage`).
- Build an **AOB/signature** for ProcessEvent so it survives rebuilds (offsets don't).

## Tools to fetch when we start Phase 1 (all into `C:\Tools\`)
| Tool | Source | Note |
| --- | --- | --- |
| UE4SS (experimental) | github.com/UE4SS-RE/RE-UE4SS releases | pick the experimental build for UE 5.8 |
| Dumper-7 | github.com/Encryqed/Dumper-7 | all UE4/UE5; build the DLL in your VS |
| FModel | fmodel.app | pak/asset browser |
| System Informer | (optional) | process/handle inspection |
