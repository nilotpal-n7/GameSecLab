# Phase 0 — Static recon (target: Veloren v0.18.0)

Game folder: `C:\Tools\GameSecLab\targets\Veloren\v0.18.0`
Time: ~1–2 hours. Do every step yourself. After each step, paste the FULL output to Claude
and answer the "Think" questions in your own words before reading the explanation.

---

## 1. CONCEPT — why recon comes first

Before attacking a running game, a cheater (and an anti-cheat engineer) answers:

1. **What is it built with?** Engine + compiler decide which tools work. Unreal games get
   UE4SS/Dumper-7; a custom Rust engine does not. Wrong guess = hours wasted.
2. **Is it protected?** A packer/virtualizer (VMProtect, Themida, Denuvo) changes everything:
   static analysis in Ghidra becomes painful, and live tools may be detected.
3. **What did the developer leave behind?** Debug symbols, console flags, logs, unencrypted
   assets, config files. Every leftover is free information.
4. **Where does the data live?** Stats defined in plain data files are easier to understand
   (and tamper with) than stats compiled into code.
5. **Who decides the truth?** Client-only game vs. client+server. This decides whether a memory
   edit "sticks" (Phase 2) — and it is the single most important anti-cheat question.

Static = without running the program. Nothing here touches a live process, so nothing here is
detectable by anti-cheat. That is why real cheat developers always do this first.

---

## 2. YOUR STEPS

Open **PowerShell** for the commands. Set this once per window:

```powershell
$G = "C:\Tools\GameSecLab\targets\Veloren\v0.18.0"
```

### Step 0.1 — Fingerprint the folder (5 min)

```powershell
Get-ChildItem $G | Format-Table Mode,Length,Name -AutoSize
Get-ChildItem $G -Filter *.exe | ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } | Format-List
Get-ChildItem $G -Include *.exe,*.dll -Recurse | Get-AuthenticodeSignature | Format-Table Status,Path -AutoSize
```

**What each command does:**

- `Get-ChildItem ... Format-Table` — lists files with sizes: *what ships, and how big*.
- `Get-FileHash -Algorithm SHA256` — a fingerprint of each exe. Every offset/signature you find later
  is only valid for this exact hash (a game update = new hash = re-check everything).
- `Get-AuthenticodeSignature` — is the file code-signed, and by whom? `NotSigned` = no proof of origin.
- Tip: if a column is cut off (`...`), add `| Format-List` or `| Select-Object -ExpandProperty Path`.

**Think:**

- There are two `.exe` files. Which is the game client, which is the server? Why would a
  single-player game ship a server?
- `libgcc_s_seh-1.dll`, `libstdc++-6.dll`, `libwinpthread-1.dll` — what toolchain do these
  three DLLs point to? (Hint: they are not from Microsoft Visual C++.)
- Is anything signed? Compare with what we saw on `KZ.exe` (signed by Neople Inc.).

### Step 0.2 — Install Detect It Easy (DIE) into `C:\Tools\DIE` (10 min)

1. Go to <https://github.com/horsicq/DIE-engine/releases> (latest release).
2. Download the **Windows 64-bit portable** zip (name like `die_win64_portable_*_x64.zip`).
3. Extract it so that `C:\Tools\DIE\die.exe` and `C:\Tools\DIE\diec.exe` exist.
4. Update the tool table in `README.md` (DIE -> installed).

### Step 0.3 — Packer / compiler / entropy check with DIE (15 min)

GUI: open `die.exe`, drag in `veloren-voxygen.exe`.

- Read the detection lines (Compiler / Linker / Language / Packer / Protector).
  Red `(Heur)` lines are **guesses** — always confirm them with a second signal (entropy, sections).
- **Entropy / Sections are hidden by default:** tick the **Advanced** checkbox (top right). Extra
  buttons appear on the right side (Entropy, Strings, Hex, Memory map, ...). If your build doesn't
  show a Sections view, the CLI commands below give you both entropy *and* every section.

CLI (paste this output to Claude):

```powershell
& C:\Tools\DIE\diec.exe -d -u "$G\veloren-voxygen.exe"
& C:\Tools\DIE\diec.exe -e "$G\veloren-voxygen.exe"
& C:\Tools\DIE\diec.exe -d -u "$G\veloren-server-cli.exe"
```

**What each command does:**

- `-d` deep scan: checks the whole file against DIE's signature database (compiler, packer, protector).
- `-u` heuristics: the "educated guess" checks the GUI runs by default. Without `-u` the CLI shows fewer lines.
- `-e` entropy: randomness per section (0–8). Code ≈ 6. Encrypted/compressed ≈ 7.5–8.
  One section high can be normal (e.g. `.pdata`); **`.text` (code) high = packed.**

**Think:**

- Did DIE find a packer or protector? What would a packed exe's entropy look like?
- Any section names you don't recognize? Protectors often add oddly named sections.

### Step 0.4 — Hunt for debug info (15 min)

The client exe is ~260 MB. That is huge for code. Find out why:

```powershell
& C:\Tools\msys64\ucrt64\bin\objdump.exe -h "$G\veloren-voxygen.exe"
```

**What it does:** `objdump -h` prints the **section headers** — name, size (hex), address, and flags.
Convert a hex size with `[Convert]::ToInt64("02e61ccd",16)` in PowerShell. Flags: `CODE` = executable,
`DEBUGGING` = debug info only (not run).

**Think:**

- On MSVC builds, debug info lives in a separate `.pdb`. On GNU/MinGW builds it can be
  embedded in the exe as **DWARF** sections named `.debug_*`. Do you see any?
- Is there a symbol table? Try:

  ```powershell
  & C:\Tools\msys64\ucrt64\bin\objdump.exe -t "$G\veloren-voxygen.exe" | Select-Object -First 30
  ```

  If you see names like `_ZN...veloren...` those are **mangled Rust function names** — a map
  of the whole program, handed to you for free.
  `-t` = dump the symbol table. The first lines are only MinGW startup code; count and decode the rest:

  ```powershell
  $sym = & C:\Tools\msys64\ucrt64\bin\objdump.exe -t "$G\veloren-voxygen.exe" 2>$null
  $sym.Count                                                    # how many symbols
  ($sym | Select-String '_ZN').Count                            # how many are Rust
  $sym | Select-String 'health' | Select-Object -First 10 | ForEach-Object { ($_ -split ' ')[-1] } | & C:\Tools\msys64\ucrt64\bin\c++filt.exe
  ```

  `c++filt` **demangles**: `_ZN14veloren_common4comp6health6Health9change_by...` ->
  `veloren_common::comp::health::Health::change_by`. The `Unable to load dwo file` warnings are harmless.

### Step 0.5 — Strings recon (15 min)

```powershell
& C:\Tools\msys64\ucrt64\bin\strings.exe -n 8 "$G\veloren-voxygen.exe" | Select-String -Pattern "health|energy|stamina|damage|poise" | Select-Object -First 40
& C:\Tools\msys64\ucrt64\bin\strings.exe -n 8 "$G\veloren-voxygen.exe" | Select-String -Pattern "veloren\.net|https?://|\.ron" | Select-Object -First 40
```

**What it does:** `strings -n 8` prints every run of 8+ readable characters in the file;
`Select-String` keeps lines matching the regex. Rust strings have no terminating zero byte, so
you'll see junk glued on (`energy_rH3` — the `H3` is machine code). The `VK_...` wall of text is
Vulkan's name table; ignore it.

**Think:**

- Which of these strings could you search for later in Ghidra to land in the damage code?
- What network endpoints does the client know about?

### Step 0.6 — Where does gameplay data live? (20 min)

```powershell
Get-ChildItem "$G\assets" -Recurse -File | Group-Object Extension | Sort-Object Count -Descending | Format-Table Count,Name -AutoSize
Get-ChildItem "$G\assets" -Recurse -Filter *.ron | Select-String -Pattern "max_health|health:|energy" -List | Select-Object -First 20 -ExpandProperty Path
notepad "$G\assets\common\abilities\sword\agile_cascade.ron"
```

**What it does:** the first line counts asset files by extension (what kinds of data ship). The
second finds `.ron` files mentioning health/energy (`-List` = first match per file, `-ExpandProperty`
= full path, not cut off). The third opens a sword ability so you can read real damage/energy values.

Open one of the matching `.ron` files in a text editor and read it. **Do not edit yet.**

**Think:**

- Are stats compiled into the exe, or loaded from plain-text data files?
- In single-player, both the client and the built-in server read these same local files.
  What happens if you change a value here and play single-player? What happens if you
  join a public server with the same edit? (Answer before testing — we test in Phase 2.)
- Compare with an Unreal game: assets packed inside `.pak` / `.utoc` / `.ucas`, possibly
  AES-encrypted. Which is easier to tamper with?

### Step 0.7 — Write it up

Fill in `C:\Tools\GameSecLab\RECON.md` (skeleton already created). Add a NOTES.md entry and
any new words to GLOSSARY.md. Then paste RECON.md to Claude for review.

---

## 3. ANTI-CHEAT LENS

| Recon finding | What it gives an attacker | Defense |
| --- | --- | --- |
| No packer / protector | Clean disassembly in Ghidra in minutes | Protector (VMProtect/Themida) on sensitive functions only — full-exe virtualization hurts performance |
| Embedded symbols / shipped `.pdb` | Function names = instant map of the code | Strip symbols from release builds; keep them private for crash reports |
| Plain-text gameplay data | Edit damage/health without touching code | Pack + encrypt + sign assets; server holds authoritative values anyway |
| Unsigned binaries | Can't tell a modified exe from the real one | Authenticode signing; anti-cheat verifies module signatures at load |
| Server binary shipped | Attackers can study server logic offline | Fine for open source; closed games keep server code private |

**The big lesson:** everything above only *slows down* an attacker. The Khazan install already
showed that even Denuvo on a AAA game gets defeated. The only thing static protection cannot
be stripped from is **logic that runs on a server you control** — keep that in mind for every phase.

---

## 4. HOW THIS TRANSFERS TO AN AAA UNREAL GAME (e.g. a legit copy of Khazan)

Same questions, Unreal-specific signals — you will practice these on Lyra:

- **Exe layout:** a tiny launcher (`KZ.exe`) + the real game `<Project>\Binaries\Win64\<Project>-Win64-Shipping.exe`.
  `Shipping` in the name = release build (no console).
- **UE version:** file version resource, or strings like `++UE5+Release-5.x`. UE4 vs UE5 decides
  which UE4SS/Dumper-7 settings you need.
- **Assets:** `<Project>\Content\Paks\*.pak/.utoc/.ucas`. FModel tells you if they're encrypted.
- **Anti-cheat present?** Look for `EasyAntiCheat\`, `start_protected_game.exe`, `BattlEye\`,
  `BEService`. If it's there, stop — don't use live tools on it.
- **DRM/protector:** DIE flags VMProtect/Themida; Denuvo shows as enormous, high-entropy extra sections.
- **Leftovers:** `.pdb` next to the exe, `-Win64-Development.exe`, `DefaultEngine.ini` with console enabled.

---

## 5. DELIVERABLE

`C:\Tools\GameSecLab\RECON.md`, written by you, reviewed by Claude. Phase 0 is done when you can
answer, without notes: *What is Veloren built with, is it protected, what did the developers
leave in, where do stats live, and who is the authority on game state?*
