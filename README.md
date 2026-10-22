# GameSecLab

Hands-on course: learn how game cheats work on a running process, and how anti-cheat
detects/prevents them — so you can build those defenses into your own games.

**You do the work. Claude explains, writes scripts, and reviews what you paste back.**
Each phase file in `phases/` is a guided lesson: CONCEPT -> YOUR STEPS -> ANTI-CHEAT LENS -> DELIVERABLE.
Do every step yourself, paste the output back, and only move on after you can explain it.

## Lab rules

1. Single-player / offline only. Never attach tools to a game while it is connected to a
   public server — that hurts real players and gets accounts banned.
2. Legit copies only. No cracked games, no DRM (Denuvo/Steam) bypass, no anti-cheat bypass.
3. Every attack you learn gets a matching defense written into `FIXLIST.md`.

## Targets

| Target | Engine | Used for | Location |
| --- | --- | --- | --- |
| Veloren v0.18.0 | Rust (custom) | Phases 0, 2, 3 (generic hooking), 4, 5 | `targets\Veloren` |
| Lyra Starter Game (Shipping build) | Unreal Engine 5 | Phases 0 (UE recon), 1, 3 (ProcessEvent) | `targets\Lyra` (later) |

## Folder map

```text
C:\Tools\                 <- reusable tools live here (Ghidra, x64dbg, DIE, Cheat Engine, ...)
C:\Tools\GameSecLab\
  README.md               <- this file
  NOTES.md                <- running learning log (what you did, what you learned)
  GLOSSARY.md             <- every term, in plain words
  FIXLIST.md              <- defenses to implement in your own games
  RECON.md                <- Phase 0 deliverable (you write it)
  phases\                 <- one lesson file per phase
  targets\                <- the practice games
  scripts\                <- cheatengine, frida, python, x64dbg, ghidra scripts
  dumps\                  <- SDK dumps, pointer scans, logs you generate
  screenshots\            <- evidence for your notes
```

## Roadmap

- [ ] Phase 0 — Static recon (Veloren: done, see RECON.md — Lyra recon when it's packaged)
- [ ] Phase 1 — Map the game live (Lyra: UE4SS, Dumper-7, offsets.json)
- [x] Phase 2 — Memory editing (Veloren: CE scan/freeze, server-vs-client copy, code anchor, ReClass) — done
- [ ] Phase 3 — Function hooking (Frida; ProcessEvent on Lyra)
- [ ] Phase 4 — Debugger & deeper RE (x64dbg + Ghidra)
- [ ] Phase 5 — Anti-cheat synthesis (ANTICHEAT_MAP.md, FIXLIST.md)

## Tool install status (all go in `C:\Tools\<Name>`)

| Tool | Phase | Status |
| --- | --- | --- |
| Ghidra | 4 | already installed (`C:\Tools\ghidra`) |
| x64dbg | 4 | installed (`C:\Tools\x96gdb` — folder name is a typo of x64dbg; `release\x96dbg.exe` launcher) |
| Detect It Easy (DIE) | 0 | already installed |
| objdump / strings / c++filt | 0 | already in msys64 (`C:\Tools\msys64\ucrt64\bin`) |
| Cheat Engine 7.7 | 2 | installed system-wide (`C:\Program Files\Cheat Engine`; includes `Tutorial-x86_64.exe`) |
| ReClass.NET 1.2 | 2 | installed (`C:\Tools\ReClass.NET`; use `x64\ReClass.NET.exe` for 64-bit games) |
| Frida (pip) | 3 | later |
| ScyllaHide | 4 | later |
| UE4SS, Dumper-7, FModel | 1 | later (Lyra) |
| System Informer | any | optional |
