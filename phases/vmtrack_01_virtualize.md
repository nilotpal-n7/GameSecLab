# Virtualization & anti-tamper track — Step 1: virtualize and recover a function

**Why this track exists.** You wanted to study how Denuvo-style protection works. Denuvo on a shipping
game is off-limits (circumventing commercial DRM is illegal under DMCA §1201 and equivalents, even in a
private lab, even if you own the game). But the *techniques* Denuvo uses — **code virtualization** and
**anti-debug** — are studied completely legally on code you own. This track does exactly that, and it has
one thing a real Denuvo target never gives you: the **answer key** (you compile the same source plain AND
virtualized, so you can check your recovery).

**What you already have (checked 2026-10-23):**
- gcc 16.1 (`C:\Tools\msys64\ucrt64\bin\gcc.exe`) — builds the plain version.
- Ghidra (`C:\Tools\ghidra`) — the disassembler/decompiler. Needs JDK 21+; you have jdk-23 (point Ghidra at
  it if it complains about `jre-1.8`).
- WSL **Ubuntu 24.04** with gcc — **Tigress runs here** (Tigress has no native Windows build; it's a
  C source-to-source tool for Linux/macOS).
- **To install:** only **Tigress** (into WSL).

---

## Correcting the plan we started from
- **Tigress is NOT a Windows program and does NOT eat a whole game.** It rewrites *C source functions* and
  emits new C source. You run it in WSL on one `.c` file, then compile the output. Feeding it a built game,
  or an entire engine, is a dead end — real anti-tamper also only virtualizes a handful of critical functions.
- **Start with a standalone toy, not a Doom function.** Doom/Quake (id Software, GPL) are great *legal*
  targets for the portfolio-story version later, but their build setup adds friction with zero extra
  learning for step 1. We virtualize one tiny function first; graduate to a real GPL game function after.
- **The deliverable is the recovery, not the obfuscation.** The skill you're demonstrating is: open the
  virtualized binary, find the **VM dispatcher / interpreter loop**, identify the **bytecode**, and
  reconstruct what the function computes — then add an **anti-debug** check and defeat that too.

---

## The toy (already built): `vmlab/keycheck.c`
One function `check_key(key)` hashes a 10-char key and compares to a magic constant.
Correct key is in `vmlab/keycheck_answer.txt`. Plain build already proven:
```
keycheck_plain.exe RELAB-2026   -> WIN
keycheck_plain.exe HELLO12345   -> LOSE
```
Keep that `.exe` as your reference: its `check_key` is readable in Ghidra in seconds. The virtualized one
won't be — that contrast is the whole lesson.

---

## Step 1 — install Tigress in WSL (15 min)
1. Open **Ubuntu** (WSL). Get the Linux package from the official site: <https://tigress.wtf/download.html>
   (the Arizona site `tigress.cs.arizona.edu` is obsolete and redirects here). Follow its install notes;
   it sets `TIGRESS_HOME` and puts `tigress` on PATH. A C compiler is needed inside WSL (`sudo apt install gcc`).
2. Sanity check: `tigress --version`.

## Step 2 — virtualize `check_key` (10 min)
From the project dir inside WSL (your Windows C: is at `/mnt/c`):
```bash
cd /mnt/c/Tools/GameSecLab/vmlab
tigress --Transform=Virtualize --Functions=check_key \
        --out=keycheck_vm.c keycheck.c
gcc -O2 -o keycheck_vm keycheck_vm.c      # Linux ELF; runs in WSL
./keycheck_vm RELAB-2026                  # -> WIN  (same behaviour, hidden logic)
```
Open `keycheck_vm.c` in a text editor: `check_key` is now a **bytecode interpreter** — a big switch/loop
over an array of numbers. The original arithmetic is gone from the source. That is virtualization.

## Step 3 — recover it in Ghidra (the real exercise)
1. Ghidra → new project → import **both** `keycheck_plain.exe` and the `keycheck_vm` ELF.
2. Analyze `keycheck_plain` first — find `check_key`, read the clean decompile. That's your answer key.
3. Analyze `keycheck_vm` — find `check_key`. Now you see the **VM**: a dispatch loop reading a bytecode
   array and a `switch` over opcodes. Your job:
   - locate the **interpreter loop** and the **opcode handlers** (add, xor, mul, load, compare…),
   - find the **bytecode array** and the **magic constant** `0x32629093`,
   - reconstruct the algorithm and confirm it matches the plain version.
4. Write it up in `vmlab/recovery_notes.md`: how you found the dispatcher, the opcode map you built, and the
   recovered logic. **That write-up is the portfolio piece.**

## Step 4 — add anti-debug, then beat it (stretch)
Add a self-check to `keycheck.c` (Linux: `ptrace(PTRACE_TRACEME,0,0,0) == -1` means "being debugged"),
virtualize it too, then practice bypassing it in a debugger (gdb in WSL, or patch the check). This mirrors
Denuvo's layered anti-debug on top of virtualization.

## Later — the "real commercial game" story (legal)
id Software GPL'd **Doom** and **Quake** (both C, both genuine commercial AAA of their era):
- Doom: <https://github.com/id-Software/DOOM>
- Quake: <https://github.com/id-Software/Quake>
Pick ONE self-contained function (e.g. a cheat-code / input check), virtualize just that with Tigress, and
recover it. Your project sentence becomes: *"virtualized a routine inside id Software's Doom with Tigress,
then reverse-engineered it out with Ghidra"* — the Denuvo-on-a-real-game story, 100% legal.

## Ties back to the course
This is the attacker side of **Phase 5** (anti-tamper/anti-cheat synthesis). Understanding how a VM-obfuscated
function looks in a disassembler is exactly what you need to decide how to harden your *own* games — and what
is worth the performance cost vs. what a determined attacker recovers anyway.
