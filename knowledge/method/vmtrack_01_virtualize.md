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

```text
keycheck_plain.exe RELAB-2026   -> WIN
keycheck_plain.exe HELLO12345   -> LOSE
```

Keep that `.exe` as your reference: its `check_key` is readable in Ghidra in seconds. The virtualized one
won't be — that contrast is the whole lesson.

---

## Step 1 — Tigress install — DONE (2026-10-23)

Installed the **3.1 binary** distribution (you downloaded that instead of the `.deb`; it works the same).

- Extracted to `~/tigress31/tigress/3.1` in WSL; `TIGRESS_HOME` + PATH persisted in `~/.bashrc`, so `tigress`
  is on PATH in every new Ubuntu shell.
- Every Tigress command needs `--Environment=x86_64:Linux:Gcc:4.6`.
- Self-test passed (virtualized Tigress's own `test1.c` and ran it).

## Step 2 — virtualize `check_key` — DONE

Produced in `vmlab/` (behaviour identical to the plain build):

```bash
# (for reference; already run) from /mnt/c/Tools/GameSecLab/vmlab
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Virtualize --Functions=check_key \
        --out=keycheck_vm.c keycheck.c && gcc -w -O2 -o keycheck_vm keycheck_vm.c
```

- `keycheck_plain_elf` — plain Linux build (answer key).
- `keycheck_vm` — Virtualize only (30 → 416 lines of interpreter; magic `0x32629093` still visible).
- `keycheck_vm2` — EncodeLiterals + EncodeArithmetic + Virtualize (638 lines; harder).

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

## Step 3 — recover it in Ghidra — STAGED, your turn

A Ghidra project is pre-built with all three binaries imported and auto-analyzed:
`vmlab/ghidra_proj/KeyCheck.gpr`. Ghidra is already pointed at jdk-23 (your system `java` is 17, too old),
so just launch `C:\Tools\ghidra\ghidraRun.bat` and open that project.
Then follow **`vmlab/recovery_notes.md`** — read the plain `check_key` (answer key), then find the VM
dispatcher + opcode handlers in `keycheck_vm`, and write up the recovery. **That write-up is the portfolio piece.**

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
