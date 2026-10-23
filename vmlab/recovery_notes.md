# Recovery notes — pulling `check_key` out of the virtualized binary

Everything is staged. Open the Ghidra project and work top to bottom. Fill in your findings as you go —
this file IS the portfolio deliverable.

## What's in the box (all built & analyzed 2026-10-23)
In `vmlab/`:
- `keycheck.c` — the source (one function `check_key`).
- `keycheck_plain_elf` — plain build = **the answer key** (readable in Ghidra in seconds).
- `keycheck_vm` — Tigress **Virtualize** only (logic hidden; magic constant still visible).
- `keycheck_vm2` — Tigress **EncodeLiterals + EncodeArithmetic + Virtualize** (harder).
- `keycheck_vm.c`, `keycheck_vm2.c` — the generated interpreter source (peek if stuck, but try the binary first).
- `ghidra_proj/KeyCheck.gpr` — Ghidra project with all three imported **and auto-analyzed**.

All three binaries behave identically: key `RELAB-2026` → WIN, anything else → LOSE.

## Open it
- Launch `C:\Tools\ghidra\ghidraRun.bat` (already pointed at jdk-23). File → Open Project →
  `C:\Tools\GameSecLab\vmlab\ghidra_proj\KeyCheck.gpr`.
- Double-click `keycheck_plain_elf` first, then `keycheck_vm`, then `keycheck_vm2`.

## Exercise A — read the answer key (`keycheck_plain_elf`)
1. Symbol Tree → Functions → `check_key`. Open the Decompiler (Window → Decompiler).
2. You should see, cleanly: `len==10` check, a loop doing `acc = acc*33 ^ key[i]; acc += i*7`, seed `0x1505`,
   compare to `0x32629093`. Write the decompiled pseudocode here:
   ```
   (paste plain check_key decompile)
   ```

## Exercise B — find the VM (`keycheck_vm`)
Now the same function is an interpreter. Your job:
1. Open `check_key` in the decompiler. It's a **dispatch loop** over an array of numbers (the bytecode) with
   a big `switch` / jump table (the opcode handlers). Find:
   - the **interpreter loop** (a `while` reading a program-counter into a byte/int array),
   - the **bytecode array** (a global or stack array of ints the loop walks),
   - the **handlers** for the ops you expect: multiply, xor, add, load byte, compare.
2. Shortcut lead: the magic `0x32629093` is still present (plain Virtualize doesn't encode literals). Search
   **Search → For Scalars → 0x32629093**, then look at **References** to it — that lands you near the final
   compare. Work backwards from there.
3. Record: where's the loop? how many opcodes? which handler does the `*33` and the `^`?
   ```
   (your opcode map + where the magic compare happens)
   ```

## Exercise C — the harder one (`keycheck_vm2`)
Same idea, but arithmetic is rewritten into bit tricks and literals are (meant to be) encoded. Note what's
harder, and whether the constant still leaks. The *method* is identical: find the dispatcher, map opcodes.

## Exercise D (stretch) — anti-debug
Add to `keycheck.c` (Linux): near the top of `check_key`, a self-check —
`if (ptrace(PTRACE_TRACEME,0,0,0) == -1) return 0;` (needs `#include <sys/ptrace.h>`). Re-run the Tigress
commands (see `phases/vmtrack_01_virtualize.md`), then practice bypassing it: run under `gdb`, or NOP the
check. That's Denuvo's layered anti-debug in miniature.

## The answer (don't peek until you've tried B)
`check_key`: `acc=0x1505; for i in 0..9: acc=(acc*33)^key[i]; acc+=i*7; return acc==0x32629093`.
Correct key `RELAB-2026`. Success = your recovered opcode trace computes exactly this.
