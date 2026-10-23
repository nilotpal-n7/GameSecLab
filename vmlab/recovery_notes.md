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

---

## RECOVERED (2026-10-24) — keycheck_vm opcode map

Dispatcher: `check_key` = `while(true) switch(*puVar5)` where **puVar5 = PC** (starts at
`&_1_check_key_$array` = bytecode) and **puVar6 = SP** (stack at `local_168`). Stack machine:
push = sp+=2, binary op pops 2 / pushes 1.

| Opcode(s) | Operation | Maps to |
| --- | --- | --- |
| 0x7b,0xa3 / 0xfe | push 4/8-byte constant | 0x1505, 33, 7, 10, 0x32629093 |
| 0xc5 | push &arg (key) | `key` |
| 0x5b | push &local | `i`, `acc` |
| 0xfa | load byte via ptr | `key[i]` |
| 0xa8 | (byte) zero-extend | uchar(key[i]) |
| 0x23,0x9a | multiply (uint) | `*33`, `i*7` |
| 0x88 | XOR | `^ key[i]` |
| 0x3a,0x84 | add | `acc += …` |
| 0xf7 | less-than | loop `i<10` |
| 0x67 | equal | `== 0x32629093` |
| 0x13 | not-equal | `len != 10` |
| 0x2a | branch-if-true | loop back-edge |
| 0x1 | unconditional jump | — |
| 0x51 | CALL extern (1=strlen) | `strlen(key)` |
| 0x5a | return top | `return` |
| 0x7,100,0x56,0xcb,0xfc… | store / load / convert | `acc`,`i` mem ops |

Recovered logic (from handlers alone, no bytecode trace needed):
`len=strlen(key); if(len!=10) return 0; acc=0x1505; for i in 0..9: acc=(acc*33)^key[i]; acc+=i*7; return acc==0x32629093;`

Anti-RE noticed: **opcode diversification** (0x23 & 0x9a both multiply, etc.) and **threaded dispatch**
(`default: goto` re-enters the switch to hide the loop). Both are techniques Denuvo also uses.

TODO (to confirm): read `_1_check_key_$array` bytes in order; diff recovered logic vs `keycheck_plain_elf` check_key.

### CONFIRMED against answer key (2026-10-24)
- Bytecode `_1_check_key_$array` @ 0x104020 starts with 0xC5 = push &key — matches the opcode map (first op).
- `keycheck_plain_elf` check_key decompile == recovered VM logic:
    acc=0x1505; do { acc = ((acc*33) ^ key[i]) + i*7; i7+=7; } while(i7 != 0x46 /*70=7*10*/); return acc==0x32629093;
- Compiler details learned: **strength reduction** (i*7 kept as a running +7 counter, no multiply) and a
  **disguised loop bound** (`while(i7 != 70)` instead of `i<10`). Virtualized -> recovered -> verified: full circle.
