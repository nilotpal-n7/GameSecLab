# Recovery notes — pulling `check_key` out of the virtualized binary

Everything is staged. Open the Ghidra project and work top to bottom. Fill in your findings as you go —
this file IS the portfolio deliverable.

## What's in the box (all built & analyzed 2026-10-23)

In `vmlab/`:

- `keycheck.c` — the source (one function `check_key`).
- `keycheck_plain_elf` — plain build = **the answer key** (readable in Ghidra in seconds).
- `keycheck_vm` — Tigress **EncodeLiterals + EncodeArithmetic + Virtualize** (harder).
- `keycheck_vm.c` — the generated interpreter source (peek if stuck, but try the binary first).
- `ghidra_proj/KeyCheck.gpr` — Ghidra project with all three imported **and auto-analyzed**.

All three binaries behave identically: key `RELAB-2026` → WIN, anything else → LOSE.

## Open it

- Launch `C:\Tools\ghidra\ghidraRun.bat` (already pointed at jdk-23). File → Open Project →
  `C:\Tools\GameSecLab\vmlab\ghidra_proj\KeyCheck.gpr`.
- Double-click `keycheck_plain_elf` first, then `keycheck_vm`.

## Exercise A — read the answer key (`keycheck_plain_elf`)

1. Symbol Tree → Functions → `check_key`. Open the Decompiler (Window → Decompiler).
2. You should see, cleanly: `len==10` check, a loop doing `acc = acc*33 ^ key[i]; acc += i*7`, seed `0x1505`,
   compare to `0x32629093`. Write the decompiled pseudocode here:

   ```text
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

   ```text
   (your opcode map + where the magic compare happens)
   ```

## Exercise C (stretch) — anti-debug

Add to `keycheck.c` (Linux): near the top of `check_key`, a self-check —
`if (ptrace(PTRACE_TRACEME,0,0,0) == -1) return 0;` (needs `#include <sys/ptrace.h>`). Re-run the Tigress
commands (see `knowledge/method/virtualize.md`), then practice bypassing it: run under `gdb`, or NOP the
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

---

## keycheck_vm (EncodeLiterals + EncodeArithmetic + Virtualize) — 2026-10-24

Same VM skeleton (puVar8=PC over `_3_check_key_$array`, puVar7=SP, while/switch/threaded-dispatch).
**Delta from vm1:** EncodeArithmetic added bitwise/arith primitives and rewrote the math as MBA:

- new opcodes: negate 0x2a; SHL 0x4d/0x6f; SHR 0x4e/0x53/0x73; OR 0x42/0xa7; AND 0xa6/0xb4;
  SUB 0x6b/0x94; LE 0x2b. (XOR/ADD/MUL/const/loadchar/strlen/return/branch still present, diversified.)
- **No eq/ne opcode:** comparisons became arithmetic — `acc==magic` -> `acc ^ magic` then branch-if-zero (0x5f);
  `len!=10` -> sub/xor then nonzero test.
- MBA identities used: `x*33=(x<<5)+x`; `a+b=(a^b)+((a&b)<<1)`; `a^b=(a|b)-(a&b)`.
Recovery = same target as vm1; peel MBA back to `(acc*33)^key[i]+i*7; ==0x32629093`. Magic still literal
in the binary (quick confirm). Lesson: Virtualize hides control flow, EncodeArithmetic hides the data math;
stacked (+encoded compares) = Denuvo-style layered cost. Deep MBA is where SMT simplifiers earn their keep.

---

## Anti-debug stretch (2026-10-24) — keycheck_ad / keycheck_ad_vm

Added `if (ptrace(PTRACE_TRACEME,0,0,0) < 0) return 0;` to check_key, then virtualized it.
Results (WSL):

- normal run: WIN (plain + vm)
- under gdb: LOSE — debugger detected even though check_key is virtualized (anti-debug lives in the VM)
- under gdb + `LD_PRELOAD=noptrace.so` (fake ptrace returns 0): **WIN** — bypassed

**Lesson:** virtualization protects the *logic*, not the *external-call boundary*. The anti-debug calls libc
`ptrace`; the VM invokes it via a call opcode, so intercepting `ptrace` (LD_PRELOAD) defeats it without
touching the obfuscated code. Other bypasses: patch/NOP the branch, `gdb catch syscall ptrace` + `return 0`,
fake `/proc/self/status` TracerPid.

**Defensive takeaway (-> FIXLIST / anti-cheat synthesis):** weak because it trusted libc. Harden by: raw `syscall(SYS_ptrace)`
(no symbol to preload), layer many independent checks (TracerPid, rdtsc timing, 0xCC breakpoint scan, parent
check), and keep them inside the VM + encoded. No single point of failure = the Denuvo model.
