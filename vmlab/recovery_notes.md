# Recovery notes — pulling `check_key` out of the virtualized binary

Everything is staged. Open the Ghidra project and work top to bottom. Fill in your findings as you go —
this file IS the portfolio deliverable.

## What's in the box

In `vmlab/`:

- `keycheck.c` — the source (one function `check_key`).
- `keycheck_plain_elf` — plain build = **the answer key** (readable in Ghidra in seconds).
- `keycheck_vm` — Tigress **EncodeLiterals + EncodeArithmetic + Virtualize** (the hard build).
- `keycheck_vm.c` — the generated interpreter source (peek if stuck, but try the binary first).
- `keycheck_ad.c` / `keycheck_ad_vm.c` — the anti-debug stretch (plain + virtualized).
- `ghidra_proj/KeyCheck.gpr` — Ghidra project with the binaries imported **and auto-analyzed**.

All builds behave identically: key `RELAB-2026` → WIN, anything else → LOSE.

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

## Exercise B — recover the VM (`keycheck_vm`)

Now the same function is an interpreter, and the arithmetic is rewritten as MBA (EncodeArithmetic) with
encoded comparisons (EncodeLiterals). Your job:

1. Open `check_key` in the decompiler. It's a **dispatch loop** over an array of numbers (the bytecode) with
   a big `switch` / jump table (the opcode handlers). Find:
   - the **interpreter loop** (a `while` reading a program-counter into a byte/int array),
   - the **bytecode array** (a global or stack array of ints the loop walks),
   - the **handlers** for the ops you expect: multiply, xor, add, load byte, compare.
2. Because arithmetic is encoded, expect **no plain eq/ne or `*33`**: the compare becomes `acc ^ magic` then
   branch-if-zero, and `*33` appears as `(acc<<5)+acc`. Peel the MBA identities back to the real math.
3. Record: where's the loop? how many opcodes? which handlers do the `*33`, the `^`, and the final compare?

   ```text
   (your opcode map + where the magic compare happens)
   ```

## Exercise C (stretch) — anti-debug

`keycheck_ad.c` adds a self-check near the top of `check_key` —
`if (ptrace(PTRACE_TRACEME,0,0,0) == -1) return 0;` (needs `#include <sys/ptrace.h>`) — then virtualizes it
(`keycheck_ad_vm`). Re-run the Tigress commands (see `knowledge/method/virtualize.md`), then practice
bypassing it: run under `gdb`, or NOP the check. That's Denuvo's layered anti-debug in miniature.

## The answer (don't peek until you've tried B)

`check_key`: `acc=0x1505; for i in 0..9: acc=(acc*33)^key[i]; acc+=i*7; return acc==0x32629093`.
Correct key `RELAB-2026`. Success = your recovered opcode trace computes exactly this.

---

## RECOVERED (2026-10-24) — `keycheck_vm` opcode map

Stack-machine VM: `check_key` = `while(true) switch(*puVar8)` where **puVar8 = PC** (starts at
`&_3_check_key_$array` = bytecode) and **puVar7 = SP**. push = sp+=2, binary op pops 2 / pushes 1,
`default: goto` re-enters the switch (threaded dispatch, hides the loop).

| Opcode(s) | Operation | Maps to |
| --- | --- | --- |
| push-const / push-&arg / push-&local | operands | 0x1505, 33, 7, 10, 0x32629093, `key`, `i`, `acc` |
| load byte via ptr / zero-extend | `key[i]` as uchar | `key[i]` |
| MUL / XOR / ADD (diversified: several opcodes each) | core math | `*33`, `^ key[i]`, `acc += …`, `i*7` |
| NEG, SHL, SHR, OR, AND, SUB, LE (EncodeArithmetic) | MBA primitives | the rewritten math (below) |
| branch-if-zero (0x5f) | encoded compare | `acc ^ 0x32629093 == 0`; `len != 10` via sub/xor nonzero |
| branch-if-true / unconditional jump | control flow | loop back-edge |
| CALL extern (1 = strlen) / return top | boundary | `strlen(key)`, `return` |

**EncodeArithmetic rewrote the math as MBA** (peel these back):
`x*33 = (x<<5)+x`; `a+b = (a^b)+((a&b)<<1)`; `a^b = (a|b)-(a&b)`. There is **no eq/ne opcode** — all
comparisons became arithmetic + branch-if-zero.

Recovered logic (from handlers alone, no bytecode trace needed):
`len=strlen(key); if(len!=10) return 0; acc=0x1505; for i in 0..9: acc=(acc*33)^key[i]; acc+=i*7; return acc==0x32629093;`

Anti-RE noticed: **opcode diversification** (multiple opcodes per operation), **threaded dispatch**, and the
**MBA / encoded compares** layered on top. All three are techniques Denuvo also uses — deep MBA is where SMT
simplifiers earn their keep (the same peeling our `reaforge/core/peel.py` automates on the VMProtect target).

### CONFIRMED against answer key (2026-10-24)

- Bytecode `_3_check_key_$array` starts with a push-&key op — matches the opcode map (first op).
- `keycheck_plain_elf` check_key decompile == recovered VM logic:
    `acc=0x1505; do { acc = ((acc*33) ^ key[i]) + i*7; i7+=7; } while(i7 != 0x46 /*70=7*10*/); return acc==0x32629093;`
- Compiler details learned: **strength reduction** (i*7 kept as a running +7 counter, no multiply) and a
  **disguised loop bound** (`while(i7 != 70)` instead of `i<10`). Virtualized -> recovered -> verified: full circle.

---

## Anti-debug stretch (2026-10-24) — keycheck_ad / keycheck_ad_vm

Added `if (ptrace(PTRACE_TRACEME,0,0,0) < 0) return 0;` to check_key, then virtualized it. Results (WSL):

- normal run: WIN (plain + vm)
- under gdb: LOSE — debugger detected even though check_key is virtualized (anti-debug lives in the VM)
- under gdb + `LD_PRELOAD=noptrace.so` (fake ptrace returns 0): **WIN** — bypassed

**Lesson:** virtualization protects the *logic*, not the *external-call boundary*. The anti-debug calls libc
`ptrace`; the VM invokes it via a call opcode, so intercepting `ptrace` (LD_PRELOAD) defeats it without
touching the obfuscated code. Other bypasses: patch/NOP the branch, `gdb catch syscall ptrace` + `return 0`,
fake `/proc/self/status` TracerPid.

**Defensive takeaway (-> FIXLIST / anti-cheat synthesis):** weak because it trusted libc. Harden by: raw
`syscall(SYS_ptrace)` (no symbol to preload), layer many independent checks (TracerPid, rdtsc timing, 0xCC
breakpoint scan, parent check), and keep them inside the VM + encoded. No single point of failure = the
Denuvo model.
