# pdf_analysis.md — the research papers, explained simply

Plain-English notes on the `docs/` papers, with examples. (Practice: when I analyze a doc, I add a simple
explanation here with an analogy + a concrete example, so it's understandable later.)

---

## 1. VMProtect's single-step anti-debug (the thing blocking our VMProtect break)

Source: `Bypassing_Anti-Analysis_of_Commercial_Protector_Methods_Using_DBI_Tools.pdf` (IEEE 2021), §IV-C +
Table 1 ("VMProtect Anti-DBI = Exception / Single Step").

### The one-paragraph version

VMProtect sets the CPU's **trap flag** and then expects the CPU to "trip" (raise a single-step exception)
into **VMProtect's own catcher**. If its catcher catches the trip, nobody's interfering → continue. If the
trip never arrives at its catcher, someone (a debugger/DBI) stole it → "A debugger has been found."

### The analogy (tripwire)

VMProtect lays a **tripwire for itself** and stands ready to catch whoever trips it:

- It flips a switch that tells the CPU: *"after the very next instruction, STOP and shout."* (the shout = a
  **single-step exception**).
- VMProtect has placed **its own catcher** (an exception handler) right there to catch the shout.

Now two worlds:

- **No debugger:** CPU runs one instruction → shouts → **VMProtect's catcher catches it** → "good, nobody's
  here" → keeps running.
- **Debugger attached:** In Windows, a debugged program's exceptions go to the **debugger first** ("first
  chance"). The debugger normally **keeps the shout** (pauses or handles it), so it never reaches VMProtect's
  catcher. VMProtect notices its catcher got nothing → *"a debugger stole my tripwire"* → aborts.

So the detection isn't "is a debugger flag set?" — it's cleverer: **"did MY exception handler get to run?"**
A debugger, by default, breaks that assumption.

### The concrete example (what the instructions look like)

The **trap flag (TF)** is **bit 8 of the EFLAGS register = `0x100`**. When TF=1, the CPU raises
`EXCEPTION_SINGLE_STEP` (code **`0x80000004`**) after the *next* instruction, then auto-clears TF.

```asm
pushfd                  ; push the flags register onto the stack
or   dword [esp], 0x100  ; set the trap-flag bit in the saved flags
popfd                   ; pop it back -> TF is now 1
nop                     ; <-- CPU runs this, THEN raises a single-step exception
; ... VMProtect's own exception handler is registered to run right here ...
; if it runs  -> "clean", continue
; if it never runs -> "debugger detected"
```

### Why the debugger "swallows" it

A **first-chance exception** in a debugged process is delivered to the debugger before the program's own
handlers (SEH/VEH). If the debugger consumes it instead of passing it on, the program's handler is skipped.
That skip is exactly what VMProtect is watching for.

### How we beat it (two ways)

1. **Tell the debugger to pass it through.** In x64dbg: add exception `0x80000004`, set **Break On = Do not
   break** and **Exception handled by = Debuggee**. Now x64dbg hands the single-step exception to VMProtect's
   own catcher → the tripwire "works" → no detection. *(This is the quick test.)*
2. **Use a DBI (Intel Pin) that re-raises the exception** (the paper's Fig 15: "DBI → Raise Exception →
   Bypass"). A Pin tool detects the trap-flag/`POPFD` moment and explicitly delivers the single-step exception
   so VMProtect's handler runs. More work, but it's the documented method and becomes a reusable REAForge tool.

### Why ScyllaHide failed (ties it together)

ScyllaHide hides *flags and API answers* (BeingDebugged, NtQueryInformationProcess, timing, DRx…). It has **no
single-step/trap-flag handler** — look at its option list: breakpoint, illegal-instruction, guard-page… but no
single-step. So it literally cannot cover this trick, no matter how many hooks we enable. That's why maxing it
out still got detected.

---

## Key terms (quick reference)

- **EFLAGS / RFLAGS** — the CPU's status/control flags register.
- **Trap Flag (TF)** — EFLAGS bit 8 (`0x100`); when 1, CPU single-steps (raises an exception after each instr).
- **Single-step exception** — `EXCEPTION_SINGLE_STEP`, code `0x80000004`.
- **First-chance exception** — an exception offered to the **debugger** before the program's own handler.
- **SEH / VEH** — Structured / Vectored Exception Handling: the program's own exception catchers.
- **DBI** — Dynamic Binary Instrumentation (Intel Pin): runs the target under a JIT, not the debug API — so it
  isn't a "debugger", but protectors still detect it via these exception/timing tricks (anti-DBI).
