# VMProtect break cheat-sheet — x64dbg + ScyllaHide + Scylla on a VMProtect'd binary

Reference while **you** drive. Target: `targets/license_app/dumps/license_app.vmp.exe` (VMProtect 3.11, `check_license`
virtualized + packed + Memory Protection + User/Kernel debugger detection). Format: **action → what it does → why.**

## The plan (why we attack the native branch, not the VM)

Only the **body** of `check_license` is VM bytecode. `main` still does, in native x86:
`if (check_license(key)) puts("LICENSED"); else puts("INVALID LICENSE");`
That `test eax,eax` + conditional jump is **not virtualized** — it's the weak point. We flip its outcome at
runtime. We do **not** devirtualize the VM (NoVmp can't touch 3.11; manual VM recovery is a later, optional drill).

> **Memory Protection gotcha:** you enabled the integrity CRC. Editing *bytes* (e.g. `jz`→`jmp`) is detected →
> the program dies. So we change a **register/flag at runtime**, not bytes. That beats virtualization + anti-tamper
> together, and is the real lesson of VMProtect.

## x64dbg keys

| Key | Does |
| --- | --- |
| **F9** | Run / continue (until next breakpoint or exception) |
| **F2** | Toggle breakpoint at the selected line |
| **F7 / F8** | Step into / step over one instruction |
| **F4** | Run to the cursor line |
| **Ctrl+G** | Go to address/expression |
| right-click → **Search for → Current Module → String references** | list decrypted strings in memory |
| right-click an address → **Follow in Disassembler / Dump** | pivot views |

## Step A — ScyllaHide (defeat the anti-debug)

**Plugins → ScyllaHide → Options** → profile preset **`x64dbg`** → OK. What the hides do:

- **PEB `BeingDebugged` / `NtGlobalFlag`** → the two cheapest "am I debugged?" flags; hidden so VMProtect's
  checks read "no".
- **`NtQueryInformationProcess` (ProcessDebugPort/Flags/Object)** → the OS's official "is there a debugger" query.
- **`NtSetInformationThread` (HideFromDebugger)** → stops the program detaching the debugger from itself.
- **`NtQuerySystemInformation` (KdDebuggerEnabled)** → the kernel-debugger check (you turned on Kernel detection).

Without these, VMProtect's "Debugger = User+Kernel" layer exits or crashes the process the moment you run it.

## Step B — load + feed an argument

**File → Open** `license_app.vmp.exe`. **File → Change Command Line** → append a **wrong** key, e.g.
`… license_app.vmp.exe DEADBEEF` → OK. *(No arg ⇒ it prints usage and exits; wrong key ⇒ we prove the
bypass by forcing LICENSED anyway.)*

## Step C — reach OEP (past the packer)

Packed code unpacks itself in memory, then jumps to the **OEP** (Original Entry Point = your real `main`-side code).

- Press **F9** through x64dbg's system breakpoints until you land in the program.
- The demo watermark messagebox appearing is a good sign you're at/near real execution.
- (Options → Preferences → Events: a breakpoint on **"Entry Breakpoint"** stops you at the unpacked entry.)

## Step D — find `main`'s decision

- right-click → **Search for → Current Module → String references** → double-click **`LICENSED`** (now decrypted
  in memory) → you land in `main`. The nearby `call` is `check_license`; right after it is `test eax,eax` + a
  `jz/jne` choosing the LICENSED vs INVALID path.
- **F2** on that conditional jump to breakpoint it.

**The exact branch (recovered from the clean build `license_app_hardened.exe`, imagebase 0x140000000):**

```x86asm
...113d:  e8 be fe ff ff   call 0x140001000     ; call check_license (virtualized in the protected build)
...1142:  85 c0            test eax,eax         ; test the VM's return value
...1144:  74 2c            je   0x140001172     ; ZF=1 → INVALID path    <-- THE BRANCH to flip
...1146:  48 8d 0d ...     lea  rcx,[0x140017369]  ; "LICENSED"
...114d:  e8 ...           call <print>         ; prints LICENSED
```

In the protected binary the addresses differ (packed + relocated) but the shape is identical: the `"LICENSED"`
string-ref lands you at the `lea`; scroll up two instructions to `test eax,eax` / `je` — that `je` is the target.
Byte-pattern to eyeball: `85 C0` (test eax,eax) immediately followed by `74 xx` (je) or `75 xx` (jne).

## Step E — the runtime bypass (no byte patch)

Run with the wrong key (F9) until the branch breakpoint hits, then **either**:

- flip the **Zero Flag (ZF)** in the Flags pane (double-click ZF) so the jump goes the LICENSED way, **or**
- set **EAX = 1** (double-click EAX in the registers pane) before the `test`.
Continue (F9) → it prints **LICENSED** on a wrong key. Integrity CRC stays happy because **no bytes changed**.

## (Optional) Step F — Scylla dump, if you want the unpacked image

Plugins → **Scylla** (or the Scylla tab): with the process stopped at OEP →

- **IAT Autosearch** → **Get Imports** (rebuilds the import table the packer hid), then
- **Dump** → **Fix Dump** → saves an unpacked `.exe` you can open statically in IDA/Ghidra.
This is how you'd feed a devirtualizer or do static VM analysis — not needed for the register-flip bypass.

## What I run in the background (so the docs/automation are right)

- `diec -e license_app.vmp.exe` → sections + entropy (shows the packed high-entropy section).
- `pefile` import counts: clean vs protected → proves **Import Protection** hid the IAT.
- plaintext-string scan: clean vs protected → strings only reappear after in-memory unpack.
Findings land in `targets/license_app/recovery/recon_vmprotect.md`.
