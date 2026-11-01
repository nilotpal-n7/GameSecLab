# Wiring the Pro gate into System Informer — the memory dumper, end to end

This is the first feature wired all the way through, so the pattern is proven once before the Memory
Editor / DLL Injection / cross-DLL handshake follow the same shape. All edits are in the user's fork; the
licensing core (`src/*.cpp`, `src/*.h`) is built into `sip_progate.lib` and linked into `SystemInformer`.

## 1. Build the licensing core as a static lib

Add a small VS project (or a `nmake`/CMake target) that compiles `pro_gate.cpp` + the chosen
`sip_crypto_*.cpp` backing into `sip_progate.lib`. **CRT must match SystemInformer**: `/MT` for Release,
`/MTd` for Debug (System Informer links the static CRT). Build flags: `/Zi /DEBUG /MAP` so the VMProtect
pass resolves `sip_gate_init` / `sip_access_mask` / `sip_xdll_respond`. Link `VMProtectSDK.lib` and the
LicenseSeat SDK lib.

A CRT mismatch does **not** fail compilation — it shows up as `LNK2005 _*` duplicate-CRT-symbol errors or
heap asserts at runtime. That is the integration trap; match `/MT[d]` and `RuntimeLibrary` across both.

## 2. Initialise once at startup

In `SystemInformer`'s early init (e.g. `main()` / `PhInitialization` path), after phlib is up:

```c
#include "pro_gate.h"
...
SipInitResult pro = sip_gate_init(NULL);   /* NULL = default machine-file search path */
/* Do NOT branch features on this result. UI may grey-out Pro menus with sip_is_pro(),
   but the privileged operations are guarded by the ACCESS_MASK below, not by this flag. */
```

## 3. Gate the dumper by the ACCESS_MASK it opens the process with

System Informer's Process Memory Dumper opens the target process, then calls `PhWriteMiniDumpProcess`.
Find where the dumper obtains its process handle (`misccmd.c`, the `ID_...DUMP...` command path /
`PhUiCreateDumpFileProcess`). Replace the fixed desired-access with the entangled mask:

```c
/* BEFORE (illustrative): a fixed mask, trivially patchable, and the gate would be a separate `if`. */
/* status = PhOpenProcess(&processHandle, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_READ, processId); */

/* AFTER: the access itself carries the license decision. 0x0450 = PROCESS_QUERY_INFORMATION |
   PROCESS_VM_READ (what a minidump needs); unlicensed callers get 0x1000 (SUSPEND_RESUME) instead. */
ACCESS_MASK want = sip_access_mask(SIP_FEAT_DUMP);
status = PhOpenProcess(&processHandle, want, processId);
if (!NT_SUCCESS(status)) {
    /* Unlicensed: the kernel denied the forensic rights. Surface SI's normal access-denied path. */
    PhShowStatus(hwndDlg, L"Unable to dump the process", status, 0);
    return;
}
/* Licensed: processHandle has PROCESS_VM_READ, PhWriteMiniDumpProcess succeeds as usual. */
```

The point: there is no boolean to flip. An unlicensed build opens the handle with `0x1000`, so
`PhWriteMiniDumpProcess` fails inside `MiniDumpWriteDump` with `STATUS_ACCESS_DENIED` — far from any
recognizable check site. A patched `.text` makes `sip_gate_init` fail to decrypt, so `g_state.mask_base`
stays zero and the mask is the trap regardless.

## 4. Verify the contrast

- **Unprotected Community build, no license** → dump fails with access denied.
- **With a valid `.sipm` for this machine + this build** → dump works.
- **Patch one `.text` byte** → `sip_gate_init` returns `SIP_KDF_MISMATCH`; dump fails. (`DEMO_SOFT` logs
  the code instead of corrupting, so it is filmable.)

## 5. The other features (same pattern)

- **Memory Editor write** (`memedit.c`): open with `sip_access_mask(SIP_FEAT_EDIT)` (0x0038 =
  `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`); without it the writer handle lacks VM_WRITE.
- **DLL Injection** (`misccmd.c`): open with `sip_access_mask(SIP_FEAT_INJECT)` (0x002A =
  `PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD`).
- **Cross-DLL handshake**: `ExtendedTools.dll` sends a 32-byte challenge; `SystemInformer.exe` answers
  with `sip_xdll_respond`; the plugin recomputes and compares. Only a genuinely Pro-verified pair match.

> KPH / ksi kernel driver must be **OFF** for the demo build. With KPH loaded, `KphOpenProcess` can grant
> access the user-mode ACCESS_MASK gate would deny, bypassing the whole scheme. Ship the demo with KPH
> disabled and say so on camera.
