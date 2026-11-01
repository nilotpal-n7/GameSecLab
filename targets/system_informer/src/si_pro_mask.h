/* si_pro_mask.h — branchless, kernel-enforced Pro gate for System Informer Pro.
 *
 * The Pro features never test a naked boolean. Instead the license state is turned into the
 * NtOpenProcess ACCESS_MASK that the feature *actually uses*, so the Windows kernel is the thing that
 * enforces the gate: an unlicensed caller receives a deliberately wrong mask and NtOpenProcess returns
 * STATUS_ACCESS_DENIED downstream — there is no JZ/JNZ to flip, and nothing to NOP.
 *
 *   m      = (ULONG)(-(LONG)(entitled & crc_ok & nodbg));   // 0xFFFFFFFF if all set, else 0
 *   access = (base & m) | (trap & ~m);                       // base when entitled, trap otherwise
 *
 * `base` is NOT a compile-time immediate in the protected build: it is read from the AES-GCM-decrypted
 * license payload (mask_dump / mask_inject / mask_edit), so it does not exist in the binary at all until
 * a correctly-signed, correctly-entangled license has been decrypted on the right machine. `trap`
 * (0x1000 = PROCESS_SUSPEND_RESUME) is enough to open a handle but denies every Pro operation, so the
 * failure surfaces as an access-denied on the real syscall rather than at a recognizable check site.
 *
 * Keep the three predicate inputs as 0/1 ULONGs. The selection below is intentionally free of branches;
 * in the protected build the call site that materialises `access` lives INSIDE a VMProtect region (see
 * pro_gate.cpp), so there is no plaintext mask-in-register -> syscall seam to hook.
 */
#ifndef SI_PRO_MASK_H
#define SI_PRO_MASK_H

#include <windows.h>  /* ULONG, LONG, ACCESS_MASK */
#include "pro_gate.h" /* SipFeature (the public contract owns the enum) */

/* The unlicensed trap mask. Grants a handle but no forensic right, so misuse denies at the syscall. */
#ifndef SIP_TRAP_MASK
#define SIP_TRAP_MASK ((ULONG)0x00001000) /* PROCESS_SUSPEND_RESUME */
#endif

/* Branchless mask selection. `entitled`, `crc_ok`, `nodbg` MUST each be exactly 0 or 1.
 * Returns `base` when all three hold, otherwise `trap`. No comparisons, no branches. */
static __forceinline ACCESS_MASK sip_select_mask(ULONG base, ULONG trap,
                                                 ULONG entitled, ULONG crc_ok, ULONG nodbg)
{
    ULONG m = (ULONG)(-(LONG)(entitled & crc_ok & nodbg));
    return (ACCESS_MASK)((base & m) | (trap & ~m));
}

#endif /* SI_PRO_MASK_H */
