/* pro_gate.h — extern "C" bridge between System Informer's C code and the C++ Pro licensing core.
 *
 * System Informer is C (phlib runtime, NTAPI). The licensing core is C++ (LicenseSeat SDK: offline
 * Ed25519 + AES-256-GCM machine files + HWID). This header is the ONLY surface the C side sees: it is
 * pure C, exchanges primitives only (no C++ types, no std::string crossing the boundary), and is
 * implemented in pro_gate.cpp which is compiled into a small static lib (sip_progate.lib) whose CRT
 * settings (/MT or /MTd) MUST match the System Informer build so the C++ runtime links cleanly. That
 * CRT match is the real integration trap — a mismatch shows up as duplicate/again-defined CRT symbols
 * or heap asserts at link/runtime, not as a compile error in this header.
 *
 * Threading: sip_gate_init() is called once, early (SI startup / plugin load). The sip_access_mask()
 * and sip_is_pro() queries are cheap, lock-free reads of the cached post-verify state and are safe to
 * call from the feature paths (misccmd.c, memedit.c). None of these functions allocates or throws
 * across the boundary.
 */
#ifndef PRO_GATE_H
#define PRO_GATE_H

#include <windows.h> /* ACCESS_MASK, ULONG */

#ifdef __cplusplus
extern "C" {
#endif

/* Result of sip_gate_init(). The feature code only ever needs OK vs not-OK, but the distinct codes let
 * the RE walkthrough show WHERE a given tampering lands (decrypt failure vs signature vs expiry). */
typedef enum SipInitResult {
    SIP_OK              = 0,
    SIP_NO_LICENSE      = 1, /* no machine file present                                          */
    SIP_BAD_FORMAT      = 2, /* magic/version/length wrong                                       */
    SIP_SIG_INVALID     = 3, /* Ed25519 signature check failed (forged/tampered, no private key) */
    SIP_KDF_MISMATCH    = 4, /* AES-GCM auth failed: wrong HWID, patched .text, or swapped pubkey */
    SIP_EXPIRED         = 5,
    SIP_SLUG_MISMATCH   = 6,
    SIP_DEBUGGER        = 7  /* anti-debug tripped during init (see DEMO_SOFT)                   */
} SipInitResult;

/* Load + verify the offline machine file and cache the entangled Pro state. `machine_file_path` may be
 * NULL to use the default search path. Safe to call more than once (re-verifies). */
SipInitResult sip_gate_init(const char *machine_file_path);

/* Non-zero iff a valid Pro license was verified. This is a convenience predicate for UI (menu grey-out);
 * it is NOT what guards the privileged operations — the ACCESS_MASK below is. */
int sip_is_pro(void);

/* THE gate. Returns the NtOpenProcess ACCESS_MASK the given feature must use: the license-carried base
 * when entitled + image-CRC-valid + no-debugger, otherwise the trap mask (handle opens, Pro op denied).
 * The selection is branchless (see si_pro_mask.h) and, in the protected build, is materialised inside a
 * VMProtect region, so there is no plaintext mask -> syscall seam. Callers pass the result straight to
 * NtOpenProcess / PhOpenProcess and must NOT branch on sip_is_pro() to decide whether to call it. */
ACCESS_MASK sip_access_mask(int /*SipFeature*/ feature);

/* Cross-DLL rolling-key handshake (SystemInformer.exe <-> plugins\ExtendedTools.dll). Both modules are
 * protected; the key is derived from HWID + verified LicenseSeat state and marshalled across the module
 * boundary as primitives only. The caller supplies a 32-byte challenge; on a valid Pro state the bridge
 * writes the 32-byte rolling response. Returns non-zero on success. A module that cannot produce the
 * correct response (unpatched-but-unlicensed, or patched) fails the handshake and ExtendedTools stays
 * in Community mode. */
int sip_xdll_respond(const unsigned char challenge[32], unsigned char response_out[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PRO_GATE_H */
