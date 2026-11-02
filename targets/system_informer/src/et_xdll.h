/* et_xdll.h — ExtendedTools (Themida) side of the cross-DLL rolling-key handshake.
 *
 * ExtendedTools.dll is the CHALLENGER; sip_progate.dll (VMProtect) is the RESPONDER. The .sipm carries an
 * "XDLB" unlock section: challenge + an AES-256-GCM blob whose key is the handshake response that ONLY a
 * genuinely Pro-verified sip_progate can produce (sip_xdll_respond). ExtendedTools reads the challenge,
 * asks sip_progate for the response, and uses it as the AES key to open the blob. Right response ->
 * decrypts -> Pro flags; wrong/absent -> GCM auth fails -> 0 (Community). "Response-as-key": no naked
 * boolean crosses the DLL boundary, so cracking ONE protector (VMProtect OR Themida) is not enough.
 *
 * This unit is deliberately free of phlib/SystemInformer dependencies (pure Win32 + CNG + the sip_progate
 * import) so it compiles both into ExtendedTools.dll AND into a standalone harness (et_xdll_test.exe) that
 * proves the protocol without loading the full plugin (which imports from SystemInformer.exe).
 */
#ifndef ET_XDLL_H
#define ET_XDLL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Run the handshake against the given .sipm and return the unlocked feature flags (0 = Community/denied,
 * non-zero = Pro bitmask). sip_progate.dll must be loaded and sip_gate_init() already called by the host. */
int EtXdllUnlock(const char *sipm_path);

/* Convenience predicate for UI grey-out; the real gate is the flags value above (and, upstream, the
 * ACCESS_MASK the dumper/editor use). Non-zero iff the last EtXdllUnlock() unlocked Pro. */
int EtIsProUnlocked(void);

#ifdef __cplusplus
}
#endif

#endif /* ET_XDLL_H */
