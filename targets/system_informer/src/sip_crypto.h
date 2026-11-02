/* sip_crypto.h — primitive crypto + environment seam used by the Pro gate.
 *
 * pro_gate.cpp is written against THIS narrow interface so the entangled-KDF / verify logic is fixed and
 * matches license_signer.py byte for byte. The backing is sip_crypto_licenseseat.cpp:
 *   - HWID + Ed25519 verify come from the LicenseSeat C++ SDK (device::generate_device_id,
 *     crypto::verify_ed25519_signature).
 *   - AES-256-GCM + HKDF-SHA256 + the image CRC come from Windows CNG (BCrypt) — LicenseSeat's public
 *     headers do not expose standalone AES-GCM/HKDF, and SI already relies on CNG.
 *
 * Contract (all little-endian where it matters; all functions are leaf, allocate nothing, never throw):
 *   - sip_hkdf_sha256: RFC 5869 HKDF with SHA-256. info = "SIP-offline-v1". Output 32 bytes.
 *   - sip_aesgcm_decrypt: AES-256-GCM; `ct` includes the trailing 16-byte tag; aad = NULL. Returns 1 on
 *       auth success and writes plaintext to `pt_out` (caller buffer >= ct_len-16), else 0.
 *   - sip_ed25519_verify: returns 1 iff `sig`(64) is a valid signature of `msg` under `pub`(32).
 *   - sip_hwid: canonical machine id bytes (LicenseSeat HWID / VMProtectGetCurrentHWID), same bytes the
 *       signer was given via --hwid. Writes up to *len; updates *len.
 *   - sip_image_text_crc32: CRC-32 (zlib polynomial) over this module's own ON-DISK image (the whole file;
 *       dominated by .text pre-pack, and packing-robust once VMProtect zeroes .text's raw data), computed at
 *       runtime. Feeds the KDF; a patched byte (incl. a debugger's 0xCC) changes it -> decrypt fails.
 */
#ifndef SIP_CRYPTO_H
#define SIP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void     sip_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *out32);

int      sip_aesgcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ct, size_t ct_len, uint8_t *pt_out);

int      sip_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                            const uint8_t sig[64]);

int      sip_hwid(uint8_t *out, size_t *len);        /* 1 on success */

uint32_t sip_image_text_crc32(void);

#ifdef __cplusplus
}
#endif

#endif /* SIP_CRYPTO_H */
