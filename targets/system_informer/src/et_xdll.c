/* et_xdll.c — ExtendedTools (Themida) cross-DLL handshake challenger. See et_xdll.h for the design.
 *
 * Build notes:
 *   - Links sip_progate.lib (import lib for sip_xdll_respond, resolved at runtime from sip_progate.dll
 *     sitting beside SystemInformer.exe) and bcrypt.lib (CNG AES-256-GCM, which SI already depends on).
 *   - When compiled with /DSIP_THEMIDA the handshake body is wrapped in Themida SecureEngine VM markers
 *     (SecureEngineSDK64.lib) so the Themida GUI pass virtualizes it; without the define the markers are
 *     no-ops, which is how the standalone et_xdll_test.exe is built (it only proves the protocol).
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "pro_gate.h"   /* sip_xdll_respond — the VMProtect-virtualized responder in sip_progate.dll */
#include "et_xdll.h"

#ifdef SIP_THEMIDA
#include "ThemidaSDK.h" /* VM_START / VM_END etc. (x64 => SecureEngineSDK64.lib lib-call macros) */
#else
#define VM_START
#define VM_END
#endif

#pragma comment(lib, "bcrypt.lib")

#define ET_XDLL_SECTION_MAGIC "XDLB"   /* outer .sipm section tag (license_signer.build_xdll_section)   */
#define ET_XUNLOCK_MAGIC      "XUNL"   /* plaintext magic inside the blob, followed by u32 feature flags */

static int g_et_pro_flags = 0;

/* AES-256-GCM open via CNG. `ct` includes the trailing 16-byte tag. Returns 1 on auth success and writes
 * the plaintext (caller buffer >= ct_len-16) + its length. The tag check is the whole point: a response
 * that is not the exact handshake key fails authentication here, so no "if (ok)" compare is forgeable. */
static int et_aesgcm_open(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *ct, uint32_t ct_len, uint8_t *pt_out, uint32_t *pt_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    int ok = 0;

    if (ct_len < 16)
        return 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0, (PUCHAR)key, 32, 0) == 0) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
            ULONG written = 0;
            BCRYPT_INIT_AUTH_MODE_INFO(info);
            info.pbNonce = (PUCHAR)nonce;
            info.cbNonce = 12;
            info.pbTag   = (PUCHAR)(ct + ct_len - 16);
            info.cbTag   = 16;
            if (BCryptDecrypt(hkey, (PUCHAR)ct, ct_len - 16, &info, NULL, 0,
                              pt_out, ct_len - 16, &written, 0) == 0) {
                *pt_len = written;
                ok = 1;
            }
            BCryptDestroyKey(hkey);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

static uint8_t *et_read_all(const char *path, uint32_t *out_len)
{
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    uint8_t *buf = NULL;
    *out_len = 0;
    if (f != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(f, NULL);
        if (sz != INVALID_FILE_SIZE && sz > 0 && sz < (16u << 20)) {
            buf = (uint8_t *)malloc(sz);
            DWORD got = 0;
            if (buf && ReadFile(f, buf, sz, &got, NULL) && got == sz)
                *out_len = sz;
            else { free(buf); buf = NULL; }
        }
        CloseHandle(f);
    }
    return buf;
}

int EtXdllUnlock(const char *sipm_path)
{
    int flags = 0;

    VM_START
    uint32_t flen = 0;
    uint8_t *buf = et_read_all(sipm_path, &flen);
    if (buf && flen > 40u + 64u) {
        uint32_t ct_len = 0;
        memcpy(&ct_len, buf + 36, 4);
        /* XDLB section sits after the ENTL ciphertext and before the trailing 64-byte Ed25519 sig. */
        uint64_t xoff = (uint64_t)40 + ct_len;
        if (xoff + 4 + 32 + 12 + 2 <= (uint64_t)flen - 64 &&
            memcmp(buf + xoff, ET_XDLL_SECTION_MAGIC, 4) == 0) {
            const uint8_t *challenge = buf + xoff + 4;
            const uint8_t *xnonce    = buf + xoff + 36;
            uint16_t xlen = 0;
            memcpy(&xlen, buf + xoff + 48, 2);
            const uint8_t *xct = buf + xoff + 50;
            if (xoff + 50 + xlen <= (uint64_t)flen - 64) {
                uint8_t ch[32];
                uint8_t resp[32];
                memcpy(ch, challenge, 32);
                /* THE cross-DLL call: only a Pro-verified sip_progate returns the right 32-byte response. */
                if (sip_xdll_respond(ch, resp)) {
                    uint8_t pt[128];
                    uint32_t ptlen = 0;
                    if (et_aesgcm_open(resp, xnonce, xct, xlen, pt, &ptlen) &&
                        ptlen >= 8 && memcmp(pt, ET_XUNLOCK_MAGIC, 4) == 0) {
                        memcpy(&flags, pt + 4, 4);   /* feature bitmask from the decrypted blob */
                    }
                    SecureZeroMemory(resp, sizeof(resp));
                }
            }
        }
    }
    if (buf)
        free(buf);
    g_et_pro_flags = flags;
    VM_END

    return flags;
}

int EtIsProUnlocked(void)
{
    return g_et_pro_flags != 0;
}
