/* sip_crypto_licenseseat.cpp — the real backing for sip_crypto.h.
 *
 * Split of responsibilities (deliberate):
 *   - HWID + Ed25519 verify  -> the LicenseSeat C++ SDK (demo/licenseseat). This is the SDK the product
 *     ships with: device::generate_device_id() is the machine fingerprint, and
 *     crypto::verify_ed25519_signature() is the offline signature check (OpenSSL EVP under the hood).
 *   - AES-256-GCM + HKDF-SHA256 + CRC-32  -> Windows CNG (BCrypt). System Informer already uses CNG, it
 *     needs no extra dependency, and the LicenseSeat public headers do not expose standalone AES-GCM /
 *     HKDF (only the whole stock verify_machine_file flow), so we implement the symmetric half ourselves
 *     to match license_signer.py's SIPM format exactly.
 *
 * This is C++ (LicenseSeat is C++), but every exported symbol is extern "C" (see sip_crypto.h) and no C++
 * object with a destructor is handed back across the boundary — results are copied into caller buffers.
 * Build into sip_progate.lib with SI's CRT (/MT release, /MTd debug); link bcrypt.lib + licenseseat.lib.
 */
#include "sip_crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include <stdlib.h>
#include <string>
#include <vector>

#include "licenseseat/crypto.hpp"
#include "licenseseat/device.hpp"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#  define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Linker-provided base of the module this code is linked into (the exe or the plugin DLL). */
extern "C" IMAGE_DOS_HEADER __ImageBase;

/* ---- CRC-32 (zlib polynomial 0xEDB88320), over this module's own mapped .text -------------------- */
static uint32_t crc32_buf(const uint8_t *p, size_t n)
{
    static uint32_t tbl[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            tbl[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = tbl[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

extern "C" uint32_t sip_image_text_crc32(void)
{
    /* CRC the ON-DISK raw .text of this module's own file, not the mapped image: ASLR relocations can make
     * the in-memory .text differ per process, which would make the KDF input non-reproducible. The on-disk
     * bytes are stable and are exactly what an attacker patches, which is the threat we bind against. */
    HMODULE self = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&__ImageBase), &self))
        return 0;
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0;

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(f, NULL);
    uint32_t crc = 0;
    if (sz != INVALID_FILE_SIZE && sz > 0x200) {
        uint8_t *buf = static_cast<uint8_t *>(malloc(sz));
        DWORD got = 0;
        if (buf && ReadFile(f, buf, sz, &got, NULL) && got == sz) {
            const IMAGE_DOS_HEADER *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(buf);
            if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) <= sz) {
                const IMAGE_NT_HEADERS *nt =
                    reinterpret_cast<const IMAGE_NT_HEADERS *>(buf + dos->e_lfanew);
                const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
                for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                    if (memcmp(sec[i].Name, ".text", 5) == 0) {
                        DWORD off = sec[i].PointerToRawData, len = sec[i].SizeOfRawData;
                        if ((uint64_t)off + len <= sz) crc = crc32_buf(buf + off, len);
                        break;
                    }
                }
            }
        }
        free(buf);
    }
    CloseHandle(f);
    return crc;
}

/* Diagnostic export: report this machine's HWID and this DLL's on-disk .text CRC, so a license can be
 * issued for this exact build (license_signer.py --hwid <> --text-crc <>). Exposing these does not weaken
 * the scheme — both are attacker-derivable; the secret is the issuer private key. */
extern "C" __declspec(dllexport) void sip_report(char *hwid_out, int hwid_cap, uint32_t *crc_out)
{
    if (hwid_out && hwid_cap > 0) {
        size_t cap = (size_t)hwid_cap - 1, n = cap;
        if (sip_hwid(reinterpret_cast<uint8_t *>(hwid_out), &n)) hwid_out[n <= cap ? n : cap] = 0;
        else hwid_out[0] = 0;
    }
    if (crc_out) *crc_out = sip_image_text_crc32();
}

/* ---- HWID + Ed25519 verify via LicenseSeat -------------------------------------------------------- */
extern "C" int sip_hwid(uint8_t *out, size_t *len)
{
    std::string id = licenseseat::device::generate_device_id(); /* C++ object stays local */
    if (id.empty() || !out || !len) { if (len) *len = 0; return 0; }
    size_t n = id.size() < *len ? id.size() : *len;
    memcpy(out, id.data(), n);
    *len = n;
    return 1;
}

extern "C" int sip_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                                  const uint8_t sig[64])
{
    /* LicenseSeat's verify takes base64 strings: pubkey std-Base64, signature Base64URL, message raw. */
    std::vector<uint8_t> pubv(pub, pub + 32), sigv(sig, sig + 64);
    std::string message(reinterpret_cast<const char *>(msg), msg_len);
    std::string pub_b64 = licenseseat::crypto::base64_encode(pubv);
    std::string sig_b64 = licenseseat::crypto::base64url_encode(sigv);
    auto r = licenseseat::crypto::verify_ed25519_signature(message, sig_b64, pub_b64);
    return (!r.is_error() && r.value()) ? 1 : 0;
}

/* ---- AES-256-GCM decrypt + HKDF-SHA256 via BCrypt ------------------------------------------------- */
static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    int ok = 0;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                               BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                                        const_cast<PUCHAR>(key), (ULONG)key_len, 0)) &&
            NT_SUCCESS(BCryptHashData(hHash, const_cast<PUCHAR>(data), (ULONG)data_len, 0)) &&
            NT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
            ok = 1;
        if (hHash) BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return ok;
}

extern "C" void sip_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                const uint8_t *info, size_t info_len,
                                uint8_t *out32)
{
    /* RFC 5869 with L == 32 (one expand block). extract: PRK = HMAC(salt, ikm). */
    uint8_t prk[32];
    uint8_t zero[32] = {0};
    if (!salt || salt_len == 0) { salt = zero; salt_len = 32; }
    if (!hmac_sha256(salt, salt_len, ikm, ikm_len, prk)) { memset(out32, 0, 32); return; }
    /* expand: T(1) = HMAC(PRK, info || 0x01). */
    std::vector<uint8_t> t(info_len + 1);
    if (info_len) memcpy(t.data(), info, info_len);
    t[info_len] = 0x01;
    if (!hmac_sha256(prk, 32, t.data(), t.size(), out32)) memset(out32, 0, 32);
}

extern "C" int sip_aesgcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *ct, size_t ct_len, uint8_t *pt_out)
{
    if (ct_len < 16) return 0;
    size_t body = ct_len - 16;                 /* ciphertext without the trailing 16-byte tag */
    const uint8_t *tag = ct + body;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    int ok = 0;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        if (NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                         (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                         sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) &&
            NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                  const_cast<PUCHAR>(key), 32, 0))) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
            BCRYPT_INIT_AUTH_MODE_INFO(info);
            info.pbNonce = const_cast<PUCHAR>(nonce);
            info.cbNonce = 12;
            info.pbTag   = const_cast<PUCHAR>(tag);
            info.cbTag   = 16;
            ULONG outlen = 0;
            NTSTATUS s = BCryptDecrypt(hKey, const_cast<PUCHAR>(ct), (ULONG)body, &info,
                                       nullptr, 0, pt_out, (ULONG)body, &outlen, 0);
            ok = NT_SUCCESS(s) ? 1 : 0;        /* GCM tag mismatch -> STATUS_AUTH_TAG_MISMATCH -> 0 */
        }
        if (hKey) BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return ok;
}
