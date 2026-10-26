/* license_app_hardened.c — VMProtect target: same license check as clean/OLLVM, but the whole
 * check_license algorithm is wrapped in a VMProtect virtualization marker so the
 * protector turns it into VM bytecode. machine_id()/expected_key() are force-inlined
 * so their arithmetic lands INSIDE the marked region (and thus gets virtualized).
 *
 * Build (unprotected, marker build — needs VMProtectSDK64.dll beside it to run):
 *   clang license_app_hardened.c -O2 -I"<VMP>\Include\C" "<VMP>\Lib\Windows\VMProtectSDK64.lib" -o license_app_hardened.exe
 * Protect (SDK markers, no project file needed):
 *   VMProtect_Con.exe license_app_hardened.exe license_app_c2_vmp.exe
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>   /* SDK header declares bool-returning helpers */
#include "VMProtectSDK.h"

#define FORCE_INLINE static __attribute__((always_inline)) inline

FORCE_INLINE unsigned int machine_id(void) {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    return (unsigned int)serial;
}

FORCE_INLINE unsigned int expected_key(unsigned int mid) {
    unsigned int acc = 0x1505u ^ mid;
    for (int i = 0; i < 8; i++) {
        acc = (acc * 33u) ^ ((mid >> (i * 4)) & 0xF);
        acc += (unsigned int)(i * 7);
    }
    return acc;
}

int check_license(const char *key) {
    int result;
    VMProtectBeginVirtualization("check_license");
    unsigned int want = expected_key(machine_id());
    unsigned int got = (unsigned int)strtoul(key, NULL, 16);
    result = (got == want);
    VMProtectEnd();
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) { printf("usage: %s <8-hex-key>\n", argv[0]); return 2; }
    if (check_license(argv[1])) { printf("LICENSED\n"); return 0; }
    printf("INVALID LICENSE\n"); return 1;
}
