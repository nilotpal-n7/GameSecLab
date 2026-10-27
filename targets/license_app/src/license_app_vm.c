/* license_app_vm.c — Themida-target variant of license_app.c.
 * Same hardware-bound check, but the WHOLE check_license body is wrapped in Themida's
 * VM_START/VM_END so SecureEngine virtualizes the license logic (machine_id + expected_key are
 * inlined into it at -O2, so they get virtualized too). Pick the hardest VM (e.g. EAGLE64 Black)
 * in the Themida GUI's "Virtual Machine" tab — that VM applies to this macro region.
 *
 * Build (MinGW x64, Themida SDK on the include path):
 *   gcc -O2 -I"C:\Tools\ThemidaDemo\ThemidaSDK\Include\C" \
 *       -o C:\Tools\GameSecLab\targets\license_app\dumps\license_app_vm.exe \
 *          C:\Tools\GameSecLab\targets\license_app\src\license_app_vm.c
 * Then protect license_app_vm.exe with Themida -> license_app.themida.exe.
 * (Keygen stays in license_app.c: gcc -O2 -DKEYGEN -o keygen.exe license_app.c)
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ThemidaSDK.h"

static unsigned int machine_id(void) {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    return (unsigned int)serial;
}

static unsigned int expected_key(unsigned int mid) {
    unsigned int acc = 0x1505u ^ mid;
    for (int i = 0; i < 8; i++) {
        acc = (acc * 33u) ^ ((mid >> (i * 4)) & 0xF);
        acc += (unsigned int)(i * 7);
    }
    return acc;
}

int check_license(const char *key) {
    int result = 0;
    VM_START                                    /* SecureEngine VM region — virtualize the verdict */
    unsigned int want = expected_key(machine_id());
    unsigned int got = (unsigned int)strtoul(key, NULL, 16);
    result = (got == want);
    VM_END
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) { printf("usage: %s <8-hex-key>\n", argv[0]); return 2; }
    if (check_license(argv[1])) { printf("LICENSED\n"); return 0; }
    printf("INVALID LICENSE\n"); return 1;
}
