/* license_app.c — Capstone C0 target: a hardware-bound license check (Windows PE).
 * machine_id() derives an ID from the C: volume serial; expected_key() mixes it;
 * check_license() accepts only the matching 8-hex-digit key. We then protect this
 * with VMProtect/Themida/OLLVM and reverse our own output.
 * Build (both from one source):
 *   gcc -O2 -o license_app.exe license_app.c
 *   gcc -O2 -DKEYGEN -o keygen.exe license_app.c   # prints this machine's valid key
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    unsigned int want = expected_key(machine_id());
    unsigned int got = (unsigned int)strtoul(key, NULL, 16);
    return got == want;
}

#ifdef KEYGEN
int main(void) { printf("%08X\n", expected_key(machine_id())); return 0; }
#else
int main(int argc, char **argv) {
    if (argc != 2) { printf("usage: %s <8-hex-key>\n", argv[0]); return 2; }
    if (check_license(argv[1])) { printf("LICENSED\n"); return 0; }
    printf("INVALID LICENSE\n"); return 1;
}
#endif
