/* keygen_recovered.c — reconstructed ONLY from IDA's decompile of check_license
 * (machine_id + expected_key were inlined at -O2). Proves the C0 baseline was fully recovered.
 */
#include <windows.h>
#include <stdio.h>
int main(void) {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", 0, 0, &serial, 0, 0, 0, 0);
    unsigned int v4 = serial ^ 0x1505u;   /* acc = mid ^ 0x1505 */
    int v2 = 0, v3 = 0;
    do {
        unsigned int v5 = 33u * v4;
        unsigned int v6 = serial >> v3;
        v3 += 4;
        v4 = (unsigned int)v2 + (v5 ^ (v6 & 0xF));  /* acc = i*7 + (33*acc ^ nibble) */
        v2 += 7;
    } while (v2 != 56);                     /* 8 rounds */
    printf("%08X\n", v4);
    return 0;
}
