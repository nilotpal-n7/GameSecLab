/* keycheck_ad.c — keycheck.c + a ptrace anti-debug self-check.
 * If a debugger is attached, PTRACE_TRACEME returns -1 and check_key rejects
 * even the correct key. Virtualize check_key so the anti-debug lives inside the VM.
 * Correct key: RELAB-2026
 */
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int check_key(const char *key) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) return 0;   /* debugger present -> fail */
    int len = (int)strlen(key);
    if (len != 10) return 0;
    unsigned int acc = 0x1505u;
    for (int i = 0; i < len; i++) {
        acc = (acc * 33u) ^ (unsigned char)key[i];
        acc += (unsigned int)(i * 7);
    }
    return acc == 0x32629093u;
}

int main(int argc, char **argv) {
    if (argc != 2) { printf("usage: %s <key>\n", argv[0]); return 2; }
    if (check_key(argv[1])) { printf("WIN: key accepted\n"); return 0; }
    printf("LOSE: wrong key (or debugger detected)\n");
    return 1;
}
