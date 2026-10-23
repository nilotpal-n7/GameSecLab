/* keycheck.c — the toy we virtualize with Tigress, then recover in Ghidra.
 *
 * ONE self-contained function (check_key) holds all the secret logic, exactly
 * like a real anti-tamper system virtualizes a license/integrity check. We own
 * this code, so we have the "answer key" a real Denuvo target never gives you:
 * compile it BOTH ways (plain + virtualized) and compare.
 *
 * Correct key: RELAB-2026   (see keycheck_answer.txt)
 */
#include <stdio.h>
#include <string.h>

/* Virtualize THIS function with Tigress (--Functions=check_key). */
int check_key(const char *key) {
    int len = (int)strlen(key);
    if (len != 10) return 0;
    unsigned int acc = 0x1505u;                 /* seed */
    for (int i = 0; i < len; i++) {
        acc = (acc * 33u) ^ (unsigned char)key[i];
        acc += (unsigned int)(i * 7);
    }
    return acc == 0x32629093u;                  /* winning keys hash to this */
}

int main(int argc, char **argv) {
    if (argc != 2) { printf("usage: %s <key>\n", argv[0]); return 2; }
    if (check_key(argv[1])) { printf("WIN: key accepted\n"); return 0; }
    printf("LOSE: wrong key\n");
    return 1;
}
