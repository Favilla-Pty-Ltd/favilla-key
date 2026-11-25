/* Host test for lib/scp03 against tests/se_sim.py (independent SCP03 impl).
 *   gcc -I../lib/scp03 -I../lib/aes128 host_scp03.c ../lib/scp03/scp03.c ../lib/aes128/aes128.c -o host_scp03
 *   ./host_scp03 <kse_hex> <blob_hex> <expect_ct_hex>   (run by run_scp03_test.sh)
 * Transport: hex APDU per line on stdout, hex response per line on stdin
 * (the shell wires it to se_sim.py with a coprocess). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scp03.h"

static FILE *to_sim, *from_sim;
static int nsteps;
static int xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) {
    (void)c; nsteps++;
    for (size_t i = 0; i < al; i++) fprintf(to_sim, "%02x", a[i]);
    fprintf(to_sim, "\n"); fflush(to_sim);
    char line[4096]; if (!fgets(line, sizeof line, from_sim)) return -1;
    size_t n = strlen(line); while (n && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n] = 0;
    if (n % 2 || n / 2 > rc) return -1;
    for (size_t i = 0; i < n / 2; i++) { unsigned v; sscanf(line + 2*i, "%2x", &v); r[i] = (uint8_t)v; }
    *rl = n / 2; return 0;
}
static void unhex(const char *h, uint8_t *o, size_t n) { for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2*i, "%2x", &v); o[i] = (uint8_t)v; } }

int main(int argc, char **argv) {
    /* RFC 4493 CMAC vectors first — the primitive everything hangs on */
    { uint8_t k[16]; unhex("2b7e151628aed2a6abf7158809cf4f3c", k, 16);
      uint8_t m[40]; unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", m, 40);
      uint8_t mac[16], e0[16], e16[16], e40[16];
      unhex("bb1d6929e95937287fa37d129b756746", e0, 16); unhex("070a16b46b4d4144f79bdd9dd04a287c", e16, 16); unhex("dfa66747de9ae63030ca32611497c827", e40, 16);
      aes128_cmac(k, m, 0, mac);  if (memcmp(mac, e0, 16))  { puts("CMAC len0 FAIL"); return 1; }
      aes128_cmac(k, m, 16, mac); if (memcmp(mac, e16, 16)) { puts("CMAC len16 FAIL"); return 1; }
      aes128_cmac(k, m, 40, mac); if (memcmp(mac, e40, 16)) { puts("CMAC len40 FAIL"); return 1; }
      puts("CMAC RFC4493: ok"); }
    if (argc < 4) { puts("no sim args"); return 0; }
    to_sim = fdopen(3, "w"); from_sim = fdopen(4, "r");
    uint8_t kse[16]; unhex(argv[1], kse, 16);
    uint8_t blob[48]; unhex(argv[2], blob, 48);
    uint8_t expect[32]; unhex(argv[3], expect, 32);
    int badkey = argc > 4 && !strcmp(argv[4], "badkey");
    if (badkey) kse[0] ^= 1;

    scp03_session_t s; uint8_t hc[8] = {1,2,3,4,5,6,7,8}, cc[8];
    int rc = scp03_open(&s, xfer, NULL, kse, 0x20000030, hc, cc);
    if (badkey) { printf("open with wrong K_SE -> rc %d (want %d, stage %d)\n", rc, SCP03_E_CRYPTOGRAM, s.stage); return rc == SCP03_E_CRYPTOGRAM ? 0 : 1; }
    printf("open: rc %d stage %d sw %04x steps %d\n", rc, s.stage, s.last_sw, nsteps);
    if (rc) return 1;
    uint8_t rd[64]; size_t rl;
    rc = scp03_read_object(&s, 0x20000002, rd, sizeof rd, &rl);
    printf("read: rc %d len %zu match %s\n", rc, rl, (rc == 0 && rl == 48 && !memcmp(rd, blob, 48)) ? "yes" : "NO");
    if (rc || rl != 48 || memcmp(rd, blob, 48)) return 1;
    uint8_t out[32];
    rc = scp03_cipher_oneshot(&s, 0x20000022, 1, rd + 16, rd, out);
    printf("cipher: rc %d match %s\n", rc, (rc == 0 && !memcmp(out, expect, 32)) ? "yes" : "NO");
    if (rc || memcmp(out, expect, 32)) return 1;
    /* a second command on the same session proves the MCV/counter chain */
    rc = scp03_read_object(&s, 0x20000002, rd, sizeof rd, &rl);
    printf("read#2: rc %d\n", rc); if (rc) return 1;
    rc = scp03_close(&s);
    printf("close: rc %d sw %04x total steps %d\n", rc, s.last_sw, nsteps);
    if (rc) return 1;
    rc = scp03_read_object(&s, 0x20000002, rd, sizeof rd, &rl);
    printf("after close: rc %d (want %d)\n", rc, SCP03_E_STATE);
    return rc == SCP03_E_STATE ? 0 : 1;
}
