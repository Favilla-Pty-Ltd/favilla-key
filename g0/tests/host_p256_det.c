/* P-256 deterministic signing in the G0 (p256_det.c over p256-m): RFC 6979
 * A.2.5 vectors (P-256, SHA-256, "sample" and "test"), then random keys and
 * hashes printed for tests/run_p256_det.sh to check against python-ecdsa's
 * RFC 6979 and to verify; DER shape checked here. */
#include <stdio.h>
#include <string.h>
#include "p256_det.h"
#include "p256-m.h"
#include "sha256.h"
static void hx(const char *s, uint8_t *o, int n) { for (int i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]); }
static void ph(const uint8_t *p, int n) { for (int i = 0; i < n; i++) printf("%02x", p[i]); }
int main(void) {
    int fails = 0;
    uint8_t x[32], h[32], sig[64], want[64];
    hx("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", x, 32);
    const char *msg[2] = { "sample", "test" };
    const char *r[2] = { "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367" };
    const char *s[2] = { "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083" };
    for (int i = 0; i < 2; i++) {
        sha256((const uint8_t *)msg[i], strlen(msg[i]), h);
        hx(r[i], want, 32); hx(s[i], want + 32, 32);
        if (p256_det_sign_raw(x, h, sig) || memcmp(sig, want, 64)) { printf("FAIL RFC 6979 A.2.5 %s\n", msg[i]); fails++; }
    }
    /* random cases for the python cross-check: "K <priv> H <hash> S <r||s> D <der>" */
    uint64_t st = 0x2545F4914F6CDD1Dull;
    for (int t = 0; t < 200; t++) {
        for (int i = 0; i < 32; i++) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; x[i] = (uint8_t)st; st ^= st << 13; st ^= st >> 7; st ^= st << 17; h[i] = (uint8_t)st; }
        x[0] &= 0x7F; if (t % 7 == 0) memset(h, 0xFF, 32);   /* some hashes >= n */
        uint8_t der[72]; size_t dl = p256_det_sign_der(x, h, der, sizeof der);
        if (p256_det_sign_raw(x, h, sig)) { puts("FAIL sign"); fails++; continue; }
        if (!dl || der[0] != 0x30 || der[1] != dl - 2 || dl > 72) { puts("FAIL der"); fails++; }
        printf("K "); ph(x, 32); printf(" H "); ph(h, 32); printf(" S "); ph(sig, 64); printf(" D "); ph(der, (int)dl); printf("\n");
    }
    /* v18: hedged (RFC 6979 3.6 extra data). "X <priv> H <hash> E <extra> S <r||s>" for the
     * python check (python-ecdsa's extra_entropy is the same construction), and here: no
     * extra = plain RFC 6979, two extras over the same key and hash = two different r. */
    for (int t = 0; t < 200; t++) {
        uint8_t e[32], e2[32], s2[64];
        for (int i = 0; i < 32; i++) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; x[i] = (uint8_t)st; h[i] = (uint8_t)(st >> 8); e[i] = (uint8_t)(st >> 16); e2[i] = (uint8_t)(st >> 24); }
        x[0] &= 0x7F;
        if (p256_det_sign_raw_x(x, h, e, sig)) { puts("FAIL hedged sign"); fails++; continue; }
        if (p256_det_sign_raw_x(x, h, e2, s2) || !memcmp(sig, s2, 32)) { puts("FAIL two extras gave the same nonce"); fails++; }
        uint8_t plain[64], viaNull[64];
        if (p256_det_sign_raw(x, h, plain) || p256_det_sign_raw_x(x, h, NULL, viaNull) || memcmp(plain, viaNull, 64)) { puts("FAIL extra NULL is not plain RFC 6979"); fails++; }
        if (!memcmp(plain, sig, 32)) { puts("FAIL hedged equals plain"); fails++; }
        uint8_t der[72]; size_t dl = p256_det_sign_der_x(x, h, e, der, sizeof der);
        if (!dl || der[0] != 0x30 || der[1] != dl - 2) { puts("FAIL hedged der"); fails++; }
        printf("X "); ph(x, 32); printf(" H "); ph(h, 32); printf(" E "); ph(e, 32); printf(" S "); ph(sig, 64); printf("\n");
    }
    uint8_t zero[32] = {0};
    if (p256_det_sign_raw(zero, h, sig) == 0) { puts("FAIL zero key accepted"); fails++; }
    printf(fails ? "FAILED %d\n" : "C: RFC 6979 A.2.5 (2) pass, DER shape ok, zero key refused, 200 hedged: fresh nonce each, NULL = plain\n", fails);
    return fails ? 1 : 0;
}
