/* RFC 2202 HMAC-SHA1, RFC 4226 HOTP and RFC 6238 TOTP (SHA-1) vectors for
 * next/totp.c. Exit 0 only when every vector matches. */
#include <stdio.h>
#include <string.h>
#include "totp.h"
static int fails = 0;
static void chk(const char *what, long got, long want) { if (got != want) { printf("FAIL %s: %ld != %ld\n", what, got, want); fails++; } }
int main(void) {
    /* RFC 2202 test 2: key "Jefe", "what do ya want for nothing?" */
    uint8_t out[20]; static const uint8_t e2[20] = {0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,0xd2,0x74,0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79};
    g0_hmac_sha1((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, out);
    if (memcmp(out, e2, 20)) { puts("FAIL RFC 2202 test 2"); fails++; }
    /* RFC 2202 test 6: 80-byte key of 0xaa (longer than a block) */
    uint8_t k80[80]; memset(k80, 0xaa, 80); static const uint8_t e6[20] = {0xaa,0x4a,0xe5,0xe1,0x52,0x72,0xd0,0x0e,0x95,0x70,0x56,0x37,0xce,0x8a,0x3b,0x55,0xed,0x40,0x21,0x12};
    g0_hmac_sha1(k80, 80, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
    if (memcmp(out, e6, 20)) { puts("FAIL RFC 2202 test 6"); fails++; }
    const uint8_t *s = (const uint8_t *)"12345678901234567890";
    static const long hotp[10] = {755224,287082,359152,969429,338314,254676,287922,162583,399871,520489};   /* RFC 4226 appendix D */
    for (int i = 0; i < 10; i++) { char w[24]; snprintf(w, sizeof w, "HOTP %d", i); chk(w, g0_hotp_sha1(s, 20, (uint64_t)i, 6), hotp[i]); }
    static const struct { unsigned long long t; long code; } totp[6] = {   /* RFC 6238 appendix B, SHA-1, 8 digits, 30 s */
        {59ULL, 94287082}, {1111111109ULL, 7081804}, {1111111111ULL, 14050471},
        {1234567890ULL, 89005924}, {2000000000ULL, 69279037}, {20000000000ULL, 65353130} };
    for (int i = 0; i < 6; i++) { char w[24]; snprintf(w, sizeof w, "TOTP t=%llu", totp[i].t); chk(w, g0_hotp_sha1(s, 20, totp[i].t / 30, 8), totp[i].code); }
    chk("digits 5 refused", g0_hotp_sha1(s, 20, 0, 5), -1);
    chk("empty key refused", g0_hotp_sha1(s, 0, 0, 6), -1);
    chk("65-byte key refused", g0_hotp_sha1(k80, 65, 0, 6), -1);
    if (!fails) puts("PASS: RFC 2202 HMAC-SHA1 (2), RFC 4226 HOTP (10), RFC 6238 TOTP SHA-1 (6), bad arguments (3)");
    return fails ? 1 : 0;
}
