/* host_secp_sha256.c — the looped libsecp256k1 SHA-256 compression against the
 * upstream unrolled one (compiled from the original text) and FIPS 180-4. 28 Oct 2026. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "util.h"
#include "hash.h"
#define secp256k1_sha256_transform_impl looped_impl
#define secp256k1_sha256_transform looped_transform
#define SECP256K1_HASH_IMPL_H_ONCE
#include "hash_impl.h"
/* the upstream body, pasted by the runner into /tmp/unrolled_impl.inc */
#include "/tmp/unrolled_impl.inc"
int main(void) {
    uint32_t a[8], b[8]; unsigned char blk[64]; uint64_t r = 0x2810;
    long n = 0, bad = 0;
    for (long it = 0; it < 2000000; it++) {
        for (int i = 0; i < 8; i++) { r ^= r << 13; r ^= r >> 7; r ^= r << 17; a[i] = b[i] = (uint32_t)r; }
        for (int i = 0; i < 64; i++) { r ^= r << 13; r ^= r >> 7; r ^= r << 17; blk[i] = (uint8_t)r; }
        looped_impl(a, blk); unrolled_impl(b, blk); n++;
        if (memcmp(a, b, 32)) bad++;
    }
    /* FIPS 180-4 "abc" and the 56-byte two-block vector, padded here, through the looped compression */
    static const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned char p[128]; uint32_t st[8];
    memset(p, 0, 64); memcpy(p, "abc", 3); p[3] = 0x80; p[63] = 24;
    memcpy(st, IV, 32); looped_impl(st, p);
    int abc = st[0] == 0xba7816bf && st[1] == 0x8f01cfea && st[7] == 0xf20015ad;
    static const char m56[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    memset(p, 0, 128); memcpy(p, m56, 56); p[56] = 0x80; p[126] = 0x01; p[127] = 0xc0;   /* 448 bits */
    memcpy(st, IV, 32); looped_impl(st, p); looped_impl(st, p + 64);
    int mil = st[0] == 0x248d6a61 && st[1] == 0xd20638b8 && st[7] == 0x19db06c1;
    printf("looped vs unrolled: %ld random blocks, %ld differ; FIPS 'abc' %s; FIPS 448-bit %s\n", n, bad, abc ? "ok" : "BAD", mil ? "ok" : "BAD");
    return (bad || !abc || !mil);
}
