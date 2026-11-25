// 23 Nov 2026 (#61): ecdh_ct (mbedTLS, constant time) must give the same
// shared secret as ecdh_raw for every key and point, and refuse the same bad
// points. Build and run: sh run.sh
#include "Arduino.h"
#include "secp256k1.h"
#include <cstdio>
#include <cstdlib>
bool (*g_nostr_ecdh_hook)(const uint8_t peer_xonly32[32], uint8_t shared[32]) = nullptr;
int main() {
    srand(12345); int fails = 0, same = 0, refused = 0;
    for (int i = 0; i < 300; i++) {
        uint8_t a[32], b[32], pb[32], s1[32], s2[32];
        for (int k = 0; k < 32; k++) { a[k] = rand(); b[k] = rand(); }
        if (!bip340_make_key(b, pb)) continue;
        if (i % 10 == 9) for (int k = 0; k < 32; k++) pb[k] = rand();   // usually off the curve
        bool r1 = ecdh_raw(a, pb, s1), r2 = ecdh_ct(a, pb, s2);
        if (r1 != r2 || (r1 && memcmp(s1, s2, 32))) { fails++; printf("FAIL case %d (raw %d ct %d)\n", i, r1, r2); }
        else if (r1) same++; else refused++;
    }
    printf("%s  %d equal shared secrets, %d refused by both\n", fails ? "FAIL" : "PASS", same, refused);
    return fails != 0;
}
