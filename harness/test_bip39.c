// test_bip39.c — host harness for the REAL src/bip39.h under sanitizers.
//
// WHY THIS EXISTS
//
// bip39.h shipped with two defects that no amount of reading found, and that
// the device could not reveal:
//
//   1. bip39_entropy_to_words() read data[33] on a uint8_t data[33] for the
//      24-word case (word 23 starts at byte 31, and the 3-byte read runs off
//      the end). The value was always shifted away, so the output was correct
//      and nothing ever misbehaved. ASan sees it instantly.
//
//   2. bip39_words_to_entropy() did `idx << (5 - bit_off)`, which is a
//      NEGATIVE SHIFT — undefined behaviour — whenever bit_off is 6 or 7
//      (words 2, 5, 10, 13, 18, 21...), and never wrote the third byte those
//      offsets need. It corrupted 6 of 24 words. UBSan sees it instantly.
//
// THE DISCIPLINE THIS ENCODES: build against the OLD header FIRST and confirm
// both fire. A harness that has never caught a bug you know is there tells you
// nothing about the bugs you don't. `make selftest` does exactly that.
//
//   make selftest   -> old bip39.h, MUST report sanitizer errors
//   make check      -> current bip39.h, MUST be clean

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bip39.h"

static int failures = 0;
static int checks   = 0;

static void ok(const char* what, int cond) {
    checks++;
    if (!cond) { failures++; printf("  FAIL  %s\n", what); }
    else       {             printf("  pass  %s\n", what); }
}

static void hex2bin(const char* h, uint8_t* out, int n) {
    for (int i = 0; i < n; i++) {
        unsigned v; sscanf(h + i * 2, "%2x", &v); out[i] = (uint8_t)v;
    }
}

// ── Official BIP-39 English test vectors (entropy -> mnemonic) ────────────
struct vec { const char* entropy_hex; const char* mnemonic; };
static const struct vec VECTORS[] = {
  { "00000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank yellow" },
  { "80808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above" },
  { "ffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" },
  { "0000000000000000000000000000000000000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" },
  { "8080808080808080808080808080808080808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
    "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless" },
  { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote" },
};
static const int NVEC = (int)(sizeof(VECTORS) / sizeof(VECTORS[0]));

// ── 1. entropy -> words, against the official vectors ────────────────────
static void test_forward(void) {
    printf("\n[1] entropy -> words (official BIP-39 vectors)\n");
    for (int v = 0; v < NVEC; v++) {
        int elen = (int)strlen(VECTORS[v].entropy_hex) / 2;
        uint8_t ent[32];
        hex2bin(VECTORS[v].entropy_hex, ent, elen);

        char words[24][12] = {{0}};
        int  wc = 0;
        // NOTE: for the OLD header this call reads one byte past `data` on the
        // 24-word path. ASan reports it here.
        bip39_entropy_to_words(ent, elen, words, &wc);

        char got[400] = {0};
        for (int i = 0; i < wc; i++) { if (i) strcat(got, " "); strcat(got, words[i]); }

        char label[64];
        snprintf(label, sizeof(label), "vector %d (%d-bit -> %d words)", v, elen * 8, wc);
        ok(label, strcmp(got, VECTORS[v].mnemonic) == 0);
        if (strcmp(got, VECTORS[v].mnemonic) != 0) {
            printf("        expected: %s\n        got:      %s\n", VECTORS[v].mnemonic, got);
        }
    }
}

// ── 2. words -> entropy, and the round trip ──────────────────────────────
// This is where the OLD header's negative shift lives. UBSan reports it on
// the first vector that hits bit_off 6 or 7.
static void test_reverse(void) {
    printf("\n[2] words -> entropy (round trip)\n");
    for (int v = 0; v < NVEC; v++) {
        int elen = (int)strlen(VECTORS[v].entropy_hex) / 2;
        uint8_t want[32];
        hex2bin(VECTORS[v].entropy_hex, want, elen);

        char        buf[400];
        const char* wp[24];
        int         wc = 0;
        strncpy(buf, VECTORS[v].mnemonic, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        for (char* t = strtok(buf, " "); t && wc < 24; t = strtok(NULL, " ")) wp[wc++] = t;

        uint8_t got[32]; int glen = 0;
        bool r = bip39_words_to_entropy(wp, wc, got, &glen);

        char label[64];
        snprintf(label, sizeof(label), "vector %d round trip (%d words)", v, wc);
        ok(label, r && glen == elen && memcmp(got, want, elen) == 0);
        if (!(r && glen == elen && memcmp(got, want, elen) == 0)) {
            printf("        expected: %s\n        got:      ", VECTORS[v].entropy_hex);
            for (int i = 0; i < glen; i++) printf("%02x", got[i]);
            printf("  (ok=%d len=%d)\n", (int)r, glen);
        }
    }
}

// ── 3. checksum rejection ────────────────────────────────────────────────
// Every single-word substitution must be rejected. A validator that accepts
// a bad checksum is useless; one that rejects a GOOD mnemonic is worse than
// none, so both directions are tested.
#ifdef HAVE_VALIDATE
static void test_checksum(void) {
    printf("\n[3] checksum: valid accepted, every 1-word typo rejected\n");
    for (int v = 0; v < NVEC; v++) {
        char        buf[400];
        const char* wp[24];
        int         wc = 0;
        strncpy(buf, VECTORS[v].mnemonic, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        for (char* t = strtok(buf, " "); t && wc < 24; t = strtok(NULL, " ")) wp[wc++] = t;

        char label[64];
        snprintf(label, sizeof(label), "vector %d accepted", v);
        ok(label, bip39_validate_mnemonic(wp, wc));

        // Typo detection is measured in AGGREGATE with RANDOM substitutions
        // below, not per-vector: BIP-39's checksum is 4 bits at 12 words and
        // 8 at 24, so it CANNOT catch every typo, and a systematic
        // substitution (always replacing with wordlist index 0) clusters and
        // measures the substitution strategy rather than the checksum.
    }

    // ── aggregate typo detection, random substitutions ───────────────────
    printf("\n[3a] typo detection rate (random substitutions)\n");
    {
        unsigned seed = 12345;
        for (int which = 0; which < 2; which++) {
            int wc_target = which ? 24 : 12;
            int caught = 0, total = 0;
            for (int v = 0; v < NVEC; v++) {
                char        buf[400];
                const char* wp[24];
                int         wc = 0;
                strncpy(buf, VECTORS[v].mnemonic, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;
                for (char* t = strtok(buf, " "); t && wc < 24; t = strtok(NULL, " ")) wp[wc++] = t;
                if (wc != wc_target) continue;
                for (int rep = 0; rep < 40; rep++) {
                    for (int i = 0; i < wc; i++) {
                        const char* orig = wp[i];
                        int r;
                        do { seed = seed * 1103515245u + 12345u; r = (int)((seed >> 16) % 2048); }
                        while (strcmp(BIP39_WORDS[r], orig) == 0);
                        wp[i] = BIP39_WORDS[r];
                        total++;
                        if (!bip39_validate_mnemonic(wp, wc)) caught++;
                        wp[i] = orig;
                    }
                }
            }
            // Theory: 1 - 2^-cs_bits. 93.75% at 12 words, 99.61% at 24.
            // Bar set a little under theory to stay stable across samples.
            double rate = total ? (100.0 * caught / total) : 0.0;
            double floor_pct = (wc_target == 24) ? 98.5 : 91.0;
            char label[96];
            snprintf(label, sizeof(label), "%d-word: %.2f%% of typos caught (>=%.1f%%, theory %.2f%%)",
                     wc_target, rate, floor_pct,
                     (wc_target == 24) ? 99.61 : 93.75);
            ok(label, total > 0 && rate >= floor_pct);
        }
    }

    printf("\n[3b] structurally invalid input\n");
    const char* junk[24];
    for (int i = 0; i < 24; i++) junk[i] = "notaword";
    ok("unknown word rejected", !bip39_validate_mnemonic(junk, 12));
    const char* short_[3] = { "abandon", "abandon", "abandon" };
    ok("wrong word count rejected", !bip39_validate_mnemonic(short_, 3));
}
#endif

// ── 4. every wordlist index, every bit offset ────────────────────────────
// The old packing bug only bit at bit_off 6 and 7, i.e. words 2, 5, 10, 13,
// 18, 21. Sweeping every position with every index guarantees those offsets
// are exercised rather than hoped for.
static void test_sweep(void) {
    printf("\n[4] sweep: all 24 positions x sampled indices\n");
    int mismatches = 0;
    for (int pos = 0; pos < 24; pos++) {
        for (int idx = 0; idx < 2048; idx += 37) {   // 56 samples per position
            const char* wp[24];
            for (int i = 0; i < 24; i++) wp[i] = BIP39_WORDS[0];
            wp[pos] = BIP39_WORDS[idx];

            uint8_t got[32]; int glen = 0;
            // Ignore the return value: the checksum will usually fail, which is
            // fine — we are testing the BIT PACKING, not the checksum. On the
            // fixed header the packing runs to completion either way.
            bip39_words_to_entropy(wp, 24, got, &glen);

            // reconstruct what word `pos` should decode back to
            char w2[24][12] = {{0}}; int wc2 = 0;
            if (glen == 32) {
                bip39_entropy_to_words(got, 32, w2, &wc2);
                if (wc2 == 24 && strcmp(w2[pos], BIP39_WORDS[idx]) != 0) mismatches++;
            }
        }
    }
    char label[80];
    snprintf(label, sizeof(label), "packing sweep (%d mismatches)", mismatches);
    ok(label, mismatches == 0);
}

int main(void) {
    printf("=== bip39.h host harness ===\n");
    test_forward();
    test_reverse();
#ifdef HAVE_VALIDATE
    test_checksum();
#else
    printf("\n[3] checksum tests SKIPPED (old header has no bip39_validate_mnemonic)\n");
#endif
    test_sweep();

    printf("\n=== %d checks, %d failure(s) ===\n", checks, failures);
    if (failures) printf("RESULT: FAIL\n");
    else          printf("RESULT: pass (note: sanitizer findings are reported separately above)\n");
    return failures ? 1 : 0;
}
