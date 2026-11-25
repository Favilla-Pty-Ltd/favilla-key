// test_seed_entropy.c — host harness for the REAL src/seed_entropy.h.
//
// Covers the three things the device cannot show you:
//   1. KNOWN-ANSWER TESTS on the pure mix. This is what stops a future
//      refactor silently changing the construction — the exact gap that let
//      COLDCARD's documented design and shipped code diverge for five years.
//   2. The FAIL-CLOSED path, by injecting a dead secure element.
//      Verified on hardware too, but here it is a regression test that runs
//      in CI on every commit instead of once by hand.
//   3. Health tests against synthetic dead sources, and — importantly — the
//      demonstration that they do NOT catch a small entropy space.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

static bool     g_se_ok    = true;    // injected: does the SE respond?
static uint8_t  g_se_fill  = 0xA5;    // injected: what does it return?
static uint8_t  g_esp_fill = 0x5A;
static bool     g_se_const = false;   // injected: return a constant byte?

extern "C" bool host_se_random(uint8_t* out, size_t len) {
    if (!g_se_ok) return false;
    for (size_t i = 0; i < len; i++)
        out[i] = g_se_const ? g_se_fill : (uint8_t)(g_se_fill + i * 7 + (i >> 3));
    return true;
}
extern "C" void host_esp_fill_random(void* out, size_t len) {
    uint8_t* p = (uint8_t*)out;
    for (size_t i = 0; i < len; i++) p[i] = (uint8_t)(g_esp_fill + i * 13);
}

static int failures = 0, checks = 0;
static void ok(const char* what, int cond) {
    checks++;
    if (!cond) { failures++; printf("  FAIL  %s\n", what); }
    else        printf("  pass  %s\n", what);
}

#define FAVILLA_HOST_TEST 1
#include "seed_entropy.h"

static void hexs(const uint8_t* b, int n, char* out) {
    for (int i = 0; i < n; i++) sprintf(out + i*2, "%02x", b[i]);
}

// ── 1. KNOWN-ANSWER TESTS ────────────────────────────────────────────────
// Fixed inputs -> fixed digest. If any of these change, the construction
// changed. That is either a bug or a deliberate version bump — and if it is
// deliberate, SEED_ENTROPY_DOMAIN_TAG must change too and these vectors must
// be regenerated on purpose, never "fixed" to make CI green.
struct kat { const char* name; uint8_t se_byte; uint8_t esp_byte; int len; const char* expect; };

static void test_kat(void) {
    printf("\n[1] known-answer tests on seedEntropyMix()\n");
    printf("      tag = \"%s\"\n", SEED_ENTROPY_DOMAIN_TAG);

    struct { const char* name; uint8_t se[32]; uint8_t esp[32]; int len; } cases[] = {
        { "all-zero se, all-zero esp", {0}, {0}, 32 },
        { "se=0x01.., esp=0x00..",     {0}, {0}, 32 },
        { "se=0x00.., esp=0x01..",     {0}, {0}, 32 },
        { "12-word length (16 bytes)", {0}, {0}, 16 },
    };
    for (int i = 0; i < 32; i++) { cases[1].se[i] = (uint8_t)(i + 1); cases[2].esp[i] = (uint8_t)(i + 1); }
    memcpy(cases[3].se, cases[1].se, 32);

    for (size_t c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
        uint8_t out[32]; char hx[80] = {0};
        bool r = seedEntropyMix(cases[c].se, cases[c].esp, out, cases[c].len);
        hexs(out, cases[c].len, hx);
        // PINNED. If one of these changes, the construction changed. That is
        // either a bug or a deliberate version bump — and if deliberate,
        // SEED_ENTROPY_DOMAIN_TAG must change too and these vectors must be
        // regenerated on purpose. NEVER edit a vector to make CI green.
        static const char* EXPECT[] = {
          "bffc1752de51b9a3fa13221fe54c7f8476c07f493da8c9c6771945df69a715c5",
          "612bed56f8c788947335e6ddc9be77d21622df8cf2b0d937a5a6563828c3e880",
          "dd6c06432cd600c90f7da5df022518f70768c84bff8ff627898b924cca84725b",
          "612bed56f8c788947335e6ddc9be77d2",
        };
        printf("      %-28s -> %s\n", cases[c].name, hx);
        ok(cases[c].name, r && strcmp(hx, EXPECT[c]) == 0);
        if (r && strcmp(hx, EXPECT[c]) != 0)
          printf("        EXPECTED: %s\n", EXPECT[c]);
    }

    // Determinism and sensitivity — the two properties a mix must have.
    uint8_t se[32], esp[32], a[32], b[32];
    memset(se, 0x11, 32); memset(esp, 0x22, 32);
    seedEntropyMix(se, esp, a, 32);
    seedEntropyMix(se, esp, b, 32);
    ok("deterministic: same input -> same output", memcmp(a, b, 32) == 0);

    se[31] ^= 0x01;
    seedEntropyMix(se, esp, b, 32);
    ok("sensitive: 1-bit change in se changes output", memcmp(a, b, 32) != 0);
    se[31] ^= 0x01;

    esp[0] ^= 0x01;
    seedEntropyMix(se, esp, b, 32);
    ok("sensitive: 1-bit change in esp changes output", memcmp(a, b, 32) != 0);

    // MONOTONICITY: a zeroed (worthless) esp still yields a well-defined
    // result determined entirely by se. This is the property XOR lacked.
    memset(esp, 0, 32);
    ok("zeroed esp still produces output", seedEntropyMix(se, esp, b, 32));
    uint8_t esp2[32]; memset(esp2, 0xFF, 32);
    uint8_t c2[32]; seedEntropyMix(se, esp2, c2, 32);
    ok("different esp -> different output (esp does contribute)", memcmp(b, c2, 32) != 0);

    ok("rejects bad length", !seedEntropyMix(se, esp, b, 24));
    ok("rejects null out",   !seedEntropyMix(se, esp, NULL, 32));
}

// ── 2. FAIL CLOSED ───────────────────────────────────────────────────────
static void test_fail_closed(void) {
    printf("\n[2] fail-closed on secure-element failure\n");
    uint8_t out[32]; uint8_t mask;

    memset(out, 0xCC, 32);
    g_se_ok = false;
    bool r = generateSeedEntropy(out, 32, &mask);
    ok("returns false when SE does not respond", !r);
    ok("mask reports no SE contribution", (mask & SEED_SRC_SE051) == 0);
    bool wiped = true; for (int i = 0; i < 32; i++) if (out[i] != 0) wiped = false;
    ok("output buffer wiped on failure", wiped);

    g_se_ok = true; g_se_const = true;   // SE answers, but with a constant byte
    memset(out, 0xCC, 32);
    r = generateSeedEntropy(out, 32, &mask);
    ok("returns false when SE output fails health check", !r);
    wiped = true; for (int i = 0; i < 32; i++) if (out[i] != 0) wiped = false;
    ok("output wiped on health-check failure", wiped);

    g_se_const = false;
    r = generateSeedEntropy(out, 32, &mask);
    ok("succeeds when SE is healthy", r);
    ok("mask reports both sources", mask == (SEED_SRC_SE051 | SEED_SRC_ESP32));
}

// ── 3. HEALTH TESTS, AND THEIR LIMIT ─────────────────────────────────────
static void test_health(void) {
    printf("\n[3] health tests catch DEAD sources\n");
    uint8_t buf[32];
    memset(buf, 0x00, 32); ok("rejects all-zero",     !seedHealthOk(buf, 32, "t"));
    memset(buf, 0xFF, 32); ok("rejects all-ones",     !seedHealthOk(buf, 32, "t"));
    memset(buf, 0x42, 32); ok("rejects constant byte",!seedHealthOk(buf, 32, "t"));
    for (int i = 0; i < 32; i++) buf[i] = (uint8_t)(i * 7 + 3);
    ok("accepts varied data", seedHealthOk(buf, 32, "t"));
    for (int i = 0; i < 32; i++) buf[i] = (i < 12) ? 0x11 : (uint8_t)(i * 7);
    ok("rejects a 12-byte stuck run", !seedHealthOk(buf, 32, "t"));

    printf("\n[3b] health tests CANNOT catch a small entropy space\n");
    // A counter run through SHA-256 has 32 bits of real entropy and passes
    // every test above. This is not a defect in the tests — it is the reason
    // fleet collision testing at provisioning is not optional.
    int passed = 0;
    for (uint32_t seed = 0; seed < 64; seed++) {
        uint8_t weak[32], ctr[4] = { (uint8_t)seed, (uint8_t)(seed>>8),
                                     (uint8_t)(seed>>16), (uint8_t)(seed>>24) };
        SHA256(ctr, 4, weak);
        if (seedHealthOk(weak, 32, "weak")) passed++;
    }
    char label[100];
    snprintf(label, sizeof(label),
             "%d/64 samples from a 2^32 space pass health checks (expected: all)", passed);
    ok(label, passed == 64);
    printf("      ^ this is the point: a pass means 'not obviously dead',\n"
           "        never 'has full entropy'. Only cross-device collision\n"
           "        testing detects a small-but-uniform space.\n");
}

int main(void) {
    printf("=== seed_entropy.h host harness ===\n");
    test_kat();
    test_fail_closed();
    test_health();
    printf("\n=== %d checks, %d failure(s) ===\n", checks, failures);
    printf(failures ? "RESULT: FAIL\n" : "RESULT: pass\n");
    return failures ? 1 : 0;
}
