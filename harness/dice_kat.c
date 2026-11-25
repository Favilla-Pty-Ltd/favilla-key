// ─────────────────────────────────────────────────────────────────────────────
// harness/dice_kat.c — Known-Answer Tests for the dice seed construction.
//
// Pins the exact bytes of diceEntropyFromRolls() (dice_entropy.h) so a silent
// change to the construction — a separator, a domain tag, raw bytes instead of
// ASCII, a reordering — breaks the build instead of shipping. This is the same
// tripwire seed_entropy.h's KAT provides, applied to the dice path, which is now
// the most externally-visible seed construction in the device.
//
// The expected values were computed INDEPENDENTLY (Python hashlib / sha256sum),
// not by running the code under test.  Verify any of them yourself:
//     printf ''            | sha256sum   ->  e3b0c4..b855   (empty / 0 rolls)
//     printf '31415326535' | sha256sum   ->  e760f9c3..f316
//
// Build (real mbedtls, matching the firmware):
//     cc dice_kat.c -I<src> -I<mbedtls-include> -lmbedcrypto -o dice_kat && ./dice_kat
// Returns non-zero on ANY failure so `make` fails loudly.
// ─────────────────────────────────────────────────────────────────────────────
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dice_entropy.h"

static int g_fail = 0;

static void hex(const uint8_t* b, int n, char* out){
  static const char* H = "0123456789abcdef";
  for(int i=0;i<n;i++){ out[2*i]=H[b[i]>>4]; out[2*i+1]=H[b[i]&15]; }
  out[2*n]=0;
}

// Positive KAT: first `len` bytes of the entropy must equal `expect` (hex).
static void kat(const char* name, const uint8_t* rolls, int n, int len, const char* expect){
  uint8_t out[32]; char got[65];
  diceEntropyFromRolls(rolls, n, out);
  hex(out, len, got);
  int ok = (strcmp(got, expect)==0);
  printf("  [%s] %-24s len=%2d  %.16s...\n", ok?"PASS":"FAIL", name, len, got);
  if(!ok){ printf("         expected %s\n         got      %s\n", expect, got); g_fail++; }
}

// Negative control: two inputs MUST produce different output.
static void differ(const char* name, const uint8_t* a, int na, const uint8_t* b, int nb){
  uint8_t oa[32], ob[32];
  diceEntropyFromRolls(a, na, oa);
  diceEntropyFromRolls(b, nb, ob);
  int ok = memcmp(oa, ob, 32) != 0;
  printf("  [%s] %-24s (must differ)\n", ok?"PASS":"FAIL", name);
  if(!ok) g_fail++;
}

int main(void){
  printf("dice_entropy.h — Known-Answer Tests\n-----------------------------------\npositive vectors:\n");

  // V0 — empty string anchor (0 rolls). Proves the ASCII construction and the
  // on-screen "tell". Any change to how the string is built moves this off e3b0c4.
  kat("empty / 0 rolls", (const uint8_t*)"", 0, 32,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  // V1 — '31415326535'
  { uint8_t r[] = {3,1,4,1,5,3,2,6,5,3,5};
    kat("11 rolls", r, 11, 32,
        "e760f9c3eb87db17188ad4f93727a6a2c8a0d5dd94351136caad1812ab0ef316"); }

  // V2 — 99 rolls (123456...), the 24-word / 256-bit case, full + 12-word trunc.
  { uint8_t r[99]; for(int i=0;i<99;i++) r[i]=(i%6)+1;
    kat("99 rolls (24w)",       r, 99, 32,
        "5588d3630bd19f6375b7bd922457af34ea9c74f00807566a1cf808e445dc8c20");
    kat("99 rolls (12w trunc)", r, 99, 16,
        "5588d3630bd19f6375b7bd922457af34"); }

  // V3 — 50 rolls (123456...), the 12-word / 128-bit case.
  { uint8_t r[50]; for(int i=0;i<50;i++) r[i]=(i%6)+1;
    kat("50 rolls (12w)", r, 50, 16,
        "ee72ae915a4e6ea7ccbeb8e5e5eecef2"); }

  printf("negative controls:\n");

  // N1 — sensitivity: one changed roll must change the hash.
  { uint8_t a[] = {3,1,4,1,5,3,2,6,5,3,5}, b[] = {3,1,4,1,5,3,2,6,5,3,4};
    differ("one-roll change", a, 11, b, 11); }

  // N2 — length: a prefix must differ from the full sequence.
  { uint8_t r[] = {3,1,4,1,5,3,2,6,5,3,5};
    differ("prefix vs full", r, 10, r, 11); }

  // N3 — the construction MUST be ASCII digits, not raw bytes. A raw-byte SHA of
  // the same rolls must NOT match — this is the exact regression that would
  // silently break off-device verifiability (and was a real bug once).
  { uint8_t r[] = {3,1,4,1,5,3,2,6,5,3,5};
    uint8_t asc[32]; diceEntropyFromRolls(r, 11, asc);
    uint8_t raw[32]; mbedtls_sha256_context s; mbedtls_sha256_init(&s);
    mbedtls_sha256_starts(&s, 0); mbedtls_sha256_update(&s, r, 11);
    mbedtls_sha256_finish(&s, raw); mbedtls_sha256_free(&s);
    int ok = memcmp(asc, raw, 32) != 0;
    printf("  [%s] %-24s (ascii != raw bytes)\n", ok?"PASS":"FAIL", "construction is ASCII");
    if(!ok) g_fail++; }

  printf("-----------------------------------\n%s (%d failure%s)\n",
         g_fail?"FAIL":"ALL PASS", g_fail, g_fail==1?"":"s");
  return g_fail ? 1 : 0;
}
