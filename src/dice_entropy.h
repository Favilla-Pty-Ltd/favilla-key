// ─────────────────────────────────────────────────────────────────────────────
// dice_entropy.h — the dice seed construction, PURE.  (Favilla KEY)
//
// Extracted from the UI (dice_roll.h) for the same reason seed_entropy.h was
// extracted from main.cpp: a construction that derives a wallet must be
// known-answer testable, and that requires a function with no globals, no I/O
// and no hardware. See harness/dice_kat.c for the pinned vectors.
//
// THE PUBLISHED, VERIFIABLE SPECIFICATION
// ---------------------------------------
//     entropy = SHA-256( ASCII digit string of the rolls )
//     seed    = BIP-39( entropy[:len] )        len = 16 (12 words) or 32 (24)
//
//   - each d6 roll (1..6) is written as its ASCII digit char '1'..'6'
//   - digits are concatenated with NO separator and NO domain tag
//   - nothing else is mixed in — no device secret, no RNG
//
// This is byte-identical to Coldcard / SeedSigner, which is the whole point:
// the owner can reproduce it on any machine
//     printf '31415...' | sha256sum
// and confirm the device did not substitute its own value. Zero rolls hashes
// the empty string, giving e3b0c4..b855 — the on-screen "tell" that proves the
// device is genuinely hashing the entered rolls.
//
// NO domain tag here is deliberate and load-bearing: a tag would break external
// reproducibility. This differs from seed_entropy.h (which tags "FAVILLA-SEED-V1")
// precisely because that path is NOT meant to be reproduced off-device and this
// one IS.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_DICE_ENTROPY_H
#define FAVILLA_DICE_ENTROPY_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

// Roll-buffer cap. Owned here so both the UI (dice_roll.h) and the KAT share it.
#ifndef DICE_ROLL_MAX
#define DICE_ROLL_MAX 128
#endif

// ── PURE. entropy = SHA-256(ascii digits of rolls[0..n]). ────────────────────
// rolls[i] MUST be a d6 face value 1..6 (written as one ASCII digit). `n` is
// clamped to [0, DICE_ROLL_MAX]. Fills out[32]; the caller takes the first
// 16 or 32 bytes as seed entropy. n == 0 hashes the empty string (e3b0c4..b855).
static void diceEntropyFromRolls(const uint8_t* rolls, int n, uint8_t out[32]) {
  char s[DICE_ROLL_MAX + 1];
  if (n < 0) n = 0;
  if (n > DICE_ROLL_MAX) n = DICE_ROLL_MAX;
  for (int i = 0; i < n; i++) s[i] = (char)('0' + (rolls[i] % 10));  // 1..6 -> '1'..'6'
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, (const uint8_t*)s, (size_t)n);
  mbedtls_sha256_finish(&sha, out);
  mbedtls_sha256_free(&sha);
  mbedtls_platform_zeroize(s, sizeof(s));
}

#endif // FAVILLA_DICE_ENTROPY_H
