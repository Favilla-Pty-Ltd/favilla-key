#pragma once
// ─────────────────────────────────────────────────────────────────────────
//  seed_entropy.h — Favilla KEY seed-generation entropy
//
//  This is the single highest-risk file in the device. Everything else — the
//  SE051, the two-door PIN, the G0 key isolation, motion lock, cover mode —
//  protects a key that is ASSUMED unguessable. If the entropy here is weak,
//  none of it matters, because the attacker never touches the device: they
//  recompute the key offline and sweep the address.
//
//  That is not hypothetical. On 2026-07-30, 500 addresses were drained of
//  594.5 BTC in fifteen minutes. Root cause (Block Engineering): COLDCARD's
//  board config set MICROPY_HW_ENABLE_RNG to 0, libngu guarded with #ifndef
//  instead of #if, the guard passed, and seed generation silently ran on a
//  software PRNG seeded from the MCU UID and timer registers. Five years.
//
//  ── DESIGN, AND WHY ────────────────────────────────────────────────────
//
//  1. FAIL CLOSED ON THE SECURE ELEMENT. The SE051 (AIS31 PTG.2 TRNG feeding
//     an AIS20 DRG.4 DRBG) is the ONLY budgeted source. If it does not
//     answer, generation ABORTS and the caller must show an error. There is
//     no fallback. Adding one recreates the defect this file exists to
//     prevent.
//
//  2. esp_fill_random IS NOT BUDGETED. On the ESP32-S3 it is only a true RNG
//     when the RF subsystem is enabled or the SAR ADC samples continuously.
//     Onboarding runs before any mode is selected — confirmed on hardware:
//     the boot log shows "no key stored -> OFFLINE boot", radios never
//     started — so it is in its documented weak state at exactly the moment
//     it would matter. It contributes; nothing depends on it.
//
//  3. CONCATENATE AND HASH, NEVER XOR. XOR of two correlated sources
//     annihilates, and XOR with a zeroed buffer is a silent no-op — which is
//     what the previous code did on SE failure. Hashing a domain-tagged
//     concatenation is MONOTONIC: an extra source can never subtract, even
//     if it is garbage or attacker-controlled.
//
//  4. HEALTH-TEST EVERY SOURCE BEFORE MIXING. These catch a DEAD peripheral
//     (stuck, constant, zeroed buffer). They do NOT catch a SMALL entropy
//     space — a PRNG with a 32-bit seed passes every one of them, and so did
//     COLDCARD's whitened output for five years. Verified on this device:
//     esp_fill_random passes these tests while in its degraded RF-off state.
//     A pass here means "not obviously dead", nothing more. Only cross-device
//     collision testing at provisioning can detect a small-but-uniform space.
//
//  5. THE MIX IS A SEPARATE, PURE FUNCTION. seedEntropyMix() takes bytes and
//     returns bytes: no I/O, no globals, no hardware. That is what makes it
//     host-testable under sanitizers, what the known-answer test targets, and
//     what the published specification describes. Never inline it back into
//     the I/O path.
//
//  6. FIXED-LENGTH FIELDS, FIXED ORDER, VERSIONED DOMAIN TAG. The
//     construction must be reproducible byte-for-byte from the published
//     spec. Never reorder or resize a field without bumping the tag — and if
//     you bump the tag, the KAT vectors change and CI will tell you.
// ─────────────────────────────────────────────────────────────────────────

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

// ── Include-order guard ──────────────────────────────────────────────────
// LOG_KEY is a function-like macro defined partway down main.cpp, so this
// header MUST be included after it. Without this check the header would
// still compile and simply log nothing — a silent degradation, which is the
// exact shape of the COLDCARD defect (#ifndef where #if was needed). Make it
// loud instead.
#if !defined(FAVILLA_HOST_TEST) && !defined(LOG_KEY)
  #error "seed_entropy.h must be included AFTER the LOG_KEY macro is defined in main.cpp."
#endif

// ── Source bindings ──────────────────────────────────────────────────────
// On device these are the real peripherals. On the host harness they are
// injectable, so the fail-closed path and the health tests can be exercised
// without hardware.
#ifdef FAVILLA_HOST_TEST
  extern "C" bool host_se_random(uint8_t* out, size_t len);
  extern "C" void host_esp_fill_random(void* out, size_t len);
  #define SEED_SE_RANDOM(b, n)  host_se_random((b), (n))
  #define SEED_ESP_RANDOM(b, n) host_esp_fill_random((b), (n))
  #ifndef LOG_KEY
    #define LOG_KEY(...) ((void)0)
  #endif
#else
  #define SEED_SE_RANDOM(b, n)  favilla::se_random((b), (n))
  #define SEED_ESP_RANDOM(b, n) esp_fill_random((b), (n))
#endif

// Bump this and the KAT vectors change. That is the point.
#define SEED_ENTROPY_DOMAIN_TAG "FAVILLA-SEED-V1"


// Source-contribution bits, for the serial log and the provisioning station.
// NEVER persisted and NEVER transmitted: a per-device record of which
// peripherals contributed is a fingerprint.
#define SEED_SRC_SE051 0x01
#define SEED_SRC_ESP32 0x02

// ── Health test ──────────────────────────────────────────────────────────
// Catastrophic-failure check for ONE source. Deliberately not a randomness
// test — see note 4 above.
static bool seedHealthOk(const uint8_t* b, size_t n, const char* label) {
  if (!b || n < 8) return false;

  bool allZero = true, allOnes = true;
  for (size_t i = 0; i < n; i++) {
    if (b[i] != 0x00) allZero = false;
    if (b[i] != 0xFF) allOnes = false;
  }
  if (allZero) { LOG_KEY("[ENT] %s: all zero\n", label); return false; }
  if (allOnes) { LOG_KEY("[ENT] %s: all ones\n", label); return false; }

  // Longest run of one repeated byte. A live source effectively never does
  // this; a stuck peripheral or a frozen DMA buffer always does.
  size_t run = 1, longest = 1;
  for (size_t i = 1; i < n; i++) {
    run = (b[i] == b[i - 1]) ? run + 1 : 1;
    if (run > longest) longest = run;
  }
  if (longest > 8) {
    LOG_KEY("[ENT] %s: run of %u\n", label, (unsigned)longest);
    return false;
  }

  // Distinct byte count. For a 32-byte draw from a uniform source expect ~30
  // distinct values; fewer than 12 means something is badly wrong. Kept loose
  // so it never false-positives in the field.
  bool seen[256];
  memset(seen, 0, sizeof(seen));
  size_t distinct = 0;
  for (size_t i = 0; i < n; i++) {
    if (!seen[b[i]]) { seen[b[i]] = true; distinct++; }
  }
  size_t minDistinct = (n >= 32) ? 12 : (n / 3);
  if (distinct < minDistinct) {
    LOG_KEY("[ENT] %s: only %u distinct bytes\n", label, (unsigned)distinct);
    return false;
  }
  return true;
}

// ── The mix — PURE. This is the published construction. ──────────────────
//
//   out = SHA-256( "FAVILLA-SEED-V1" || se[32] || esp[32] )   truncated to len
//
// No I/O, no globals, no hardware. Deterministic for a given input, which is
// what the known-answer test relies on. A caller that passes a zeroed esp[]
// gets a well-defined result — that is the monotonicity property, not a bug.
static bool seedEntropyMix(const uint8_t se[32], const uint8_t esp[32],
                           uint8_t* out, int len) {
  if (!se || !esp || !out || (len != 16 && len != 32)) return false;

  uint8_t digest[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, (const uint8_t*)SEED_ENTROPY_DOMAIN_TAG,
                        sizeof(SEED_ENTROPY_DOMAIN_TAG) - 1);
  mbedtls_sha256_update(&sha, se,  32);
  mbedtls_sha256_update(&sha, esp, 32);
  mbedtls_sha256_finish(&sha, digest);
  mbedtls_sha256_free(&sha);

  memcpy(out, digest, (size_t)len);
  mbedtls_platform_zeroize(digest, sizeof(digest));
  return true;
}


// ── The I/O wrapper — what the device calls ──────────────────────────────
//
// Fills out[] with `len` bytes of seed entropy. len is 16 (12 words) or 32
// (24 words).
//
// RETURNS FALSE IF THE SECURE ELEMENT DID NOT PROVIDE USABLE ENTROPY.
// The caller MUST abort onboarding on false and show the user an error.
// DO NOT ADD A FALLBACK PATH HERE.
//
// srcMask (out, optional): which sources passed their health test. Serial log
// and provisioning station only — never persisted, never transmitted.
static bool generateSeedEntropy(uint8_t* out, int len, uint8_t* srcMask) {
  if (!out || (len != 16 && len != 32)) return false;

  uint8_t seBuf[32];    // BUDGETED — 256 bits claimed here and nowhere else
  uint8_t espBuf[32];   // unbudgeted extra; cannot subtract
  uint8_t mask = 0;
  bool ok = false;

  memset(seBuf, 0, sizeof(seBuf));
  memset(espBuf, 0, sizeof(espBuf));

  // ── 1. SE051 TRNG — mandatory ──────────────────────────────────────────
  // Always draw the full 32 bytes regardless of len, so the hash input has a
  // fixed shape and the KAT has one construction to target.
  //
  // TEST HOOK: build with -DFAVILLA_TEST_ENTROPY_SE_FAIL to simulate a dead
  // secure element without stubbing se_random globally (which would also
  // break pairing, session sealing and the bunker, making the result
  // ambiguous). Verified on hardware 2026-07-31: onboarding shows "Entropy
  // source failed", returns to menu, no words, no SE slots provisioned.
  {
    bool seOk;
#ifdef FAVILLA_TEST_ENTROPY_SE_FAIL
  #warning "*** TEST BUILD: SE051 entropy FORCED TO FAIL. Never ship this. ***"
    LOG_KEY("[ENT] *** TEST BUILD *** forcing SE051 entropy failure\n");
    seOk = false;
#else
    seOk = SEED_SE_RANDOM(seBuf, 32);
#endif
    if (!seOk) {
      LOG_KEY("[ENT] FATAL: SE051 TRNG did not respond\n");
      goto done;
    }
  }
  if (!seedHealthOk(seBuf, 32, "SE051")) {
    LOG_KEY("[ENT] FATAL: SE051 TRNG failed health check\n");
    goto done;
  }
  mask |= SEED_SRC_SE051;

  // ── 2. ESP32-S3 RNG — contributes, never relied upon ───────────────────
  // A health-test failure here is a WARNING, not an abort: the source is
  // unbudgeted, so its absence cannot reduce the entropy of the result. Worth
  // logging because a failure means the RF/ADC precondition is unmet, which
  // is useful diagnostic information at provisioning time.
  SEED_ESP_RANDOM(espBuf, 32);
  if (seedHealthOk(espBuf, 32, "ESP32")) mask |= SEED_SRC_ESP32;
  else LOG_KEY("[ENT] WARN: ESP32 RNG failed health check (unbudgeted, continuing)\n");

  // ── 3. Mix ─────────────────────────────────────────────────────────────
  ok = seedEntropyMix(seBuf, espBuf, out, len);
  if (!ok) LOG_KEY("[ENT] FATAL: mix rejected its inputs\n");

done:
  mbedtls_platform_zeroize(seBuf,  sizeof(seBuf));
  mbedtls_platform_zeroize(espBuf, sizeof(espBuf));
  if (srcMask) *srcMask = mask;
  if (!ok) mbedtls_platform_zeroize(out, (size_t)len);
  return ok;
}
