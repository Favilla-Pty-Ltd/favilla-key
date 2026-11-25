// =============================================================================
// pk_restorable.cpp — restorable passkeys, ESP32 side (30 Oct 2026, spec v0.7)
// =============================================================================
// The ESP32 never holds S_pk or a site key. It asks the G0 (PKSIGN), which
// derives the key, writes it into the SE's scratch object over its own
// encrypted session, has the SE sign, and writes junk over it.
//   register: the G0 returns nonce, tag and two signatures over FIXED hashes;
//             the public key is recovered here from those (public data only).
//   sign:     the G0 checks the ID's tag for this site, then signs the hash.
// Credential ID (34 B) = 0x01 ver || 0x01 kind || nonce16 || tag16.
// fido_hid.h serves it in the NOSTR life (main.cpp backend pkrOpen etc.).
// =============================================================================
#ifdef FAVILLA_PK_RESTORABLE
#include <Arduino.h>
#include <string.h>
#include "esp_task_wdt.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/private_access.h"
#include "g0_signer.h"
#include "se_signer.h"
#include "pk_restorable.h"
#include "pkrecover.inc"

void pwrBoostHold(uint32_t ms);   // main.cpp: 240 MHz, and pwrIdle() from the main loop waits until the hold ends
void pwrHoldEnd();

namespace favilla {

static bool s_scrubbed = false;   // PKSCRUB once per ESP32 boot, before the first PKSIGN

const char* pkr_res_name(uint8_t r) {
  switch (r) {
    case 0x00: return "ok";
    case 0xE1: return "bad request";
    case 0xE2: return "G0 has no keys / no Door-1 lock this life";
    case 0xE3: return "master not readable (not set up, or KEY locked)";
    case 0xE4: return "not this KEY's credential for this site";
    case 0xE5: return "G0 session to the SE did not open";
    case 0xE6: return "site key write refused";
    case 0xE7: return "signature failed (v15: by the SE; v16: by the G0)";
    case 0xE8: return "junk not confirmed (site key may remain; scrub again)";
    case 0xE9: return "derivation failed";
    case 0xEA: return "scratch object is not the G0's (planted?) or could not be made";
    case 0xEB: return "this sitting's 32 passkey signatures are used: lock and unlock the KEY (G0 v16)";
    case 0xEC: return "the G0's P-256 self-check failed this life: nothing signed (G0 v16)";
    case PKR_E_NOG0: return "G0 unreachable or has no PKSIGN";
    case PKR_E_DER: return "bad DER from the SE";
    case PKR_E_RECOVER: return "public key recovery failed";
    case PKR_E_ID: return "not a restorable credential ID";
    default: return "unknown";
  }
}

int pkr_der_to_raw(const uint8_t* d, size_t n, uint8_t raw[64]) {
  if (n < 8 || n > 72 || d[0] != 0x30 || d[1] != n - 2) return 0;
  size_t p = 2; memset(raw, 0, 64);
  for (int i = 0; i < 2; i++) {
    if (p + 2 > n || d[p] != 0x02) return 0;
    size_t l = d[p + 1]; p += 2;
    if (l == 0 || p + l > n) return 0;
    const uint8_t* v = d + p; size_t vl = l;
    while (vl > 32 && *v == 0) { v++; vl--; }
    if (vl > 32) return 0;
    memcpy(raw + i * 32 + (32 - vl), v, vl); p += l;
  }
  return p == n;
}

// The two fixed recovery hashes, the same the G0 signs (pk_glue.inc).
static void pkrRecoverHash(int which, uint8_t h[32]) {
  char m[] = "FAVILLA-PK-RECOVER-1"; m[sizeof(m) - 2] = (char)('0' + which);
  mbedtls_sha256((const uint8_t*)m, sizeof(m) - 1, h, 0);
}

// Two candidates from the first signature, then the one the second verifies.
static bool pkrRecover(const uint8_t s1[64], const uint8_t s2[64], uint8_t pub65[65]) {
  uint8_t h1[32], h2[32], c[2][65];
  pkrRecoverHash(1, h1); pkrRecoverHash(2, h2);
  int n = pkrecover_p256(h1, s1, c), hits = 0;
  mbedtls_ecp_group g; mbedtls_ecp_group_init(&g);
  if (mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1) != 0) n = 0;
  for (int i = 0; i < n; i++) {
    mbedtls_ecp_point Q; mbedtls_mpi r, s; mbedtls_ecp_point_init(&Q); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecp_point_read_binary(&g, &Q, c[i], 65) == 0 &&
              mbedtls_mpi_read_binary(&r, s2, 32) == 0 && mbedtls_mpi_read_binary(&s, s2 + 32, 32) == 0 &&
              mbedtls_ecdsa_verify(&g, h2, 32, &Q, &r, &s) == 0;
    mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    if (ok) { if (!hits) memcpy(pub65, c[i], 65); hits++; }
  }
  mbedtls_ecp_group_free(&g);
  return hits == 1;
}

static void pkrIn(uint8_t op, const uint8_t* nonce, const uint8_t* tag, const uint8_t rp[32], const uint8_t* hash, uint8_t in[97]) {
  memset(in, 0, 97); in[0] = op;
  if (nonce) memcpy(in + 1, nonce, 16);
  if (tag) memcpy(in + 17, tag, 16);
  memcpy(in + 33, rp, 32);
  if (hash) memcpy(in + 65, hash, 32);
}

bool pkr_scrub(uint8_t* res, uint16_t* sw) {
  uint8_t r = 0xFF; uint16_t w = 0;
  bool ran = g0_pk_scrub(&r, &w);
  if (res) *res = r;
  if (sw) *sw = w;
  s_scrubbed = ran && r == 0;
  return s_scrubbed;
}
static void pkrScrubOnce() {
  if (s_scrubbed) return;
  uint8_t r; uint16_t w;
  if (!pkr_scrub(&r, &w)) Serial.printf("[PKR] boot scrub: res %02X SW %04X\n", r, w);
}

int pkr_register(const uint8_t rp[32], uint8_t credId[PKR_ID_LEN], uint8_t pub65[65], pkr_timing_t* t) {
  if (!g0_pk_present()) return PKR_E_NOG0;
  pkrScrubOnce();
  uint8_t in[97], out[G0_BTC_OUT_LEN], s1[64], s2[64];
  pkrIn(1, nullptr, nullptr, rp, nullptr, in);
  uint32_t a = millis();
  bool ran = g0_pk_sign(in, out);
  uint32_t b = millis();
  if (t) t->g0Ms = b - a;
  if (!ran) { s_scrubbed = false; return PKR_E_NOG0; }   // a reset mid-relay can leave the site key: scrub before the next
  if (out[5] != 0) { s_scrubbed = false; return out[5]; }
  if (!pkr_der_to_raw(out + 45, out[44], s1) || !pkr_der_to_raw(out + 118, out[117], s2)) return PKR_E_DER;
  pwrBoostHold(3000);   // recovery: ~0.8 s at 240 MHz, 2.4 s at 80 (silicon); held so the main loop's screens cannot drop the clock under it
  esp_task_wdt_reset();
  bool ok = pkrRecover(s1, s2, pub65);
  pwrHoldEnd();         // the loop's safety net brings it back to 80 MHz
  esp_task_wdt_reset();
  if (t) t->recoverMs = millis() - b;
  if (!ok) return PKR_E_RECOVER;
  credId[0] = PKR_ID_VER; credId[1] = PKR_ID_KIND;
  memcpy(credId + 2, out + 12, 16); memcpy(credId + 18, out + 28, 16);
  return 0;
}

int pkr_sign(const uint8_t rp[32], const uint8_t credId[PKR_ID_LEN], const uint8_t hash[32],
             uint8_t* der, size_t* derN, pkr_timing_t* t) {
  if (credId[0] != PKR_ID_VER || credId[1] != PKR_ID_KIND) return PKR_E_ID;
  if (!g0_pk_present()) return PKR_E_NOG0;
  pkrScrubOnce();
  uint8_t in[97], out[G0_BTC_OUT_LEN];
  pkrIn(2, credId + 2, credId + 18, rp, hash, in);
  uint32_t a = millis();
  bool ran = g0_pk_sign(in, out);
  if (t) { t->g0Ms = millis() - a; t->recoverMs = 0; }
  if (!ran) { s_scrubbed = false; return PKR_E_NOG0; }
  if (out[5] != 0) { if (out[5] != 0xE4) s_scrubbed = false; return out[5]; }   // a tag refusal writes nothing
  uint8_t l = out[44], raw[64];
  if (!pkr_der_to_raw(out + 45, l, raw)) return PKR_E_DER;
  memcpy(der, out + 45, l); *derN = l;
  mbedtls_platform_zeroize(out, sizeof(out)); mbedtls_platform_zeroize(raw, sizeof(raw));
  return 0;
}

}  // namespace favilla
#endif  // FAVILLA_PK_RESTORABLE
