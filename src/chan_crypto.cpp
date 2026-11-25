// chan_crypto.cpp - mbedTLS for the Favilla channel's pairing (Vault phase 5
// stage 2, 4 Nov 2026): HMAC-SHA256, one ephemeral P-256 key per pairing
// window, ECDH. Its own file so the mbedTLS headers sit at global scope.
// The key's randomness: an HMAC-DRBG seeded from pwGenSeed (secure element
// TRNG mixed with the ESP32's), because a life with no radio has no RF noise
// feeding esp_random.
#if defined(FAVILLA_FIDO_PROBE) && (defined(FAVILLA_VCHAN) || defined(FAVILLA_BLE_KBD))   // 9g: the app channel over Bluetooth pairs the same way
#include <Arduino.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/platform_util.h"

static mbedtls_hmac_drbg_context s_drbg;
static bool s_drbgOk = false;
static mbedtls_ecp_group s_grp; static mbedtls_mpi s_d; static mbedtls_ecp_point s_Q;
static bool s_kpOk = false;

static int drbgRng(void*, unsigned char* out, size_t n){ return s_drbgOk ? mbedtls_hmac_drbg_random(&s_drbg, out, n) : -1; }

bool chanc_hmac(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, kl, d, dl, out) == 0;
}
// 9g: HMAC over a || b without joining them (the app channel's mac covers up to 1.1 KB).
bool chanc_hmac2(const uint8_t* k, size_t kl, const uint8_t* a, size_t al, const uint8_t* b, size_t bl, uint8_t out[32]){
  mbedtls_md_context_t c; mbedtls_md_init(&c);
  bool ok = mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) == 0 && mbedtls_md_hmac_starts(&c, k, kl) == 0 &&
            mbedtls_md_hmac_update(&c, a, al) == 0 && (bl == 0 || mbedtls_md_hmac_update(&c, b, bl) == 0) && mbedtls_md_hmac_finish(&c, out) == 0;
  mbedtls_md_free(&c);
  return ok;
}
void chanc_close(){
  if(s_kpOk){ mbedtls_ecp_point_free(&s_Q); mbedtls_mpi_free(&s_d); mbedtls_ecp_group_free(&s_grp); s_kpOk = false; }
  if(s_drbgOk){ mbedtls_hmac_drbg_free(&s_drbg); s_drbgOk = false; }
}
// A fresh DRBG and key for one pairing window.
bool chanc_open(const uint8_t seed[32]){
  chanc_close();
  mbedtls_hmac_drbg_init(&s_drbg);
  if(mbedtls_hmac_drbg_seed_buf(&s_drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), seed, 32) != 0){ mbedtls_hmac_drbg_free(&s_drbg); return false; }
  s_drbgOk = true;
  mbedtls_ecp_group_init(&s_grp); mbedtls_mpi_init(&s_d); mbedtls_ecp_point_init(&s_Q);
  s_kpOk = true;
  if(mbedtls_ecp_group_load(&s_grp, MBEDTLS_ECP_DP_SECP256R1) != 0 || mbedtls_ecp_gen_keypair(&s_grp, &s_d, &s_Q, drbgRng, nullptr) != 0){ chanc_close(); return false; }
  return true;
}
void chanc_rng(uint8_t* p, size_t n){ if(drbgRng(nullptr, p, n) != 0) esp_fill_random(p, n); }
// This window's public key (uncompressed P-256).
bool chanc_mypub(uint8_t mine[65]){
  if(!s_kpOk) return false;
  size_t ol = 0;
  return mbedtls_ecp_point_write_binary(&s_grp, &s_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ol, mine, 65) == 0 && ol == 65;
}
// The shared secret with peer (checked on the curve).
bool chanc_ecdh(const uint8_t peer[65], uint8_t z[32]){
  if(!s_kpOk) return false;
  mbedtls_ecp_point P; mbedtls_mpi zz; mbedtls_ecp_point_init(&P); mbedtls_mpi_init(&zz);
  bool ok = mbedtls_ecp_point_read_binary(&s_grp, &P, peer, 65) == 0 && mbedtls_ecp_check_pubkey(&s_grp, &P) == 0;
  if(ok) ok = mbedtls_ecdh_compute_shared(&s_grp, &zz, &P, &s_d, drbgRng, nullptr) == 0;
  if(ok) ok = mbedtls_mpi_write_binary(&zz, z, 32) == 0;
  mbedtls_mpi_free(&zz); mbedtls_ecp_point_free(&P);
  return ok;
}
bool chanc_ready(){ return s_kpOk; }
#endif
