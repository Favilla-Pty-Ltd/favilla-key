// ec_gate_verify.cpp — P-256 ECDSA verify for the passkey-door bench check
// (ec_gate_probe.inc). BENCH ONLY. Lives in its own file so mbedtls headers
// are included at global scope, not inside se_signer.cpp's namespace.
#ifdef FAVILLA_BENCH_PROBES
#include <Arduino.h>
#include "esp_random.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

namespace favilla {
// Restorable passkeys bench check 2 (30 Oct 2026): a throwaway P-256 key made
// here (bench only) so the SE's IMPORT path can be tested against a known key.
static int eiRng(void*, unsigned char* out, size_t n) { esp_fill_random(out, n); return 0; }
bool ecgate_make_p256(uint8_t priv32[32], uint8_t pub65[65]) {
  mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&Q);
  size_t ol = 0;
  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (!rc) rc = mbedtls_ecp_gen_keypair(&grp, &d, &Q, eiRng, nullptr);
  if (!rc) rc = mbedtls_mpi_write_binary(&d, priv32, 32);
  if (!rc) rc = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ol, pub65, 65);
  mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&grp);
  return rc == 0 && ol == 65;
}
bool ecgate_verify_p256(const uint8_t pub65[65], const uint8_t hash32[32], const uint8_t sig64[64]) {
  mbedtls_ecp_group grp; mbedtls_ecp_point Q; mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&Q); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (!rc) rc = mbedtls_ecp_point_read_binary(&grp, &Q, pub65, 65);
  if (!rc) rc = mbedtls_mpi_read_binary(&r, sig64, 32);
  if (!rc) rc = mbedtls_mpi_read_binary(&s, sig64 + 32, 32);
  if (!rc) rc = mbedtls_ecdsa_verify(&grp, hash32, 32, &Q, &r, &s);
  mbedtls_mpi_free(&s); mbedtls_mpi_free(&r); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp);
  return rc == 0;
}
// Restorable passkeys bench check 2e (30 Oct 2026): public-key recovery from
// two SE signatures, because the SE gives no public key for a private-only key.
#include "mbedtls/private_access.h"
#include "pkrecover.inc"   // shared with pk_restorable.cpp and the G0 host test
bool ecgate_recover_pair(const uint8_t h1[32], const uint8_t s1[64],
                         const uint8_t h2[32], const uint8_t s2[64], uint8_t pub65[65]) {
  return pkrecover_p256_pair(h1, s1, h2, s2, pub65);
}
}  // namespace favilla
#endif
