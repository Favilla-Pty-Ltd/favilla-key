// ECDSA P-256 public-key recovery (restorable passkeys, 30 Oct 2026). C and C++.
// Needs mbedtls/ecp.h and mbedtls/private_access.h included first.
// From a signature (r, s) over a known 32-byte hash, the signer's public key is
// one of two points: Q = r^-1 (s*R - e*G), R = (r, +/-y). Inputs are public
// data only; no private key is involved. Two signatures over different hashes
// share exactly one candidate, which is the key.
// Returns the number of candidates written to cand (0..2), each 65 bytes.
static int pkrecover_p256(const uint8_t hash32[32], const uint8_t sig64[64], uint8_t cand[2][65]) {
  mbedtls_ecp_group grp; mbedtls_ecp_point R, Q;
  mbedtls_mpi r, s, e, ri, u1, u2, x, y2, t, y, ex;
  mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&Q);
  mbedtls_mpi *all[] = { &r, &s, &e, &ri, &u1, &u2, &x, &y2, &t, &y, &ex };
  for (size_t i_ = 0; i_ < sizeof(all) / sizeof(all[0]); i_++) mbedtls_mpi_init(all[i_]);
  int found = 0, rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (!rc) rc = mbedtls_mpi_read_binary(&r, sig64, 32);
  if (!rc) rc = mbedtls_mpi_read_binary(&s, sig64 + 32, 32);
  if (!rc && (mbedtls_mpi_cmp_int(&r, 1) < 0 || mbedtls_mpi_cmp_mpi(&r, &grp.N) >= 0 ||
              mbedtls_mpi_cmp_int(&s, 1) < 0 || mbedtls_mpi_cmp_mpi(&s, &grp.N) >= 0)) rc = -1;
  if (!rc) rc = mbedtls_mpi_read_binary(&e, hash32, 32);
  if (!rc) rc = mbedtls_mpi_mod_mpi(&e, &e, &grp.N);
  if (!rc) rc = mbedtls_mpi_inv_mod(&ri, &r, &grp.N);                 // r^-1 mod n
  if (!rc) rc = mbedtls_mpi_mul_mpi(&u1, &s, &ri);                     // u1 = s r^-1
  if (!rc) rc = mbedtls_mpi_mod_mpi(&u1, &u1, &grp.N);
  if (!rc) rc = mbedtls_mpi_mul_mpi(&u2, &e, &ri);                     // u2 = -e r^-1
  if (!rc) rc = mbedtls_mpi_mod_mpi(&u2, &u2, &grp.N);
  if (!rc && mbedtls_mpi_cmp_int(&u2, 0) != 0) rc = mbedtls_mpi_sub_mpi(&u2, &grp.N, &u2);
  // x = r (r + n would exceed p for P-256 with probability ~2^-128; ignored)
  if (!rc) rc = mbedtls_mpi_copy(&x, &r);
  // y^2 = x^3 - 3x + b mod p
  if (!rc) rc = mbedtls_mpi_mul_mpi(&t, &x, &x);
  if (!rc) rc = mbedtls_mpi_mod_mpi(&t, &t, &grp.P);
  if (!rc) rc = mbedtls_mpi_sub_int(&t, &t, 3);
  if (!rc) rc = mbedtls_mpi_mul_mpi(&y2, &t, &x);
  if (!rc) rc = mbedtls_mpi_add_mpi(&y2, &y2, &grp.B);
  if (!rc) rc = mbedtls_mpi_mod_mpi(&y2, &y2, &grp.P);
  // y = y2^((p+1)/4) mod p (p = 3 mod 4)
  if (!rc) rc = mbedtls_mpi_add_int(&ex, &grp.P, 1);
  if (!rc) rc = mbedtls_mpi_shift_r(&ex, 2);
  if (!rc) rc = mbedtls_mpi_exp_mod(&y, &y2, &ex, &grp.P, NULL);
  if (!rc) { rc = mbedtls_mpi_mul_mpi(&t, &y, &y); if (!rc) rc = mbedtls_mpi_mod_mpi(&t, &t, &grp.P);
             if (!rc && mbedtls_mpi_cmp_mpi(&t, &y2) != 0) rc = -1; }    // r is not an x on the curve
  for (int sign = 0; !rc && sign < 2; sign++) {
    int k = 0;
    k |= mbedtls_mpi_copy(&R.MBEDTLS_PRIVATE(X), &x);
    if (sign == 0) k |= mbedtls_mpi_copy(&R.MBEDTLS_PRIVATE(Y), &y);
    else           k |= mbedtls_mpi_sub_mpi(&R.MBEDTLS_PRIVATE(Y), &grp.P, &y);
    k |= mbedtls_mpi_lset(&R.MBEDTLS_PRIVATE(Z), 1);
    if (k) { rc = k; break; }
    if (mbedtls_ecp_muladd(&grp, &Q, &u1, &R, &u2, &grp.G) != 0) continue;
    if (mbedtls_ecp_is_zero(&Q) || mbedtls_ecp_check_pubkey(&grp, &Q) != 0) continue;
    size_t ol = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ol, cand[found], 65) == 0 && ol == 65) found++;
  }
  for (size_t i_ = 0; i_ < sizeof(all) / sizeof(all[0]); i_++) mbedtls_mpi_free(all[i_]);
  mbedtls_ecp_point_free(&Q); mbedtls_ecp_point_free(&R); mbedtls_ecp_group_free(&grp);
  return rc ? 0 : found;
}
// The one public key consistent with two signatures over two different hashes.
// True and pub65 set only if exactly one candidate is shared.
static int pkrecover_p256_pair(const uint8_t h1[32], const uint8_t s1[64],
                                const uint8_t h2[32], const uint8_t s2[64], uint8_t pub65[65]) {
  uint8_t a[2][65], b[2][65];
  int na = pkrecover_p256(h1, s1, a), nb = pkrecover_p256(h2, s2, b), hits = 0;
  for (int i = 0; i < na; i++) for (int j = 0; j < nb; j++)
    if (!memcmp(a[i], b[j], 65)) { if (!hits) memcpy(pub65, a[i], 65); hits++; }
  return hits == 1;
}
