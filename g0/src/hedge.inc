/* Included by main.c after entropy_mix(), g_pool and g_kg0; the host tests
 * include it the same way after their own stubs, so they test this code. */
/* v18 (7 Nov 2026): hedged nonces. out = SHA256(K_G0 || label || in || fresh),
 * fresh from the pool (SE TRNG card challenges, K_SE, clocks): unpredictable to
 * the ESP32 and different every call, so a signature is never repeated over the
 * same message, whatever the ESP32 or host sends (the do_sign_init pattern of
 * 19 Oct 2026, now for the passkey and Bitcoin signatures too). */
static void hedge32(const char *label, const uint8_t in[32], uint8_t out[32]) {
    uint8_t fresh[32];
    entropy_mix((const uint8_t *)label, strlen(label)); sha256(g_pool, 32, fresh);
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, (const uint8_t *)label, strlen(label));
    sha256_update(&c, in, 32); sha256_update(&c, fresh, 32); sha256_final(&c, out);
    secure_wipe(fresh, 32);
}
