/* ===========================================================================
 * Vault backup publishing key (v14, 2 Nov 2026, Favilla Vault spec phase 3).
 * Included from main.c after vault_glue.inc.
 *
 * KEY. k_pub = the first HMAC(K_vault, "PUB" || ctr) (ctr = 0, 1, ...) that is
 * a valid secp256k1 secret key. K_vault comes from S_pk (words only, D6), so a
 * restore from the words finds the backup by the x-only public key P.
 *
 * WHY A COPY. Backups are signed in the NOSTR life (the PASSKEY life has no
 * radio), and v19 (13 Nov 2026, one door one PIN) the NOSTR life never reads
 * S_pk. So the key gets its own copy, opened with the daily PIN:
 *   PUBSEAL (VAULT op 4, PASSKEY life, in a passkey window): out =
 *           AES-CBC(K_G0, VPUB_IV, k_pub) || P || check8. The ESP32 keeps the
 *           first 32 bytes (ciphertext under K_G0) until the next NOSTR life.
 *   The ESP32, in the daily-PIN session, wraps them under the daily wrap key and
 *   writes SE_OBJ_VPUB = IV16 || CT32 (G0 READ only while Door 1 is unlocked;
 *   daily PIN DELETE; RECOVER DELETE), exactly the Nostr key's shape.
 *   VSIGN_INIT (NOSTR or UNSET life, Door 1 unlocked): reads SE_OBJ_VPUB,
 *   strips the daily layer on the SE and K_G0 here, and starts an anti-exfil
 *   Schnorr signature of the event id exactly as SIGN_INIT does (AE_IN = id ||
 *   h, SIG_OUT = R0). AE_FINISH releases it after verifying against P.
 * k_pub signs ONLY backup events: it opens no record and signs no passkey.
 * ========================================================================= */
/* G0_CMD_VSIGN_INIT 0x29 is defined in main.c with the other anti-exfil commands. */

static void vpub_iv(uint8_t iv[16]) {
    uint8_t h[32];
    static const uint8_t label[] = "favilla-g0-vault-pub-iv";
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, h);
    memcpy(iv, h, 16); secure_wipe(h, sizeof(h));
}

/* k_pub from K_vault. 0 or -1. */
static int vlt_kpub(const uint8_t kv[32], uint8_t k[32]) {
    for (unsigned c = 0; c < 256; c++) {
        uint8_t ctr = (uint8_t)c;
        vlt_sub(kv, "PUB", &ctr, 1, k);
        if (secp256k1_ec_seckey_verify(g_ctx, k)) return 0;
    }
    secure_wipe(k, 32);
    return -1;
}

/* VAULT op 4. out72 = sealed32 || xonly32 || check8. 0 or -1. */
static int vlt_pubseal(const uint8_t kv[32], uint8_t out72[72]) {
    uint8_t k[32], iv[16], h[32]; secp256k1_keypair kp; secp256k1_xonly_pubkey xp; int rc = -1;
    if (vlt_kpub(kv, k) != 0) goto out;
    if (!secp256k1_keypair_create(g_ctx, &kp, k) || !secp256k1_keypair_xonly_pub(g_ctx, &xp, NULL, &kp)) goto out;
    memcpy(out72, k, 32);
    vpub_iv(iv);
    { struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv); AES_CBC_encrypt_buffer(&a, out72, 32); secure_wipe(&a, sizeof(a)); }
    secp256k1_xonly_pubkey_serialize(g_ctx, out72 + 32, &xp);
    vlt_sub(kv, "CHK", NULL, 0, h); memcpy(out72 + 64, h, 8);
    rc = 0;
out:
    secure_wipe(k, 32); secure_wipe(iv, 16); secure_wipe(h, 32); secure_wipe(&kp, sizeof(kp));
    return rc;
}

/* k_pub from SE_OBJ_VPUB in one session. Door 1 must be unlocked (the object's
 * READ entry); a PASSKEY life never gets here (door_permits). 0 or -1. */
static int vpub_fetch(uint8_t k[32]) {
    scp03_session_t s; uint8_t blob[SE_BLOB_LEN], inner[32], iv[16]; size_t bl = 0; int rc;
    if (!g_keys_valid || !g_door1_locked) return -1;
    memset(&s, 0, sizeof(s));
    rc = pk_open(&s);
    if (rc == 0) rc = scp03_read_object(&s, SE_OBJ_VPUB, blob, sizeof(blob), &bl);
    if (rc == 0 && bl != SE_BLOB_LEN) rc = SCP03_E_FORMAT;
    if (rc == 0) rc = scp03_cipher_oneshot(&s, SE_OBJ_AES_WRAP_DAILY, 1, blob + 16, blob, inner);   /* v19: the daily layer, as the Nostr key */
    scp03_close(&s); scp03_wipe(&s);
    if (rc == 0) {
        vpub_iv(iv);
        struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv);
        memcpy(k, inner, 32); AES_CBC_decrypt_buffer(&a, k, 32);
        secure_wipe(&a, sizeof(a));
    }
    secure_wipe(blob, sizeof(blob)); secure_wipe(inner, sizeof(inner)); secure_wipe(iv, 16);
    return rc ? -1 : 0;
}

/* VSIGN_INIT: as SIGN_INIT, with k_pub. The x-only public key is kept with the
 * pending operation (g_ae.pub33[0..31]) so AE_FINISH verifies against it. */
static int do_vsign_init(void) {
    uint8_t k[32], aux[32]; secp256k1_keypair kp; secp256k1_xonly_pubkey xp; int rc = -1;
    if (!g_ae_in_valid) return -1;
    if (g_ae.kind != AE_KIND_NONE) return -1;        /* one at a time; the pending one is NOT cleared */
    if (vpub_fetch(k) != 0) return -1;
    if (!secp256k1_ec_seckey_verify(g_ctx, k) || !secp256k1_keypair_create(g_ctx, &kp, k) ||
        !secp256k1_keypair_xonly_pub(g_ctx, &xp, NULL, &kp)) goto out;
    {
        static const uint8_t label[] = "favilla-g0-vault-aux";
        uint8_t fresh[32]; sha256_ctx c;
        entropy_mix(label, sizeof(label) - 1); sha256(g_pool, 32, fresh);
        sha256_init(&c); sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, g_ae_in, 32); sha256_update(&c, fresh, 32); sha256_final(&c, aux);
        secure_wipe(fresh, 32);
    }
    if (ae_schnorr_init(g_ctx, k, g_ae_in, aux, g_ae_in + 32, g_ae.k0, g_ae.r0) == 0) {
        memcpy(g_ae.key, k, 32);
        memcpy(g_ae.h, g_ae_in + 32, 32);
        memcpy(g_ae.msg, g_ae_in, 32);
        secp256k1_xonly_pubkey_serialize(g_ctx, g_ae.pub33, &xp);
        g_ae.vault = 1;
        g_ae.t0 = HAL_GetTick();
        g_ae.kind = AE_KIND_SCHNORR;
        memset(g_sig_out, 0, 64); memcpy(g_sig_out, g_ae.r0, 33);
        rc = 0;
    } else ae_wipe();
out:
    secure_wipe(k, 32); secure_wipe(aux, 32); secure_wipe(&kp, sizeof(kp));
    return rc;
}
