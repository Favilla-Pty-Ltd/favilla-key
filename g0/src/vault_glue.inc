/* ===========================================================================
 * Vault records (2 Nov 2026, Favilla Vault spec v0.15 section 3, ruling P1).
 * Included from main.c after pk_glue.inc (it reuses pk_open and
 * pk_fetch_master_in).
 *
 * K_vault = HMAC-SHA256(S_pk, "FAVILLA-VAULT-v1")       (D1; no passphrase yet)
 * K_enc   = HMAC(K_vault, "ENC")   K_mac = HMAC(K_vault, "MAC")
 * site tag = HMAC(K_vault, "SITE" || site)[0:8]
 *
 * One command, VAULT 0x28. Input VAULT_IN 0x23, exactly 514 bytes:
 *   op (1) || len (2, big endian) || data (511, zero padded)
 * op 1 SEAL: data = hdr13 (id8 || updated4 || kind1) || plaintext.
 *            The plaintext starts [siteLen][site], siteLen 1..253, and is at
 *            most VLT_PT_MAX bytes. Out: hdr13 || tag8 || iv16 || ct || mac32,
 *            mac = HMAC(K_mac, hdr13 || tag8 || iv16 || ct), AES-256-CBC with
 *            PKCS#7. The tag is computed HERE from the site in the plaintext.
 * op 2 OPEN: data = a sealed record. Refused once this sitting's OPEN budget
 *            is spent (P5 = C+, pk_glue.inc: 32 per sitting, refilled by a PIN
 *            on the KEY at most 4 times per power-on life). The MAC is
 *            checked (constant time) before anything is decrypted; only a
 *            good MAC and good padding use one OPEN. Out: hdr13 || plaintext.
 * op 3 TAG:  data = site (1..253 bytes). Out: tag8. Its own budget, 32 per
 *            sitting on the same refill rule (C+: guessing sites stays slow).
 * op 4 PUBSEAL (v14, 2 Nov 2026, Vault spec phase 3): data empty. Derives
 *            the backup publishing key k_pub from K_vault (vpub_glue.inc) and
 *            outputs sealed32 || xonly_pub32 || check8, where sealed = k_pub
 *            under K_G0 (useless to the ESP32) and check = HMAC(K_vault, "CHK")[0:8].
 *            The ESP32 wraps sealed under K_PKN and stores it as SE_OBJ_VPUB,
 *            which VSIGN_INIT reads in a NOSTR life. No budget: it opens nothing.
 * op 5 IMPORT (v15): opens the import window (pk_glue.inc).
 * op 6 LABEL (v15, 3 Nov 2026, Vault spec 7f P4-8): data = a sealed record of
 *            kind 2 (a password entry; the kind is in the MACed header).
 *            Checked and opened as OPEN, but the output is only
 *            LABELs left (2) || hdr13 (id first: the pick maps to the OPEN by
 *            id) || [siteLen][site] || [uLen][username]. Never the password or
 *            the note: the rest of the plaintext is wiped before output. Its own
 *            budget, VLT_LABEL_PER_LIFE (800 from v23) per power-on life, kept in the
 *            life token; it never touches the OPEN budget. A bad MAC costs
 *            nothing, as OPEN.
 * op 7 TOTP (v17, 7 Nov 2026, Josh's ruling B): data = unix time (8, big
 *            endian) || a sealed record of kind 3. The record is checked and
 *            opened as OPEN, but only the code leaves: out = code (4, big
 *            endian) || digits (1) || period (1). Plaintext of kind 3:
 *            [siteLen][site][uLen][account][kLen][secret][digits 6..8][period s]
 *            (secret 1..64 bytes, period 1..255). Costs one OPEN. Within one
 *            power-on life of the G0 the time may not go back more than 60 s
 *            or forward more than 1200 s from the last code served (the G0 has
 *            no clock; the first is not bounded). OPEN refuses kind 3: the
 *            secret never leaves the G0. LABEL takes kind 3 as well (its site
 *            and account have the same shape as a password entry's).
 * Every op reads S_pk in its own SE session: Door 1 unlocked, as PKSIGN.
 *
 * Output VAULT_OUT 0x24 (readable in SIG_READY), VLT_OUT_LEN bytes:
 *   0..3 "VLT1"  4 ver 1  5 result (0 ok, else VLT_E_*)  6 op  7 OPENs left
 *   8..9 out length (big endian)  10..11 SW of the failing SE command
 *   12.. out data (zero on any failure)
 * ========================================================================= */
#define G0_CMD_VAULT     0x28
#define G0_REG_VAULT_IN  0x23
#define G0_REG_VAULT_OUT 0x24
#define VLT_IN_LEN       514
#define VLT_DATA_MAX     511
#define VLT_OUT_LEN      (12 + VLT_DATA_MAX)
#define VLT_HDR          13
#define VLT_OVER         (VLT_HDR + 8 + 16 + 32)            /* 69: sealed = VLT_OVER + ct */
#define VLT_CT_MAX       (((VLT_DATA_MAX - VLT_OVER) / 16) * 16)   /* 432 */
#define VLT_PT_MAX       (VLT_CT_MAX - 1)                   /* 431: PKCS#7 always adds a byte */
#define VLT_OP_SEAL 1
#define VLT_OP_OPEN 2
#define VLT_OP_TAG  3
#define VLT_OP_PUBSEAL 4   /* v14 */
#define VLT_OP_IMPORT 5    /* v15 (3 Nov 2026): open the import window (pk_glue.inc). Out: SEALs left (2) || TAGs left (2) */
#define VLT_OP_LABEL  6    /* v15 (3 Nov 2026): site and username of a password entry, own budget */
#define VLT_KIND_PASSWORD 2
#define VLT_OP_TOTP   7    /* v17 (7 Nov 2026): a TOTP code from a kind 3 record; the secret never leaves */
#define VLT_KIND_TOTP 3
#define VLT_OP_LIMIT  8    /* v24 (25 Nov 2026): read the vault limit. data empty. Out: limit now ||
                            * limit from the next power-on || OPENs left || TAGs left (0xFF: no limit) ||
                            * refills used || refills per power-on. No SE, no budget. */
#define VLT_OP_SETLIM 9    /* v24: set it. data = limit (0, 8, 16, 32, 64 or 128). Only straight after a
                            * right UVCHECK (a PIN on the KEY), in a PASSKEY life, with the passkey master
                            * readable. Stored in flash. Stricter: at once (the budgets drop to it). Looser
                            * or none: from the next power-on. Out: the LIMIT output. */

#define VLT_E_INPUT  0xE1   /* no VAULT_IN, bad op, bad length or a malformed plaintext */
#define VLT_E_KEYS   0xE2   /* no keys, or no Door-1 boot lock this life */
#define VLT_E_MASTER 0xE3   /* S_pk not readable (Door 1 locked, absent) */
#define VLT_E_OPEN   0xE5   /* session to the SE did not open */
#define VLT_E_AUTH   0xE6   /* OPEN: MAC or padding wrong (not sealed by this vault, or altered) */
#define VLT_E_BUDGET 0xE7   /* OPEN: this sitting's budget is spent - enter the PIN on the KEY (or power cycle once the refills are used) */
#define VLT_E_TAGBUDGET 0xE8 /* TAG: this sitting's TAG budget is spent - same refill rule */
#define VLT_E_PUBKEY 0xE9   /* PUBSEAL: no valid publishing key could be derived (never expected) */
#define VLT_E_IMPORT 0xEA   /* IMPORT: not right after a right UVCHECK, not a NOSTR life, or this life's window was already used */
#define VLT_E_LABEL  0xEB   /* LABEL: this life's 800 are used (power cycle) */
#define VLT_E_TIME   0xEC   /* TOTP: the time is outside the window around the last code served this life */
#define VLT_E_LIMIT  0xED   /* SETLIM: not a valid limit, not right after a right UVCHECK, not a PASSKEY life, or the flash write failed */
#define VLT_TOTP_BACK 60u
#define VLT_TOTP_FWD  1200u
static uint64_t g_totp_last = 0;   /* v17: the time of the last code served this power-on life (0: none yet) */
static int vlt_pubseal(const uint8_t kv[32], uint8_t out72[72]);   /* vpub_glue.inc (v14) */

static uint8_t g_vlt_in[VLT_IN_LEN]; static volatile uint8_t g_vlt_in_valid = 0;
static uint8_t g_vlt_out[VLT_OUT_LEN];

static void vlt_sub(const uint8_t kv[32], const char *lab, const uint8_t *x, size_t xn, uint8_t out[32]) {
    uint8_t m[4 + 253]; size_t ln = strlen(lab);
    if (ln > 4 || xn > sizeof(m) - ln) { memset(out, 0, 32); return; }   /* review 2 Nov: never past m (callers cap the site at 253) */
    memcpy(m, lab, ln); if (xn) memcpy(m + ln, x, xn);
    hmac_sha256(kv, 32, m, ln + xn, out);
    secure_wipe(m, sizeof(m));
}

static void vlt_lim_out(uint8_t *o) {
    o[0] = g_vlt_limit; o[1] = g_vlt_limit_next;
    o[2] = g_vlt_limit ? g_vlt_open_left : 0xFF; o[3] = g_vlt_limit ? g_vlt_tag_left : 0xFF;
    o[4] = g_vlt_refills; o[5] = VLT_REFILLS_MAX;
}
static int do_vault(void) {
    uint8_t op = g_vlt_in_valid ? g_vlt_in[0] : 0;
    size_t n = g_vlt_in_valid ? (((size_t)g_vlt_in[1] << 8) | g_vlt_in[2]) : 0;
    const uint8_t *in = g_vlt_in + 3;
    uint8_t *o = g_vlt_out + 12;
    uint8_t res = 0; int rc = 0; uint16_t sw = 0; size_t on = 0;
    uint8_t spk[32], kv[32], ke[32], km[32], h[32];
    scp03_session_t s; memset(&s, 0, sizeof(s));
    memset(g_vlt_out, 0, VLT_OUT_LEN);
    uint8_t armed = g_imp_armed; g_imp_armed = 0;   /* v15: the PIN check arms only the very next VAULT op */
    uint8_t impS = (uint8_t)(g_imp_on && g_imp_seal), impT = (uint8_t)(g_imp_on && g_imp_tag);

    /* Input shape first: nothing is fetched for a request that cannot be served. */
    if (!g_vlt_in_valid || n > VLT_DATA_MAX) res = VLT_E_INPUT;
    else if (op == VLT_OP_LIMIT) { if (n != 0) res = VLT_E_INPUT; else { vlt_lim_out(o); on = 6; goto out; } }   /* v24: no keys, no SE */
    else if (op == VLT_OP_SETLIM) { if (n != 1 || !VLT_LIM_OK(in[0])) res = VLT_E_LIMIT; else if (!armed || g_door != DOOR_PASSKEY) res = VLT_E_LIMIT; }
    else if (op == VLT_OP_SEAL) { if (n < VLT_HDR + 2 || n - VLT_HDR > VLT_PT_MAX || in[VLT_HDR] == 0 || in[VLT_HDR] > 253 || 1u + in[VLT_HDR] > n - VLT_HDR) res = VLT_E_INPUT;   /* site 1..253 (review 2 Nov) */
                                  else if (!impS && g_vlt_limit && !g_vlt_tag_left) res = VLT_E_TAGBUDGET; }   /* 2b review (M2): SEAL outputs a site tag; v15: the import window pays instead */
    else if (op == VLT_OP_OPEN) { if (n < VLT_OVER + 16 || (n - VLT_OVER) % 16 || in[12] == VLT_KIND_TOTP) res = VLT_E_INPUT; else if (g_vlt_limit && !g_vlt_open_left) res = VLT_E_BUDGET; }   /* v17: a TOTP record never opens to the ESP32 */
    else if (op == VLT_OP_TOTP) {
        if (n < 8 + VLT_OVER + 16 || (n - 8 - VLT_OVER) % 16 || in[8 + 12] != VLT_KIND_TOTP) res = VLT_E_INPUT;
        else if (g_vlt_limit && !g_vlt_open_left) res = VLT_E_BUDGET;
        else { uint64_t t = 0; for (int i = 0; i < 8; i++) t = (t << 8) | in[i];
               if (g_totp_last && (t + VLT_TOTP_BACK < g_totp_last || t > g_totp_last + VLT_TOTP_FWD)) res = VLT_E_TIME; } }
    else if (op == VLT_OP_TAG)  { if (n < 1 || n > 253) res = VLT_E_INPUT; else if (!impT && g_vlt_limit && !g_vlt_tag_left) res = VLT_E_TAGBUDGET; }
    else if (op == VLT_OP_PUBSEAL) { if (n != 0) res = VLT_E_INPUT; }
    else if (op == VLT_OP_LABEL) { if (n < VLT_OVER + 16 || (n - VLT_OVER) % 16 || (in[12] != VLT_KIND_PASSWORD && in[12] != VLT_KIND_TOTP)) res = VLT_E_INPUT; else if (g_lbl_used >= VLT_LABEL_PER_LIFE) res = VLT_E_LABEL; }
    else if (op == VLT_OP_IMPORT) { if (n != 0) res = VLT_E_INPUT; else if (!armed || g_door != DOOR_PASSKEY || g_imp_used) res = VLT_E_IMPORT; }   /* v19: imports happen in VAULT mode */
    else res = VLT_E_INPUT;
    if (!res && (!g_keys_valid || !g_door1_locked)) res = VLT_E_KEYS;
    if (res) goto out;

    rc = pk_open(&s);
    if (rc) { res = VLT_E_OPEN; sw = s.last_sw; goto out; }
    rc = pk_fetch_master_in(&s, spk, &sw);
    scp03_close(&s);
    if (rc) { res = VLT_E_MASTER; goto out; }
    { static const uint8_t lab[] = "FAVILLA-VAULT-v1"; hmac_sha256(spk, 32, lab, sizeof(lab) - 1, kv); }
    secure_wipe(spk, 32);
    vlt_sub(kv, "ENC", NULL, 0, ke);
    vlt_sub(kv, "MAC", NULL, 0, km);

    if (op == VLT_OP_SETLIM) {   /* v24: the master read above proves a passkey-PIN window is open */
        uint8_t L = in[0];
        if (!ks_lim_store(L)) { res = VLT_E_LIMIT; goto out; }
        g_vlt_limit_next = L;
        if (L && (!g_vlt_limit || L < g_vlt_limit)) {   /* stricter: at once */
            g_vlt_limit = L;
            if (g_vlt_open_left > L || !g_vlt_open_left) g_vlt_open_left = L;   /* from no limit the counters were idle: start full at L */
            if (g_vlt_tag_left > L || !g_vlt_tag_left)  g_vlt_tag_left = L;
        }
        vlt_lim_out(o); on = 6;
    } else if (op == VLT_OP_IMPORT) {   /* v15; v19: the master read above proves a passkey-PIN window is open */
        g_imp_on = 1; g_imp_used = 1; life_save(); g_imp_seal = VLT_IMP_MAX; g_imp_tag = VLT_IMP_MAX;
        o[0] = (uint8_t)(g_imp_seal >> 8); o[1] = (uint8_t)g_imp_seal; o[2] = (uint8_t)(g_imp_tag >> 8); o[3] = (uint8_t)g_imp_tag; on = 4;
    } else if (op == VLT_OP_PUBSEAL) {
        if (vlt_pubseal(kv, o) != 0) { res = VLT_E_PUBKEY; goto out; }
        on = 72;
    } else if (op == VLT_OP_TAG) {
        vlt_sub(kv, "SITE", in, n, h); memcpy(o, h, 8); on = 8;
        if (impT) g_imp_tag--; else if (g_vlt_limit) g_vlt_tag_left--;
    } else if (op == VLT_OP_SEAL) {
        size_t pt = n - VLT_HDR, ct = (pt / 16 + 1) * 16;
        uint8_t pad = (uint8_t)(ct - pt);
        memcpy(o, in, VLT_HDR);                                          /* hdr */
        vlt_sub(kv, "SITE", in + VLT_HDR + 1, in[VLT_HDR], h); memcpy(o + VLT_HDR, h, 8);   /* tag from the plaintext's site */
        {   static const uint8_t lab[] = "favilla-g0-vault-iv";       /* iv after the session open: the pool holds the card challenge */
            entropy_mix(lab, sizeof(lab) - 1); sha256(g_pool, 32, h); memcpy(o + VLT_HDR + 8, h, 16); }
        uint8_t *c = o + VLT_HDR + 24;
        memcpy(c, in + VLT_HDR, pt); memset(c + pt, pad, pad);
        {   struct AES_ctx a; AES_init_ctx_iv(&a, ke, o + VLT_HDR + 8);
            AES_CBC_encrypt_buffer(&a, c, ct); secure_wipe(&a, sizeof(a)); }
        hmac_sha256(km, 32, o, VLT_HDR + 24 + ct, o + VLT_HDR + 24 + ct);
        on = VLT_OVER + ct;
        if (impS) g_imp_seal--; else if (g_vlt_limit) g_vlt_tag_left--;
    } else {   /* OPEN, LABEL (v15) and TOTP (v17) */
        uint64_t tnow = 0;
        if (op == VLT_OP_TOTP) { for (int i = 0; i < 8; i++) tnow = (tnow << 8) | in[i]; in += 8; n -= 8; }
        size_t ct = n - VLT_OVER;
        hmac_sha256(km, 32, in, n - 32, h);
        uint8_t d = 0; for (int i = 0; i < 32; i++) d |= (uint8_t)(h[i] ^ in[n - 32 + i]);
        if (d) { res = VLT_E_AUTH; goto out; }
        uint8_t *p = o + VLT_HDR;
        memcpy(o, in, VLT_HDR); memcpy(p, in + VLT_HDR + 24, ct);
        {   struct AES_ctx a; AES_init_ctx_iv(&a, ke, in + VLT_HDR + 8);
            AES_CBC_decrypt_buffer(&a, p, ct); secure_wipe(&a, sizeof(a)); }
        uint8_t pad = p[ct - 1], bad = (uint8_t)(pad == 0 || pad > 16);
        for (size_t i = 0; i < 16; i++) bad |= (uint8_t)((i < pad) & (p[ct - 1 - i] != pad));
        if (bad) { res = VLT_E_AUTH; goto out; }
        on = VLT_HDR + ct - pad;
        if (op == VLT_OP_TOTP) {   /* [sl][site][ul][acct][kl][secret][digits][period]: only the code leaves */
            size_t pl = ct - pad, k = 0; int ok = 0;
            if (pl >= 1) { k = 1u + p[0]; if (k < pl) { k += 1u + p[k]; if (k < pl) { size_t kl = p[k];
                if (kl >= 1 && kl <= 64 && k + 1 + kl + 2 == pl) {
                    uint8_t dg = p[k + 1 + kl], per = p[k + 2 + kl];
                    if (dg >= 6 && dg <= 8 && per >= 1) {
                        long code = g0_hotp_sha1(p + k + 1, kl, tnow / per, dg);
                        if (code >= 0) { ok = 1; secure_wipe(o, VLT_OUT_LEN - 12);
                            o[0] = (uint8_t)(code >> 24); o[1] = (uint8_t)(code >> 16); o[2] = (uint8_t)(code >> 8); o[3] = (uint8_t)code; o[4] = dg; o[5] = per; on = 6; }
                    } } } } }
            if (!ok) { res = VLT_E_AUTH; goto out; }   /* not a TOTP record's shape */
            if (g_vlt_limit) g_vlt_open_left--;
            g_totp_last = tnow;
        } else if (op == VLT_OP_LABEL) {   /* keep [siteLen][site][uLen][user]; the password and note never leave */
            size_t pl = ct - pad, k = 0;
            if (pl >= 1) { k = 1u + p[0]; if (k < pl) k += 1u + p[k]; else k = pl + 1; }
            if (pl < 1 || k > pl) { res = VLT_E_AUTH; goto out; }   /* not a password entry's shape */
            secure_wipe(p + k, ct - k);
            memmove(o + 2, o, VLT_HDR + k);
            g_lbl_used++; life_save();
            { uint16_t left = (uint16_t)(VLT_LABEL_PER_LIFE - g_lbl_used); o[0] = (uint8_t)(left >> 8); o[1] = (uint8_t)left; }
            on = 2 + VLT_HDR + k;
        } else if (g_vlt_limit) g_vlt_open_left--;
    }
out:
    if (res) { secure_wipe(g_vlt_out, VLT_OUT_LEN); on = 0; }
    g_vlt_out[0]='V'; g_vlt_out[1]='L'; g_vlt_out[2]='T'; g_vlt_out[3]='1'; g_vlt_out[4]=1;
    g_vlt_out[5] = res; g_vlt_out[6] = op; g_vlt_out[7] = g_vlt_limit ? g_vlt_open_left : 0xFF;   /* v24: 0xFF = no limit */
    g_vlt_out[8] = (uint8_t)(on >> 8); g_vlt_out[9] = (uint8_t)on;
    g_vlt_out[10] = (uint8_t)(sw >> 8); g_vlt_out[11] = (uint8_t)sw;
    scp03_wipe(&s);
    secure_wipe(spk, 32); secure_wipe(kv, 32); secure_wipe(ke, 32); secure_wipe(km, 32); secure_wipe(h, 32);
    return 0;
}
