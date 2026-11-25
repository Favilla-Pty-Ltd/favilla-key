/* ===========================================================================
 * Restorable passkeys (30 Oct 2026, spec v0.8). Included from main.c.
 *
 * MASTER. S_pk = HMAC-SHA256(BIP-39 seed without passphrase,
 * "FAVILLA-PASSKEY-MASTER-v1"), computed by the ESP32 in the air-gapped
 * onboarding step that already sees the seed. PKMASTER seals it with K_G0 under
 * its OWN IV label ("favilla-g0-pk-master-iv"), and ONLY inside the onboarding
 * seal window, once. So a compromised ESP32 at run time cannot plant a master
 * it chose (PROVISION output uses the scalar's IV, which this chip turns into
 * an unknown value when read as a master). The ESP32 adds the daily-wrap layer
 * and writes SE_OBJ_PK_MASTER. PKSIGN reads it back inside its ONE session
 * (Door 1 unlocked) and strips the K_G0 layer with the master IV.
 *
 * SCRATCH OBJECT. Owned by this chip: on the first PKSIGN / PKSCRUB of a
 * power-on life the G0 deletes whatever sits at SE_OBJ_PK_SCRATCH (refusing if
 * it may not: an object it cannot delete is not its own) and creates it itself,
 * inside its session, with its own policy: G0 SIGN|WRITE|DELETE, RECOVER DELETE,
 * nothing else. The ESP32 then holds no right on it at all, so it can neither
 * sign with it nor swap it.
 *
 * PKSIGN (PK_IN 0x22 = op || nonce16 || tag16 || rpIdHash32 || hash32, 97 B):
 *   op 1 REGISTER: nonce made here, tag = HMAC(S_pk, "ID"||1||1||nonce||rp)[0:16],
 *                  k derived, written to the scratch object, the SE signs the two
 *                  FIXED recovery hashes, junk written over k. The ESP32 recovers
 *                  the public key from the two signatures (public data only).
 *   op 2 SIGN:     tag checked for (nonce, rpIdHash) BEFORE anything is
 *                  written; k derived, written, the SE signs `hash`, junk.
 * Junk is attempted on every path once the site-key write was sent (a fresh
 * session if the first one broke). g_pk_dirty stays set until a junk write is
 * confirmed; while it is set nothing is released and the result is PK_E_JUNK.
 * PKSCRUB: claims the scratch object if needed and writes junk.
 *
 * Output on BTC_OUT, rc always 0 so the diagnostic survives finish():
 *   0..3 "PKSG"  4 ver 2  5 result (0 ok, else PK_E_*)  6 op  7 scp03 rc (int8)
 *   8..9 SW of the failing (or last) SE command  10 relay steps  11 dirty flag
 *   12..27 nonce  28..43 tag   (REGISTER only)
 *   44 len1 45..116 DER1       (REGISTER: recovery hash 1; SIGN: the hash)
 *   117 len2 118..189 DER2     (REGISTER: recovery hash 2)
 * On any failure every field after 11 is zero.
 * ========================================================================= */
#define G0_CMD_PKSIGN   0x22
#define G0_CMD_PKSCRUB  0x23
#define G0_CMD_PKMASTER 0x24   /* HASH_IN = S_pk -> SIG_OUT = inner32 || tag32 (v19); onboarding seal window only, once */
#define G0_REG_PK_IN    0x22   /* 0x1B is Emberwill's EM_HDR */
/* v19 (13 Nov 2026, one door one PIN): the passkey master reaches this chip only
 * from the ESP32's passkey-PIN session. The ESP32 READs PK_MASTER_P and DECs it
 * with K_PK (the SE allows both only to the passkey PIN at MODE_PCR == V_3) and
 * writes the 64 bytes here: inner || tag. This chip no longer has any right on
 * K_PK or PK_MASTER_P, so a read of its flash (K_SE, K_G0, S) gives no master. */
#define G0_REG_PKM_IN   0x25
#define PKM_IN_LEN      64
#define PK_IN_LEN       97
#define PK_OP_REGISTER  1
#define PK_OP_SIGN      2
#define PK_ID_VER       0x01
#define PK_ID_KIND      0x01   /* restorable */

#define PK_E_INPUT   0xE1   /* no PK_IN, or a bad op */
#define PK_E_KEYS    0xE2   /* no keys, or no Door-1 boot lock this life */
#define PK_E_MASTER  0xE3   /* S_pk not readable (absent, Door 1 locked, session) */
#define PK_E_TAG     0xE4   /* SIGN: the ID is not ours for this site */
#define PK_E_OPEN    0xE5   /* session to the SE did not open */
#define PK_E_WRITE   0xE6   /* site key write refused */
#define PK_E_SIGN    0xE7   /* SE signature failed */
#define PK_E_JUNK    0xE8   /* junk not confirmed: the site key may still be in the slot. Nothing released; PKSCRUB again */
#define PK_E_DERIVE  0xE9   /* no valid scalar in 256 tries (never happens) */
#define PK_E_SCRATCH 0xEA   /* the object at the scratch id is not deletable by this chip (not ours), or could not be created */
#define PK_E_BUDGET  0xEB   /* v16: this sitting's PKSIGN budget is spent - enter the PIN on the KEY (C+ refill rule) */
#define PK_E_KAT     0xEC   /* v16: the G0's P-256 known-answer test failed this life: nothing is signed */

/* v16 (7 Nov 2026): the site key never leaves this chip. Until v15 the G0
 * derived k and the SE051 signed with it (written into the scratch object),
 * so a backdoored SE051 saw every site key it signed with. Now the G0 signs
 * itself: p256-m (constant time) with RFC 6979 nonces (p256_det.c), after the
 * master is read and the SE session is closed. The scratch object is no
 * longer written by PKSIGN; PKSCRUB still clears what an older version may
 * have left in it. Output format unchanged (DER on BTC_OUT), so the ESP32
 * recovers the public key from the two REGISTER signatures as before.
 * Budget: PK_PER_SITTING signatures per sitting, refilled with the vault's
 * (a PIN entered on the KEY, at most VLT_REFILLS_MAX times per life). */
#include "p256_det.h"
#define PK_PER_SITTING 32
static uint8_t g_pk_sign_left = PK_PER_SITTING;
static int8_t g_pk_kat = 0;   /* 0 not run this life, 1 passed, -1 failed */
/* RFC 6979 A.2.5 (P-256, SHA-256, "sample"), once per life before the first signature. */
static int pk_kat(void) {
    if (g_pk_kat) return g_pk_kat;
    static const uint8_t x[32] = {0xC9,0xAF,0xA9,0xD8,0x45,0xBA,0x75,0x16,0x6B,0x5C,0x21,0x57,0x67,0xB1,0xD6,0x93,
                                  0x4E,0x50,0xC3,0xDB,0x36,0xE8,0x9B,0x12,0x7B,0x8A,0x62,0x2B,0x12,0x0F,0x67,0x21};
    static const uint8_t want[64] = {0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,0x9C,0xD4,0x5E,0x81,0xD6,
                                     0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,0xA8,0x4E,0xAF,0x37,0x16,
                                     0xF7,0xCB,0x1C,0x94,0x2D,0x65,0x7C,0x41,0xD4,0x36,0xC7,0xA1,0xB6,0xE2,0x9F,0x65,
                                     0xF3,0xE9,0x00,0xDB,0xB9,0xAF,0xF4,0x06,0x4D,0xC4,0xAB,0x2F,0x84,0x3A,0xCD,0xA8};
    uint8_t h[32], sig[64];
    sha256((const uint8_t *)"sample", 6, h);
    g_pk_kat = (p256_det_sign_raw(x, h, sig) == 0 && memcmp(sig, want, 64) == 0) ? 1 : -1;
    secure_wipe(sig, 64);
    return g_pk_kat;
}

static uint8_t g_pk_in[PK_IN_LEN]; static volatile uint8_t g_pk_in_valid = 0;
static uint8_t g_pk_scratch_own = 0;   /* this power-on life: the G0 created the scratch object itself */
static uint8_t g_pk_dirty = 0;         /* a site key may be in the scratch object */
static uint8_t g_pk_master_done = 0;   /* PKMASTER already used in this seal window */
static uint8_t g_pkm_in[PKM_IN_LEN]; static volatile uint8_t g_pkm_valid = 0;   /* v19: inner || tag from the passkey session */

/* P-256 group order n, big-endian. */
static const uint8_t PK_P256_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };
/* 1 if 1 <= k < n. Constant time over the 32 bytes. */
static int pk_scalar_ok(const uint8_t k[32]) {
    int lt = 0, gt = 0; uint8_t nz = 0;
    for (int i = 0; i < 32; i++) {
        int a = k[i], b = PK_P256_N[i];
        int undecided = !(lt | gt);
        lt |= undecided & (a < b);
        gt |= undecided & (a > b);
        nz |= k[i];
    }
    return lt && nz != 0;
}

/* The two fixed recovery hashes: SHA-256("FAVILLA-PK-RECOVER-1"/"-2"). Fixed
 * here so a REGISTER is never a signing oracle for the ESP32. */
static void pk_recover_hash(int which, uint8_t h[32]) {
    static const uint8_t lab[] = "FAVILLA-PK-RECOVER-1";
    uint8_t m[sizeof(lab) - 1]; memcpy(m, lab, sizeof(m));
    m[sizeof(m) - 1] = (uint8_t)('0' + which);
    sha256(m, sizeof(m), h);
}

/* tag = HMAC-SHA256(S_pk, "ID" || ver || kind || nonce16 || rpIdHash32)[0:16] */
static void pk_tag(const uint8_t spk[32], const uint8_t nonce[16], const uint8_t rp[32], uint8_t tag[16]) {
    uint8_t m[2 + 2 + 16 + 32], h[32];
    m[0] = 'I'; m[1] = 'D'; m[2] = PK_ID_VER; m[3] = PK_ID_KIND;
    memcpy(m + 4, nonce, 16); memcpy(m + 20, rp, 32);
    hmac_sha256(spk, 32, m, sizeof(m), h);
    memcpy(tag, h, 16);
    secure_wipe(h, 32); secure_wipe(m, sizeof(m));
}

/* k = HMAC-SHA256(S_pk, "KEY" || ctr || nonce16 || rpIdHash32), first ctr with 1 <= k < n. */
static int pk_derive(const uint8_t spk[32], const uint8_t nonce[16], const uint8_t rp[32], uint8_t k[32]) {
    uint8_t m[3 + 1 + 16 + 32];
    m[0] = 'K'; m[1] = 'E'; m[2] = 'Y';
    memcpy(m + 4, nonce, 16); memcpy(m + 20, rp, 32);
    for (int ctr = 0; ctr < 256; ctr++) {
        m[3] = (uint8_t)ctr;
        hmac_sha256(spk, 32, m, sizeof(m), k);
        if (pk_scalar_ok(k)) { secure_wipe(m, sizeof(m)); return 0; }
    }
    secure_wipe(m, sizeof(m)); secure_wipe(k, 32);
    return -1;
}

/* A fresh junk scalar from the pool (never the ESP32's alone). */
static void pk_junk(uint8_t j[32]) {
    static const uint8_t label[] = "favilla-g0-pk-junk";
    do { entropy_mix(label, sizeof(label) - 1); sha256(g_pool, 32, j); } while (!pk_scalar_ok(j));
}

static int pk_ct_eq16(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0; for (int i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static void pk_iv(uint8_t iv[16]) {
    uint8_t h[32];
    static const uint8_t label[] = "favilla-g0-pk-master-iv";
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, label, sizeof(label) - 1);
    sha256_final(&c, h);
    memcpy(iv, h, 16); secure_wipe(h, sizeof(h));
}

/* v19: the tag that binds the master's inner layer to this chip. The ESP32
 * never holds K_G0, so it can neither make a tag nor move one to other bytes. */
static void pk_master_tag(const uint8_t inner[32], uint8_t tag[32]) {
    static const uint8_t label[] = "favilla-g0-pk-master-tag";
    uint8_t m[sizeof(label) - 1 + 32];
    memcpy(m, label, sizeof(label) - 1); memcpy(m + sizeof(label) - 1, inner, 32);
    hmac_sha256(g_kg0, KG0_LEN, m, sizeof m, tag);
    secure_wipe(m, sizeof m);
}

/* PKMASTER: seal S_pk (HASH_IN) under K_G0 with the master IV. Onboarding seal
 * window only (SETKEYS opened it; SEEDSTORE or a door commit closes it), once.
 * v19: SIG_OUT = inner32 || tag32. */
static int do_pkmaster(void) {
    if (!g_hash_in_valid || !g_keys_valid || !g_seal_window || g_pk_master_done) return -1;
    uint8_t iv[16]; pk_iv(iv);
    struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv);
    memcpy(g_sig_out, g_hash_in, 32); AES_CBC_encrypt_buffer(&a, g_sig_out, 32);
    secure_wipe(&a, sizeof(a)); secure_wipe(iv, 16);
    pk_master_tag(g_sig_out, g_sig_out + 32);
    g_pk_master_done = 1;
    return 0;
}

static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]);   /* main.c */
static void door_secret(uint8_t d, uint8_t out[32]);                /* main.c */

/* S_pk inside an OPEN session (v19, 13 Nov 2026, one door one PIN).
 * Until v18 this chip read PK_MASTER_P and decrypted it with K_PK in its own
 * session, which the SE allowed at MODE_PCR == V_3. But V_3 is minted from S,
 * and the "a PIN armed it" check was this chip's firmware only: a read of its
 * flash (K_SE, K_G0, S) gave the master with no PIN. Now the SE layer is
 * stripped by the passkey-PIN session (the ESP32's) and handed here on PKM_IN.
 * Used only:
 *   - in a PASSKEY life (door memory);
 *   - when the tag checks (constant time): the bytes are what PKMASTER made;
 *   - when MODE_PCR reads V_3 in this session: the passkey PIN armed this
 *     window and it is not burned yet, so 64 bytes kept from an earlier window
 *     are useless.
 * Returns 0, or the scp03 rc / -1; *sw = the failing SE status. */
static int pk_fetch_master_in(scp03_session_t *s, uint8_t spk[32], uint16_t *sw) {
    *sw = 0;
    if (!g_door1_locked) return -1;   /* as fetch_scalar_se: no Door-1 boot lock this life */
    if (g_door != DOOR_PASSKEY || !g_pkm_valid) return -1;
    uint8_t t[32], cur[32], v3[32], buf[64];
    pk_master_tag(g_pkm_in, t);
    const int tag_ok = pk_ct_eq16(t, g_pkm_in + 32) & pk_ct_eq16(t + 16, g_pkm_in + 48);
    secure_wipe(t, 32);
    if (!tag_ok) return -1;
    int rc = g0_read_mode_pcr(s, cur);
    *sw = s->last_sw;
    if (rc) { secure_wipe(cur, 32); return rc; }
    {   /* V_3 = SHA256(NEUTRAL || S_3), NEUTRAL = SHA256(zeros), as do_modedoor */
        uint8_t z[32] = {0}, sd[32];
        door_secret(DOOR_PASSKEY, sd);
        sha256(z, 32, buf); memcpy(buf + 32, sd, 32); sha256(buf, 64, v3);
        secure_wipe(sd, 32); secure_wipe(buf, 64);
    }
    const int at_v3 = pk_ct_eq16(cur, v3) & pk_ct_eq16(cur + 16, v3 + 16);
    secure_wipe(cur, 32); secure_wipe(v3, 32);
    if (!at_v3) return -1;
    uint8_t iv[16]; pk_iv(iv);
    struct AES_ctx a; AES_init_ctx_iv(&a, g_kg0, iv);
    memcpy(spk, g_pkm_in, 32); AES_CBC_decrypt_buffer(&a, spk, 32);
    secure_wipe(&a, sizeof(a)); secure_wipe(iv, 16);
    return 0;
}

static int pk_open(scp03_session_t *s) {
    uint8_t hc[8], cc[8] = {0};
    memset(s, 0, sizeof(*s));
    host_challenge(hc);
    int rc = scp03_open(s, relay_xfer, NULL, g_kse, SE_AUTH_OBJ_G0, hc, cc);
    entropy_mix(cc, 8);
    secure_wipe(hc, 8);
    return rc;
}

static void pk_put32(uint8_t *o, uint32_t v) { o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16); o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v; }

/* Claim the scratch object once per power-on life: delete what is there (an
 * absent object is fine; a refusal means it is not ours), then create it with
 * this chip's policy and a junk key. 0 or PK_E_SCRATCH. */
static uint8_t pk_scratch_claim(scp03_session_t *s, uint16_t *sw) {
    if (g_pk_scratch_own) return 0;
    uint8_t d[96]; size_t n = 0;
    d[n++] = 0x41; d[n++] = 4; pk_put32(d + n, SE_OBJ_PK_SCRATCH); n += 4;
    int rc = scp03_cmd(s, 0x04 /*INS_MGMT*/, 0x00, 0x28 /*P2_DELETE_OBJECT*/, d, n, 0, NULL, 0, NULL);
    *sw = s->last_sw;
    if (rc && !(s->last_sw == 0x6A82 || s->last_sw == 0x6985 || s->last_sw == 0x6A88)) return PK_E_SCRATCH;
    /* WriteECKey create: TAG_POLICY, TAG_1 id, TAG_2 curve P-256, TAG_3 junk private key. */
    uint8_t junk[32]; pk_junk(junk);
    n = 0;
    d[n++] = 0x11; d[n++] = 18;
    d[n++] = 8; pk_put32(d + n, SE_AUTH_OBJ_G0); n += 4; pk_put32(d + n, 0x10000000u | 0x00100000u | 0x00040000u); n += 4;   /* SIGN | WRITE | DELETE */
    d[n++] = 8; pk_put32(d + n, SE_AUTH_OBJ_RECOVER); n += 4; pk_put32(d + n, 0x00040000u); n += 4;                       /* DELETE (wipe) */
    d[n++] = 0x41; d[n++] = 4; pk_put32(d + n, SE_OBJ_PK_SCRATCH); n += 4;
    d[n++] = 0x42; d[n++] = 1; d[n++] = 0x03;   /* NIST P-256 */
    d[n++] = 0x43; d[n++] = 32; memcpy(d + n, junk, 32); n += 32;
    rc = scp03_cmd(s, 0x01 /*INS_WRITE*/, 0x41 /*P1_PRIVATE|P1_EC*/, 0x00, d, n, 0, NULL, 0, NULL);
    *sw = s->last_sw;
    secure_wipe(junk, 32); secure_wipe(d, sizeof(d));
    if (rc) return PK_E_SCRATCH;
    g_pk_scratch_own = 1; g_pk_dirty = 0;
    return 0;
}

/* Junk over the scratch object in this session; on failure, in a fresh one
 * (a bad MAC breaks the first). Clears g_pk_dirty only when confirmed. */
static int pk_junk_write(scp03_session_t *s, uint16_t *sw) {
    uint8_t junk[32]; pk_junk(junk);
    int rc = scp03_ec_write_priv(s, SE_OBJ_PK_SCRATCH, junk);
    *sw = s->last_sw;
    if (rc) {
        scp03_close(s);
        scp03_session_t s2;
        if (pk_open(&s2) == 0) {
            rc = scp03_ec_write_priv(&s2, SE_OBJ_PK_SCRATCH, junk);
            *sw = s2.last_sw;
            scp03_close(&s2);
        }
        scp03_wipe(&s2);
    }
    secure_wipe(junk, 32);
    if (rc == 0) g_pk_dirty = 0;
    return rc;
}

static void pk_diag(uint8_t res, uint8_t op, int rc, uint16_t sw, uint8_t nx) {
    g_btc_out[0]='P'; g_btc_out[1]='K'; g_btc_out[2]='S'; g_btc_out[3]='G'; g_btc_out[4]=2;
    g_btc_out[5] = res; g_btc_out[6] = op; g_btc_out[7] = (uint8_t)(int8_t)rc;
    g_btc_out[8] = (uint8_t)(sw >> 8); g_btc_out[9] = (uint8_t)sw; g_btc_out[10] = nx; g_btc_out[11] = g_pk_dirty;
    if (res != 0) memset(g_btc_out + 12, 0, BTC_OUT_LEN - 12);
}

static int do_pksign(void) {
    memset(g_btc_out, 0, BTC_OUT_LEN);
    uint8_t op = g_pk_in_valid ? g_pk_in[0] : 0;
    if (!g_pk_in_valid || (op != PK_OP_REGISTER && op != PK_OP_SIGN)) { pk_diag(PK_E_INPUT, op, 0, 0, 0); return 0; }
    if (!g_keys_valid || !g_door1_locked)                              { pk_diag(PK_E_KEYS, op, 0, 0, 0); return 0; }
    if (!g_pk_sign_left)                                               { pk_diag(PK_E_BUDGET, op, 0, 0, 0); return 0; }   /* v16 */
    if (pk_kat() != 1)                                                 { pk_diag(PK_E_KAT, op, 0, 0, 0); return 0; }      /* v16 */

    uint8_t spk[32], k[32], nonce[16], tag[16], h[32];
    const uint8_t *rp = g_pk_in + 33, *hin = g_pk_in + 65;
    scp03_session_t s; memset(&s, 0, sizeof(s));
    uint8_t res = 0, nx = 0; int rc = 0; uint16_t sw = 0;
    size_t l1 = 0, l2 = 0;

    rc = pk_open(&s);
    if (rc) { res = PK_E_OPEN; sw = s.last_sw; goto out; }
    rc = pk_fetch_master_in(&s, spk, &sw);
    if (rc) { res = PK_E_MASTER; nx = s.nxfer; scp03_close(&s); goto out; }
    if (op == PK_OP_SIGN) {   /* the tag is checked before anything is written */
        memcpy(nonce, g_pk_in + 1, 16);
        pk_tag(spk, nonce, rp, tag);
        if (!pk_ct_eq16(tag, g_pk_in + 17)) { res = PK_E_TAG; rc = 0; sw = 0; nx = s.nxfer; scp03_close(&s); goto out; }
    }
    if (op == PK_OP_REGISTER) {   /* nonce after the session open: the pool now holds the SE's card challenge too */
        static const uint8_t label[] = "favilla-g0-pk-nonce";
        entropy_mix(label, sizeof(label) - 1); sha256(g_pool, 32, h);
        memcpy(nonce, h, 16);
        pk_tag(spk, nonce, rp, tag);
    }
    nx = s.nxfer; sw = s.last_sw;
    scp03_close(&s);   /* v16: the SE is done (the master is read); the slow part runs with no session open */
    if (pk_derive(spk, nonce, rp, k) != 0) { res = PK_E_DERIVE; goto out; }
    secure_wipe(spk, 32);
    g_pk_sign_left--;   /* counted once the request is valid and ours, whether or not the signing below works */
    if (op == PK_OP_REGISTER) {
        pk_recover_hash(1, h);
        uint8_t x[32];   /* v18: hedged nonces (RFC 6979 3.6), fresh for each signature */
        hedge32("favilla-g0-p256-hedge", h, x); l1 = p256_det_sign_der_x(k, h, x, g_btc_out + 45, 72);
        if (l1) { pk_recover_hash(2, h); hedge32("favilla-g0-p256-hedge", h, x); l2 = p256_det_sign_der_x(k, h, x, g_btc_out + 118, 72); }
        secure_wipe(x, 32);
        if (!l1 || !l2) res = PK_E_SIGN;
    } else {
        { uint8_t x[32]; hedge32("favilla-g0-p256-hedge", hin, x); l1 = p256_det_sign_der_x(k, hin, x, g_btc_out + 45, 72); secure_wipe(x, 32); }   /* v18: hedged */
        if (!l1) res = PK_E_SIGN;
    }
    secure_wipe(k, 32);
    if (res == 0) {
        g_btc_out[44] = (uint8_t)l1; g_btc_out[117] = (uint8_t)l2;
        if (op == PK_OP_REGISTER) { memcpy(g_btc_out + 12, nonce, 16); memcpy(g_btc_out + 28, tag, 16); }
    }
out:
    pk_diag(res, op, rc, sw, nx);
    scp03_wipe(&s);
    secure_wipe(spk, 32); secure_wipe(k, 32);
    secure_wipe(nonce, 16); secure_wipe(tag, 16); secure_wipe(h, 32);
    return 0;
}

/* PKSCRUB diag on SIG_OUT: "PKSC", [4]=2, [5]=0 ok / PK_E_KEYS / PK_E_OPEN /
 * PK_E_SCRATCH / PK_E_JUNK, [6] scp03 rc, [7..8] SW, [9] dirty after. */
static int do_pkscrub(void) {
    memset(g_sesdiag, 0, 64);
    g_sesdiag[0]='P'; g_sesdiag[1]='K'; g_sesdiag[2]='S'; g_sesdiag[3]='C'; g_sesdiag[4]=2;
    scp03_session_t s; memset(&s, 0, sizeof(s));
    int rc = 0; uint16_t sw = 0; uint8_t res = 0;
    if (!g_keys_valid) { res = PK_E_KEYS; goto out; }
    rc = pk_open(&s);
    if (rc) { res = PK_E_OPEN; sw = s.last_sw; goto out; }
    res = pk_scratch_claim(&s, &sw);
    if (res == 0) {
        rc = pk_junk_write(&s, &sw);   /* closes s itself on failure */
        if (rc) res = PK_E_JUNK;
    }
    if (s.authed) scp03_close(&s);
out:
    g_sesdiag[5] = res; g_sesdiag[6] = (uint8_t)(int8_t)rc;
    g_sesdiag[7] = (uint8_t)(sw >> 8); g_sesdiag[8] = (uint8_t)sw; g_sesdiag[9] = g_pk_dirty;
    memcpy(g_sig_out, g_sesdiag, 64);
    scp03_wipe(&s);
    return 0;
}

/* ===========================================================================
 * User verification check (31 Oct 2026, Vault spec D3).
 * The SE051 will not verify the daily PIN in a second session while the
 * unlock session is open (silicon, 31 Oct), and the ESP32 must not keep
 * anything that can check a PIN offline (review). So this chip keeps the check:
 *   UVSET   0x25: HASH_IN = PIN (ASCII digits, zero padded to 32). Stores
 *                 ref = HMAC(K_G0, "FAVILLA-UV-v1" || pin32) in RAM, 3 tries.
 *                 Sent by the ESP32 right after the PIN was entered ON THE KEY
 *                 and accepted by the SE.
 *   UVCHECK 0x26: HASH_IN = candidate. Constant-time compare. Right: tries back
 *                 to 3. Wrong: one try gone; at 0 the ref is wiped (UV off
 *                 until the next UVSET, i.e. the next real unlock on the KEY).
 *   UVCLEAR 0x27: wipe the ref (every lock).
 * The ref never leaves this chip and K_G0 never leaves it, so the ESP32 cannot
 * test guesses offline; online it gets 3 per real unlock. RAM only: a power
 * cycle forgets it. Diagnostic on SIG_OUT "UVCK": [4]=1, [5] 0 ok / 0xE1 no
 * ref / 0xE2 wrong / 0xE3 no keys, [6] tries left.
 * ========================================================================= */
#define G0_CMD_UVSET   0x25
#define G0_CMD_UVCHECK 0x26
#define G0_CMD_UVCLEAR 0x27
static uint8_t g_uv_ref[32]; static uint8_t g_uv_set = 0, g_uv_tries = 0;

/* Vault budget, P5 = C+ (2 Nov 2026). 32 OPENs and 32 TAGs per sitting; a PIN
 * entered on the KEY (UVSET at an unlock, or a right UVCHECK) starts a new
 * sitting, at most VLT_REFILLS_MAX times per power-on life, then only a power
 * cycle. The PIN reaches this chip through the ESP32, so the cap, not the PIN,
 * is what bounds an ESP32 that resends a PIN it saw: 160 OPENs per life. The
 * refill count is kept in the life token; the per-sitting counts are RAM (a
 * restored life starts a fresh sitting, but never gets its refills back).
 * A PIN entry with both budgets still full counts nothing (review, M3), so
 * the unlock's own UVSET does not use one of the four. SEAL draws on the TAG
 * budget too (review, M2): its output carries the tag of a site the caller
 * chose, so an unbudgeted SEAL was an unbudgeted TAG. */
#define VLT_PER_SITTING 32
/* v24 (25 Nov 2026): the owner sets the per-sitting number in Settings on the
 * KEY: 8, 16, 32, 64, 128, or 0 = no limit (the default). It is kept in flash
 * (key_store.c, ks_lim_*) and read at power-on (main.c). A stricter one applies
 * at once; a looser one (or none) only from the next power-on, so code running
 * on the ESP32 right now (which a power cycle ends: Secure Boot) cannot raise
 * the cap it is held to. With no limit the OPEN and TAG budgets are not
 * counted; PKSIGN keeps its own. */
static uint8_t g_vlt_limit = 0, g_vlt_limit_next = 0;
static uint8_t g_vlt_open_left = 0, g_vlt_tag_left = 0;
#define VLT_LIM_OK(l) ((l) == 0 || (l) == 8 || (l) == 16 || (l) == 32 || (l) == 64 || (l) == 128)
/* v15 (3 Nov 2026, Vault spec 7f, P4-4): the import window. One per power-on
 * life, opened by VAULT op IMPORT right after a right UVCHECK (a PIN entered on
 * the KEY), NOSTR life only, and only if the master copy is readable (the NOSTR
 * gate allowed). Inside it SEAL and TAG draw on their own 300 instead of the
 * sitting's TAG budget; OPEN is never covered. It ends at the next UVSET (an
 * unlock) or UVCLEAR (a lock), and a second window in the same life is refused.
 * g_imp_used is kept in the life token's second word (BKP1R, v15 review), so a
 * reset that keeps the life cannot give a second window. */
#define VLT_IMP_MAX 450u   /* v23 (KEY 11dr, RK_MAX 400): a full vault plus room for retries; was 300 */
static uint16_t g_imp_seal = 0, g_imp_tag = 0;
static uint8_t g_imp_on = 0, g_imp_armed = 0;   /* g_imp_used: main.c, kept in the life token (BKP1R) */
static void imp_end(void) { g_imp_on = 0; g_imp_seal = 0; g_imp_tag = 0; g_imp_armed = 0; }
static void vlt_refill(void) {
    const uint8_t L = g_vlt_limit;   /* v24: 0 = no vault limit, nothing of it to refill */
    if ((!L || (g_vlt_open_left == L && g_vlt_tag_left == L)) && g_pk_sign_left == PK_PER_SITTING) return;   /* review 2 Nov (M3): nothing spent, nothing to count */
    if (g_vlt_refills >= VLT_REFILLS_MAX) return;
    if (L) { g_vlt_open_left = L; g_vlt_tag_left = L; }
    g_pk_sign_left = PK_PER_SITTING;   /* v16: and the PKSIGN budget */
    g_vlt_refills++; life_save();
}

static void uv_ref_of(const uint8_t pin32[32], uint8_t out[32]) {
    static const uint8_t lab[] = "FAVILLA-UV-v1";
    uint8_t m[sizeof(lab) - 1 + 32];
    memcpy(m, lab, sizeof(lab) - 1); memcpy(m + sizeof(lab) - 1, pin32, 32);
    hmac_sha256(g_kg0, KG0_LEN, m, sizeof(m), out);
    secure_wipe(m, sizeof(m));
}
static void uv_diag(uint8_t res) {
    memset(g_sig_out, 0, 64);
    g_sig_out[0]='U'; g_sig_out[1]='V'; g_sig_out[2]='C'; g_sig_out[3]='K'; g_sig_out[4]=1;
    g_sig_out[5] = res; g_sig_out[6] = g_uv_tries;
}
static void uv_clear(void) { secure_wipe(g_uv_ref, 32); g_uv_set = 0; g_uv_tries = 0; imp_end(); }   /* v15: a lock ends the import window */
static int do_uvset(void) {
    if (!g_keys_valid) { uv_diag(0xE3); return 0; }
    if (!g_hash_in_valid) { uv_diag(0xE1); return 0; }
    uv_ref_of(g_hash_in, g_uv_ref); g_uv_set = 1; g_uv_tries = 3;
    imp_end();      /* v15: an unlock ends any import window (a resume needs a new life) */
    vlt_refill();   /* C+: a PIN entered on the KEY starts a new sitting (capped) */
    uv_diag(0);
    return 0;
}
static int do_uvcheck(void) {
    if (!g_keys_valid) { uv_diag(0xE3); return 0; }
    if (!g_uv_set || !g_hash_in_valid) { uv_diag(0xE1); return 0; }
    uint8_t c[32]; uv_ref_of(g_hash_in, c);
    uint8_t d = 0; for (int i = 0; i < 32; i++) d |= (uint8_t)(c[i] ^ g_uv_ref[i]);
    secure_wipe(c, 32);
    if (d == 0) { g_uv_tries = 3; vlt_refill(); g_imp_armed = 1; uv_diag(0); return 0; }   /* v15: arms one IMPORT, consumed by the next VAULT op */   /* C+: the PIN re-ask counts too */
    if (g_uv_tries) g_uv_tries--;
    if (g_uv_tries == 0) uv_clear();
    uv_diag(0xE2);
    return 0;
}
static int do_uvclear(void) { uv_clear(); uv_diag(0); return 0; }
