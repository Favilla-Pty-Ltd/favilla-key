/* Host test for generic doors (30 Oct 2026, passkey door spec v1.0 s.4).
 * Runs the REAL life_save/life_restore, door_secret, mode_latch_class,
 * g0_read_mode_pcr, do_modedoor/do_modebtc, em_door_permits, do_door,
 * door_permits and door_autocommit source (extracted by run_doors_test.sh)
 * against a fake SE whose MODE_PCR reads, resets and extends like the SE051. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "scp03.h"
#include "se_objects.h"
#define G0_CMD_PROVISION 0x03
#define G0_CMD_ECDH 0x04
#define G0_CMD_PUBKEY 0x05
#define G0_CMD_CACHEKEY 0x06
#define G0_CMD_SETKEYS 0x07
#define G0_CMD_SESSIONTEST 0x09
#define G0_CMD_MODERESET 0x0A
#define G0_CMD_MODEBTC 0x0B
#define G0_CMD_DOORKEYS 0x0E
#define G0_CMD_DOORNOSTR 0x11
#define G0_CMD_DOORBTC 0x12
#define G0_CMD_WIPEALL 0x14
#define G0_CMD_SIGN_INIT 0x1C
#define G0_CMD_AE_FINISH 0x1D
#define G0_CMD_BTCSIGN_INIT 0x1E
#define G0_CMD_MSGSIGN_INIT 0x1F
#define G0_CMD_DOORPASSKEY 0x20
#define G0_CMD_MODEDOOR 0x21
#define G0_CMD_PKSIGN 0x22   /* restorable passkeys, 30 Oct 2026 */
#define G0_CMD_VSIGN_INIT 0x29   /* v14 vault backup signature */
#define G0_CMD_VAULT 0x28    /* vault records, 2 Nov 2026 */
#define G0_CMD_EM_HEADER 0x30
#define G0_CMD_EM_SET 0x31
#define G0_CMD_EM_CER_INIT 0x32
#define G0_CMD_EM_CER_FIN 0x33
#define G0_CMD_EM_COMMIT 0x34
#define G0_CMD_EM_PROOF 0x35
#define G0_CMD_EM_LIFE 0x36
#define G0_CMD_EM_STATUS 0x37
#define G0_CMD_EM_RELEASE 0x38
#define G0_CMD_EM_PULSE 0x39
#define G0_CMD_EM_CLEAR 0x3A
#define G0_CMD_EM_AWAY 0x3B
#define G0_CMD_EM_SAVE 0x3C
#define AE_KIND_NONE 0
#define AE_KIND_SCHNORR 1
#define AE_KIND_BTC 2
static struct { uint8_t kind; } g_ae;
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC 2
#define DOOR_PASSKEY 3
#define KMODE_LEN 32
#define LIFE_MAGIC 0xA5F1u
#define PASS_BUDGET_PER_LIFE 5
uint32_t g_gen_off = 0x300;
typedef struct { uint32_t BKP0R, BKP1R; } tamp_t; static tamp_t tamp; static tamp_t *TAMP = &tamp;
static uint32_t HAL_GetTick(void) { return 1234; }
static uint32_t g_boot_rcc_csr = 0;
static int g_keys_valid = 1, g_seal_window = 0;
static uint8_t g_door = DOOR_UNSET, g_sesdiag[64], g_sig_out[64], g_kmode[32], g_kse[16];
static uint8_t g_mode_reset_arm = 1, g_mode_btc_arm = 1, g_mode_pk_arm = 1, g_pass_budget = 5;
#define VLT_REFILLS_MAX 4u
static uint8_t g_vlt_refills = 0;   /* 2 Nov 2026: vault budget refills in the life token, bits [15:13] */
#define LIFE2_MAGIC 0xA5F2u
#define VLT_LABEL_PER_LIFE 800u
static uint16_t g_lbl_used = 0; static uint8_t g_imp_used = 0, g_wiped_life = 0;   /* v15: BKP1R; v22: wiped bit */
static void secure_wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void host_challenge(uint8_t hc[8]) { memset(hc, 0x11, 8); }
static void entropy_mix(const uint8_t *p, size_t n) { (void)p; (void)n; }
static int relay_xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) { (void)c;(void)a;(void)al;(void)r;(void)rc;(void)rl; return -1; }

/* ── fake SE: MODE_PCR only ── */
static uint8_t PCR[32], NEUTRAL[32];
static int n_writes;
int scp03_open(scp03_session_t *s, scp03_xfer_fn x, void *xc, const uint8_t k[16], uint32_t auth, const uint8_t h[8], uint8_t cc[8]) {
    (void)x;(void)xc;(void)k;(void)h;(void)auth; memset(s, 0, sizeof(*s)); if (cc) memset(cc, 0x22, 8); s->stage = 4; s->authed = 1; return 0; }
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *d, size_t dl, int hasle, uint8_t *o, size_t oc, size_t *ol) {
    (void)p2;(void)hasle; s->nxfer++;
    uint32_t oid = dl >= 6 ? ((uint32_t)d[2] << 24 | (uint32_t)d[3] << 16 | (uint32_t)d[4] << 8 | d[5]) : 0;
    if (oid != SE_OBJ_PCR_MODE) { s->last_sw = 0x6A82; return -1; }
    if (ins == 0x02) { if (oc < 34) return -1; o[0] = 0x41; o[1] = 32; memcpy(o + 2, PCR, 32); *ol = 34; s->last_sw = 0x9000; return 0; }
    if (ins == 0x01 && p1 == 0x09) {
        n_writes++;
        if (dl == 6) { memcpy(PCR, NEUTRAL, 32); s->last_sw = 0x9000; return 0; }          /* reset */
        if (dl == 8 + 32 && d[6] == 0x43 && d[7] == 32) {                                    /* extend */
            uint8_t b[64]; memcpy(b, PCR, 32); memcpy(b + 32, d + 8, 32); sha256(b, 64, PCR); s->last_sw = 0x9000; return 0; }
    }
    s->last_sw = 0x6985; return -1; }
int scp03_close(scp03_session_t *s) { memset(s, 0, sizeof(*s)); return 0; }
void scp03_wipe(scp03_session_t *s) { memset(s, 0, sizeof(*s)); }

#include "extracted_doors.inc"

static int fails = 0;
static void check(int c, const char *m) { printf("%s  %s\n", c ? "PASS" : "FAIL", m); if (!c) fails++; }
static void ext(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) { uint8_t t[64]; memcpy(t, a, 32); memcpy(t + 32, b, 32); sha256(t, 64, out); }
static void hex(const char *l, const uint8_t *p) { printf("      %s ", l); for (int i = 0; i < 32; i++) printf("%02x", p[i]); printf("\n"); }

int main(void) {
    uint8_t z[32] = {0}; sha256(z, 32, NEUTRAL);
    for (int i = 0; i < 32; i++) g_kmode[i] = (uint8_t)(0xA0 + i);
    uint8_t v2[32], v3[32], s3[32], spent3[32], spent2[32], t[32];

    /* KATs */
    door_secret(DOOR_BTC, t); check(!memcmp(t, g_kmode, 32), "KAT: S_2 is S itself");
    ext(NEUTRAL, g_kmode, v2);
    { uint8_t b[45]; memcpy(b, g_kmode, 32); memcpy(b + 32, "FAVILLA-DOOR", 12); b[44] = 3; sha256(b, 45, s3); }
    door_secret(DOOR_PASSKEY, t); check(!memcmp(t, s3, 32), "KAT: S_3 = SHA256(S || \"FAVILLA-DOOR\" || 0x03)");
    hex("S_3", t);
    ext(NEUTRAL, s3, v3); ext(v3, MODE_CONST_SPENT, spent3); ext(v2, MODE_CONST_SPENT, spent2);
    hex("V_3", v3);
    check(memcmp(v3, v2, 32) != 0, "KAT: V_3 differs from V_2 (BTC)");

    /* door_permits table */
    struct { uint8_t c; int want[4]; const char *n; } T[] = {
        { G0_CMD_SIGN_INIT,   {1,1,0,0}, "SIGN_INIT"   }, { G0_CMD_ECDH,        {1,1,0,0}, "ECDH" },
        { G0_CMD_PUBKEY,      {1,1,0,0}, "PUBKEY"      }, { G0_CMD_CACHEKEY,    {1,1,0,0}, "CACHEKEY" },
        { G0_CMD_PROVISION,   {1,1,0,0}, "PROVISION"   }, { G0_CMD_SESSIONTEST, {1,1,0,0}, "SESSIONTEST" },
        { G0_CMD_MODEBTC,     {0,0,1,0}, "MODEBTC"     }, { G0_CMD_DOORKEYS,    {0,0,1,0}, "DOORKEYS" },
        { G0_CMD_BTCSIGN_INIT,{0,0,1,0}, "BTCSIGN_INIT"}, { G0_CMD_MSGSIGN_INIT,{0,0,1,0}, "MSGSIGN_INIT" },
        { G0_CMD_MODEDOOR,    {0,0,1,1}, "MODEDOOR"    },
        { G0_CMD_EM_SET,      {0,0,1,0}, "EM_SET"      }, { G0_CMD_EM_COMMIT,   {0,0,1,0}, "EM_COMMIT" },
        { G0_CMD_EM_RELEASE,  {1,1,0,0}, "EM_RELEASE"  }, { G0_CMD_EM_PULSE,    {1,1,0,0}, "EM_PULSE" },
        { G0_CMD_EM_AWAY,     {1,1,0,0}, "EM_AWAY"     }, { G0_CMD_EM_STATUS,   {1,1,1,1}, "EM_STATUS" },
        { G0_CMD_MODERESET,   {1,1,1,1}, "MODERESET"   }, { G0_CMD_WIPEALL,     {1,1,1,1}, "WIPEALL" },
        { G0_CMD_DOORPASSKEY, {1,1,1,1}, "DOORPASSKEY (first-wins is in do_door)" },
        { G0_CMD_PKSIGN,      {0,0,0,1}, "PKSIGN (v19: PASSKEY only)" }, { G0_CMD_VSIGN_INIT, {1,1,0,0}, "VSIGN_INIT (v14: NOSTR only, never PASSKEY)" }, { G0_CMD_VAULT, {0,0,0,1}, "VAULT (v19: PASSKEY only)" },
    };
    int tbl = 1;
    for (unsigned i = 0; i < sizeof T / sizeof T[0]; i++)
        for (int d = 0; d < 4; d++) { g_door = d; if (door_permits(T[i].c) != T[i].want[d]) { printf("      %s in door %d: got %d\n", T[i].n, d, door_permits(T[i].c)); tbl = 0; } }
    check(tbl, "door_permits: every listed command x every door (UNSET, NOSTR, BTC, PASSKEY) as the table says");
    g_door = DOOR_PASSKEY; g_ae.kind = AE_KIND_SCHNORR; check(door_permits(G0_CMD_AE_FINISH) == 0, "AE_FINISH of a Schnorr INIT refused in a PASSKEY life");
    g_door = DOOR_NOSTR;  check(door_permits(G0_CMD_AE_FINISH) == 1, "... and still allowed in a NOSTR life");
    g_ae.kind = AE_KIND_NONE;

    /* do_door first-wins */
    g_door = DOOR_UNSET; tamp.BKP0R = 0;
    do_door(DOOR_PASSKEY); check(g_door == DOOR_PASSKEY && g_sig_out[5] == 0, "DOORPASSKEY in an unset life commits PASSKEY");
    do_door(DOOR_PASSKEY); check(g_sig_out[5] == 1, "DOORPASSKEY again: accepted as the same door");
    do_door(DOOR_NOSTR);   check(g_door == DOOR_PASSKEY && g_sig_out[5] == 0xEE, "DOORNOSTR after it: refused, door stays PASSKEY");
    do_door(DOOR_BTC);     check(g_door == DOOR_PASSKEY && g_sig_out[5] == 0xEE, "DOORBTC after it: refused");
    door_autocommit(G0_CMD_SIGN_INIT); check(g_door == DOOR_PASSKEY, "a Nostr command does not move a PASSKEY life");

    /* life token round trip */
    g_mode_pk_arm = 0; life_save(); g_door = 0; g_mode_pk_arm = 1; g_mode_btc_arm = 0;
    check(life_restore() && g_door == DOOR_PASSKEY && g_mode_pk_arm == 0 && g_mode_btc_arm == 1, "life token: door 3 and the spent PASSKEY arm (bit 12) survive a non-power reset");
    g_mode_pk_arm = 1; life_save(); life_restore(); check(g_mode_pk_arm == 1 && (tamp.BKP0R & (1u << 12)) == 0, "life token: an unspent PASSKEY arm round-trips as unspent");
    { uint8_t pb = g_pass_budget, d0 = g_door;
      g_vlt_refills = 3; life_save(); g_vlt_refills = 0; life_restore();
      check(g_vlt_refills == 3 && ((tamp.BKP0R >> 13) & 7u) == 3 && g_pass_budget == pb && g_door == d0, "life token: vault refills (bits 15:13) round-trip without touching the door or the passphrase budget");
      tamp.BKP0R = (tamp.BKP0R & ~(7u << 13)) | (7u << 13); life_restore();
      check(g_vlt_refills == VLT_REFILLS_MAX, "life token: an out-of-range refill count reads as the cap (no free refills)");
      g_vlt_refills = 0; life_save(); }
    { uint32_t w0;   /* v15: the second word (BKP1R) */
      g_lbl_used = 321; g_imp_used = 1; life_save(); w0 = tamp.BKP0R; g_lbl_used = 0; g_imp_used = 0; life_restore();
      check(g_lbl_used == 322 && g_imp_used == 1 && tamp.BKP0R == w0 && (tamp.BKP1R >> 16) == LIFE2_MAGIC, "life token word 2: LABELs used (v23: in pairs, 321 comes back as 322, never fewer) and the import window round-trip, word 1 unchanged");
      g_lbl_used = 799; life_save(); g_lbl_used = 0; life_restore();
      check(g_lbl_used == 800, "v23: 799 LABELs used comes back as the cap (800), never under it");
      g_lbl_used = 0; life_save(); life_restore();
      check(g_lbl_used == 0, "v23: none used stays none");
      tamp.BKP1R = 0; g_lbl_used = 0; g_imp_used = 0; life_restore();
      check(g_lbl_used == VLT_LABEL_PER_LIFE && g_imp_used == 1, "word 1 valid, word 2 missing (a token from before v15): fails closed, no LABELs, no window");
      tamp.BKP1R = (LIFE2_MAGIC << 16) | 0x1FFu; life_restore();
      check(g_lbl_used == VLT_LABEL_PER_LIFE, "an out-of-range LABEL count reads as the cap");
      g_lbl_used = 0; g_imp_used = 0; life_save(); }

    /* MODEDOOR in a PASSKEY life */
    g_door = DOOR_PASSKEY; g_mode_pk_arm = 1; g_mode_btc_arm = 1;
    memcpy(PCR, NEUTRAL, 32);
    do_modedoor(g_door); check(g_sig_out[5] == 0xEC && !memcmp(PCR, NEUTRAL, 32), "bare NEUTRAL (no PIN session armed it): refused 0xEC, latch untouched");
    ext(NEUTRAL, MODE_CONST_ARM, PCR);
    do_modedoor(g_door);
    check(g_sig_out[5] == 0 && !memcmp(PCR, v3, 32), "ARM_N -> latch reads V_3");
    check(!memcmp(g_sig_out, "MDOR", 4) && g_sig_out[21] == 3 && g_sig_out[20] == 1 && g_mode_pk_arm == 0, "diag MDOR, door 3, class ARM_N, PASSKEY one-shot spent");
    check(g_mode_btc_arm == 1, "the BTC one-shot is untouched by a PASSKEY mint");
    check(mode_latch_class(PCR) == 6, "mode_latch_class(V_3) = 6 (PASSKEY open)");
    ext(v3, MODE_CONST_SPENT, PCR);                    /* the ESP32 burns after the signature */
    check(!memcmp(PCR, spent3, 32) && mode_latch_class(PCR) == 7, "burn -> SPENT_3, class 7");
    do_modedoor(g_door); check(g_sig_out[5] == 0xEC, "bare SPENT_3 (no PIN since the burn): refused 0xEC");
    ext(spent3, MODE_CONST_ARM, PCR); check(mode_latch_class(PCR) == 5, "ARM_S3 classifies as ARMed");
    do_modedoor(g_door); check(g_sig_out[5] == 0 && !memcmp(PCR, v3, 32) && g_sig_out[20] == 2, "ARM_S3 -> V_3 again (no limit after a burn)");
    ext(v3, MODE_CONST_ARM, PCR);
    do_modedoor(g_door); check(g_sig_out[5] == 0 && !memcmp(PCR, v3, 32), "ARM_V3 (leftover) -> reset and V_3 again, never accepted as found");
    memcpy(PCR, NEUTRAL, 32); ext(NEUTRAL, MODE_CONST_ARM, PCR);
    do_modedoor(g_door); check(g_sig_out[5] == 0xEE && g_sig_out[20] == 1, "second ARM_N in the same physical boot: refused 0xEE");
    { uint8_t nostr[32]; ext(NEUTRAL, MODE_CONST_NOSTR, nostr); ext(nostr, MODE_CONST_ARM, PCR); }
    do_modedoor(g_door); check(g_sig_out[5] == 0xEA, "armed NOSTR latch: refused 0xEA");
    ext(spent2, MODE_CONST_ARM, PCR);
    do_modedoor(g_door); check(g_sig_out[5] == 0xEA, "armed SPENT_2 (a BTC life's burn) in a PASSKEY life: refused 0xEA");

    /* BTC path unchanged */
    g_door = DOOR_BTC; g_mode_btc_arm = 1; ext(NEUTRAL, MODE_CONST_ARM, PCR);
    do_modebtc();
    check(g_sig_out[5] == 0 && !memcmp(PCR, v2, 32) && !memcmp(g_sig_out, "MBTC", 4) && g_sig_out[21] == 0, "MODEBTC: ARM_N -> V_2 = SHA256(NEUTRAL || S), diag MBTC as before");
    ext(v2, MODE_CONST_ARM, PCR); do_modedoor(g_door);
    check(g_sig_out[5] == 0 && !memcmp(PCR, v2, 32) && !memcmp(g_sig_out, "MBTC", 4), "MODEDOOR in a BTC life = MODEBTC (alias)");
    ext(v3, MODE_CONST_ARM, PCR); do_modedoor(g_door); check(g_sig_out[5] == 0xEA, "armed V_3 in a BTC life: refused 0xEA");

    /* doors without a latch */
    g_door = DOOR_NOSTR; do_modedoor(g_door); check(g_sig_out[5] == 0xED, "do_modedoor for NOSTR: refused 0xED (dispatch never reaches it: door_permits)");
    g_door = DOOR_UNSET; do_modedoor(g_door); check(g_sig_out[5] == 0xED, "do_modedoor for UNSET: refused 0xED");

    printf(fails ? "\n%d generic-door check(s) FAILED\n" : "\nall generic-door G0 checks passed\n", fails);
    return fails != 0;
}
