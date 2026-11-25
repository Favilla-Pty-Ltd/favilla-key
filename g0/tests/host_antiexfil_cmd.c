/* 27 Oct 2026: the anti-exfil COMMAND layer of src/main.c (extracted verbatim:
 * g_ae, do_sign_init, do_ae_finish, do_btcsign_init, do_msgsign_init,
 * door_permits) driven the way the ESP32 drives it, with real libsecp256k1
 * and the real btc.c, against a host stand-in for the ESP32's verify.
 *
 *  A. honest Nostr flow: SIGN_INIT -> R0, AE_FINISH -> sig; host relation and
 *     BIP-340 verify pass; the pending state is gone afterwards
 *  B. honest Bitcoin flow (P2WPKH and P2WSH): BTCSIGN_INIT -> pub33, R0,
 *     sighash (== the untweaked reference's sighash); AE_FINISH -> DER; host
 *     relation on r passes; ECDSA verify passes; latch burned exactly once
 *  C. honest BIP-137 flow: MSGSIGN_INIT / AE_FINISH; recovery gives the key
 *  D. pending-state rules: FINISH with nothing pending -> refused; INIT while
 *     pending -> refused and the pending one still finishes; wrong t ->
 *     refused and cleared (next INIT works); no t -> refused and cleared;
 *     timeout (10 s on the tick) -> refused, next INIT works; RESET
 *     (wipe_transient) clears; a Bitcoin INIT with a non-zero message half
 *     is refused before any fetch; cross-kind: SIGN_INIT pending then a
 *     Bitcoin INIT is refused (one at a time) and the Nostr FINISH still works
 *  E. door gate: AE_FINISH is admitted only under the door that admitted its
 *     INIT
 *  F. -DBENCH_LEAKY_NONCE: a G0 that puts key bits in the FINAL nonce (ignores
 *     t) is caught by the host relation on every signature, while the
 *     signatures themselves still verify (so a host that skips the check
 *     accepts them). This is acceptance test 4 on the host. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
#include "antiexfil.h"
#include "btc.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}

/* ---- the slice of main.c's world these handlers touch ------------------- */
#include "extracted_ae_defs.inc"      /* G0_CMD_*, G0_REG_*, AE_*, *_VER, BTC_OUT_LEN, KG0_LEN */
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC   2
#define DOOR_PASSKEY 3       /* 30 Oct 2026: generic doors */
#define G0_CMD_MODEDOOR 0x21
#define G0_CMD_PKSIGN 0x22   /* restorable passkeys, 30 Oct 2026 */
#define G0_CMD_VAULT 0x28    /* vault records, 2 Nov 2026 */
static uint8_t g_door = DOOR_UNSET;
static secp256k1_context *g_ctx; static uint8_t g_ctxbuf[512] __attribute__((aligned(16)));
static void secure_wipe(void *p, size_t n){ volatile uint8_t *v = p; while(n--) *v++ = 0; }
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint32_t g_tick = 1000;
static uint32_t HAL_GetTick(void) { return g_tick; }
static uint8_t g_kg0[KG0_LEN], g_pool[32];
static void entropy_mix(const uint8_t *d, size_t n){ sha256_ctx c; sha256_init(&c); sha256_update(&c, g_pool, 32); if(d&&n) sha256_update(&c, d, n); g_tick++; sha256_update(&c,(const uint8_t*)&g_tick,4); sha256_final(&c, g_pool); }
#include "hedge.inc"   /* v18: the firmware's own hedge32 */
static void ctx_reblind(void){ unsigned char sd[32]; memset(sd, 7, 32); (void)secp256k1_context_randomize(g_ctx, sd); }
static uint8_t g_sig_out[64], g_btc_out[BTC_OUT_LEN];
static uint8_t g_btc_in[BTC_REQ_LEN]; static uint8_t g_btc_in_valid = 0;
static const uint8_t SK[32] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x12};
static int fetches = 0;
static int fetch_scalar(uint8_t s[32]){ fetches++; memcpy(s, SK, 32); return 0; }
static uint8_t SEED[64]; static int burns = 0;
static uint8_t get_seed(uint8_t seed[64], int *step, uint8_t d[8]) { (void)step; (void)d; burns++; memcpy(seed, SEED, 64); return 0; }
#include "extracted_ae_state.inc"     /* g_ae_in, g_ae_t, g_ae, ae_wipe, ae_expired */
#include "extracted_ae_sign.inc"      /* true_pubkey_fill, do_sign_init, do_ae_finish */
#include "extracted_ae_btc.inc"       /* ae_in_msg_is_zero, do_btcsign_init, do_msgsign_init */
/* 28 Oct 2026: door_permits now asks the Emberwill table first (ember_glue.inc); not exercised here */
static int em_door_permits(uint8_t c) { (void)c; return -1; }
#include "extracted_ae_door.inc"      /* door_permits */

/* ---- the ESP32 side, as g0_signer.cpp will do it ------------------------- */
static int fails = 0, total = 0;
static void check(const char *n, int ok){ total++; if(!ok){ fails++; printf("FAIL %s\n", n);} }
/* checks that only hold for an HONEST G0: skipped (not counted) in the leaky bench build */
#ifdef BENCH_LEAKY_NONCE
static void checkh(const char *n, int ok){ (void)n; (void)ok; }
#else
#define checkh check
#endif
static void host_t(uint8_t t[32], uint8_t seed){ for(int i=0;i<32;i++) t[i]=(uint8_t)(seed*13+i*5+1); }
static void write_ae_in(const uint8_t msg[32], const uint8_t h[32]){ if(msg) memcpy(g_ae_in, msg, 32); else memset(g_ae_in,0,32); memcpy(g_ae_in+32,h,32); g_ae_in_valid=1; }
static void write_ae_t(const uint8_t t[32]){ memcpy(g_ae_t,t,32); g_ae_t_valid=1; }
/* what finish() does to the single-use inputs */
static void esp_finish(void){ secure_wipe(g_ae_in,64); g_ae_in_valid=0; secure_wipe(g_ae_t,32); g_ae_t_valid=0; g_btc_in_valid=0; }
static void wipe_transient(void){ esp_finish(); ae_wipe(); }

static int nostr_sign(const uint8_t msg[32], uint8_t t_seed, uint8_t sig[64], uint8_t r0[33], int *rc_init, int *rc_fin) {
    uint8_t t[32], h[32]; host_t(t, t_seed); ae_host_commit(AE_KIND_SCHNORR, t, h);
    write_ae_in(msg, h); memset(g_sig_out,0,64);
    *rc_init = do_sign_init(); esp_finish();
    memcpy(r0, g_sig_out, 33);
    if (*rc_init) return -1;
    write_ae_t(t); memset(g_sig_out,0,64);
    *rc_fin = do_ae_finish(); esp_finish();
    memcpy(sig, g_sig_out, 64);
    if (*rc_fin) return -2;
    return ae_host_check(g_ctx, AE_KIND_SCHNORR, r0, t, sig) ? 0 : -3;   /* -3 = ANTI-EXFIL FAULT */
}

int main(void) {
    g_ctx = secp256k1_context_preallocated_create(g_ctxbuf, SECP256K1_CONTEXT_NONE);
    memset(g_kg0, 0x5a, 32); memset(g_pool, 0x33, 32); for (int i=0;i<64;i++) SEED[i]=(uint8_t)(i*3+1);
    secp256k1_xonly_pubkey PK; { secp256k1_keypair kp; secp256k1_keypair_create(g_ctx,&kp,SK); secp256k1_keypair_xonly_pub(g_ctx,&PK,NULL,&kp); }
    uint8_t msg[32], sig[64], r0[33]; int ri, rf;
    for (int i=0;i<32;i++) msg[i]=(uint8_t)(i*17+9);

    /* ── A ──────────────────────────────────────────────────────────────── */
    g_door = DOOR_NOSTR;
    check("A: first sign of the life refused (no PUBKEY yet)", nostr_sign(msg, 1, sig, r0, &ri, &rf) == -1 && ri == -1 && fetches == 1);
    check("A: true pubkey cached by that refusal", g_true_pk_ok == 1);
    check("A: nothing pending after the refusal", g_ae.kind == AE_KIND_NONE);
    int r = nostr_sign(msg, 2, sig, r0, &ri, &rf);
    checkh("A: INIT ok, FINISH ok, host relation ok", r == 0);
    check("A: BIP-340 verify", secp256k1_schnorrsig_verify(g_ctx, sig, msg, 32, &PK));
    check("A: R0 is a compressed point", r0[0] == 2 || r0[0] == 3);
    check("A: pending cleared after FINISH", g_ae.kind == AE_KIND_NONE && g_ae.k0[0]==0 && g_ae.key[5]==0);
    check("A: one SE fetch per signature", fetches == 2);
    { uint8_t sig2[64], r02[33]; checkh("A: same message, different nonce (fresh aux)", nostr_sign(msg, 2, sig2, r02, &ri, &rf) == 0 && memcmp(sig2, sig, 64) != 0 && memcmp(r02, r0, 33) != 0); }

    /* ── D: pending-state rules ────────────────────────────────────────── */
    { uint8_t t[32], h[32]; host_t(t, 9); ae_host_commit(AE_KIND_SCHNORR, t, h);
      write_ae_t(t); check("D: FINISH with nothing pending refused", do_ae_finish() == -1); esp_finish();
      write_ae_in(msg, h); check("D: INIT ok", do_sign_init() == 0); esp_finish(); memcpy(r0, g_sig_out, 33);
      check("D: pending", g_ae.kind == AE_KIND_SCHNORR);
      write_ae_in(msg, h); int f0 = fetches; check("D: second INIT refused, no fetch", do_sign_init() == -1 && fetches == f0); esp_finish();
      check("D: pending kept", g_ae.kind == AE_KIND_SCHNORR && !memcmp(g_ae.r0, r0, 33));
      /* cross-kind INIT while a Nostr op is pending (door would refuse it in main(); here the handler's own check) */
      g_door = DOOR_BTC; memset(g_btc_in, 0, BTC_REQ_LEN); g_btc_in[0]=1; g_btc_in[1]=1; g_btc_in_valid=1; write_ae_in(NULL, h); do_btcsign_init(); esp_finish();
      check("D: Bitcoin INIT while Nostr pending refused 0xD6, no burn", g_btc_out[5] == 0xD6 && burns == 0 && g_ae.kind == AE_KIND_SCHNORR);
      g_door = DOOR_NOSTR;
      write_ae_t(t); check("D: the first INIT's FINISH still succeeds", do_ae_finish() == 0); esp_finish(); memcpy(sig, g_sig_out, 64);
      checkh("D: and passes the relation", ae_host_check(g_ctx, AE_KIND_SCHNORR, r0, t, sig));
      /* wrong t */
      write_ae_in(msg, h); check("D: INIT", do_sign_init() == 0); esp_finish();
      { uint8_t tw[32]; memcpy(tw, t, 32); tw[3]^=1; write_ae_t(tw); }
      check("D: wrong t refused", do_ae_finish() == -1); esp_finish();
      check("D: wrong t cleared the pending op", g_ae.kind == AE_KIND_NONE);
      check("D: next INIT works", (write_ae_in(msg, h), do_sign_init()) == 0); esp_finish();
      /* no t */
      check("D: FINISH with no t refused", do_ae_finish() == -1); esp_finish();
      check("D: no t cleared the pending op", g_ae.kind == AE_KIND_NONE);
      /* timeout */
      write_ae_in(msg, h); check("D: INIT", do_sign_init() == 0); esp_finish();
      g_tick += 9000; check("D: 9 s: still pending", !ae_expired());
      g_tick += 1500; check("D: 10.5 s: expired", ae_expired()); if (ae_expired()) ae_wipe();   /* main() does this on the tick */
      write_ae_t(t); check("D: FINISH after timeout refused", do_ae_finish() == -1); esp_finish();
      check("D: next INIT works after timeout", (write_ae_in(msg, h), do_sign_init()) == 0); esp_finish();
      /* RESET */
      wipe_transient(); check("D: RESET clears pending", g_ae.kind == AE_KIND_NONE);
      write_ae_t(t); check("D: FINISH after RESET refused", do_ae_finish() == -1); esp_finish();
    }

    /* ── E: door gate ───────────────────────────────────────────────────── */
    { uint8_t t[32], h[32]; host_t(t, 11); ae_host_commit(AE_KIND_SCHNORR, t, h);
      g_door = DOOR_NOSTR; write_ae_in(msg, h); check("E: INIT under NOSTR", do_sign_init() == 0); esp_finish();
      check("E: FINISH permitted under NOSTR", door_permits(G0_CMD_AE_FINISH));
      g_door = DOOR_BTC;   check("E: FINISH of a Nostr op refused under BTC", !door_permits(G0_CMD_AE_FINISH));
      check("E: SIGN_INIT refused under BTC", !door_permits(G0_CMD_SIGN_INIT));
      check("E: BTCSIGN_INIT refused under NOSTR", (g_door = DOOR_NOSTR, !door_permits(G0_CMD_BTCSIGN_INIT)));
      wipe_transient(); }

    /* ── B: Bitcoin ─────────────────────────────────────────────────────── */
    g_door = DOOR_BTC; burns = 0;
    for (int kind = 1; kind <= 2; kind++) {
        uint8_t req[BTC_REQ_LEN]; memset(req, 0, sizeof(req));
        req[0] = (uint8_t)kind; req[1] = 1;
        if (kind == 2) { req[2] = 71; for (int i = 0; i < 71; i++) req[164+i] = (uint8_t)(0x50 + i); }
        req[4] = 2; for (int i = 12; i < 108; i++) req[i] = (uint8_t)(i*7); for (int i=108;i<144;i++) req[i]=(uint8_t)(i+1); req[148] = 0x10; req[149] = 0x27; req[160] = 5;
        /* reference (untweaked) for pubkey + sighash */
        uint8_t rpub[33], rder[72], rdl, rsh[32]; check("B: reference signs", btc_sign_request(g_ctx, SEED, req, rpub, rder, &rdl, rsh) == 0);
        uint8_t t[32], h[32]; host_t(t, (uint8_t)(20+kind)); ae_host_commit(AE_KIND_ECDSA, t, h);
        memcpy(g_btc_in, req, BTC_REQ_LEN); g_btc_in_valid = 1; write_ae_in(NULL, h);
        check("B: BTCSIGN_INIT rc 0", do_btcsign_init() == 0 && g_btc_out[5] == 0); esp_finish();
        check("B: BSIG v3 header + kind", !memcmp(g_btc_out, "BSIG", 4) && g_btc_out[4] == 3 && g_btc_out[6] == kind);
        check("B: pub33 and sighash match the reference", !memcmp(g_btc_out + 8, rpub, 33) && !memcmp(g_btc_out + 113, rsh, 32));
        uint8_t R0[33]; memcpy(R0, g_btc_out + 41, 33); check("B: R0 is a point", R0[0] == 2 || R0[0] == 3);
        check("B: pending ECDSA, latch burned once", g_ae.kind == AE_KIND_ECDSA && burns == kind);
        write_ae_t(t); check("B: AE_FINISH rc 0", do_ae_finish() == 0 && g_btc_out[5] == 0); esp_finish();
        check("B: no second burn at FINISH", burns == kind);
        uint8_t dl = g_btc_out[7]; secp256k1_ecdsa_signature sg; uint8_t c64[64];
        check("B: DER parses", dl >= 68 && dl <= 72 && secp256k1_ecdsa_signature_parse_der(g_ctx, &sg, g_btc_out + 41, dl));
        secp256k1_ecdsa_signature_serialize_compact(g_ctx, c64, &sg);
        checkh("B: host relation on r", ae_host_check(g_ctx, AE_KIND_ECDSA, R0, t, c64));
        { secp256k1_pubkey P; secp256k1_ec_pubkey_parse(g_ctx, &P, rpub, 33); check("B: ECDSA verify", secp256k1_ecdsa_verify(g_ctx, &sg, rsh, &P)); }
        check("B: pub33 / sighash / R0 echoed at FINISH", !memcmp(g_btc_out+8, rpub, 33) && !memcmp(g_btc_out+113, rsh, 32) && !memcmp(g_btc_out+152, R0, 33));
        check("B: differs from the untweaked reference", dl != rdl || memcmp(g_btc_out + 41, rder, dl) != 0);
        check("B: pending cleared", g_ae.kind == AE_KIND_NONE);
        /* v18: hedged. The same request and the same host commitment again: a different R0
         * (the ESP32 repeating everything cannot repeat the nonce), and it still signs. */
        { const int bb = burns; memcpy(g_btc_in, req, BTC_REQ_LEN); g_btc_in_valid = 1; write_ae_in(NULL, h);
          check("B v18: same request again: INIT rc 0", do_btcsign_init() == 0 && g_btc_out[5] == 0); esp_finish();
          uint8_t R1[33]; memcpy(R1, g_btc_out + 41, 33);
          check("B v18: hedged: a different R0 for the identical request and commitment", memcmp(R0, R1, 33) != 0);
          write_ae_t(t); check("B v18: and it finishes", do_ae_finish() == 0 && g_btc_out[5] == 0); esp_finish();
          uint8_t dl2 = g_btc_out[7]; secp256k1_ecdsa_signature sg2; uint8_t c2[64];
          check("B v18: DER parses", dl2 >= 68 && dl2 <= 72 && secp256k1_ecdsa_signature_parse_der(g_ctx, &sg2, g_btc_out + 41, dl2));
          secp256k1_ecdsa_signature_serialize_compact(g_ctx, c2, &sg2);
          checkh("B v18: host relation on r", ae_host_check(g_ctx, AE_KIND_ECDSA, R1, t, c2));
          secp256k1_pubkey P; secp256k1_ec_pubkey_parse(g_ctx, &P, rpub, 33); check("B v18: ECDSA verify", secp256k1_ecdsa_verify(g_ctx, &sg2, rsh, &P));
          check("B v18: the repeat burned its own latch, once", burns == bb + 1); burns = bb; }
        /* non-zero message half: refused before any fetch */
        int b0 = burns; memcpy(g_btc_in, req, BTC_REQ_LEN); g_btc_in_valid = 1; write_ae_in(msg, h);
        do_btcsign_init(); esp_finish(); check("B: non-zero msg half refused 0xD1, no burn", g_btc_out[5] == 0xD1 && burns == b0);
        /* FINISH with no INIT on the Bitcoin side */
        write_ae_t(t); check("B: FINISH with nothing pending -> ERROR (no kind to answer with)", do_ae_finish() == -1); esp_finish();
    }
    /* ── C: BIP-137 ─────────────────────────────────────────────────────── */
    {
        uint8_t req[BTC_REQ_LEN]; memset(req, 0, sizeof(req)); memcpy(req, "FMSG", 4); req[4] = 1; req[5] = 0; req[6] = 3;
        const char *m = "Favilla KEY anti-exfil test"; req[10] = (uint8_t)strlen(m); memcpy(req + 11, m, strlen(m));
        uint8_t rpub[33], rsig[65], rdg[32]; check("C: reference signs", btc_sign_message(g_ctx, SEED, req, rpub, rsig, rdg) == 0);
        uint8_t t[32], h[32]; host_t(t, 31); ae_host_commit(AE_KIND_ECDSA_RC, t, h);
        memcpy(g_btc_in, req, BTC_REQ_LEN); g_btc_in_valid = 1; write_ae_in(NULL, h);
        int b0 = burns; check("C: MSGSIGN_INIT rc 0", do_msgsign_init() == 0 && g_btc_out[5] == 0); esp_finish();
        check("C: MSIG v2, pub33 + digest match", !memcmp(g_btc_out, "MSIG", 4) && g_btc_out[4] == 2 && !memcmp(g_btc_out + 8, rpub, 33) && !memcmp(g_btc_out + 106, rdg, 32));
        uint8_t R0[33]; memcpy(R0, g_btc_out + 41, 33); check("C: burned once", burns == b0 + 1);
        write_ae_t(t); check("C: AE_FINISH rc 0", do_ae_finish() == 0 && g_btc_out[5] == 0); esp_finish();
        uint8_t *s65 = g_btc_out + 41;
        check("C: header 39..42", s65[0] >= 39 && s65[0] <= 42);
        checkh("C: host relation on r", ae_host_check(g_ctx, AE_KIND_ECDSA_RC, R0, t, s65 + 1));
        { secp256k1_ecdsa_recoverable_signature rs; secp256k1_pubkey rec; uint8_t a[33]; size_t l = 33;
          check("C: recoverable parses", secp256k1_ecdsa_recoverable_signature_parse_compact(g_ctx, &rs, s65 + 1, s65[0] - 39));
          check("C: recovers the leaf key", secp256k1_ecdsa_recover(g_ctx, &rec, &rs, rdg) && secp256k1_ec_pubkey_serialize(g_ctx, a, &l, &rec, SECP256K1_EC_COMPRESSED) && !memcmp(a, rpub, 33)); }
        check("C: differs from the untweaked reference", memcmp(s65, rsig, 65) != 0);
        /* a malformed message request is refused before the burn */
        int b1 = burns; req[11] = 0x01; memcpy(g_btc_in, req, BTC_REQ_LEN); g_btc_in_valid = 1; write_ae_in(NULL, h);
        do_msgsign_init(); esp_finish(); check("C: bad request refused 0xD1 before the fetch", g_btc_out[5] == 0xD1 && burns == b1);
    }
#ifdef BENCH_LEAKY_NONCE
    /* ── F ──────────────────────────────────────────────────────────────── */
    g_door = DOOR_NOSTR;
    { int caught = 0, valid = 0;
      for (int i = 0; i < 8; i++) { msg[0] = (uint8_t)i;
        int rr = nostr_sign(msg, (uint8_t)(50+i), sig, r0, &ri, &rf);
        if (rr == -3) caught++;
        if (ri == 0 && rf == 0 && secp256k1_schnorrsig_verify(g_ctx, sig, msg, 32, &PK)) valid++; }
      check("F: leaky G0: every signature is a valid BIP-340 signature (a host that skips the check accepts it)", valid == 8);
      check("F: leaky G0: every signature is caught by the host relation", caught == 8);
      printf("F: leaky nonce bench: %d/8 valid signatures, %d/8 ANTI-EXFIL FAULT\n", valid, caught); }
#endif
    printf("antiexfil cmd: %d/%d passed%s\n", total - fails, total, fails ? "  <-- FAIL" : "");
    return fails ? 1 : 0;
}
