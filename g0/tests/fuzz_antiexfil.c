/* 27 Oct 2026: libFuzzer + ASan + UBSan over the anti-exfil INIT / FINISH
 * state machine (the REAL handlers, extracted from src/main.c), driven by an
 * RCE'd ESP32 that sends commands in any order with any bytes.
 *
 * Invariants asserted after every operation:
 *   I1  a FINISH, whatever its outcome, leaves nothing pending
 *   I2  an INIT while something is pending is refused and changes nothing
 *   I3  a released signature always satisfies the host relation for the R0
 *       that was pending and the t the host sent, and that t opened h
 *   I4  nothing is released after the 10 s timeout or after a RESET
 *   I5  the private key / leaf key never appears in SIG_OUT or BTC_OUT
 *   I6  a Bitcoin INIT fetches (burns the latch) at most once, and never when
 *       it is refused for a non-zero message half or a pending operation
 * Ops (one byte each + payload): 0 SIGN_INIT(msg,h) 1 BTCSIGN_INIT(req,h)
 *   2 MSGSIGN_INIT(req,h) 3 FINISH(t) 4 FINISH(correct t) 5 RESET 6 tick+N
 *   7 door=NOSTR 8 door=BTC 9 corrupt AE_IN length (dropped by the ISR rule) */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
#include "antiexfil.h"
#include "btc.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;(void)m;abort();}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;(void)m;abort();}
#include "extracted_ae_defs.inc"
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC   2
#define DOOR_PASSKEY 3
#define G0_CMD_MODEDOOR 0x21
#define G0_CMD_PKSIGN 0x22
#define G0_CMD_VAULT 0x28    /* vault records, 2 Nov 2026 */
static uint8_t g_door = DOOR_NOSTR;
static secp256k1_context *g_ctx; static uint8_t g_ctxbuf[512] __attribute__((aligned(16)));
static void secure_wipe(void *p, size_t n){ volatile uint8_t *v = p; while(n--) *v++ = 0; }
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint32_t g_tick = 5000;
static uint32_t HAL_GetTick(void) { return g_tick; }
static uint8_t g_kg0[KG0_LEN], g_pool[32];
static void entropy_mix(const uint8_t *d, size_t n){ sha256_ctx c; sha256_init(&c); sha256_update(&c, g_pool, 32); if(d&&n) sha256_update(&c, d, n); sha256_final(&c, g_pool); }
#include "hedge.inc"   /* v18: the firmware's own hedge32 */
static void ctx_reblind(void){}
static uint8_t g_sig_out[64], g_btc_out[BTC_OUT_LEN];
static uint8_t g_btc_in[BTC_REQ_LEN]; static uint8_t g_btc_in_valid = 0;
static const uint8_t SK[32] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x12};
static int fetch_scalar(uint8_t s[32]){ memcpy(s, SK, 32); return 0; }
static uint8_t SEED[64]; static int burns = 0;
static uint8_t get_seed(uint8_t seed[64], int *step, uint8_t d[8]) { (void)step; (void)d; burns++; memcpy(seed, SEED, 64); return 0; }
#include "extracted_ae_state.inc"
#include "extracted_ae_sign.inc"
#include "extracted_ae_btc.inc"
/* 28 Oct 2026: door_permits asks the Emberwill table first (ember_glue.inc); not fuzzed here */
static int em_door_permits(uint8_t c) { (void)c; return -1; }
#include "extracted_ae_door.inc"

static int inited = 0;
static void init_once(void) {
    if (inited) return; inited = 1;
    g_ctx = secp256k1_context_preallocated_create(g_ctxbuf, SECP256K1_CONTEXT_NONE);
    memset(g_kg0, 0x5a, 32); memset(g_pool, 0x33, 32); for (int i=0;i<64;i++) SEED[i]=(uint8_t)(i*3+1);
    uint8_t s[32]; fetch_scalar(s); true_pubkey_fill(s);
}
static void fin_inputs(void){ secure_wipe(g_ae_in,64); g_ae_in_valid=0; secure_wipe(g_ae_t,32); g_ae_t_valid=0; g_btc_in_valid=0; }
static int contains(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn) {
    for (size_t i = 0; i + nn <= hn; i++) if (!memcmp(hay + i, needle, nn)) return 1; return 0;
}
static void run_cmd(uint8_t cmd) {   /* main()'s per-command envelope */
    if (ae_expired()) ae_wipe();
    secure_wipe(g_sig_out, 64); secure_wipe(g_btc_out, BTC_OUT_LEN);
    if (!door_permits(cmd)) { fin_inputs(); return; }
    if (cmd == G0_CMD_SIGN_INIT && g_door == DOOR_UNSET) g_door = DOOR_NOSTR;   /* door_autocommit (19 Oct 2026) */
    int rc = -1;
    switch (cmd) {
    case G0_CMD_SIGN_INIT:    rc = do_sign_init(); break;
    case G0_CMD_AE_FINISH:    rc = do_ae_finish(); break;
    case G0_CMD_BTCSIGN_INIT: rc = do_btcsign_init(); break;
    case G0_CMD_MSGSIGN_INIT: rc = do_msgsign_init(); break;
    }
    if (rc != 0) { secure_wipe(g_sig_out, 64); secure_wipe(g_btc_out, BTC_OUT_LEN); }
    fin_inputs();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    ae_wipe(); fin_inputs(); g_door = DOOR_UNSET; burns = 0; g_tick = 5000;   /* door memory: set once per life, as on the chip */
    /* the host's view of the pending op */
    uint8_t host_t[32] = {0}, host_r0[33] = {0}, host_kind = 0, host_key[32]; int host_pending = 0, host_expired = 0;
    uint8_t leaf_cache[32] = {0}; int leaf_known = 0;
    size_t p = 0;
    while (p < size) {
        uint8_t op = data[p++] % 10;
        if (ae_expired()) { ae_wipe(); host_pending = 0; }   /* the tick in main() */
        uint8_t prev_kind = g_ae.kind; ae_pending_t prev = g_ae;
        switch (op) {
        case 0: case 1: case 2: {
            uint8_t kind = op == 0 ? AE_KIND_SCHNORR : op == 1 ? AE_KIND_ECDSA : AE_KIND_ECDSA_RC;
            uint8_t t[32], h[32], msg[32]; int honest = (p < size) ? (data[p++] & 1) : 1;
            for (int i = 0; i < 32; i++) { t[i] = (p < size) ? data[p++] : (uint8_t)i; msg[i] = (p < size) ? data[p++] : (uint8_t)(i*3); }
            ae_host_commit(kind, t, h);
            if (op == 0) { memcpy(g_ae_in, msg, 32); memcpy(g_ae_in + 32, h, 32); g_ae_in_valid = 1; }
            else {
                memset(g_btc_in, 0, BTC_REQ_LEN);
                if (op == 1) { g_btc_in[0] = 1; g_btc_in[1] = 1; g_btc_in[4] = 2; g_btc_in[160] = msg[0] & 0x3F; memcpy(g_btc_in + 12, msg, 32); }
                else { memcpy(g_btc_in, "FMSG", 4); g_btc_in[4] = 1; g_btc_in[6] = msg[1] & 0x3F; g_btc_in[10] = 5; memcpy(g_btc_in + 11, "hello", 5); }
                g_btc_in_valid = 1;
                if (honest) memset(g_ae_in, 0, 32); else memcpy(g_ae_in, msg, 32);   /* dishonest: non-zero message half */
                memcpy(g_ae_in + 32, h, 32); g_ae_in_valid = 1;
            }
            int b0 = burns;
            run_cmd(op == 0 ? G0_CMD_SIGN_INIT : op == 1 ? G0_CMD_BTCSIGN_INIT : G0_CMD_MSGSIGN_INIT);
            if (prev_kind != AE_KIND_NONE) {               /* I2 */
                if (memcmp(&prev, &g_ae, sizeof(g_ae)) != 0) abort();
                if (burns != b0) abort();                  /* I6 */
            } else if (g_ae.kind != AE_KIND_NONE) {        /* accepted */
                if (g_ae.kind != kind) abort();
                host_pending = 1; host_expired = 0; host_kind = kind; memcpy(host_t, t, 32); memcpy(host_r0, g_ae.r0, 33);
                memcpy(host_key, g_ae.key, 32);
                if (op != 0) { if (burns != b0 + 1) abort(); memcpy(leaf_cache, g_ae.key, 32); leaf_known = 1; }
            } else {
                if (op != 0 && !honest && burns != b0) abort();   /* I6: refused before the fetch */
            }
            break; }
        case 3: case 4: {
            uint8_t t[32]; for (int i = 0; i < 32; i++) t[i] = (p < size) ? data[p++] : (uint8_t)(i*7);
            int correct = (op == 4 && host_pending); if (correct) memcpy(t, host_t, 32);
            int send_t = (p < size) ? (data[p++] != 0) : 1;
            if (send_t) { memcpy(g_ae_t, t, 32); g_ae_t_valid = 1; }
            uint8_t kind = g_ae.kind; int was_pending = kind != AE_KIND_NONE;
            int expired_now = ae_expired();
            run_cmd(G0_CMD_AE_FINISH);
            if (g_ae.kind != AE_KIND_NONE) abort();        /* I1 */
            /* did it release? */
            int released = 0; const uint8_t *r32 = NULL;
            if (kind == AE_KIND_SCHNORR) { uint8_t z[64] = {0}; released = memcmp(g_sig_out, z, 64) != 0; r32 = g_sig_out; }
            else if (kind == AE_KIND_ECDSA && g_btc_out[0] == 'B' && g_btc_out[5] == 0) {
                released = 1; secp256k1_ecdsa_signature sg; static uint8_t c64[64];
                if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &sg, g_btc_out + 41, g_btc_out[7])) abort();
                secp256k1_ecdsa_signature_serialize_compact(g_ctx, c64, &sg); r32 = c64; }
            else if (kind == AE_KIND_ECDSA_RC && g_btc_out[0] == 'M' && g_btc_out[5] == 0) { released = 1; r32 = g_btc_out + 42; }
            if (released) {
                if (!was_pending || !send_t || expired_now) abort();                     /* I4 */
                if (memcmp(t, host_t, 32) != 0) abort();                                  /* only the committed t opens it */
                if (!ae_host_check(g_ctx, host_kind, host_r0, t, r32)) abort();           /* I3 */
            }
            host_pending = 0;
            break; }
        case 5: { fin_inputs(); ae_wipe(); host_pending = 0; break; }
        case 6: { uint32_t n = (p < size) ? (uint32_t)data[p++] * 64 : 64; g_tick += n; if (host_pending && (g_tick - g_ae.t0) > AE_TIMEOUT_MS) host_expired = 1; break; }
        case 7: if (g_door == DOOR_UNSET) g_door = DOOR_NOSTR; break;   /* DOORNOSTR: first wins */
        case 8: if (g_door == DOOR_UNSET) g_door = DOOR_BTC; break;     /* DOORBTC: first wins */
        case 9: { /* the ISR drops wrong-length writes: emulate as "no write" */ break; }
        }
        /* I5: the key never appears in any output */
        if (contains(g_sig_out, 64, SK, 16) || contains(g_btc_out, BTC_OUT_LEN, SK, 16)) abort();
        if (leaf_known && (contains(g_sig_out, 64, leaf_cache, 16) || contains(g_btc_out, BTC_OUT_LEN, leaf_cache, 16))) abort();
        if (contains(g_sig_out, 64, SEED, 16) || contains(g_btc_out, BTC_OUT_LEN, SEED, 16)) abort();
        (void)host_expired; (void)host_key;
    }
    return 0;
}
