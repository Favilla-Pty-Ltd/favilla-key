/* host_ember_plan.c — the plan chain (src/ember_plan.c) against an independent
 * Python/embit model of r7 + the 28 Oct decisions. 28 Oct 2026.
 * Each plan is parsed from its EMBER_SET wire bytes, validated, and every
 * transaction is built, compared byte for byte (no-witness) and by txid,
 * then signed and written to /tmp/ember_signed.txt for tools/check_signed.py,
 * which re-verifies every signature with embit. */
#include "ember_plan.h"
#include "secp256k1.h"
#include "data/plan_vectors.h"
#include <stdio.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static secp256k1_context *ctx;
static void pub_of(const uint8_t k[32], uint8_t p[33]) {
    secp256k1_pubkey P; size_t l = 33; secp256k1_ec_pubkey_create(ctx, &P, k); secp256k1_ec_pubkey_serialize(ctx, p, &l, &P, SECP256K1_EC_COMPRESSED);
}

static void test_vectors(FILE *out) {
    size_t n = sizeof PLANS / sizeof PLANS[0]; int txs = 0, sigs = 0;
    for (size_t k = 0; k < n; k++) {
        const plan_vec_t *v = &PLANS[k]; ep_set_t s;
        CHECK(ep_set_parse(v->wire, sizeof v->wire, &s) == EP_OK, "plan %zu parse", k);
        CHECK(ep_validate(&s, v->tip) == EP_OK, "plan %zu validate: %d", k, ep_validate(&s, v->tip));
        CHECK(ep_count(&s) == v->ntx, "plan %zu count %u vs %u", k, ep_count(&s), v->ntx);
        uint8_t cpub[EP_MAX_COINS][33] = {{0}}, rpub[EP_MAX_LINKS][33] = {{0}};
        for (int i = 0; i < s.ncoins; i++) pub_of(v->cpriv[i], cpub[i]);
        for (int i = 0; i < s.nlinks; i++) pub_of(v->rpriv[i], rpub[i]);
        for (uint32_t t = 0; t < ep_count(&s); t++) {
            et_tx_t tx; uint8_t buf[1200], id[32]; ep_id_t e = ep_id_at(t);
            int rc = ep_build(&s, v->tip, (const uint8_t (*)[33])cpub, (const uint8_t (*)[33])rpub, e, &tx);
            size_t len = et_serialize(&tx, 0, buf, sizeof buf); et_txid(&tx, id);
            int ok = rc == EP_OK && len == v->len[t] && !memcmp(buf, PLAN_BLOBS + v->off[t], len) && !memcmp(id, v->txid[t], 32);
            CHECK(ok, "plan %zu tx %u (%c%u v%u) differs from the embit model (rc %d)", k, t, e.kind, e.link, e.var, rc);
            txs++;
            /* sign every input with the key it pays to */
            for (int i = 0; i < tx.nin; i++) {
                const uint8_t *priv = NULL;
                for (int c = 0; c < s.ncoins; c++) if (!memcmp(tx.in[i].pub, cpub[c], 33)) priv = v->cpriv[c];
                for (int r = 0; r < s.nlinks; r++) if (!memcmp(tx.in[i].pub, rpub[r], 33)) priv = v->rpriv[r];
                uint8_t sh[32]; et_sighash(&tx, i, sh);
                secp256k1_ecdsa_signature sg; secp256k1_ecdsa_sign(ctx, &sg, sh, priv, NULL, NULL);
                size_t dl = 72; secp256k1_ecdsa_signature_serialize_der(ctx, tx.in[i].sig, &dl, &sg);
                tx.in[i].sig[dl] = 0x01; tx.in[i].siglen = (uint8_t)(dl + 1); sigs++;
            }
            len = et_serialize(&tx, 1, buf, sizeof buf);
            fprintf(out, "%zu %c %u %u ", k, e.kind, e.link, e.var);
            for (int i = 0; i < tx.nin; i++) fprintf(out, "%llu%s", (unsigned long long)tx.in[i].amount, i + 1 < tx.nin ? "," : " ");
            for (size_t i = 0; i < len; i++) fprintf(out, "%02x", buf[i]);
            fprintf(out, "\n");
            /* actual vsize never exceeds the bound the fee was computed on */
            size_t base = et_serialize(&tx, 0, 0, 0);
            CHECK((base * 3 + len + 3) / 4 <= et_vsize_max(&tx), "vsize bound");
        }
    }
    printf("  %zu plans, %d transactions identical to the embit model, %d inputs signed\n", n, txs, sigs);
}

static void test_rejects(void) {
    const plan_vec_t *v = &PLANS[0]; uint8_t w[430]; ep_set_t s;
    #define MUT(off, val, want, what) do { memcpy(w, v->wire, 430); w[off] = (val); int r = ep_set_parse(w, 430, &s); if (r == EP_OK) r = ep_validate(&s, v->tip); \
        CHECK(r == (want), "%s: %d want %d", what, r, want); } while (0)
    CHECK(ep_set_parse(v->wire, 429, &s) == EP_E_LEN && ep_set_parse(v->wire, 431, &s) == EP_E_LEN, "length must be exact");
    MUT(0, 0, EP_E_COUNT, "0 coins"); MUT(0, 4, EP_E_COUNT, "4 coins"); MUT(1, 7, EP_E_COUNT, "7 heirs"); MUT(2, 9, EP_E_COUNT, "9 links");
    MUT(3, 1, EP_E_PAD, "reserved byte");
    MUT(376, 0x6a, EP_E_SPK, "executor OP_RETURN");
    MUT(160, 0x52, EP_E_SPK, "heir witness v2");
    MUT(160 + 34, (uint8_t)(v->wire[160 + 34] + 1), EP_E_BP, "shares not 10000");
    MUT(413, 0x7f, EP_E_QUIET, "quiet huge");
    MUT(411, 0, EP_E_QUIET, "quiet small");          /* clears the middle byte: below 4032 for every test value */
    MUT(418, 0, EP_E_RATE, "coupon rate 0");
    MUT(424, 0, EP_E_RATE, "refresh rate 0");
    MUT(4 + 44, 2, EP_E_DERIV, "change 2");
    MUT(4 + 51, 0x80, EP_E_DERIV, "hardened index");
    /* an unused slot with data in it */
    { int nc = v->wire[0]; if (nc < 3) { memcpy(w, v->wire, 430); w[4 + 52 * nc] = 1; CHECK(ep_set_parse(w, 430, &s) == EP_E_PAD, "junk in unused coin slot"); } }
    /* rates so high the coupon can't pay its heirs */
    memcpy(w, v->wire, 430); w[422] = 0xd0; w[423] = 0x07; ep_set_parse(w, 430, &s); s.crate[0] = 1998; s.crate[1] = 1999; s.crate[2] = 2000;
    s.coin[0].amount = 100000; for (int i = 1; i < s.ncoins; i++) s.coin[i].amount = 600;
    CHECK(ep_validate(&s, v->tip) == EP_E_DUST, "fees above value: %d", ep_validate(&s, v->tip));
    /* the same outpoint twice */
    ep_set_parse(v->wire, 430, &s);
    if (s.ncoins >= 2) { s.coin[1] = s.coin[0]; CHECK(ep_validate(&s, v->tip) == EP_E_DUPCOIN, "duplicate coin"); }
}

int main(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("Emberwill plan chain, host tests\n");
    FILE *f = fopen("/tmp/ember_signed.txt", "w");
    test_vectors(f); fclose(f); test_rejects();
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
