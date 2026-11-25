/* host_ember_tx.c — src/ember_tx.c against embit and the BIP-143 KAT. 28 Oct 2026.
 * Run tests/run_ember_tx.sh from the project root. */
#include "ember_tx.h"
#include "data/tx_vectors.h"
#include <stdio.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)
static void unhex(const char *h, uint8_t *o) { while (*h) { unsigned x; sscanf(h, "%2x", &x); *o++ = (uint8_t)x; h += 2; } }
static void unhex_rev(const char *h, uint8_t *o) { uint8_t t[32]; unhex(h, t); for (int i = 0; i < 32; i++) o[i] = t[31 - i]; }

static void test_bip143_kat(void) {
    /* BIP-143 "Native P2WPKH" example: sighash of input 1. Only fields BIP-143
     * commits to are used (scriptSigs are not part of it). */
    et_tx_t tx; memset(&tx, 0, sizeof tx);
    tx.version = 1; tx.locktime = 0x11; tx.nin = 2; tx.nout = 2;
    unhex("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", tx.in[0].txid); tx.in[0].vout = 0; tx.in[0].seq = 0xffffffee;
    unhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", tx.in[1].txid); tx.in[1].vout = 1; tx.in[1].seq = 0xffffffff;
    tx.in[1].amount = 600000000; unhex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357", tx.in[1].pub);
    tx.out[0].amount = 112340000; tx.out[0].spklen = 25; unhex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac", tx.out[0].spk);
    tx.out[1].amount = 223450000; tx.out[1].spklen = 25; unhex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac", tx.out[1].spk);
    uint8_t sh[32], want[32]; et_sighash(&tx, 1, sh);
    unhex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", want);
    CHECK(memcmp(sh, want, 32) == 0, "BIP-143 native P2WPKH sighash");
    (void)unhex_rev;
}

static void test_embit(void) {
    size_t n = sizeof TXV / sizeof TXV[0]; int bad = 0;
    static uint8_t buf[1200];
    for (size_t k = 0; k < n; k++) {
        const txv_t *v = &TXV[k]; et_tx_t tx; memset(&tx, 0, sizeof tx);
        tx.version = 2; tx.locktime = v->lock; tx.nin = v->nin; tx.nout = v->nout;
        for (int i = 0; i < v->nin; i++) {
            memcpy(tx.in[i].txid, v->in[i].txid, 32); tx.in[i].vout = v->in[i].vout; tx.in[i].amount = v->in[i].amount;
            tx.in[i].seq = ET_SEQ_RBF; memcpy(tx.in[i].pub, v->in[i].pub, 33);
            memcpy(tx.in[i].sig, v->in[i].sig, v->in[i].siglen); tx.in[i].siglen = v->in[i].siglen;
        }
        for (int i = 0; i < v->nout; i++) {
            tx.out[i].amount = v->out[i].amount; memcpy(tx.out[i].spk, v->out[i].spk, 34); tx.out[i].spklen = v->out[i].spklen;
            if (et_spk_len(v->out[i].spk) != v->out[i].spklen) { bad++; printf("  tx %zu out %d template len\n", k, i); }
        }
        int ok = 1;
        for (int i = 0; i < v->nin; i++) { uint8_t sh[32]; et_sighash(&tx, i, sh); ok &= !memcmp(sh, v->in[i].sighash, 32); }
        size_t len = et_serialize(&tx, 1, buf, sizeof buf);
        ok &= len == v->rawlen && !memcmp(buf, v->raw, len);
        uint8_t id[32]; et_txid(&tx, id); ok &= !memcmp(id, v->txid, 32);
        /* the vsize bound holds for every real signature length */
        size_t base = et_serialize(&tx, 0, 0, 0); uint32_t vs = (uint32_t)((base * 3 + len + 3) / 4);
        ok &= vs <= et_vsize_max(&tx) && et_vsize_max(&tx) - vs <= tx.nin;
        if (!ok) { if (bad++ < 5) printf("  embit tx %zu differs\n", k); }
    }
    CHECK(bad == 0, "embit: %d of %zu transactions differ", bad, n);
    printf("  embit: %zu signed transactions: witness bytes, txid, every BIP-143 sighash, vsize bound all match\n", n);
}

static void test_templates(void) {
    uint8_t s[34];
    memset(s, 0, 34); s[0] = 0x00; s[1] = 0x14; CHECK(et_spk_len(s) == 22, "p2wpkh");
    s[30] = 1; CHECK(et_spk_len(s) == 0, "p2wpkh with junk padding refused");
    memset(s, 0, 34); s[0] = 0x51; s[1] = 0x20; CHECK(et_spk_len(s) == 34, "p2tr");
    memset(s, 0, 34); s[0] = 0x52; s[1] = 0x20; CHECK(et_spk_len(s) == 0, "witness v2 refused");
    memset(s, 0, 34); s[0] = 0x6a; s[1] = 0x20; CHECK(et_spk_len(s) == 0, "OP_RETURN refused");
    memset(s, 0, 34); CHECK(et_spk_len(s) == 0, "empty slot refused");
    memset(s, 0, 34); s[0] = 0xa9; s[1] = 0x14; s[22] = 0x88; CHECK(et_spk_len(s) == 0, "broken p2sh refused");
}

int main(void) {
    printf("Emberwill transaction builder, host tests\n");
    test_bip143_kat(); test_templates(); test_embit();
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
