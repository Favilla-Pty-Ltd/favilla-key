// Host KAT + negative tests for multisig.h / psbt_passthrough.h / psbt.h.
// Vectors come from gen_vectors.py (embit — an independent implementation).
// Build: make (see Makefile). Runs under UBSan and ASan.
#include "Arduino.h"
#include "psbt.h"
#include "psbt_sign.h"
#include "multisig.h"
#include "psbt_passthrough.h"
#include "ur_psbt.h"
#include "btc_state.h"
#include "ms_vectors.h"
#include "host_g0.h"   // v3: host stand-in for the G0 signer

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, name) do { if (cond) { g_pass++; printf("  ok   %s\n", name); } else { g_fail++; printf("  FAIL %s  (%s:%d)\n", name, __FILE__, __LINE__); } } while (0)

static void hexdump_to_file(const char* path, const uint8_t* b, size_t n) {
  FILE* f = fopen(path, "w"); if (!f) return;
  for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
  fprintf(f, "\n"); fclose(f);
}

// Walk the raw maps and count PSBT_IN_PARTIAL_SIG (0x02) keys across all inputs.
static int count_partial_sigs(const uint8_t* b, size_t n, int n_inputs) {
  psbt_reader_t r = { b, n, 0 }; psbt_r_skip(&r, 5); int count = 0;
  for (int map = 0; map < 1 + n_inputs; map++) {
    for (;;) { uint64_t kl; if (!psbt_r_varint(&r, &kl)) return -1; if (kl == 0) break;
      const uint8_t* k = psbt_r_view(&r, kl); uint64_t vl; if (!k || !psbt_r_varint(&r, &vl) || !psbt_r_view(&r, vl)) return -1;
      if (map > 0 && k[0] == 0x02 && kl == 34) count++; }
  }
  return count;
}

static psbt_t g_psbt;          // ~15KB: static, never on the stack
static ms_store_t g_store;

int main() {
  printf("multisig harness\n");

  // ── 1. config parse ───────────────────────────────────────────────────
  ms_wallet_t w; char err[32] = {0};
  bool ok = ms_config_parse(MS_KAT_CONFIG, strlen(MS_KAT_CONFIG), &w, err);
  CHECK(ok, "config parses");
  if (!ok) { printf("   err=%s\n", err); return 1; }
  CHECK(w.m == 2 && w.n == 3, "policy 2 of 3");
  CHECK(strcmp(w.name, "KAT 2of3") == 0, "name");
  CHECK(memcmp(w.cs[0].fp, MS_KAT_FP0, 4) == 0 && memcmp(w.cs[1].fp, MS_KAT_FP1, 4) == 0 && memcmp(w.cs[2].fp, MS_KAT_FP2, 4) == 0, "fingerprints");
  CHECK(memcmp(w.cs[0].xpub.pubkey, MS_KAT_XPUB78_0 + 45, 33) == 0 && memcmp(w.cs[0].xpub.chain_code, MS_KAT_XPUB78_0 + 13, 32) == 0, "xpub 0 decoded");
  CHECK(memcmp(w.cs[2].xpub.pubkey, MS_KAT_XPUB78_2 + 45, 33) == 0, "xpub 2 decoded");
  CHECK(w.cs[0].xpub.depth == 4, "xpub depth 4");
  { // round trip string
    char s[128]; CHECK(ms_xpub_to_string(&w.cs[1].xpub, MS_VER_XPUB, s, sizeof(s)) && strcmp(s, MS_KAT_XPUBSTR_1) == 0, "xpub re-encodes identically");
  }

  // ── 2. our key from seed A ────────────────────────────────────────────
  bip32_xpub ours; uint8_t our_fp[4];
  CHECK(ms_derive_account_xpub(MS_KAT_SEED_A, &ours, our_fp), "derive m/48h/0h/0h/2h from seed");
  CHECK(memcmp(our_fp, MS_KAT_FP0, 4) == 0, "our master fp");
  CHECK(memcmp(ours.pubkey, MS_KAT_XPUB78_0 + 45, 33) == 0 && memcmp(ours.chain_code, MS_KAT_XPUB78_0 + 13, 32) == 0, "our account xpub == embit");
  CHECK(ours.depth == 4 && memcmp(ours.parent_fingerprint, MS_KAT_XPUB78_0 + 5, 4) == 0 && ours.child_number == 0x80000002UL, "xpub metadata (depth/parent fp/child)");
  CHECK(ms_wallet_find_ours(&w, our_fp, &ours) && w.our_index == 0, "we are cosigner 0");
  { char ke[200]; CHECK(ms_key_expr(our_fp, &ours, ke, sizeof(ke)) && strcmp(ke, MS_KAT_KEYEXPR_A) == 0, "key expression for Sparrow"); }

  // ── 3. addresses + scripts ────────────────────────────────────────────
  { char a[96]; uint8_t ws[PSBT_MAX_WITNESS_SCRIPT]; size_t wl; uint8_t spk[34];
    CHECK(ms_address(&w, 0, 0, a, sizeof(a)) && strcmp(a, MS_KAT_ADDR_0_0) == 0, "address 0/0");
    CHECK(ms_address(&w, 0, 5, a, sizeof(a)) && strcmp(a, MS_KAT_ADDR_0_5) == 0, "address 0/5");
    CHECK(ms_address(&w, 1, 3, a, sizeof(a)) && strcmp(a, MS_KAT_ADDR_1_3) == 0, "address 1/3");
    CHECK(ms_expected_scripts(&w, 1, 3, ws, &wl, spk, NULL) && wl == sizeof(MS_KAT_WS_1_3) && memcmp(ws, MS_KAT_WS_1_3, wl) == 0, "witness script 1/3 (sorted)");
    CHECK(memcmp(spk, MS_KAT_SPK_1_3, 34) == 0, "spk 1/3");
  }

  // ── 4. store ──────────────────────────────────────────────────────────
  ms_store_init(&g_store);
  CHECK(ms_store_add(&g_store, &w) && g_store.count == 1, "store add");
  CHECK(!ms_store_add(&g_store, &w), "duplicate wallet refused");
  printf("   sizeof(ms_store_t)=%zu sizeof(psbt_t)=%zu\n", sizeof(ms_store_t), sizeof(g_psbt));

  // ── 5. parse the PSBT that already carries cosigner B's signature ─────
  CHECK(psbt_parse(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B), &g_psbt), "psbt parses");
  if (!psbt_parse(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B), &g_psbt)) { printf("   %s\n", psbt_err_str(psbt_last_err)); return 1; }
  CHECK(g_psbt.tx.n_inputs == 2 && g_psbt.tx.n_outputs == 2, "2 in / 2 out");
  CHECK(g_psbt.inputs[0].n_bip32 == 3 && g_psbt.inputs[1].n_bip32 == 3, "3 derivation records per input");
  CHECK(g_psbt.inputs[0].witness_script_present && g_psbt.inputs[0].witness_script_len == sizeof(MS_KAT_WS_0_0) && memcmp(g_psbt.inputs[0].witness_script, MS_KAT_WS_0_0, sizeof(MS_KAT_WS_0_0)) == 0, "input 0 witness script captured");
  CHECK(g_psbt.outputs[1].n_bip32 == 3 && g_psbt.outputs[1].witness_script_present, "change output records + script captured");
  CHECK(memcmp(&g_psbt.inputs[0].bip32, &g_psbt.inputs[0].bip32s[0], sizeof(psbt_bip32_t)) == 0, "legacy bip32 mirrors bip32s[0]");

  int widx = -1;
  CHECK(ms_classify_psbt(&g_store, &g_psbt, our_fp, &widx) == MS_CLASS_MULTISIG && widx == 0, "classified MULTISIG wallet 0");
  { uint32_t c, x; uint8_t pub[33];
    CHECK(ms_verify_input(&g_store.w[0], &g_psbt.inputs[0], &c, &x, pub) && c == 0 && x == 0 && memcmp(pub, MS_KAT_PUBA_0_0, 33) == 0, "input 0 verifies as 0/0, our pubkey");
    CHECK(ms_verify_input(&g_store.w[0], &g_psbt.inputs[1], &c, &x, pub) && c == 0 && x == 5 && memcmp(pub, MS_KAT_PUBA_0_5, 33) == 0, "input 1 verifies as 0/5");
    CHECK(ms_verify_change_output(&g_store.w[0], &g_psbt.outputs[1], &g_psbt.tx.outputs[1], &c, &x) && c == 1 && x == 3, "change output verifies as 1/3");
    CHECK(!ms_verify_change_output(&g_store.w[0], &g_psbt.outputs[0], &g_psbt.tx.outputs[0], &c, &x), "recipient output is not change");
  }
  psbt_summary_t sum;
  CHECK(ms_build_summary(&g_store.w[0], &g_psbt, our_fp, &sum), "summary builds");
  CHECK(sum.n_recipients == 1 && sum.recipients[0].value == 150000 && sum.n_changes == 1 && sum.changes[0].verified && sum.changes[0].value == 48000 && sum.fee == 2000 && sum.n_changes_unverified == 0, "summary: 1 recipient, 1 verified change, fee 2000");

  // ── 6. sighash + signature KATs ───────────────────────────────────────
  static psbt_partial_sig_t sigs[PSBT_MAX_INPUTS];
  g_host_g0_seed = MS_KAT_SEED_A;
  int n = ms_sign_all(&g_store.w[0], &g_psbt, host_g0_sign, true, sigs, PSBT_MAX_INPUTS);
  CHECK(n == 2, "signed 2 inputs");
  CHECK(ms_sign_all(&g_store.w[0], &g_psbt, host_g0_sign, false, sigs, PSBT_MAX_INPUTS) == 0, "approved=false signs nothing");
  for (int i = 0; i < 2; i++) {
    const uint8_t* exp = i ? MS_KAT_SIG_A_1 : MS_KAT_SIG_A_0;
    size_t el = i ? sizeof(MS_KAT_SIG_A_1) : sizeof(MS_KAT_SIG_A_0);
    bool same = (size_t)sigs[i].der_len + 1 == el && memcmp(sigs[i].der, exp, sigs[i].der_len) == 0 && exp[el - 1] == sigs[i].sighash_type;
    CHECK(same, i ? "sig input 1 == embit (RFC6979 low-S)" : "sig input 0 == embit (RFC6979 low-S)");
  }

  // ── 7. pass-through ───────────────────────────────────────────────────
  static uint8_t out1[4096], out2[4096];
  int l1 = psbt_add_partial_sigs(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B), &g_psbt, sigs, n, out1, sizeof(out1));
  CHECK(l1 > 0, "pass-through writes");
  CHECK(l1 == (int)sizeof(MS_KAT_PSBT_WITH_B) + 2 * (1 + 34 + 1 + (int)sigs[0].der_len + 1) - (sigs[0].der_len - sigs[1].der_len), "size = original + 2 partial sigs");
  static psbt_t re;
  CHECK(psbt_parse(out1, (size_t)l1, &re), "pass-through output re-parses");
  CHECK(re.inputs[0].n_bip32 == 3 && re.inputs[0].witness_script_present && re.outputs[1].n_bip32 == 3, "pass-through kept records + scripts");
  CHECK(count_partial_sigs(out1, (size_t)l1, 2) == 4, "4 partial sigs total (B x2 preserved + A x2 added)");
  CHECK(count_partial_sigs(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B), 2) == 2, "original had 2 (B only)");
  int l2 = psbt_add_partial_sigs(out1, (size_t)l1, &re, sigs, n, out2, sizeof(out2));
  CHECK(l2 == l1 && memcmp(out1, out2, l1) == 0, "re-signing is idempotent (replaces, never duplicates)");
  hexdump_to_file("out_ab.hex", out1, (size_t)l1);
  CHECK(psbt_add_partial_sigs(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B) - 1, &g_psbt, sigs, n, out2, sizeof(out2)) < 0, "truncated input refused");
  CHECK(psbt_add_partial_sigs(MS_KAT_PSBT_WITH_B, sizeof(MS_KAT_PSBT_WITH_B), &g_psbt, sigs, n, out2, 100) < 0, "small output refused");

  // ── 8. negative: tampering ────────────────────────────────────────────
  { static psbt_t t; uint32_t c, x; uint8_t pub[33];
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].witness_script[5] ^= 1;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "tampered witness script refused");
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].witness_utxo_script[10] ^= 1;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "tampered UTXO spk refused");
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].bip32s[1].pubkey[5] ^= 1;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "wrong cosigner pubkey in record refused");
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].n_bip32 = 2;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "missing derivation record refused");
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].bip32s[2].path[5] = 7;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "mismatched index across records refused");
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].sighash_type = 0x83;
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "non-ALL sighash refused");
    memcpy(&t, &g_psbt, sizeof(t)); memcpy(t.inputs[0].bip32s[0].fingerprint, MS_KAT_FP1, 4);
    CHECK(!ms_verify_input(&g_store.w[0], &t.inputs[0], &c, &x, pub), "duplicate cosigner fingerprint refused");
    // change redirection: keep the records, point the output somewhere else
    memcpy(&t, &g_psbt, sizeof(t)); t.tx.outputs[1].script_pubkey[9] ^= 1;
    CHECK(!ms_verify_change_output(&g_store.w[0], &t.outputs[1], &t.tx.outputs[1], &c, &x), "change redirection refused");
    psbt_summary_t s2; CHECK(ms_build_summary(&g_store.w[0], &t, our_fp, &s2) && s2.n_changes == 1 && !s2.changes[0].verified && s2.n_changes_unverified == 1, "redirected change surfaced as UNVERIFIED, not hidden");
    // wrong wallet: replace cosigner 2's xpub with cosigner 0's shifted chain code
    ms_store_t s3; memcpy(&s3, &g_store, sizeof(s3)); s3.w[0].cs[2].xpub.chain_code[0] ^= 1;
    int wi; CHECK(ms_classify_psbt(&s3, &g_psbt, our_fp, &wi) == MS_CLASS_NO_WALLET, "PSBT for an unregistered quorum -> NO_WALLET");
    // mixed: turn input 1 into a P2WPKH input carrying our fp
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[1].witness_utxo_script_len = 22; memcpy(t.inputs[1].witness_utxo_script, MS_KAT_SPK84_0_0, 22);
    CHECK(ms_classify_psbt(&g_store, &t, our_fp, &wi) == MS_CLASS_MIXED, "mixed P2WPKH+P2WSH -> MIXED");
    // no P2WSH at all
    memcpy(&t, &g_psbt, sizeof(t)); t.inputs[0].witness_utxo_script_len = 22; t.inputs[1].witness_utxo_script_len = 22;
    CHECK(ms_classify_psbt(&g_store, &t, our_fp, &wi) == MS_CLASS_SINGLESIG, "no P2WSH -> SINGLESIG");
    // multisig PSBT that does not include us
    uint8_t other_fp[4] = {1,2,3,4};
    CHECK(ms_classify_psbt(&g_store, &g_psbt, other_fp, &wi) == MS_CLASS_NO_WALLET || ms_classify_psbt(&g_store, &g_psbt, other_fp, &wi) == MS_CLASS_MULTISIG, "classification with foreign fp is defined");
    ms_store_t s4; ms_store_init(&s4);
    CHECK(ms_classify_psbt(&s4, &g_psbt, other_fp, &wi) == MS_CLASS_NONE_OURS, "empty store, foreign fp -> NONE_OURS");
    CHECK(ms_classify_psbt(&s4, &g_psbt, our_fp, &wi) == MS_CLASS_NO_WALLET, "empty store, our fp -> NO_WALLET (register first)");
    // sign with the wrong seed: verification passes (public), pubkey check must catch it
    uint8_t bad_seed[64]; memcpy(bad_seed, MS_KAT_SEED_A, 64); bad_seed[0] ^= 1;
    g_host_g0_seed = bad_seed;
    CHECK(ms_sign_all(&g_store.w[0], &g_psbt, host_g0_sign, true, sigs, PSBT_MAX_INPUTS) == -1, "wrong seed on the G0 refused (pubkey cross-check)");
    g_host_g0_seed = MS_KAT_SEED_A;
  }

  // ── 9. config negatives ───────────────────────────────────────────────
  { ms_wallet_t x; char e[32];
    const char* bad1 = "Name: a\nPolicy: 4 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n";
    CHECK(!ms_config_parse(bad1, strlen(bad1), &x, e), "m > n refused");
    const char* bad2 = "Name: a\nPolicy: 2 of 3\nDerivation: m/48'/0'/0'/1'\nFormat: P2WSH\n";
    CHECK(!ms_config_parse(bad2, strlen(bad2), &x, e), "non-P2WSH path refused");
    const char* bad3 = "Name: a\nPolicy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2SH-P2WSH\n";
    CHECK(!ms_config_parse(bad3, strlen(bad3), &x, e), "wrapped format refused");
    // 2 keys for a 2-of-3
    char two[1024]; snprintf(two, sizeof(two), "Policy: 2 of 3\nDerivation: m/48h/0h/0h/2h\nFormat: p2wsh\n%02X%02X%02X%02X: %s\n%02X%02X%02X%02X: %s\n",
      MS_KAT_FP0[0],MS_KAT_FP0[1],MS_KAT_FP0[2],MS_KAT_FP0[3], MS_KAT_XPUBSTR_0, MS_KAT_FP1[0],MS_KAT_FP1[1],MS_KAT_FP1[2],MS_KAT_FP1[3], MS_KAT_XPUBSTR_1);
    CHECK(!ms_config_parse(two, strlen(two), &x, e), "too few keys refused");
    // duplicate fp
    char dup[1024]; snprintf(dup, sizeof(dup), "Policy: 2 of 3\nDerivation: m/48h/0h/0h/2h\nFormat: p2wsh\n%02X%02X%02X%02X: %s\n%02X%02X%02X%02X: %s\n%02X%02X%02X%02X: %s\n",
      MS_KAT_FP0[0],MS_KAT_FP0[1],MS_KAT_FP0[2],MS_KAT_FP0[3], MS_KAT_XPUBSTR_0, MS_KAT_FP0[0],MS_KAT_FP0[1],MS_KAT_FP0[2],MS_KAT_FP0[3], MS_KAT_XPUBSTR_1, MS_KAT_FP2[0],MS_KAT_FP2[1],MS_KAT_FP2[2],MS_KAT_FP2[3], MS_KAT_XPUBSTR_2);
    CHECK(!ms_config_parse(dup, strlen(dup), &x, e), "duplicate fingerprint refused");
    // bad checksum xpub
    char bc[1024]; snprintf(bc, sizeof(bc), "Policy: 2 of 3\nDerivation: m/48h/0h/0h/2h\nFormat: p2wsh\n%02X%02X%02X%02X: %s\n", MS_KAT_FP0[0],MS_KAT_FP0[1],MS_KAT_FP0[2],MS_KAT_FP0[3], MS_KAT_XPUBSTR_0);
    bc[strlen(bc) - 2] = (bc[strlen(bc) - 2] == 'a') ? 'b' : 'a';
    CHECK(!ms_config_parse(bc, strlen(bc), &x, e), "xpub with bad checksum refused");
    // CRLF + comments + 'h' notation + lowercase keys accepted
    char crlf[1024]; snprintf(crlf, sizeof(crlf), "# exported\r\nname: X\r\npolicy: 2 of 3\r\nderivation: m/48h/0h/0h/2h\r\nformat: p2wsh\r\n\r\n%02x%02x%02x%02x: %s\r\n%02x%02x%02x%02x: %s\r\n%02x%02x%02x%02x: %s\r\n",
      MS_KAT_FP0[0],MS_KAT_FP0[1],MS_KAT_FP0[2],MS_KAT_FP0[3], MS_KAT_XPUBSTR_0, MS_KAT_FP1[0],MS_KAT_FP1[1],MS_KAT_FP1[2],MS_KAT_FP1[3], MS_KAT_XPUBSTR_1, MS_KAT_FP2[0],MS_KAT_FP2[1],MS_KAT_FP2[2],MS_KAT_FP2[3], MS_KAT_XPUBSTR_2);
    CHECK(ms_config_parse(crlf, strlen(crlf), &x, e) && x.n == 3, "CRLF/comments/h-notation accepted");
    // not a member
    ms_wallet_t y = w; uint8_t fpz[4] = {9,9,9,9};
    CHECK(!ms_wallet_find_ours(&y, fpz, &ours), "non-member refused");
    y = w; bip32_xpub oz = ours; oz.chain_code[3] ^= 1;
    CHECK(!ms_wallet_find_ours(&y, our_fp, &oz), "fp match but xpub mismatch refused");
  }

  // ── 10. search ────────────────────────────────────────────────────────
  { uint32_t c, x;
    CHECK(ms_search_spk(&g_store.w[0], MS_KAT_SPK_1_3, 34, 0, 10, &c, &x, NULL) && c == 1 && x == 3, "scan-to-verify finds change 1/3");
    CHECK(ms_search_spk(&g_store.w[0], MS_KAT_SPK_0_5, 34, 20, 20, &c, &x, NULL) && c == 0 && x == 5, "scan-to-verify finds 0/5 from centre 20");
    uint8_t nope[34] = {0x00, 0x20}; CHECK(!ms_search_spk(&g_store.w[0], nope, 34, 0, 8, &c, &x, NULL), "foreign address not found");
  }

  // ── 11. ur:bytes wrapper → config ─────────────────────────────────────
  { static uint8_t msg[2048], outb[2048];
    size_t cl = strlen(MS_KAT_CONFIG);
    size_t h = ur_cbor_w_bstr_hdr(msg, cl); memcpy(msg + h, MS_KAT_CONFIG, cl);
    int bl = ur_extract_bytes(msg, h + cl, outb, sizeof(outb));
    ms_wallet_t z; char e[32];
    CHECK(bl == (int)cl && ms_config_parse((const char*)outb, (size_t)bl, &z, e) && z.n == 3, "ur:bytes payload -> config parses");
    // ur_feed type gate: a crypto-psbt sequence must refuse a bytes part
    static ur_decoder_t d; ur_decoder_reset(&d);
    char l1s[64] = "ur:crypto-psbt/1-2/aaaaaaaa"; (void)ur_feed(&d, l1s);   // parse fails on bytewords, but type is latched only on ok path
    strncpy(d.ur_type, "crypto-psbt", sizeof(d.ur_type)); char l2s[64] = "ur:bytes/1-2/aaaaaaaa";
    CHECK(ur_feed(&d, l2s) == -1 && d.err, "mixing UR types in one sequence is refused");
  }

  // ── 12. bip143 P2WSH KAT (direct) ─────────────────────────────────────
  { static bip143_input_t bin[2]; static bip143_output_t bout[2];
    for (int i = 0; i < 2; i++) { memcpy(bin[i].outpoint, g_psbt.tx.inputs[i].prev_txid, 32); uint32_t v = g_psbt.tx.inputs[i].prev_vout; bin[i].outpoint[32]=v&0xff; bin[i].outpoint[33]=(v>>8)&0xff; bin[i].outpoint[34]=(v>>16)&0xff; bin[i].outpoint[35]=(v>>24)&0xff; bin[i].nSequence = g_psbt.tx.inputs[i].n_sequence; }
    for (int i = 0; i < 2; i++) { bout[i].value = g_psbt.tx.outputs[i].value; bout[i].scriptPubKey[0] = g_psbt.tx.outputs[i].script_pubkey_len; memcpy(bout[i].scriptPubKey+1, g_psbt.tx.outputs[i].script_pubkey, g_psbt.tx.outputs[i].script_pubkey_len); bout[i].scriptPubKey_len = g_psbt.tx.outputs[i].script_pubkey_len + 1; }
    uint8_t hp[32], hs[32], ho[32]; bip143_tx_hashes(bin, 2, bout, 2, hp, hs, ho);
    uint8_t sc[BIP143_MAX_SCRIPTCODE]; size_t scl = bip143_p2wsh_scriptcode(g_psbt.inputs[1].witness_script, g_psbt.inputs[1].witness_script_len, sc);
    uint8_t sh[32];
    CHECK(bip143_input_sighash_sc(g_psbt.tx.version, g_psbt.tx.locktime, bin[1].outpoint, bin[1].nSequence, g_psbt.inputs[1].witness_utxo_value, sc, scl, hp, hs, ho, 1, sh) && memcmp(sh, MS_KAT_SIGHASH_1, 32) == 0, "P2WSH sighash input 1 == embit");
    uint8_t big[PSBT_MAX_WITNESS_SCRIPT + 1];
    CHECK(bip143_p2wsh_scriptcode(big, sizeof(big), sc) == 0, "oversized witness script refused by scriptcode builder");
  }

  // ── 13. parser caps ───────────────────────────────────────────────────
  { // 8 derivation records on one input -> overflow flag, parse still ok, multisig refuses
    static uint8_t buf[4096]; size_t bl = sizeof(MS_KAT_PSBT_UNSIGNED); memcpy(buf, MS_KAT_PSBT_UNSIGNED, bl);
    // find input 0's first 0x06 record and duplicate it 6 times with tweaked pubkeys, inserted right after
    size_t pos = 0; for (size_t i = 0; i + 40 < bl; i++) if (buf[i] == 0x22 && buf[i+1] == 0x06) { pos = i; break; }
    CHECK(pos > 0, "found a derivation record to duplicate");
    if (pos) {
      size_t reclen = 1 + 34 + 1 + buf[pos + 35];   // keylen byte + key + vallen byte + val
      uint8_t rec[128]; memcpy(rec, buf + pos, reclen);
      size_t ins = pos + reclen;
      memmove(buf + ins + 6 * reclen, buf + ins, bl - ins);
      for (int k = 0; k < 6; k++) { rec[10] ^= (uint8_t)(k + 1); memcpy(buf + ins + k * reclen, rec, reclen); rec[10] ^= (uint8_t)(k + 1); }
      bl += 6 * reclen;
      static psbt_t p9;
      CHECK(psbt_parse(buf, bl, &p9) && p9.inputs[0].bip32_overflow && p9.inputs[0].n_bip32 == PSBT_MAX_KEYS, "9 records: parse ok, overflow flagged");
      uint32_t c, x; uint8_t pub[33];
      CHECK(!ms_verify_input(&g_store.w[0], &p9.inputs[0], &c, &x, pub), "overflowed input refused by multisig");
    }
  }

  // ── 14. bech32 decode (scan-to-verify input) ──────────────────────────
  { uint8_t spk[40];
    CHECK(ms_addr_to_spk(MS_KAT_ADDR_1_3, spk, sizeof(spk)) == 34 && memcmp(spk, MS_KAT_SPK_1_3, 34) == 0, "bech32 P2WSH address -> spk");
    char uri[160]; snprintf(uri, sizeof(uri), "bitcoin:%s?amount=0.001&label=x", MS_KAT_ADDR_0_0);
    CHECK(ms_addr_to_spk(uri, spk, sizeof(spk)) == 34 && memcmp(spk, MS_KAT_SPK_0_0, 34) == 0, "bitcoin: URI -> spk");
    char up[100]; strcpy(up, MS_KAT_ADDR_0_5); for (char* q = up; *q; q++) if (*q >= 'a' && *q <= 'z') *q -= 32;
    CHECK(ms_addr_to_spk(up, spk, sizeof(spk)) == 34 && memcmp(spk, MS_KAT_SPK_0_5, 34) == 0, "UPPERCASE bech32 -> spk");
    char bad[100]; strcpy(bad, MS_KAT_ADDR_0_0); bad[20] = (bad[20] == 'q') ? 'p' : 'q';
    CHECK(ms_addr_to_spk(bad, spk, sizeof(spk)) == 0, "bad checksum refused");
    char mixed[100]; strcpy(mixed, MS_KAT_ADDR_0_0); mixed[5] -= 32;
    CHECK(ms_addr_to_spk(mixed, spk, sizeof(spk)) == 0, "mixed case refused");
    // P2WPKH (20-byte) and P2TR (bech32m) decode
    CHECK(ms_addr_to_spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", spk, sizeof(spk)) == 22 && spk[0] == 0x00 && spk[1] == 0x14, "P2WPKH (BIP-173 vector) decodes");
    CHECK(ms_addr_to_spk("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", spk, sizeof(spk)) == 34 && spk[0] == 0x51 && spk[1] == 0x20, "P2TR (BIP-350 vector) decodes as bech32m");
    CHECK(ms_addr_to_spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", spk, sizeof(spk)) == 0, "BIP-173 invalid checksum vector refused");
  }

  // ── 15. crypto-account export + UR round trip ─────────────────────────
  { static uint8_t acct[512]; bip32_xprv a84; uint8_t fp84[4]; bip32_xpub x84;
    CHECK(bip84_derive_account_xprv(MS_KAT_SEED_A, BIP84_NETWORK_MAINNET, &a84, fp84) && bip32_xprv_to_xpub(&a84, &x84), "m/84 xpub for the combined export");
    size_t al = ms_export_crypto_account(our_fp, &x84, &ours, acct, sizeof(acct));
    CHECK(al > 200 && acct[0] == 0xA2, "crypto-account CBOR built");
    hexdump_to_file("out_account.hex", acct, al);
    static char frags[UR_MAX_ENCODE_PARTS][640];
    int nf = ur_encode_message("crypto-account", acct, al, frags, 640, UR_MAX_ENCODE_PARTS);
    CHECK(nf >= 1, "crypto-account fragments into UR");
    static ur_decoder_t d; ur_decoder_reset(&d); int rc = 0;
    for (int i = 0; i < nf; i++) { char line[640]; strcpy(line, frags[i]); rc = ur_feed(&d, line); }
    static uint8_t back[512]; int bl = (rc == 1) ? ur_decoder_result(&d, back, sizeof(back)) : -1;
    CHECK(rc == 1 && bl == (int)al && memcmp(back, acct, al) == 0 && strcmp(d.ur_type, "crypto-account") == 0, "UR encode -> feed -> result round trips (type latched)");
    // single-part form for a small message
    static uint8_t tiny[16] = {0x45,1,2,3,4,5}; int n1 = ur_encode_message("bytes", tiny, 6, frags, 640, 4);
    CHECK(n1 == 1 && strncmp(frags[0], "UR:BYTES/", 9) == 0 && strchr(frags[0] + 9, '/') == NULL, "1-fragment message uses single-part UR form");
    ur_decoder_reset(&d); { char line[640]; strcpy(line, frags[0]); rc = ur_feed(&d, line); }
    bl = (rc == 1) ? ur_decoder_result(&d, back, sizeof(back)) : -1;
    CHECK(rc == 1 && bl == 6 && memcmp(back, tiny, 6) == 0, "single-part UR decodes");
  }

  // ── 16. sealed Bitcoin state (btc_state.h) ────────────────────────────
  { static bst_state_t st, back; static uint8_t scratch[BST_PLAIN_MAX], blob[BST_SEALED_MAX], blob2[BST_SEALED_MAX];
    uint8_t key[32], key2[32];
    CHECK(bst_derive_key(MS_KAT_SEED_A, key), "derive state key from seed");
    uint8_t seed2[64]; memcpy(seed2, MS_KAT_SEED_A, 64); seed2[7] ^= 1; bst_derive_key(seed2, key2);
    CHECK(memcmp(key, key2, 32) != 0, "different seed -> different key");
    bst_init(&st); st.recv_index = 42; st.addr_count = 2;
    strcpy(st.addrs[0].label, "Cold"); strcpy(st.addrs[0].addr, MS_KAT_ADDR_0_0); st.addrs[0].n_sent = 3;
    strcpy(st.addrs[1].label, "Exchange"); strcpy(st.addrs[1].addr, MS_KAT_ADDR_0_5);
    ms_store_add(&st.ms, &w);
    auto rng = [](uint8_t* o, size_t n){ for (size_t i = 0; i < n; i++) o[i] = (uint8_t)rand(); };
    size_t bl = bst_seal(key, &st, rng, scratch, blob, sizeof(blob));
    CHECK(bl > 0 && memcmp(blob, "FBS1", 4) == 0, "seal produces a blob");
    printf("   sealed blob %zu bytes (1 wallet, 2 addresses); BST_SEALED_MAX %d\n", bl, BST_SEALED_MAX);
    bool z = true; for (size_t i = 0; i < BST_PLAIN_MAX; i++) if (scratch[i]) z = false;
    CHECK(z, "plaintext scratch zeroised after seal");
    CHECK(bst_open(key, blob, bl, scratch, &back), "open with right key");
    CHECK(back.recv_index == 42 && back.addr_count == 2 && strcmp(back.addrs[1].label, "Exchange") == 0 && back.addrs[0].n_sent == 3, "address book round trips");
    CHECK(back.ms.count == 1 && back.ms.w[0].valid && back.ms.w[0].n == 3 && memcmp(back.ms.w[0].cs[2].xpub.pubkey, w.cs[2].xpub.pubkey, 33) == 0 && strcmp(back.ms.w[0].name, w.name) == 0, "multisig wallet round trips");
    CHECK(back.ms.w[0].our_index == 0xFF, "our_index is NOT trusted from storage");
    size_t bl2 = bst_seal(key, &st, rng, scratch, blob2, sizeof(blob2));
    CHECK(bl2 == bl && memcmp(blob + 4, blob2 + 4, BST_NONCE_LEN) != 0 && memcmp(blob + 16, blob2 + 16, bl - 16) != 0, "re-seal uses a fresh nonce, different ciphertext");
    memcpy(blob2, blob, bl); blob2[40] ^= 1;
    CHECK(!bst_open(key, blob2, bl, scratch, &back) && back.addr_count == 0 && back.ms.count == 0, "flipped ciphertext byte -> refused, state left EMPTY");
    memcpy(blob2, blob, bl); blob2[bl - 1] ^= 1;
    CHECK(!bst_open(key, blob2, bl, scratch, &back), "flipped tag byte -> refused");
    memcpy(blob2, blob, bl); blob2[5] ^= 1;
    CHECK(!bst_open(key, blob2, bl, scratch, &back), "flipped nonce byte -> refused");
    CHECK(!bst_open(key2, blob, bl, scratch, &back), "wrong seed -> refused");
    CHECK(!bst_open(key, blob, bl - 1, scratch, &back), "truncated -> refused");
    CHECK(!bst_open(key, blob, 20, scratch, &back), "too short -> refused");
    // empty state seals and opens (first BTC life)
    bst_init(&st); bl = bst_seal(key, &st, rng, scratch, blob, sizeof(blob));
    CHECK(bl > 0 && bst_open(key, blob, bl, scratch, &back) && back.addr_count == 0 && back.ms.count == 0 && back.recv_index == 0, "empty state round trips");
    // max state fits the caps
    bst_init(&st); st.addr_count = BST_ADDR_MAX; for (int i = 0; i < 4; i++) { ms_wallet_t x = w; x.cs[0].xpub.chain_code[0] = (uint8_t)i; x.cs[0].xpub.pubkey[5] ^= (uint8_t)i; ms_store_add(&st.ms, &x); }
    bl = bst_seal(key, &st, rng, scratch, blob, sizeof(blob));
    CHECK(bl > 0 && bl <= BST_SEALED_MAX && bst_open(key, blob, bl, scratch, &back) && back.ms.count == st.ms.count && back.addr_count == BST_ADDR_MAX, "maximum state (32 addrs, 4 wallets) fits and round trips");
    printf("   maximum sealed blob %zu bytes\n", bl);
    // a forged plaintext that claims 40 addresses cannot even be sealed
    bst_init(&st); st.addr_count = 40;
    CHECK(bst_seal(key, &st, rng, scratch, blob, sizeof(blob)) == 0, "over-cap address count refused at seal");
  }

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail ? 1 : 0;
}
