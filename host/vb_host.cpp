// Phase 3 host test (2 Nov 2026): the REAL vault_backup.cpp (blob, event, checks)
// and the REAL pk_records.cpp export / merge (rk_host.cpp), with libsecp256k1
// standing in for the ESP32's curve code (vbh_*) and for the G0's k_pub signer.
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "../src/vault_backup.h"
#include "../src/pk_records.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "USBHID.h"
S Serial; std::map<std::string, std::vector<uint8_t>> g_nvs;
namespace favilla { void rk_test_reboot(); }
extern "C" {
void secp256k1_default_illegal_callback_fn(const char* m, void*) { printf("ILLEGAL %s\n", m); }
void secp256k1_default_error_callback_fn(const char* m, void*) { printf("ERROR %s\n", m); }
}
static secp256k1_context* ctx;
bool vbh_xonly_pub(const uint8_t k[32], uint8_t x32[32]) {
  secp256k1_keypair kp; secp256k1_xonly_pubkey xp;
  if (!secp256k1_ec_seckey_verify(ctx, k) || !secp256k1_keypair_create(ctx, &kp, k) || !secp256k1_keypair_xonly_pub(ctx, &xp, nullptr, &kp)) return false;
  secp256k1_xonly_pubkey_serialize(ctx, x32, &xp); return true;
}
bool vbh_schnorr_verify(const uint8_t pub32[32], const uint8_t msg32[32], const uint8_t sig64[64]) {
  secp256k1_xonly_pubkey xp; return secp256k1_xonly_pubkey_parse(ctx, &xp, pub32) && secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &xp);
}
static int pass = 0, fail = 0;
static void check(bool c, const char* m) { (c ? pass : fail)++; printf("%s %s\n", c ? "PASS" : "FAIL", m); }
static void unhex(const char* s, uint8_t* o, size_t n) { for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]); }
static void hexs(const uint8_t* b, size_t n, char* o) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]); }
// the k_pub the G0 would hold for S (same rule as vpub_glue.inc), to sign as the G0 does
static void kpub(const uint8_t spk[32], uint8_t k[32]) {
  uint8_t kv[32]; mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), spk, 32, (const uint8_t*)"FAVILLA-VAULT-v1", 16, kv);
  for (int c = 0; c < 256; c++) { uint8_t m[4] = {'P','U','B',(uint8_t)c}; mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kv, 32, m, 4, k); if (secp256k1_ec_seckey_verify(ctx, k)) return; }
}
static std::string make_event(const uint8_t spk[32], const uint8_t* blob, size_t bn, uint32_t created) {
  uint8_t pub[32], chk[8], k[32], id[32], sig[64]; favilla::vb_derive(spk, pub, chk); kpub(spk, k);
  size_t bl = 0; static unsigned char b64[64 * 1024]; mbedtls_base64_encode(b64, sizeof b64, &bl, blob, bn);
  char ph[65]; hexs(pub, 32, ph);
  favilla::vb_event_id(ph, created, (const char*)b64, bl, id);
  secp256k1_keypair kp; secp256k1_keypair_create(ctx, &kp, k);
  uint8_t aux[32] = {7}; secp256k1_schnorrsig_sign32(ctx, sig, id, &kp, aux);
  static char js[80 * 1024]; size_t n = favilla::vb_event_json(js, sizeof js, id, ph, created, (const char*)b64, bl, sig);
  return std::string(js, n);
}
static int save(const char* site, uint8_t h, const char* name) {
  uint8_t id34[34] = {1, 1}; id34[2] = h; return favilla::rk_save(site, strlen(site), &h, 1, name, strlen(name), "", 0, id34);
}
static int body(uint8_t* b, size_t cap, size_t* n) { int nr = 0, nt = 0; uint32_t g = 0; return favilla::rk_export(b, cap, n, &nr, &nt, &g) ? -1 : nr; }

int main() {
  static unsigned char cbuf[1024]; (void)cbuf;
  setvbuf(stdout, nullptr, _IONBF, 0);
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  // 1. derivation matches the G0 (vector printed by g03b tests/run_vault_test.sh)
  { uint8_t spk[32], pub[32], chk[8], ep[32], ec[8];
    unhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", spk, 32);
    unhex("b4714db3a2db2e34130e9bc3ab09f5d6653f34ad3b064fadd6a783d1b8877f0b", ep, 32);
    unhex("b0237b2f38326721", ec, 8);
    check(favilla::vb_derive(spk, pub, chk) && !memcmp(pub, ep, 32) && !memcmp(chk, ec, 8), "vb_derive: P and the check value equal the G0's PUBSEAL output for the same S_pk"); }
  // the rk_host G0 model's S_pk
  uint8_t S[32] = { 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,
                    0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70 };
  uint8_t P[32], C[8]; favilla::vb_derive(S, P, C);
  favilla::rk_mount();
  static uint8_t b[40 * 1024], blob[40 * 1024]; size_t bn = 0;
  // 2. KEY A: three records, one deleted; export; dirty flags
  check(!favilla::rk_dirty(), "a fresh store is clean");
  save("webauthn.io", 0xA1, "josh"); save("webauthn.io", 0xB2, "alicia"); save("github.com", 0xC3, "jc");
  check(favilla::rk_dirty(), "a saved record marks the store dirty (the backup lacks it)");
  favilla::rk_delete(favilla::rk_slot_at(1));
  int nr = body(b, sizeof b, &bn);
  check(nr == 2 && bn > 2, "export: 2 sealed records and the tombstone, nothing opened");
  size_t blobN = favilla::vb_blob(C, b, bn, blob);
  // 3. blob checks
  { const uint8_t* bd; size_t bdn; uint8_t bad[8]; memcpy(bad, C, 8); bad[0] ^= 1;
    check(favilla::vb_blob_parse(blob, blobN, C, &bd, &bdn) == favilla::VB_OK && bdn == bn, "blob parses with the right check value");
    check(favilla::vb_blob_parse(blob, blobN, bad, &bd, &bdn) == favilla::VB_E_CHECK, "another vault's check value: refused (wrong words)");
    blob[5] = 1; check(favilla::vb_blob_parse(blob, blobN, C, &bd, &bdn) == favilla::VB_E_PASS, "passphrase flag set: refused, never imported empty (D6)"); blob[5] = 0;
    blob[4] = 2; check(favilla::vb_blob_parse(blob, blobN, C, &bd, &bdn) == favilla::VB_E_VERSION, "a newer version: refused"); blob[4] = 1;
    blob[0] = 'X'; check(favilla::vb_blob_parse(blob, blobN, C, &bd, &bdn) == favilla::VB_E_FORMAT, "bad magic: refused"); blob[0] = 'F'; }
  // 4. event: build, check, and every way a relay could lie
  std::string ev = make_event(S, blob, blobN, 1793600000);
  printf("EVENT %s\n", ev.c_str());
  { const char* ca; size_t cn; uint32_t t;
    check(favilla::vb_event_check(ev.data(), ev.size(), P, &ca, &cn, &t) == favilla::VB_OK && t == 1793600000, "our event: author, kind, tags, id and BIP-340 signature check");
    uint8_t Q[32]; memcpy(Q, P, 32); Q[5] ^= 1;
    check(favilla::vb_event_check(ev.data(), ev.size(), Q, &ca, &cn, &t) != favilla::VB_OK, "someone else's key: refused");
    std::string e2 = ev; size_t i = e2.find("\"content\":\"") + 20; e2[i] = e2[i] == 'A' ? 'B' : 'A';
    check(favilla::vb_event_check(e2.data(), e2.size(), P, &ca, &cn, &t) != favilla::VB_OK, "content changed by a relay: refused (id)");
    std::string e3 = ev; size_t j = e3.find("\"sig\":\"") + 7; e3[j] = e3[j] == '0' ? '1' : '0';
    check(favilla::vb_event_check(e3.data(), e3.size(), P, &ca, &cn, &t) != favilla::VB_OK, "signature changed: refused");
    std::string e4 = ev; size_t k = e4.find("favilla-vault"); e4.replace(k, 13, "favilla-vaulx");
    check(favilla::vb_event_check(e4.data(), e4.size(), P, &ca, &cn, &t) != favilla::VB_OK, "another d-tag: refused");
    std::string e5 = ev; size_t m = e5.find("[[\"d\""); e5.insert(m + 1, "[\"p\",\"x\"],");
    check(favilla::vb_event_check(e5.data(), e5.size(), P, &ca, &cn, &t) != favilla::VB_OK, "an extra tag: refused");
    std::string e6 = ev; size_t q = e6.find("30078"); e6.replace(q, 5, "30079");
    check(favilla::vb_event_check(e6.data(), e6.size(), P, &ca, &cn, &t) != favilla::VB_OK, "another kind: refused");
    check(favilla::vb_event_check("{\"id\":1}", 8, P, &ca, &cn, &t) != favilla::VB_OK && favilla::vb_event_check("not json", 8, P, &ca, &cn, &t) != favilla::VB_OK, "junk: refused"); }
  // 5. restore on a wiped KEY (same words): records come back sealed, open, deleted one stays deleted
  { const char* ca; size_t cn; uint32_t t; favilla::vb_event_check(ev.data(), ev.size(), P, &ca, &cn, &t);
    static uint8_t raw[40 * 1024]; size_t rn = 0; mbedtls_base64_decode(raw, sizeof raw, &rn, (const uint8_t*)ca, cn);
    { size_t z; uint8_t tmp[1]; (void)z; (void)tmp; uint32_t g = 0; static uint8_t eb[40*1024]; size_t en; int a, b2; favilla::rk_export(eb, sizeof eb, &en, &a, &b2, &g); favilla::rk_set_clean(g); }
    favilla::rk_wipe_all(); check(favilla::rk_count() == 0, "wiped KEY: no records");
    const uint8_t* bd; size_t bdn; favilla::vb_blob_parse(raw, rn, C, &bd, &bdn);
    favilla::RkImport st{}; int r = favilla::rk_import(bd, bdn, &st);
    check(r == 0 && st.added == 2 && favilla::rk_count() == 2, "restore: both records written as they came");
    favilla::rk_test_reboot();
    favilla::RkAcct a[4]; int n1 = favilla::rk_find("webauthn.io", 11, a, 4), n2 = favilla::rk_find("github.com", 10, a + 1, 3);
    check(n1 == 1 && !strcmp(a[0].name, "josh") && n2 == 1 && !strcmp(a[1].name, "jc"), "restored records open with the same words (sign-in works), the deleted one is gone");
    check(favilla::rk_import(bd, bdn, &st) == 0 && st.added == 0 && st.same == 2 && favilla::rk_count() == 2, "importing the same backup twice changes nothing"); }
  // 6. merge rules: newest wins, tombstones win over older copies, local extras make the store dirty
  { { size_t z; uint8_t tmp[1]; (void)z; (void)tmp; uint32_t g = 0; static uint8_t eb[40*1024]; size_t en; int a, b2; favilla::rk_export(eb, sizeof eb, &en, &a, &b2, &g); favilla::rk_set_clean(g); }
    std::vector<uint8_t> oldBody(b, b + bn);                                  // backup with josh + jc
    save("webauthn.io", 0xA1, "josh-renamed");                                // same handle: replaced, newer
    int nr2 = body(b, sizeof b, &bn); (void)nr2;
    std::vector<uint8_t> newBody(b, b + bn);
    favilla::RkImport st{};
    check(favilla::rk_import(oldBody.data(), oldBody.size(), &st) == 0 && st.added == 0, "an older backup never overwrites a newer record here");
    check(favilla::rk_dirty(), "...and the store stays dirty: the backup lacks the newer one");
    favilla::rk_wipe_all();
    favilla::rk_import(oldBody.data(), oldBody.size(), &st);                  // old state on this KEY
    check(favilla::rk_import(newBody.data(), newBody.size(), &st) == 0 && st.added == 1, "a newer backup updates the record");
    favilla::RkAcct a; favilla::rk_test_reboot(); favilla::rk_find("webauthn.io", 11, &a, 1);
    check(!strcmp(a.name, "josh-renamed"), "...to the newer name");
    // a tombstone made on another KEY removes the record here
    favilla::rk_delete(favilla::rk_slot_at(0)); int nr3 = body(b, sizeof b, &bn); (void)nr3;
    std::vector<uint8_t> tombBody(b, b + bn);
    favilla::rk_wipe_all(); favilla::rk_import(newBody.data(), newBody.size(), &st);
    int before = favilla::rk_count();
    check(favilla::rk_import(tombBody.data(), tombBody.size(), &st) == 0 && st.removed == 1 && favilla::rk_count() == before - 1, "a tombstone from the backup deletes the older record here");
    check(favilla::rk_import(newBody.data(), newBody.size(), &st) == 0 && st.added == 0 && favilla::rk_count() == before - 1, "...and an older backup does not bring it back"); }
  // 7. malformed bodies never change anything
  { favilla::RkImport st{}; int c0 = favilla::rk_count();
    uint8_t junk[64] = {0, 5};
    check(favilla::rk_import(junk, sizeof junk, &st) != 0 && favilla::rk_count() == c0, "a body that does not parse: refused before any write");
    uint8_t shortb[3] = {0, 1, 0};
    check(favilla::rk_import(shortb, 3, &st) != 0 && favilla::rk_count() == c0, "truncated body: refused"); }
  // 8. review fixes (2 Nov 2026)
  { favilla::rk_wipe_all(); save("a.example", 0x01, "a");
    static uint8_t eb[40 * 1024]; size_t en; int nr2, nt2; uint32_t g0 = 0;
    favilla::rk_export(eb, sizeof eb, &en, &nr2, &nt2, &g0);
    save("b.example", 0x02, "b");                                   // lands while the backup is "on its way"
    check(!favilla::rk_set_clean(g0) && favilla::rk_dirty(), "a change after the export keeps the store dirty (not marked as backed up)");
    uint32_t g1 = 0; favilla::rk_export(eb, sizeof eb, &en, &nr2, &nt2, &g1);
    check(favilla::rk_set_clean(g1) && !favilla::rk_dirty(), "...and the next export's backup clears it");
    // a record of another kind: counted as foreign, so a publish must stop
    std::vector<uint8_t> body2(eb, eb + en); body2[2 + 2 + 12] = 7;   // first record's kind byte
    favilla::rk_wipe_all(); favilla::RkImport st{};
    favilla::rk_import(body2.data(), body2.size(), &st);
    check(st.foreign == 1 && st.added == 1, "a record of a kind this firmware does not hold: counted (the publish refuses), the rest imported");
    // a tombstone dated far ahead: ignored
    std::vector<uint8_t> body3(eb, eb + en); size_t tpos = body3.size() - 2;
    body3[tpos] = 0; body3[tpos + 1] = 1; uint8_t tomb[12]; memcpy(tomb, eb + 4, 8); uint32_t far = (uint32_t)time(nullptr) + 30 * 86400;
    tomb[8] = far >> 24; tomb[9] = far >> 16; tomb[10] = far >> 8; tomb[11] = far; body3.insert(body3.end(), tomb, tomb + 12);
    favilla::rk_wipe_all(); st = {};
    favilla::rk_import(body3.data(), body3.size(), &st);
    check(st.future == 1 && favilla::rk_count() == 2, "a tombstone dated 30 days ahead: ignored, the record stays");
    // the same id and time on two KEYs: both orders end with the same bytes
    std::vector<uint8_t> x(eb, eb + en), y(eb, eb + en); y[2 + 2 + 40] ^= 0x5A;   // same header, other bytes
    auto run2 = [&](std::vector<uint8_t>& p, std::vector<uint8_t>& q) { favilla::rk_wipe_all(); favilla::RkImport s2{}; favilla::rk_import(p.data(), p.size(), &s2); favilla::rk_import(q.data(), q.size(), &s2);
      static uint8_t o[40 * 1024]; size_t on; int a, b2; uint32_t g; favilla::rk_export(o, sizeof o, &on, &a, &b2, &g); return std::vector<uint8_t>(o, o + on); };
    check(run2(x, y) == run2(y, x), "equal time on two KEYs: the merge picks the same version in either order"); }
  printf("\n%s (%d passed, %d failed)\n", fail ? "SOME FAILED" : "ALL PASS", pass, fail);
  return fail ? 1 : 0;
}
