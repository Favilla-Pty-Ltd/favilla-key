// libFuzzer (9u, 8 Nov 2026): the Bluetooth app channel as a phone reaches it.
// The input is a stream of 64-byte reports (what an iPhone writes to 8F1A0005),
// fed through the real reassembly (chan::appRxFeed); each whole message goes
// through the real request split, the login and API decoders, and, for the
// pairing and HELLO commands, the real chan::Key state machine (pairing has no
// MAC yet, so that is the surface open to any phone that can connect).
#include "chan_key.h"
#include <openssl/hmac.h>
#include <cstdlib>
#include <cctype>
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned n = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &n) != nullptr; }
static bool mp(uint8_t m[65]){ memset(m, 4, 65); return true; }
static bool ec(const uint8_t*, uint8_t z[32]){ memset(z, 9, 32); return true; }
static uint32_t s_rng = 1; static void rg(uint8_t* p, size_t n){ for(size_t i = 0; i < n; i++){ s_rng = s_rng * 1103515245u + 12345u; p[i] = (uint8_t)(s_rng >> 16); } }
static bool sv(const chan::Client*, int){ return true; }
static uint8_t lf(){ return 3; }
static bool wn(){ return true; }
static bool sh(uint32_t, const uint8_t*){ return true; }
static chan::Status rq(uint8_t, const char* s, const char* u){ if(strlen(s) > chan::FIELD_MAX || strlen(u) > chan::FIELD_MAX) abort(); return chan::S_OK; }
static void sd(const uint8_t* m, size_t n){ if(n > chan::MSG_MAX) abort(); uint8_t r[32][64]; (void)chan::fragment(m, n, r, 32); }
static uint8_t* s_rx;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(!s_rx) s_rx = (uint8_t*)malloc(chan::APP_MAX);   // exactly APP_MAX, as the KEY's PSRAM buffer: ASan sees any overrun
  static chan::Key k; static bool init = false;
  if(!init){ k.h = { hm, mp, ec, rg, sv, lf, wn, sh, rq, sd, "fz" }; init = true; }
  memset(k.cl, 0, sizeof k.cl); k.cl[0].used = 1; memset(k.cl[0].id, 1, chan::ID); memset(k.cl[0].k, 2, chan::KEYLEN);
  chan::AppRx st; uint32_t now = 1000;
  for(size_t o = 0; o + 1 <= size; o += 64){
    uint8_t r[64] = {0}; const size_t c = size - o < 64 ? size - o : 64; memcpy(r, data + o, c);
    now += r[63] & 0x0F ? 10 : 4000;   // now and then a gap long enough to drop a half-sent message
    const int f = chan::appRxFeed(st, s_rx, r, now);
    if(f < 0) continue;
    if(f == 0) { if(st.have > st.want || st.want > chan::APP_MAX) abort(); continue; }
    const size_t n = st.want; st.want = 0;
    const uint8_t cmd = s_rx[0];
    if(cmd == chan::C_PAIR_COMMIT || cmd == chan::C_PAIR_REVEAL || cmd == chan::C_HELLO){ if(n <= chan::MSG_MAX) k.process(s_rx, n); continue; }
    chan::Req q; if(!chan::splitReq(s_rx, n, &q)) continue;
    if(q.body + q.bodyLen > s_rx + n) abort();
    char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1];
    if(chan::parseLogin(q.body, q.bodyLen, site, user) && (strlen(site) < 1 || strlen(site) > chan::FIELD_MAX)) abort();
    {   // 11ax: PW_SAVE's body (the fuzzer feeds it in the clear; the KEY decrypts first)
      uint8_t id[chan::ID]; char ps[chan::VAULT_SITE_MAX + 1], pu[chan::VAULT_FIELD_MAX + 1], pp[chan::VAULT_FIELD_MAX + 1], pn[chan::VAULT_FIELD_MAX + 1];
      uint8_t fl = 0xFF;
      if(chan::parsePwSave(q.body, q.bodyLen, id, ps, pu, pp, pn, &fl)){
        const size_t a = strlen(ps), b = strlen(pu), c = strlen(pp), d = strlen(pn);
        if(a < 1 || a > chan::VAULT_SITE_MAX || b > chan::VAULT_FIELD_MAX || c > chan::VAULT_FIELD_MAX || d > chan::VAULT_FIELD_MAX) abort();
        if(fl & ~chan::PW_KEEP_OLD) abort();   // 11bi: only the known flag
        if(chan::ID + 4 + a + b + c + d != q.bodyLen && chan::ID + 4 + a + b + c + d + 1 != q.bodyLen) abort();
        if(!chan::utf8Text((const uint8_t*)ps, a) || !chan::utf8Text((const uint8_t*)pu, b) || !chan::utf8Text((const uint8_t*)pp, c) || !chan::utf8Text((const uint8_t*)pn, d)) abort();
      }
    }
    {   // 11bf: IMPORT_ITEM's body (in the clear here; the KEY decrypts first)
      chan::ImportItem it;
      if(chan::parseImportItem(q.body, q.bodyLen, &it)){
        const size_t a = strlen(it.site), b = strlen(it.user), c = strlen(it.pass), d = strlen(it.note);
        if(a < 1 || a > chan::VAULT_SITE_MAX || b > chan::VAULT_FIELD_MAX || c > chan::VAULT_FIELD_MAX || d > chan::VAULT_FIELD_MAX) abort();
        if(it.kind == chan::IMPORT_PW && (c < 1 || 1 + 4 + a + b + c + d != q.bodyLen)) abort();
        if(it.kind == chan::IMPORT_OTP && (c || d || it.digits < 6 || it.digits > 8 || !it.period || it.secretN < 1 || it.secretN > chan::IMPORT_SECRET_MAX || 1 + 2 + a + b + 3 + it.secretN != q.bodyLen)) abort();
        if(it.kind != chan::IMPORT_PW && it.kind != chan::IMPORT_OTP) abort();
      } else if(it.kind || it.site[0] || it.secretN) abort();   // a refusal leaves nothing behind
    }
    {   // 11bi: GEN_PW's rules
      chan::GenPwRules g;
      if(chan::parseGenPw(q.body, q.bodyLen, &g)){
        if(g.minLen < chan::GEN_LEN_MIN || g.maxLen > chan::GEN_LEN_MAX || g.minLen > g.maxLen) abort();
        if((g.required & ~g.allowed) || !(g.allowed & 0x07) || (g.allowed & ~0x0F)) abort();
        if(g.sN > chan::GEN_SPECIALS_MAX || strlen(g.specials) != g.sN || ((g.allowed & 0x08) != 0) != (g.sN != 0)) abort();
        for(size_t i = 0; i < g.sN; i++){ const char x = g.specials[i]; if(x < 0x21 || x > 0x7E || isalnum((unsigned char)x)) abort(); }
      }
    }
    chan::ApiReq a;
    if(chan::apiDecode(q.body, q.bodyLen, &a)){
      if(a.pathLen > a.fullLen || a.fullLen > 2048 || (const uint8_t*)a.full + a.fullLen > q.body + q.bodyLen) abort();
      if(a.body + a.bodyLen != q.body + q.bodyLen || a.bodyLen > chan::API_BODY_MAX) abort();
      for(int i = 1; i <= 3; i++) if(a.hv[i] && (a.hl[i] > 1024 || (const uint8_t*)a.hv[i] + a.hl[i] > q.body + q.bodyLen)) abort();
    }
  }
  return 0;
}
