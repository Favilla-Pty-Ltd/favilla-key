// libFuzzer (9u): the USB channel (browser extension): chan::Reasm and the
// whole chan::Key state machine on any report stream, with a paired client so
// MAC-valid paths are reachable when the input carries a right MAC.
#include "chan_key.h"
#include <openssl/hmac.h>
#include <cstdlib>
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned n = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &n) != nullptr; }
static bool mp(uint8_t m[65]){ memset(m, 4, 65); return true; }
static bool ec(const uint8_t*, uint8_t z[32]){ memset(z, 9, 32); return true; }
static uint32_t s_rng = 7; static void rg(uint8_t* p, size_t n){ for(size_t i = 0; i < n; i++){ s_rng = s_rng * 1103515245u + 12345u; p[i] = (uint8_t)(s_rng >> 16); } }
static bool sv(const chan::Client*, int){ return true; }
static uint8_t lf(){ return 3; } static bool wn(){ return true; } static bool sh(uint32_t, const uint8_t*){ return true; }
static chan::Status rq(uint8_t, const char* s, const char* u){ if(strlen(s) > chan::FIELD_MAX || strlen(u) > chan::FIELD_MAX) abort(); return chan::S_OK; }
static void sd(const uint8_t* m, size_t n){ if(n > chan::MSG_MAX) abort(); uint8_t r[32][64]; (void)chan::fragment(m, n, r, 32); }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  static chan::Key k; static bool init = false;
  if(!init){ k.h = { hm, mp, ec, rg, sv, lf, wn, sh, rq, sd, "fz" }; init = true; }
  memset(k.cl, 0, sizeof k.cl); k.cl[0].used = 1; memset(k.cl[0].id, 1, chan::ID); memset(k.cl[0].k, 2, chan::KEYLEN);
  chan::Reasm ra;
  for(size_t o = 0; o < n; o += 64){
    uint8_t r[64] = {0}; memcpy(r, d + o, n - o < 64 ? n - o : 64);
    const int m = ra.feed(r); if(m > 0) k.process(ra.buf, (size_t)m);
    if(r[63] == 0xA5) k.finish((chan::Status)(r[62] % 16));
    if(r[63] == 0x5A) k.pairDecision(r[62] & 1, k.pId);
    if(r[63] == 0x33) k.windowOpened();
  }
  return 0;
}
