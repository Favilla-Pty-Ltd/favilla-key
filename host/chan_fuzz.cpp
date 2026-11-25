// Random and mutated reports into Reasm + Key.process: ASan/UBSan find overruns.
#include "chan_key.h"
#include <openssl/hmac.h>
#include <random>
#include <cstdio>
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned n = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &n); }
static bool mp(uint8_t m[65]){ memset(m, 4, 65); return true; }
static bool ec(const uint8_t*, uint8_t z[32]){ memset(z, 9, 32); return true; }
static std::mt19937 R(7);
static void rg(uint8_t* p, size_t n){ for(size_t i = 0; i < n; i++) p[i] = R(); }
static bool sv(const chan::Client*, int){ return true; }
static uint8_t lf(){ return (uint8_t)(1 + R() % 4); }
static bool wn(){ return R() & 1; }
static bool sh(uint32_t, const uint8_t*){ return R() & 1; }
static chan::Status rq(uint8_t, const char* s, const char* u){ if(strlen(s) > 100 || strlen(u) > 100) abort(); return (R() & 1) ? chan::S_OK : chan::S_BUSY; }
static long sent = 0; static void sd(const uint8_t* m, size_t n){ uint8_t r[16][64]; if(chan::fragment(m, n, r, 16) <= 0) abort(); sent++; }
int main(){
  chan::Key k; k.h = { hm, mp, ec, rg, sv, lf, wn, sh, rq, sd, "fz" };
  // one real client so mac-valid paths are reachable
  k.cl[0].used = 1; memset(k.cl[0].id, 1, 8); memset(k.cl[0].k, 2, 32);
  chan::Reasm ra; long done = 0;
  for(int it = 0; it < 400000; it++){
    uint8_t r[64]; rg(r, 64);
    int t = R() % 4; if(t == 0) r[0] = 0x10; else if(t == 1) r[0] = 0x11;
    if(t == 0 && (R() & 1)) { r[1] = R() % 200; r[2] = 0; }
    int n = ra.feed(r); if(n > 0){ k.process(ra.buf, (size_t)n); done++; }
    if(R() % 50 == 0){ // a valid-mac request with a random body
      uint8_t m[300]; size_t bl = R() % 220; uint8_t body[220]; rg(body, bl);
      if(R() & 1){ size_t sl = 1 + R() % 100; body[0] = sl; for(size_t i = 0; i < sl; i++) body[1 + i] = 0x20 + R() % 95; size_t ul = R() % 101; body[1 + sl] = ul; for(size_t i = 0; i < ul; i++) body[2 + sl + i] = 0x20 + R() % 95; bl = 2 + sl + ul; }
      uint32_t ctr = k.cl[0].ctr + 1 + (R() % 2 ? 0 : 0);
      size_t mn = chan::buildRsp(hm, k.cl[0].k, 0x31 + R() % 2, k.cl[0].id, ctr, body, bl, m, sizeof m);
      if(mn){ // re-mac as a request
        uint8_t mac[16]; chan::mac16(hm, k.cl[0].k, "REQ", m, mn - 16, mac); memcpy(m + mn - 16, mac, 16); k.process(m, mn); }
      if(R() % 3 == 0) k.finish((chan::Status)(R() % 14));
      if(R() % 3 == 0) k.pairDecision(R() & 1, k.pId);
      if(R() % 7 == 0) k.windowOpened();
    }
  }
  printf("chan fuzz: %ld messages processed, %ld sent, stats rx %u badmac %u replay %u req %u refused %u badbody %u\n", done, sent, k.stats[0], k.stats[1], k.stats[2], k.stats[4], k.stats[5], k.stats[6]);
}
