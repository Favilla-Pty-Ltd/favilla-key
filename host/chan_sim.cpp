// chan_sim.cpp - the KEY's channel state machine (chan_key.h) on the host, with
// OpenSSL for ECDH/HMAC, driven line by line from stdin. The extension's chan.js
// is tested against this (chan_test.mjs), so both ends speak the same bytes.
//   in:  R <128 hex>   a 64-byte report from the browser
//        D 1|0         the user's answer on the code screen
//        F <status>    the KEY finished the request
//        W 1|0         pairing window open/closed
//        L <life>      1 locked, 2 ready, 3 NOSTR
//        Q             print stats and exit
//   out: R <128 hex>   a report to the browser
//        SHOW <code>   the code screen
//        REQ <cmd> <site>|<user>
// g++ -std=c++17 -O1 -fsanitize=address,undefined -I../../pbuild/src chan_sim.cpp -o chan_sim -lcrypto
#include "chan_key.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <cstdio>
#include <string>
#include <iostream>

static bool hmacFn(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned int n = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &n) != nullptr; }
static EC_KEY* g_me = nullptr;   // this window's key
static void newWindowKey(){ if(g_me) EC_KEY_free(g_me); g_me = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_me); }
static bool myPubFn(uint8_t mine[65]){ if(!g_me) return false; const EC_GROUP* g = EC_KEY_get0_group(g_me); return EC_POINT_point2oct(g, EC_KEY_get0_public_key(g_me), POINT_CONVERSION_UNCOMPRESSED, mine, 65, nullptr) == 65; }
static bool ecdhFn(const uint8_t peer[65], uint8_t z[32]){
  if(!g_me) return false;
  const EC_GROUP* g = EC_KEY_get0_group(g_me);
  EC_POINT* p = EC_POINT_new(g); bool ok = EC_POINT_oct2point(g, p, peer, 65, nullptr) == 1 && EC_POINT_is_on_curve(g, p, nullptr) == 1;
  if(ok) ok = ECDH_compute_key(z, 32, p, g_me, nullptr) == 32;
  EC_POINT_free(p); return ok;
}
static void rngFn(uint8_t* p, size_t n){ RAND_bytes(p, (int)n); }
static bool saveFn(const chan::Client*, int){ return true; }
static uint8_t g_life = chan::L_PASSKEY_READY; static bool g_window = false;
static uint8_t lifeFn(){ return g_life; }
static bool winFn(){ return g_window; }
static uint8_t g_shownId[8];
static bool showFn(uint32_t code, const uint8_t id[8]){ memcpy(g_shownId, id, 8); printf("SHOW %06u\n", code); fflush(stdout); return true; }
static chan::Status reqFn(uint8_t cmd, const char* s, const char* u){ printf("REQ %02x %s|%s\n", cmd, s, u); fflush(stdout); return chan::S_OK; }
static void sendFn(const uint8_t* m, size_t n){
  uint8_t r[16][64]; int k = chan::fragment(m, n, r, 16);
  for(int i = 0; i < k; i++){ printf("R "); for(int j = 0; j < 64; j++) printf("%02x", r[i][j]); printf("\n"); }
  fflush(stdout);
}
int main(){
  chan::Key key; key.h = { hmacFn, myPubFn, ecdhFn, rngFn, saveFn, lifeFn, winFn, showFn, reqFn, sendFn, "sim" };
  chan::Reasm ra; std::string line;
  while(std::getline(std::cin, line)){
    if(line.size() < 1) continue;
    char c = line[0];
    if(c == 'R' && line.size() >= 2 + 128){
      uint8_t r[64]; for(int i = 0; i < 64; i++) r[i] = (uint8_t)std::stoi(line.substr(2 + 2 * i, 2), nullptr, 16);
      int n = ra.feed(r);
      if(n < 0) key.stats[7]++; else if(n > 0) key.process(ra.buf, (size_t)n);
    } else if(c == 'D') key.pairDecision(line.size() > 2 && line[2] == '1', g_shownId);
    else if(c == 'X'){ uint8_t other[8] = {9,9,9,9,9,9,9,9}; key.pairDecision(true, other); }   // a decision for another attempt: ignored
    else if(c == 'F') key.finish((chan::Status)std::stoi(line.substr(2)));
    else if(c == 'W'){ g_window = line.size() > 2 && line[2] == '1'; if(g_window){ newWindowKey(); key.windowOpened(); } else key.windowClosed(); }
    else if(c == 'B'){ key = chan::Key{key}; for(auto& cc : key.cl) cc.ctr = 0; key.afterLoad(); }   // a restart: RAM counters lost, the stored ceiling stays
    else if(c == 'L') g_life = (uint8_t)std::stoi(line.substr(2));
    else if(c == 'Q'){ printf("STATS"); for(int i = 0; i < 8; i++) printf(" %u", key.stats[i]); printf(" clients %d\n", key.count()); return 0; }
  }
  return 0;
}
