// libFuzzer (11ah): the app's pairing QR parser (app_pair_qr.h). Also a few
// fixed vectors: the shape the app draws must parse, and near misses must not.
#include <stdint.h>
#include "app_pair_qr.h"
#include <cstdlib>
#include <cstdio>
static void vectors(){
  static bool done = false; if(done) return; done = true;
  char q[260]; uint8_t e[65], nn[16];
  char p[131]; p[0] = '0'; p[1] = '4'; for(int i = 2; i < 130; i++) p[i] = "0123456789abcdef"[i % 16]; p[130] = 0;
  snprintf(q, sizeof q, "favilla:pair?v=1&p=%s&n=00112233445566778899aabbccddeeff", p);
  if(apppairqr::parse(q, strlen(q), e, nn) != apppairqr::OK || e[0] != 0x04) abort();
  if(nn[0] != 0x00 || nn[15] != 0xff) abort();
  snprintf(q, sizeof q, "FAVILLA:PAIR?n=00112233445566778899AABBCCDDEEFF&p=%s&v=1&x=ignored", p);
  if(apppairqr::parse(q, strlen(q), e, nn) != apppairqr::OK) abort();
  snprintf(q, sizeof q, "favilla:pair?v=2&p=%s&n=00112233445566778899aabbccddeeff", p);
  if(apppairqr::parse(q, strlen(q), e, nn) != apppairqr::E_VERSION) abort();
  snprintf(q, sizeof q, "favilla:pair?v=1&n=00112233445566778899aabbccddeeff");
  if(apppairqr::parse(q, strlen(q), e, nn) != apppairqr::E_NO_KEY) abort();
  p[1] = '2';   // compressed prefix: refused, the QR carries the uncompressed key
  snprintf(q, sizeof q, "favilla:pair?v=1&p=%s&n=00112233445566778899aabbccddeeff", p);
  if(apppairqr::parse(q, strlen(q), e, nn) != apppairqr::E_BAD) abort();
  if(apppairqr::parse("favilla:recovery?v=1", 20, e, nn) != apppairqr::NOT_PAIR) abort();
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  vectors();
  char* in = (char*)malloc(n + 1); memcpy(in, d, n); in[n] = 0;
  uint8_t e[65], nn[16];
  int r = apppairqr::parse(in, n, e, nn);
  if(r == apppairqr::OK && e[0] != 0x04) abort();
  free(in); return 0;
}
