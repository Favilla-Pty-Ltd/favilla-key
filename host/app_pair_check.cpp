// Runs the KEY's chan::derive and chan::commitment on tests/app_pair_vector.py's
// inputs and checks K, the code and the commitment match.
//   python3 tests/app_pair_vector.py | grep CHECK | g++ ... && ./a.out
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <openssl/hmac.h>
#include "../src/chan_proto.h"
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned n = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &n) != nullptr; }
static void hex(const char* s, uint8_t* o, size_t n){ for(size_t i = 0; i < n; i++){ unsigned v; sscanf(s + 2 * i, "%2x", &v); o[i] = (uint8_t)v; } }
int main(){
  char w[8], zs[80], es[140], ks[140], ns[40], Ks[80], Cs[80]; unsigned long code;
  if(scanf("%7s %79s %139s %139s %39s %79s %lu %79s", w, zs, es, ks, ns, Ks, &code, Cs) != 8){ puts("FAIL  read the vector"); return 1; }
  uint8_t z[32], e[65], kp[65], no[16], Kw[32], Cw[32], K[32], C[32]; uint32_t c = 0;
  hex(zs, z, 32); hex(es, e, 65); hex(ks, kp, 65); hex(ns, no, 16); hex(Ks, Kw, 32); hex(Cs, Cw, 32);
  int fail = 0;
  if(!chan::derive(hm, z, e, kp, K, &c)){ puts("FAIL  derive"); return 1; }
  if(memcmp(K, Kw, 32)){ puts("FAIL  K differs"); fail++; } else puts("PASS  K: the KEY's derive matches the worked example");
  if(c != code){ printf("FAIL  code %u vs %lu\n", c, code); fail++; } else printf("PASS  code %03u %03u matches\n", c / 1000, c % 1000);
  if(!chan::commitment(hm, e, no, C) || memcmp(C, Cw, 32)){ puts("FAIL  commitment"); fail++; } else puts("PASS  commitment matches");
  return fail;
}
