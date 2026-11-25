// 9f: chan::encBody against an independent Python implementation (the vector
// below was computed with hmac/hashlib, see tests/chan_enc_vector.py). Also
// checks it round-trips, that the keystream differs per rsp / client / ctr,
// and that a long body (3 blocks) works.
#include <cstdio>
#include <cstring>
#include <openssl/hmac.h>
#include "../src/chan_proto.h"
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned l = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &l) != nullptr; }
int main(int argc, char** argv){
  uint8_t k[32], id[8]; for(int i = 0; i < 32; i++) k[i] = (uint8_t)i; for(int i = 0; i < 8; i++) id[i] = (uint8_t)(0xA0 + i);
  uint8_t b[70]; for(int i = 0; i < 70; i++) b[i] = (uint8_t)(i * 3);
  uint8_t e[70]; memcpy(e, b, 70);
  if(!chan::encBody(hm, k, chan::R_LOGIN, id, 7, e, 70)) { puts("FAIL enc"); return 1; }
  for(int i = 0; i < 70; i++) printf("%02x", e[i]); printf("\n");   // compared by the script
  uint8_t d[70]; memcpy(d, e, 70); chan::encBody(hm, k, chan::R_LOGIN, id, 7, d, 70);
  int fails = memcmp(d, b, 70) != 0;
  uint8_t x[70]; memcpy(x, b, 70); chan::encBody(hm, k, chan::R_LIST, id, 7, x, 70); fails += memcmp(x, e, 70) == 0;
  memcpy(x, b, 70); chan::encBody(hm, k, chan::R_LOGIN, id, 8, x, 70); fails += memcmp(x, e, 70) == 0;
  uint8_t id2[8]; memcpy(id2, id, 8); id2[7] ^= 1; memcpy(x, b, 70); chan::encBody(hm, k, chan::R_LOGIN, id2, 7, x, 70); fails += memcmp(x, e, 70) == 0;
  // 11ad: a 9000-byte body crosses block 255; the first 8160 bytes keep the
  // one-byte index (same bytes as before), the rest use [0xFF][i u16 LE].
  { static uint8_t L[9000], E[9000], S[8160]; for(int i = 0; i < 9000; i++) L[i] = (uint8_t)(i * 7 + 1);
    memcpy(E, L, 9000); memcpy(S, L, 8160);
    if(!chan::encBody(hm, k, chan::R_API, id, 9, E, 9000)) { puts("FAIL enc long"); return 1; }
    if(!chan::encBody(hm, k, chan::R_API, id, 9, S, 8160)) { puts("FAIL enc 8160"); return 1; }
    fails += memcmp(E, S, 8160) != 0;   // the old scheme's bytes are untouched
    uint8_t ke[32], in[16], ks[32]; hm(k, 32, (const uint8_t*)"FAVILLA-CHAN-ENC-1", 18, ke);
    in[0] = chan::R_API; memcpy(in + 1, id, 8); chan::put32(in + 9, 9); in[13] = 0xFF; in[14] = 0xFF; in[15] = 0x00;   // block 255
    hm(ke, 32, in, 16, ks); for(int j = 0; j < 32; j++) fails += (uint8_t)(E[8160 + j] ^ L[8160 + j]) != ks[j];
    in[14] = 0x00; in[15] = 0x01; hm(ke, 32, in, 16, ks);   // block 256
    for(int j = 0; j < 32; j++) fails += (uint8_t)(E[8192 + j] ^ L[8192 + j]) != ks[j];
    chan::encBody(hm, k, chan::R_API, id, 9, E, 9000); fails += memcmp(E, L, 9000) != 0;
    uint8_t big[1]; fails += chan::encBody(hm, k, chan::R_API, id, 9, big, 65536) != false; }
  fprintf(stderr, fails ? "FAIL encBody\n" : "C: encBody round-trips; keystream differs per reply kind, counter and client; 9000-byte body: blocks 255+ use [0xFF][i u16]\n");
  (void)argc; (void)argv; return fails;
}
