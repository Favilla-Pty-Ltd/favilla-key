// pw_save_test.cpp - 11ax (issue #30): PW_SAVE's encrypted body and its parser
// (src/chan_proto.h). The cipher below was computed independently with Python
// hmac/hashlib (the same construction as tests/chan_enc_vector.py, cmd 0x47 in
// the answer byte's place). The app checks its side against the same bytes
// (docs/BLE_PASSKEY_PROTOCOL.md, VAULT mode edits).
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -I src tests/pw_save_test.cpp -lcrypto -o /tmp/pws && /tmp/pws
#include <cstdio>
#include <cstring>
#include <openssl/hmac.h>
#include "chan_proto.h"
static bool hm(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]){ unsigned l = 32; return HMAC(EVP_sha256(), k, (int)kl, d, dl, out, &l) != nullptr; }
static int unhex(const char* h, uint8_t* o){ int n = 0; for(; h[0] && h[1]; h += 2) { unsigned v; sscanf(h, "%2x", &v); o[n++] = (uint8_t)v; } return n; }
int main(){
  int bad = 0, n = 0;
#define CHECK(c, what) do{ n++; if(!(c)){ printf("FAIL %s\n", what); bad++; } }while(0)
  uint8_t k[32], id[8]; for(int i = 0; i < 32; i++) k[i] = (uint8_t)i; for(int i = 0; i < 8; i++) id[i] = (uint8_t)(0xA0 + i);
  uint8_t plain[64], want[64], b[64];
  const int pn = unhex("00000000000000000970726f746f6e2e6d650a666176696c6c616b65790768756e7465723200", plain);
  const int cn = unhex("2ecc7f5386084dacbafe031c7f0a0a26a881f92d9ac2ea98b02fc77c89b62f713c3a64d57f01", want);
  CHECK(pn == cn, "vector lengths");
  memcpy(b, plain, pn);
  CHECK(chan::encBody(hm, k, chan::C_PW_SAVE, id, 7, b, pn) && !memcmp(b, want, pn), "encrypts to the Python vector");
  CHECK(chan::encBody(hm, k, chan::C_PW_SAVE, id, 7, b, pn) && !memcmp(b, plain, pn), "decrypts back");
  uint8_t pid[8]; char s[200], u[129], p[129], no[129];
  CHECK(chan::parsePwSave(b, pn, pid, s, u, p, no) && !strcmp(s, "proton.me") && !strcmp(u, "favillakey") && !strcmp(p, "hunter2") && !no[0], "parses");
  uint8_t r[64]; memcpy(r, want, pn); chan::encBody(hm, k, chan::R_ACK, id, 7, r, pn);
  CHECK(memcmp(r, plain, pn) != 0, "an answer's keystream does not open a request body");
  CHECK(!chan::parsePwSave(b, pn - 1, pid, s, u, p, no), "truncated refused");
  b[8] = 0; CHECK(!chan::parsePwSave(b, pn, pid, s, u, p, no), "empty site refused");
  // a field over its limit, a control character, bad UTF-8
  uint8_t big[8 + 4 + 200]; memset(big, 0, sizeof big); big[8] = 200; memset(big + 9, 'a', 200);
  CHECK(!chan::parsePwSave(big, 8 + 1 + 200 + 3, pid, s, u, p, no), "site over 199 refused");
  memcpy(b, plain, pn); b[10] = '\n'; CHECK(!chan::parsePwSave(b, pn, pid, s, u, p, no), "control character refused");
  memcpy(b, plain, pn); b[10] = 0xC3; CHECK(!chan::parsePwSave(b, pn, pid, s, u, p, no), "broken UTF-8 refused");
  // 11az: NEW_LOGIN's form byte rides on the login body (parseLogin); chan_key
  // takes it only on a new login. The extension's bytes for account.proton.me /
  // favillakey on a sign-up page with a confirm box: form 0x85.
  { uint8_t lb[64]; const int ln = unhex("116163636f756e742e70726f746f6e2e6d650a666176696c6c616b657985", lb);
    char ls[101], lu[101]; uint8_t f = 0;
    CHECK(chan::parseLogin(lb, ln, ls, lu, &f) && f == 0x85 && !strcmp(ls, "account.proton.me") && !strcmp(lu, "favillakey") && chan::formByte(f), "form byte 0x85 parses");
    lb[ln - 1] = 0x9F; CHECK(chan::parseLogin(lb, ln, ls, lu, &f) && f == 0x9F, "every form bit");
    lb[ln - 1] = 0xA0; CHECK(!chan::parseLogin(lb, ln, ls, lu, &f), "bit 5 refused");
    lb[ln - 1] = 0xC0; CHECK(!chan::parseLogin(lb, ln, ls, lu, &f), "bit 6 refused");
    lb[ln - 1] = 0x03; CHECK(!chan::parseLogin(lb, ln, ls, lu, &f), "fields 3 refused");
    lb[ln - 1] = 0x02; CHECK(chan::parseLogin(lb, ln, ls, lu, &f) && f == 2 && !chan::formByte(f), "fields 2 is not a form byte");
    CHECK(chan::parseLogin(lb, ln - 1, ls, lu, &f) && f == 0, "no last byte"); }
  printf("pw_save: %d checks, %d failures\n", n, bad);
  return bad ? 1 : 0;
}
