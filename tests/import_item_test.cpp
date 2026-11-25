// import_item_test.cpp - 11bf: IMPORT_ITEM's encrypted body and its parser
// (src/chan_proto.h). The ciphers below come from tests/import_item_vector.py,
// which follows the protocol doc's construction with Python hmac/hashlib, not
// the KEY's code. The app checks its side against the same bytes
// (docs/BLE_PASSKEY_PROTOCOL.md, "Import in VAULT mode").
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -I src tests/import_item_test.cpp -lcrypto -o /tmp/imp && /tmp/imp
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
  chan::ImportItem it;
  // A password, ctr 9.
  { uint8_t plain[128], want[128], b[128];
    const int pn = unhex("010a6769746875622e636f6d0a666176696c6c616b65790768756e746572320e66726f6d2042697477617264656e", plain);
    const int cn = unhex("40eecc09628efbdf463d6975b48102cbd1c7754fff37d52cb738766404b6319f6a18b995bf244df0129fc8e0258c", want);
    CHECK(pn == cn, "pw vector lengths");
    memcpy(b, plain, pn);
    CHECK(chan::encBody(hm, k, chan::C_IMPORT_ITEM, id, 9, b, pn) && !memcmp(b, want, pn), "pw encrypts to the Python vector");
    CHECK(chan::encBody(hm, k, chan::C_IMPORT_ITEM, id, 9, b, pn) && !memcmp(b, plain, pn), "pw decrypts back");
    CHECK(chan::parseImportItem(b, pn, &it) && it.kind == chan::IMPORT_PW && !strcmp(it.site, "github.com") && !strcmp(it.user, "favillakey") &&
          !strcmp(it.pass, "hunter2") && !strcmp(it.note, "from Bitwarden"), "pw parses");
    CHECK(!chan::parseImportItem(b, pn - 1, &it) && it.kind == 0 && !it.pass[0], "pw truncated refused and wiped");
    uint8_t c[128]; memcpy(c, plain, pn); c[0] = 3; CHECK(!chan::parseImportItem(c, pn, &it), "unknown kind refused");
    memcpy(c, plain, pn); c[1 + 1 + 10 + 1 + 10] = 0;   // pLen = 0
    CHECK(!chan::parseImportItem(c, pn, &it), "pw with no password refused");
    memcpy(c, plain, pn); c[3] = '\n'; CHECK(!chan::parseImportItem(c, pn, &it), "control character refused");
    memcpy(c, plain, pn); memset(c + 2, ' ', 10); CHECK(!chan::parseImportItem(c, pn, &it), "a site of spaces refused");
    uint8_t r[128]; memcpy(r, want, pn); chan::encBody(hm, k, chan::C_PW_SAVE, id, 9, r, pn);
    CHECK(memcmp(r, plain, pn) != 0, "PW_SAVE's keystream does not open an IMPORT_ITEM"); }
  // A one-time code, ctr 10.
  { uint8_t plain[64], want[64], b[64];
    const int pn = unhex("020a6769746875622e636f6d0a666176696c6c616b6579061e0a48656c6c6f21deadbeef", plain);
    const int cn = unhex("22e22922fd54b25add3423b08cd0d9f747adfcc007fc08df82b00f19b05278715a50a708", want);
    CHECK(pn == cn, "otp vector lengths");
    memcpy(b, plain, pn);
    CHECK(chan::encBody(hm, k, chan::C_IMPORT_ITEM, id, 10, b, pn) && !memcmp(b, want, pn), "otp encrypts to the Python vector");
    chan::encBody(hm, k, chan::C_IMPORT_ITEM, id, 10, b, pn);
    const uint8_t sec[10] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef };
    CHECK(chan::parseImportItem(b, pn, &it) && it.kind == chan::IMPORT_OTP && !strcmp(it.site, "github.com") && !strcmp(it.user, "favillakey") &&
          it.digits == 6 && it.period == 30 && it.secretN == 10 && !memcmp(it.secret, sec, 10), "otp parses");
    uint8_t c[64]; const size_t dOff = 1 + 1 + 10 + 1 + 10;
    memcpy(c, plain, pn); c[dOff] = 5; CHECK(!chan::parseImportItem(c, pn, &it), "5 digits refused");
    memcpy(c, plain, pn); c[dOff] = 9; CHECK(!chan::parseImportItem(c, pn, &it), "9 digits refused");
    memcpy(c, plain, pn); c[dOff + 1] = 0; CHECK(!chan::parseImportItem(c, pn, &it), "period 0 refused");
    memcpy(c, plain, pn); c[dOff + 2] = 0; CHECK(!chan::parseImportItem(c, dOff + 3, &it), "empty secret refused");
    memcpy(c, plain, pn); c[dOff + 2] = 11; CHECK(!chan::parseImportItem(c, pn, &it), "secret length past the end refused");
    uint8_t big[1 + 11 + 11 + 3 + 65]; memcpy(big, plain, dOff + 2); big[dOff + 2] = 65; memset(big + dOff + 3, 7, 65);
    CHECK(!chan::parseImportItem(big, dOff + 3 + 65, &it), "secret over 64 bytes refused");
    big[dOff + 2] = 64; CHECK(chan::parseImportItem(big, dOff + 3 + 64, &it) && it.secretN == 64, "a 64-byte secret accepted"); }
  // Limits shared with PW_SAVE.
  { uint8_t b[1 + 1 + 200 + 4]; memset(b, 'a', sizeof b); b[0] = 1; b[1] = 200; b[202] = 0; b[203] = 1; b[205] = 0;
    CHECK(!chan::parseImportItem(b, 206, &it), "site over 199 refused"); }
  CHECK(!chan::parseImportItem(nullptr, 0, &it), "empty body refused");
  printf("%s: %d of %d checks passed\n", bad ? "FAILED" : "OK", n - bad, n);
  return bad ? 1 : 0;
}
