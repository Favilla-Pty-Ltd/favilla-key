// Seeds for the fuzz corpora (9u), built with the KEY's own encoders so the
// fuzzers start from inputs that reach deep: framed app-channel messages, API
// bodies, a real PSBT, its UR parts (single and multi-part), QR texts.
//   clang++ -std=c++17 -Iinc -I../src gen_seeds.cpp -lmbedcrypto -o out/gen && out/gen
#include "ur_psbt.h"
#include "chan_proto.h"
#include <cstdio>
#include <vector>
#include <string>
#include <sys/stat.h>
static void put(const char* dir, const char* name, const void* d, size_t n){
  std::string p = std::string("corpus/") + dir; mkdir("corpus", 0755); mkdir(p.c_str(), 0755);
  p += "/"; p += name; FILE* f = fopen(p.c_str(), "wb"); fwrite(d, 1, n, f); fclose(f);
}
static std::vector<uint8_t> frame(const std::vector<uint8_t>& m){   // as the phone sends it: 0x10 start, 0x11 continue
  std::vector<uint8_t> o; size_t off = 0; uint8_t idx = 0;
  while(off < m.size() || idx == 0){
    uint8_t r[64] = {0};
    if(idx == 0){ r[0] = chan::F_START; r[1] = (uint8_t)m.size(); r[2] = (uint8_t)(m.size() >> 8); size_t c = m.size() < 61 ? m.size() : 61; memcpy(r + 3, m.data(), c); off = c; }
    else { r[0] = chan::F_CONT; r[1] = idx; size_t c = m.size() - off; if(c > 62) c = 62; memcpy(r + 2, m.data() + off, c); off += c; }
    r[63] = 0x01; o.insert(o.end(), r, r + 64); idx++;
  }
  return o;
}
static std::vector<uint8_t> api(uint8_t meth, const char* path, const char* hs, const char* body){
  std::vector<uint8_t> b; b.push_back(meth); size_t pl = strlen(path); b.push_back(pl); b.push_back(pl >> 8); b.insert(b.end(), path, path + pl);
  b.push_back(hs ? 1 : 0); if(hs){ size_t l = strlen(hs); b.push_back(1); b.push_back(l); b.push_back(l >> 8); b.insert(b.end(), hs, hs + l); }
  size_t bl = strlen(body); b.push_back(bl); b.push_back(bl >> 8); b.insert(b.end(), body, body + bl); return b;
}
static std::vector<uint8_t> req(uint8_t cmd, const std::vector<uint8_t>& body){
  std::vector<uint8_t> m; m.push_back(cmd); for(int i = 0; i < 8; i++) m.push_back(1); for(int i = 0; i < 4; i++) m.push_back(i == 3 ? 5 : 0);
  m.insert(m.end(), body.begin(), body.end()); for(int i = 0; i < 16; i++) m.push_back(0xEE); return m;
}
static std::vector<uint8_t> hex(const char* h){ std::vector<uint8_t> o; for(size_t i = 0; h[i] && h[i + 1]; i += 2){ unsigned v; sscanf(h + i, "%2x", &v); o.push_back(v); } return o; }
int main(){
  // API bodies
  auto a1 = api(0x01, "/api/link", nullptr, ""), a2 = api(0x02, "/api/sign?x=1", "sess0123456789abcdef", "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1762560000}");
  auto a3 = api(0x02, "/api/nip-decrypt", "s", "{\"pubkey\":\"00\",\"ciphertext\":\"abc\"}");
  put("api_decode", "link", a1.data(), a1.size()); put("api_decode", "sign", a2.data(), a2.size()); put("api_decode", "decrypt", a3.data(), a3.size());
  // app channel streams: API, FILL, TIME, HELLO, a pairing commit, two messages back to back
  std::vector<uint8_t> login = { 10 }; const char* site = "github.com"; login.insert(login.end(), site, site + 10); login.push_back(4); const char* u = "josh"; login.insert(login.end(), u, u + 4);
  std::vector<uint8_t> t8 = { 0, 0, 0, 0, 0x69, 0x0E, 0x60, 0x00 };
  auto s1 = frame(req(0x3A, a2)), s2 = frame(req(0x34, login)), s3 = frame(req(0x39, t8));
  std::vector<uint8_t> hello = { 0x33 }; for(int i = 0; i < 40; i++) hello.push_back(i);
  std::vector<uint8_t> commit = { 0x31 }; for(int i = 0; i < 33 + 32; i++) commit.push_back(i * 7);
  auto s4 = frame(hello), s5 = frame(commit); std::vector<uint8_t> s6 = s1; s6.insert(s6.end(), s2.begin(), s2.end());
  put("app_channel", "api_sign", s1.data(), s1.size()); put("app_channel", "fill", s2.data(), s2.size()); put("app_channel", "time", s3.data(), s3.size());
  put("app_channel", "hello", s4.data(), s4.size()); put("app_channel", "commit", s5.data(), s5.size()); put("app_channel", "two", s6.data(), s6.size());
  put("chan_key", "hello", s4.data(), s4.size()); put("chan_key", "commit", s5.data(), s5.size()); put("chan_key", "fill", s2.data(), s2.size());
  // a real PSBT: BIP-174's first test vector with a P2WPKH input (one in, two out)
  auto psbt = hex("70736274ff0100710200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000");
  put("psbt", "bip174_v1", psbt.data(), psbt.size());
  // its UR parts: single-part and multi-part (with fountain parts), one QR text per line
  static char fr[UR_MAX_ENCODE_PARTS][640];
  for(size_t fb : { 0u, 60u, 120u }){
    g_ur_frag_bytes = fb ? fb : UR_ENCODE_FRAG_MAX;
    int k = ur_encode_psbt(psbt.data(), psbt.size(), fr, 640, UR_MAX_ENCODE_PARTS);
    std::string all; for(int i = 0; i < k; i++){ all += fr[i]; all += "\n"; }
    char nm[32]; snprintf(nm, sizeof nm, "psbt_%zu_parts_%d", fb, k); put("ur", nm, all.data(), all.size());
  }
  // QR texts
  const char* otp[] = { "otpauth://totp/GitHub:josh?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub", "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=60" };
  for(int i = 0; i < 2; i++){ char nm[8]; snprintf(nm, sizeof nm, "o%d", i); put("otpauth", nm, otp[i], strlen(otp[i])); }
  const char* lq[] = { "favilla:login?v=1&s=github.com&u=josh", "FAVILLA:LOGIN?V=1&S=MY%20BANK&U=A+B%40X.COM" };
  for(int i = 0; i < 2; i++){ char nm[8]; snprintf(nm, sizeof nm, "l%d", i); put("login_qr", nm, lq[i], strlen(lq[i])); }
  printf("seeds written\n");
}
