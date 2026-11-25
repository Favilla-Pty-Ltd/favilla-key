// libFuzzer (11t, 10 Nov 2026): the vault RESTORE path as the phone now feeds it
// over Bluetooth (VAULT_PUT 0x42) and as a relay fed it before: the event JSON
// through vb_event_check (ArduinoJson on hostile input), base64, vb_blob_parse,
// and rk_import into the REAL record store (host/rk_host.cpp). The Schnorr
// check is stubbed true so the fuzzer reaches everything behind the signature.
// Input: [byte 0: flags (bit0 wrong check value, bit1 drop the OPEN budget)][event JSON]
#include "../host/inc/Arduino.h"
#include <map>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include "mbedtls/base64.h"
#include "../src/vault_backup.h"
#include "../src/pk_records.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
extern bool g_vaultPresent; extern int g_vaultOpenLeft;
bool vbh_xonly_pub(const uint8_t k[32], uint8_t pub[32]){ memcpy(pub, k, 32); return true; }
bool vbh_schnorr_verify(const uint8_t*, const uint8_t*, const uint8_t*){ return true; }
static uint8_t s_pub[32], s_chk[8];
extern "C" int LLVMFuzzerInitialize(int*, char***){
  favilla::rk_mount();
  uint8_t spk[32]; for(int i = 0; i < 32; i++) spk[i] = (uint8_t)(0x51 + i);
  favilla::vb_derive(spk, s_pub, s_chk);
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size < 1) return 0;
  const uint8_t fl = data[0]; const char* json = (const char*)data + 1; const size_t n = size - 1;
  static unsigned runs = 0; runs++;
  if((runs & 0x3FF) == 0) favilla::rk_wipe_all();
  g_vaultOpenLeft = (fl & 2) ? 0 : 32;
  const char* ct; size_t cn; uint32_t at;
  int e = favilla::vb_event_check(json, n, s_pub, &ct, &cn, &at);
  if(e) return 0;
  if(ct < json || ct + cn > json + n) abort();   // content must point inside the input
  size_t cap = cn / 4 * 3 + 4, rn = 0;
  uint8_t* raw = (uint8_t*)malloc(cap);
  if(rn > favilla::VB_BLOB_MAX) abort();
  if(!mbedtls_base64_decode(raw, cap, &rn, (const uint8_t*)ct, cn)){
    uint8_t chk[8]; memcpy(chk, s_chk, 8); if(fl & 1) chk[0] ^= 1;
    if(fl & 4){   // re-wrap whatever the fuzzer produced as a blob with the right header, so rk_import sees it
      uint8_t* w = (uint8_t*)malloc(rn + favilla::VB_HDR + 1); size_t wn = favilla::vb_blob(chk, raw, rn, w);
      free(raw); raw = w; rn = wn;
    }
    const uint8_t* body; size_t bn;
    int pe = favilla::vb_blob_parse(raw, rn, chk, &body, &bn);
    if(!pe){
      if(body < raw || body + bn > raw + rn) abort();
      favilla::RkImport st{}; favilla::rk_import(body, bn, &st);
      if(st.added < 0 || st.removed < 0 || st.added > favilla::RK_MAX) abort();
    }
  }
  free(raw);
  return 0;
}
