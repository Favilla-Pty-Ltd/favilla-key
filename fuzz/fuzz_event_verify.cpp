// libFuzzer (22 Nov audit): nostrverify::eventOk on arbitrary relay JSON, with
// the srcLen sizing of the preimage buffer (any event ArduinoJson accepts).
#include <ArduinoJson.h>
#include "nostr_verify.h"
#include <cstdlib>
#include <cstring>
static bool vf(const uint8_t*, const uint8_t*, const uint8_t*){ return true; }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  char* in = (char*)malloc(n + 1); memcpy(in, d, n); in[n] = 0;
  JsonDocument doc;
  if(!deserializeJson(doc, in, n)) (void)nostrverify::eventOk(doc.as<JsonVariantConst>(), n, vf);
  free(in); return 0;
}
