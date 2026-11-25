// libFuzzer (11an): nostrcanon::eventPreimage on arbitrary JSON. Any input
// ArduinoJson accepts must produce a terminated preimage that re-parses as a
// six-element array, or 0; never a read or write past the buffer.
#include <ArduinoJson.h>
#include "nostr_canon.h"
#include <cstdlib>
#include <cstring>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  if(n < 1) return 0;
  const size_t cap = 16 + (d[0] * 64);   // small buffers too, so the fit check is exercised
  char* in = (char*)malloc(n); memcpy(in, d + 1, n - 1); in[n - 1] = 0;
  JsonDocument doc;
  if(!deserializeJson(doc, in)){
    char* out = (char*)malloc(cap);
    size_t w = nostrcanon::eventPreimage(doc["pubkey"] | "", doc["created_at"], doc["kind"], doc["tags"], doc["content"] | "", out, cap);
    if(w){
      if(w >= cap || out[w] != 0 || strlen(out) != w) abort();
      JsonDocument back; if(deserializeJson(back, out) || !back.is<JsonArray>() || back.as<JsonArray>().size() != 6) abort();
    }
    // the reply writer on the whole document: valid JSON with no raw control characters, or 0
    size_t w2 = nostrcanon::serialize(doc.as<JsonVariantConst>(), out, cap);
    if(w2){
      if(w2 >= cap || out[w2] != 0 || strlen(out) != w2) abort();
      for(size_t i = 0; i < w2; i++) if((unsigned char)out[i] < 0x20) abort();
      JsonDocument back; if(deserializeJson(back, out)) abort();
    }
    free(out);
  }
  free(in); return 0;
}
