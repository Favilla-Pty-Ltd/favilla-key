// event_id_test.cpp - the KEY's NIP-01 event id against Node's JSON.stringify
// (src/nostr_canon.h, 11an, audit finding 1). Reads the vectors that
// tests/event_id_vectors.mjs writes, one JSON line each, and walks the same
// road the KEY walks for /api/sign: parse the request with ArduinoJson,
// re-serialise the event into the staging buffer (as handleApiSign does),
// parse that again (as computeEventId does), write the preimage with
// nostr_canon.h and sha256 it. Every id must match Node's; every "refuse"
// vector must come back 0.
//
//   node tests/event_id_vectors.mjs 3000 > /tmp/ev.jsonl
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -I src -I lib/ArduinoJson/src tests/event_id_test.cpp -lcrypto -o /tmp/evid && /tmp/evid < /tmp/ev.jsonl
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <openssl/sha.h>
#include <ArduinoJson.h>
#include "nostr_canon.h"

static void hex(const unsigned char* b, size_t n, char* out){ for(size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", b[i]); }

int main(){
  std::string line; size_t n = 0, ok = 0, refused = 0, bad = 0;
  static char staging[65536], pre[131072];
  while(std::getline(std::cin, line)){
    n++;
    JsonDocument req;
    if(deserializeJson(req, line)){
      // ArduinoJson's nesting limit: the KEY answers 400 Invalid JSON, which is a refusal too
      if(line.find("\"refuse\":true") != std::string::npos){ refused++; continue; }
      printf("line %zu: vector does not parse\n", n); bad++; continue;
    }
    bool refuse = req["refuse"] | false;
    const char* want = req["id"] | "";
    // handleApiSign: fill in tags when absent, re-serialise into iosSignEvent
    JsonObject evt = req["event"];
    if(!evt.containsKey("tags")) evt["tags"].to<JsonArray>();
    size_t sl = serializeJson(evt, staging, sizeof(staging));
    if(sl == 0 || sl >= sizeof(staging) - 1){ printf("line %zu: staging overflow\n", n); bad++; continue; }
    // computeEventId: parse the staging buffer, write the preimage, hash
    JsonDocument doc;
    if(deserializeJson(doc, staging)){ printf("line %zu: staging does not re-parse\n", n); bad++; continue; }
    const char* pk = doc["pubkey"] | "";
    size_t pl = nostrcanon::eventPreimage(pk, doc["created_at"], doc["kind"], doc["tags"], doc["content"] | "", pre, sizeof(pre));
    if(refuse){
      if(pl == 0){ refused++; continue; }
      printf("line %zu: should have been refused, got %.100s\n", n, pre); bad++; continue;
    }
    if(pl == 0){ printf("line %zu: refused but Node hashed it: %.200s\n", n, line.c_str()); bad++; continue; }
    // the reply writer: what the KEY hands back must be valid JSON that re-parses to the same event
    {
      static char back[65536];
      size_t bl = nostrcanon::serialize(doc.as<JsonVariantConst>(), back, sizeof(back));
      if(bl == 0){ printf("line %zu: reply writer refused a hashable event\n", n); bad++; continue; }
      for(size_t i = 0; i < bl; i++) if((unsigned char)back[i] < 0x20){ printf("line %zu: raw control character in reply\n", n); bad++; break; }
      JsonDocument d2; if(deserializeJson(d2, back)){ printf("line %zu: reply does not parse\n", n); bad++; continue; }
      const char* want_json = req["event_json"] | "";
      if(want_json[0] && strcmp(back, want_json) != 0){ printf("line %zu: reply differs from JSON.stringify\n  want %.200s\n  got  %.200s\n", n, want_json, back); bad++; continue; }
    }
    unsigned char h[32]; SHA256((const unsigned char*)pre, pl, h);
    char got[65]; hex(h, 32, got);
    if(strcmp(got, want) != 0){ printf("line %zu: id mismatch\n  want %s\n  got  %s\n  pre  %.300s\n", n, want, got, pre); bad++; continue; }
    ok++;
  }
  printf("event id: %zu vectors, %zu match Node, %zu refused as required, %zu failures\n", n, ok, refused, bad);
  return (bad == 0 && ok > 0 && refused > 0) ? 0 : 1;
}
