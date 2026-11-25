// 11bl (issues #41, #45): src/nostr_verify.h, the check the KEY now makes on
// every NIP-46 envelope and every NIP-17 seal, against events signed by the
// BIP-340 reference code (tests/event_verify_vectors.py) and tampered copies.
// The verifier is the KEY's own (secp256k1.h + antiexfil_host.h schnorr_verify).
//   python3 tests/event_verify_vectors.py 300 > /tmp/evv.jsonl
//   g++ -std=c++17 -Wno-deprecated-declarations -fsanitize=address,undefined -Ifuzz/inc -Isrc -Ilib/ArduinoJson/src tests/event_verify_test.cpp -lmbedcrypto -o /tmp/evv && /tmp/evv < /tmp/evv.jsonl
#include <cstdio>
#include <iostream>
#include <string>
#include "secp256k1.h"
#include "antiexfil_host.h"
#include "nostr_verify.h"
bool (*g_nostr_ecdh_hook)(const uint8_t peer_xonly32[32], uint8_t shared[32]) = nullptr;   // secp256k1.h wants it; unused here

static bool verifyFn(const uint8_t p[32], const uint8_t m[32], const uint8_t s[64]) { return schnorr_verify(p, m, s); }

int main() {
  std::string line; int n = 0, fail = 0, good = 0;
  while (std::getline(std::cin, line)) {
    JsonDocument d; if (deserializeJson(d, line)) { printf("bad vector line\n"); return 1; }
    std::string ev; serializeJson(d["event"], ev);
    JsonDocument e; deserializeJson(e, ev);
    const bool want = d["ok"].as<bool>();
    const bool got = nostrverify::eventOk(e.as<JsonVariantConst>(), ev.size(), verifyFn);
    n++; if (want) good++;
    if (got != want) { fail++; printf("FAIL (%s): want %d got %d\n", d["why"].as<const char*>(), want, got); }
  }
  { JsonDocument e; deserializeJson(e, "[1,2]"); if (nostrverify::eventOk(e.as<JsonVariantConst>(), 5, verifyFn)) { fail++; printf("FAIL: array accepted\n"); } n++; }
  printf("event_verify: %d vectors (%d signed), %d failures\n", n, good, fail);
  return (fail || good == 0) ? 1 : 0;
}
