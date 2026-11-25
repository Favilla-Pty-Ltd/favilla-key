// health_parts_test.cpp - 11bc (13 Nov 2026): a breach bucket in parts. The real
// record store (host/rk_host.cpp). "password" has SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:
// prefix 5BAA6, suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
//   clang++ -std=c++17 -fsanitize=address,undefined -DARDUINO_USB_CDC_ON_BOOT=1 -DFAVILLA_PK_RESTORABLE=1 -Ihost/inc -Isrc -Ihost -Ilib/ArduinoJson/src tests/health_parts_test.cpp host/rk_host.cpp -lcrypto -o /tmp/hp && /tmp/hp
#include "../host/inc/Arduino.h"
#include <map>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include "../src/pk_records.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
static void pack(const char* hex35, uint8_t out[18]){ memset(out, 0, 18); for(int i = 0; i < 35; i++){ int c = hex35[i]; int v = c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; out[i / 2] |= (i & 1) ? v : v << 4; } }
int main(){
  using namespace favilla;
  int bad = 0, n = 0;
#define CHECK(c, what) do{ n++; if(!(c)){ printf("FAIL %s\n", what); bad++; } }while(0)
  rk_mount();
  RkPass p{}; p.slot = -1; strcpy(p.site, "example.com"); strcpy(p.user, "u"); strcpy(p.pass, "password");
  int slot = -1; CHECK(rk_pw_save(&p, &slot) == 0 && slot >= 0, "saved");
  const uint8_t pre[3] = {0x5B, 0xAA, 0x60};
  uint8_t mine[18], other[18 * 3];
  pack("1E4C9B93F3F0682250B6CF8331B7EE68FD8", mine);
  pack("00000000000000000000000000000000001", other); pack("00000000000000000000000000000000002", other + 18); pack("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", other + 36);
  auto health = [&](){ for(int i = 0; i < rk_pw_count(); i++) if(rk_pw_slot_at(i) == slot) return (int)rk_pw_health(i); return -1; };
  // 1. a whole bucket that holds it
  rk_health_bucket(pre, mine, 1); CHECK((health() & RK_H_BREACHED) && (health() & RK_H_CHECKED), "whole bucket: breached");
  // 2. a whole bucket without it: checked, not breached
  rk_health_bucket(pre, other, 3); CHECK(!(health() & RK_H_BREACHED) && (health() & RK_H_CHECKED), "whole bucket without it: clean");
  // 3. parts: the hit in the first part, the last part without it
  rk_health_bucket(pre, mine, 1, false); CHECK(!(health() & RK_H_BREACHED), "a part decides nothing");
  rk_health_bucket(pre, other, 3, true); CHECK((health() & RK_H_BREACHED) && (health() & RK_H_CHECKED), "hit in an earlier part counts");
  // 4. parts without it anywhere: clean, and the remembered hit was used up
  rk_health_bucket(pre, other, 2, false); rk_health_bucket(pre, other + 36, 1, true);
  CHECK(!(health() & RK_H_BREACHED) && (health() & RK_H_CHECKED), "parts without it: clean");
  // 5. the hit in the last part
  rk_health_bucket(pre, other, 3, false); rk_health_bucket(pre, mine, 1, true); CHECK(health() & RK_H_BREACHED, "hit in the last part");
  // 6. a part's hit is forgotten when the password changes
  rk_health_bucket(pre, mine, 1, false);
  RkPass q{}; q.slot = slot; strcpy(q.site, "example.com"); strcpy(q.user, "u"); strcpy(q.pass, "password");   // saved again (same hash: noted afresh)
  int s2 = -1; rk_pw_save(&q, &s2);
  rk_health_bucket(pre, other, 3, true); CHECK(!(health() & RK_H_BREACHED), "a part from before a save is forgotten");
  printf("health_parts: %d checks, %d failures\n", n, bad);
  return bad ? 1 : 0;
}
