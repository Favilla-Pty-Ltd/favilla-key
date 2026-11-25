// import_dup_test.cpp - 11bh (bench 17 Nov 2026): an import never replaces an
// entry already on the KEY, and finding it costs a LABEL, not an OPEN. The real
// record store (host/rk_host.cpp, the G0 model with its 32-OPEN budget).
//   g++ -std=c++17 -fsanitize=address,undefined -DARDUINO_USB_CDC_ON_BOOT=1 -DFAVILLA_PK_RESTORABLE=1 -Ihost/inc -Isrc -Ihost -Ilib/ArduinoJson/src tests/import_dup_test.cpp host/rk_host.cpp -lcrypto -o /tmp/id && /tmp/id
#include "../host/inc/Arduino.h"
#include <map>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include "../src/pk_records.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
extern int g_vaultOpenLeft, g_vaultCalls[4]; extern bool g_v15;
int main(){
  using namespace favilla;
  int bad = 0, n = 0;
#define CHECK(c, what) do{ n++; if(!(c)){ printf("FAIL %s\n", what); bad++; } }while(0)
  rk_mount();
  auto mk = [](RkPass& p, const char* site, const char* user, const char* pass, uint8_t origin){ memset(&p, 0, sizeof p); p.slot = -1; strcpy(p.site, site); strcpy(p.user, user); strcpy(p.pass, pass); p.origin = origin; };
  RkPass p; int slot = -1;
  // 40 entries already on the KEY (more than the sitting's 32 OPENs).
  char site[32];
  for(int i = 0; i < 40; i++){ snprintf(site, sizeof site, "site%02d.com", i); mk(p, site, "me", "on-the-key", RK_ORIGIN_OWN); CHECK(rk_pw_save(&p, &slot) == RK_OK, "seed entry saved"); }
  const int before = rk_pw_count();
  const int opens0 = g_vaultOpenLeft, openCalls0 = g_vaultCalls[2];
  // The same 40 in an import: every one kept, no OPEN spent, nothing replaced.
  int kept = 0;
  for(int i = 0; i < 40; i++){ snprintf(site, sizeof site, "site%02d.com", i); mk(p, site, "me", "from-export", RK_ORIGIN_IMPORT); if(rk_pw_save(&p, &slot) == RK_E_EXISTS) kept++; }
  CHECK(kept == 40, "40 duplicates kept, none refused for the budget");
  CHECK(g_vaultOpenLeft == opens0 && g_vaultCalls[2] == openCalls0, "no OPEN for a duplicate");
  CHECK(rk_pw_count() == before, "nothing added");
  { RkPass o{}; int i0 = -1; for(int i = 0; i < rk_pw_count(); i++){ RkLabel L; if(rk_pw_label(i, &L) == RK_OK && !strcmp(L.site, "site07.com")) { i0 = i; break; } }
    CHECK(i0 >= 0 && rk_pw_open(i0, &o) == RK_OK && !strcmp(o.pass, "on-the-key"), "the KEY's password kept"); rk_pw_wipe(&o); }
  // Another username on the same site is a new entry.
  mk(p, "site07.com", "someone-else", "x", RK_ORIGIN_IMPORT); CHECK(rk_pw_save(&p, &slot) == RK_OK && rk_pw_count() == before + 1, "same site, other user: added");
  // A new site is a new entry.
  mk(p, "new.example", "me", "y", RK_ORIGIN_IMPORT); CHECK(rk_pw_save(&p, &slot) == RK_OK && rk_pw_count() == before + 2, "a new site: added");
  // Not an import: a save of the same site and user still replaces (keeps the id).
  mk(p, "site03.com", "me", "changed", RK_ORIGIN_OWN); CHECK(rk_pw_save(&p, &slot) == RK_OK && rk_pw_count() == before + 2, "an own save replaces");
  printf("import_dup: %d checks, %d failures\n", n, bad);
  return bad ? 1 : 0;
}
