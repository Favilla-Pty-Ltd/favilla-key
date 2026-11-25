// 24 Nov 2026: the breach-check floor. A bucket with too few suffixes (an
// empty or failed fetch) must not record "checked, not breached"; a real-sized
// bucket must; parts are counted together; `vault recheck` sends clean
// verdicts back to pending and keeps breached ones.
// Build: see the line at the end of fuzz/build.sh (health_floor_test).
#include "../host/inc/Arduino.h"
#include <map>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <openssl/sha.h>
#include "../src/pk_records.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
extern bool g_vaultPresent; extern int g_vaultOpenLeft;
using namespace favilla;
static int fails = 0;
#define CHECK(c, msg) do{ if(!(c)){ printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } else printf("ok:   %s\n", msg); }while(0)
static int save(const char* site, const char* pass){
  RkPass* p = (RkPass*)calloc(1, sizeof(RkPass)); p->slot = -1; p->origin = 2;
  strcpy(p->site, site); strcpy(p->user, "u"); strcpy(p->pass, pass);
  int slot = -1; rk_pw_save(p, &slot); rk_pw_wipe(p); free(p); return slot;
}
static void openSlot(int slot){   // an open puts the password's hash in RAM, as a sign-in does
  RkPass* p = (RkPass*)calloc(1, sizeof(RkPass));
  for(int i = 0; i < rk_pw_count(); i++) if(rk_pw_slot_at(i) == slot){ rk_pw_open(i, p); break; }
  rk_pw_wipe(p); free(p);
}
static void suffixOf(const char* pass, uint8_t pre[3], uint8_t suf[18]){
  uint8_t h[20]; SHA1((const uint8_t*)pass, strlen(pass), h);
  pre[0] = h[0]; pre[1] = h[1]; pre[2] = h[2] & 0xF0;
  suf[0] = (uint8_t)((h[2] & 0x0F) << 4 | (h[3] >> 4));
  for(int i = 1; i < 17; i++) suf[i] = (uint8_t)((h[i + 2] & 0x0F) << 4 | (h[i + 3] >> 4));
  suf[17] = (uint8_t)((h[19] & 0x0F) << 4);
}
static std::vector<uint8_t> filler(int n, int seed){ std::vector<uint8_t> v((size_t)n * 18); for(size_t i = 0; i < v.size(); i++) v[i] = (uint8_t)(i * 31 + seed * 7 + 1); for(int k = 0; k < n; k++) v[k * 18 + 17] &= 0xF0; return v; }
static uint8_t health(int slot){ for(int i = 0; i < rk_pw_count(); i++) if(rk_pw_slot_at(i) == slot) return rk_pw_health(i); return 0xFF; }
int main(){
  rk_mount(); g_vaultOpenLeft = 32;
  const int a = save("a.example", "correct horse battery staple 1");
  const int b = save("b.example", "correct horse battery staple 2");
  const int c = save("c.example", "correct horse battery staple 3");
  openSlot(a); openSlot(b); openSlot(c);
  uint8_t pa[3], sa[18], pb[3], sb[18], pc[3], sc[18];
  suffixOf("correct horse battery staple 1", pa, sa); suffixOf("correct horse battery staple 2", pb, sb); suffixOf("correct horse battery staple 3", pc, sc);
  // 1. the bench case: an empty bucket
  CHECK(rk_health_bucket(pa, nullptr, 0, true) == -1, "empty bucket refused (-1)");
  CHECK(!(health(a) & RK_H_CHECKED), "empty bucket: entry still not checked");
  // 2. a small bucket that even holds the hash: still too few to judge
  { auto v = filler(50, 1); memcpy(v.data(), sa, 18); CHECK(rk_health_bucket(pa, v.data(), 50, true) == -1, "50-suffix bucket refused"); CHECK(!(health(a) & RK_H_CHECKED), "small bucket: no verdict"); }
  // 3. a real-sized bucket without the hash: checked, clean
  { auto v = filler(800, 2); CHECK(rk_health_bucket(pa, v.data(), 800, true) == 1, "800-suffix bucket decides 1 entry");
    CHECK((health(a) & RK_H_CHECKED) && !(health(a) & RK_H_BREACHED), "real bucket without the hash: checked, clean"); }
  // 4. parts: 60 then 60 (120 in all) with the hash in the first part: breached
  { auto v1 = filler(60, 3), v2 = filler(60, 4); memcpy(v1.data() + 18 * 5, sb, 18);
    CHECK(rk_health_bucket(pb, v1.data(), 60, false) == 0, "part 1 of 2: no verdict yet");
    CHECK(rk_health_bucket(pb, v2.data(), 60, true) == 1, "part 2 of 2: 120 in all, decided");
    CHECK((health(b) & RK_H_CHECKED) && (health(b) & RK_H_BREACHED), "hit in an earlier part: breached"); }
  // 5. parts that add up to too few: refused, and the earlier hit does not leak into the next bucket
  { auto v1 = filler(40, 5), v2 = filler(40, 6); memcpy(v1.data(), sc, 18);
    rk_health_bucket(pc, v1.data(), 40, false);
    CHECK(rk_health_bucket(pc, v2.data(), 40, true) == -1, "40 + 40 parts refused");
    CHECK(!(health(c) & RK_H_CHECKED), "refused parts: no verdict");
    auto v3 = filler(300, 7); CHECK(rk_health_bucket(pc, v3.data(), 300, true) == 1, "then a real bucket without the hash decides");
    CHECK((health(c) & RK_H_CHECKED) && !(health(c) & RK_H_BREACHED), "the refused part's hit did not carry over"); }
  // 6. recheck: clean verdicts back to pending, breached kept
  const int n = rk_health_recheck_clean();
  CHECK(n == 2, "recheck reset the 2 clean entries");
  CHECK(!(health(a) & RK_H_CHECKED) && !(health(c) & RK_H_CHECKED), "clean entries pending again");
  CHECK((health(b) & RK_H_CHECKED) && (health(b) & RK_H_BREACHED), "breached entry kept");
  printf(fails ? "\n%d FAILED\n" : "\nall passed\n", fails);
  return fails ? 1 : 0;
}
