// Phase 4 fuzz (3 Nov 2026): parsePw on random and mutated plaintexts, and
// rk_import on mutated backup bodies holding passwords and passkeys, under
// ASan + UBSan. Every import must either refuse the body or leave a store
// whose counts stay within RK_MAX.
#include "Arduino.h"
#include "rk_host.cpp"
#include <vector>
#include <random>
#include <cstdio>
S Serial; std::map<std::string, std::vector<uint8_t>> g_nvs;
extern int g_vaultOpenLeft;
using namespace favilla;
int main(int argc, char** argv) {
  long iters = argc > 1 ? atol(argv[1]) : 200000;
  std::mt19937 rng(12345);
  rk_mount(); rk_wipe_all();
  for (int i = 0; i < 30; i++) {
    RkPass e; memset(&e, 0, sizeof e); e.slot = -1; snprintf(e.site, sizeof e.site, "s%d.example", i); strcpy(e.user, "u"); snprintf(e.pass, sizeof e.pass, "p%d", i);
    rk_pw_save(&e, nullptr);
    if (i % 3 == 0) { uint8_t h = (uint8_t)i, id34[34] = {1, 1}; rk_save(e.site, strlen(e.site), &h, 1, "n", 1, "", 0, id34); }
  }
  for (int i = 0; i < 5; i++) rk_delete(rk_pw_slot_at(0));
  static uint8_t body[128 * 1024]; size_t bn = 0; int nr, nt; uint32_t g;
  if (rk_export(body, sizeof body, &bn, &nr, &nt, &g)) { printf("export failed\n"); return 1; }
  std::vector<uint8_t> base(body, body + bn);
  // a valid plaintext to mutate
  uint8_t pt[512]; size_t pn = 0; { memset(pt, 0, 13); pt[12] = 2; pn = 13; const char* f[4] = {"site.example", "user", "pass", "note"}; for (auto s : f) { pt[pn++] = (uint8_t)strlen(s); memcpy(pt + pn, s, strlen(s)); pn += strlen(s); } memset(pt + pn, 1, 12); pn += 12; }
  long refused = 0, merged = 0;
  for (long it = 0; it < iters; it++) {
    // parsePw
    uint8_t b[512]; size_t n;
    if (rng() % 2) { n = rng() % 512; for (size_t k = 0; k < n; k++) b[k] = (uint8_t)rng(); b[12] = 2; }
    else { memcpy(b, pt, pn); n = pn; int m = 1 + rng() % 4; for (int k = 0; k < m; k++) b[rng() % n] = (uint8_t)rng(); if (rng() % 4 == 0) n = rng() % (pn + 1); }
    RkPass o; parsePw(b, n, &o);
    if (strlen(o.site) > RK_SITE_MAX || strlen(o.user) > RK_PW_FIELD_MAX || strlen(o.pass) > RK_PW_FIELD_MAX || strlen(o.note) > RK_PW_FIELD_MAX) { printf("FAIL parsePw overlong field\n"); return 1; }
    // rk_import on a mutated body
    if (it % 20 == 0) {
      std::vector<uint8_t> m = base; int k = 1 + rng() % 6;
      for (int j = 0; j < k; j++) { switch (rng() % 4) { case 0: m[rng() % m.size()] = (uint8_t)rng(); break; case 1: m.resize(rng() % (m.size() + 1)); if (m.empty()) m.push_back(0); break; case 2: m.insert(m.begin() + rng() % m.size(), (uint8_t)rng()); break; default: m[rng() % 4] = (uint8_t)rng(); } }
      RkImport st{}; int r = rk_import(m.data(), m.size(), &st);
      if (r) refused++; else merged++;
      if (rk_count_all() > RK_MAX || rk_count() + rk_pw_count() > rk_count_all()) { printf("FAIL counts out of range\n"); return 1; }
      if (it % 2000 == 0) { rk_wipe_all(); RkImport s2{}; rk_import(base.data(), base.size(), &s2); }
    }
  }
  printf("fuzz_pw: %ld iterations, %ld bodies refused, %ld merged, no fault\n", iters, refused, merged);
  return 0;
}
