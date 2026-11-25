#include <cstdio>
// libFuzzer (11t, 10 Nov 2026): the password-health layer of the REAL record
// store (host/rk_host.cpp): saves with origins, opens, HEALTH buckets as the
// phone sends them (prefix + packed suffixes), prefix requests, backfill, locks.
// Input: a stream of ops: [op][args...]
#include "../host/inc/Arduino.h"
#include <map>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include "../src/pk_records.h"
S Serial; std::map<std::string,std::vector<uint8_t>> g_nvs;
static unsigned long g_ms = 0; unsigned long millis(){ return g_ms += 5; }
extern bool g_vaultPresent; extern int g_vaultOpenLeft;
// 11ae (11 Nov 2026): before the mount, every entry point a lock, a boot or a
// settings screen can reach must come back without touching the index (the
// KEY reset on rk_forget_cache in an onboarding life, where nothing mounts).
static void beforeMount(){
  using namespace favilla;
  rk_forget_cache(); rk_count(); rk_count_all(); rk_pw_count(); rk_open_left(); rk_last_res(); rk_dirty();
  rk_health_pending(); rk_health_unseen(); rk_health_backfill_one(); rk_lock_epoch(); rk_idx_have_key(); rk_idx_flush(); rk_idx_batch(false);
  RkAcct a; rk_at(0, &a); rk_slot_at(0); rk_find("x", 1, &a, 1);
  RkPass pw; rk_pw_open(0, &pw); rk_pw_slot_at(0); rk_pw_health(0); rk_pw_health_slot(0); rk_pw_label_cached(0); rk_pw_site_known(0);
  uint8_t id8[8] = {0}; rk_pw_id_of(0, id8); rk_pw_index_of(0, id8); rk_pw_index_of_id(id8);
  char site[80]; bool pend, cut; rk_pw_site(0, site, sizeof site, &pend, &cut);
  int idx[4]; rk_pw_order(idx, 4); RkRow rows[2]; rk_pw_rows(rows, 2);
  uint8_t pre[4][3]; rk_health_prefixes(pre, 4);
  int sl = 0, tl = 0; rk_pw_import_window(&sl, &tl);
  int n = 0, u = 0; rk_rc_counts(0, &n, &u); rk_rc_slot_for_pw(0);
  int del = 0, sk = 0; int slots[1] = {0}; uint8_t ids[1][8] = {{0}}; rk_delete_many(slots, ids, 1, &del, &sk); rk_delete(0);
  uint8_t out[64]; size_t on = 0; int nr = 0, nt = 0; uint32_t g = 0; rk_export(out, sizeof out, &on, &nr, &nt, &g);
  RkImport st{}; rk_import(out, 0, &st);
  rk_set_clean(0);
}
extern "C" int LLVMFuzzerInitialize(int*, char***){ beforeMount(); favilla::rk_mount(); return 0; }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  static unsigned runs = 0; runs++;
  if((runs & 0x1FF) == 0) favilla::rk_wipe_all();
  size_t i = 0; int steps = 0;
  while(i < n && steps++ < 64){
    const uint8_t op = d[i++];
    switch(op & 7){
      case 0: { // save: [origin][siteLen][site][userLen][user][passLen][pass]
        if(i + 3 > n) return 0;
        favilla::RkPass* p = (favilla::RkPass*)calloc(1, sizeof(favilla::RkPass));
        p->slot = -1; p->origin = d[i++] & 3;
        size_t sl = d[i++] % 40; if(i + sl > n){ free(p); return 0; } memcpy(p->site, d + i, sl); p->site[sl] = 0; i += sl;
        if(i >= n){ free(p); return 0; } size_t ul = d[i++] % 40; if(i + ul > n){ free(p); return 0; } memcpy(p->user, d + i, ul); p->user[ul] = 0; i += ul;
        if(i >= n){ free(p); return 0; } size_t pl = d[i++] % 64; if(i + pl > n){ free(p); return 0; } memcpy(p->pass, d + i, pl); p->pass[pl] = 0; i += pl;
        if(!sl) strcpy(p->site, "x.y"); if(!pl) strcpy(p->pass, "p");
        if(d[i - pl - 1 - ul - 1 - sl - 1] & 0x80){   // 11v: a one-time code record instead (origin byte's top bit), so links have something to hold
          static const uint8_t sec[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
          int ts = -1; favilla::rk_totp_save(p->site, p->user, sec, sizeof sec, 6, 30, &ts);
          // 11aa: a fresh code saved under exactly one entry's site is linked to it by the site tag; the two lookups must agree
          if(ts >= 0){ const int ps = favilla::rk_totp_linked_pw(ts); if(ps >= 0){ const int back = favilla::rk_pw_totp_slot(ps); if(back < 0 || favilla::rk_totp_linked_pw(back) != ps) do{ fprintf(stderr, "ABORT 1 at line %d\n", __LINE__); abort(); }while(0); } }
          favilla::rk_pw_wipe(p); free(p); break;
        }
        int slot = -1; favilla::rk_pw_save(p, &slot); favilla::rk_pw_wipe(p); free(p); break; }
      case 1: { // open i
        if(i >= n) return 0; int k = d[i++];
        favilla::RkPass* p = (favilla::RkPass*)calloc(1, sizeof(favilla::RkPass));
        favilla::rk_pw_open(k, p); favilla::rk_pw_wipe(p); free(p); break; }
      case 2: { // bucket: [prefix 3][cnt][suffixes 18 x cnt]
        if(i + 4 > n) return 0; uint8_t pre[3]; memcpy(pre, d + i, 3); i += 3; int cnt = d[i++];
        if(i + (size_t)cnt * 18 > n) cnt = (int)((n - i) / 18);
        int dec = favilla::rk_health_bucket(pre, d + i, cnt); i += (size_t)cnt * 18;
        if(dec < -1 || dec > favilla::RK_MAX || (dec == -1 && cnt >= (int)favilla::RK_HEALTH_MIN_BUCKET)) do{ fprintf(stderr, "ABORT 2 at line %d\n", __LINE__); abort(); }while(0); break; }
      case 3: { uint8_t pf[favilla::RK_MAX][3]; int k = favilla::rk_health_prefixes(pf, favilla::RK_MAX); if(k < 0 || k > favilla::RK_MAX) do{ fprintf(stderr, "ABORT 3 at line %d\n", __LINE__); abort(); }while(0);
        for(int a = 0; a < k; a++) for(int b = a + 1; b < k; b++) if(!memcmp(pf[a], pf[b], 3)) do{ fprintf(stderr, "ABORT 4 at line %d\n", __LINE__); abort(); }while(0);   // distinct
        break; }
      case 4: { favilla::rk_health_backfill_one(); break; }
      case 5: { favilla::rk_forget_cache(); g_vaultOpenLeft = 32; break; }
      case 6: { if(i >= n) return 0; int k = d[i++]; uint8_t h = favilla::rk_pw_health(k); if((h & 0x80)) do{ fprintf(stderr, "ABORT 5 at line %d\n", __LINE__); abort(); }while(0); (void)favilla::rk_health_pending(); (void)favilla::rk_health_unseen(); break; }
      case 7: {
        if(i >= n) return 0;
        const uint8_t a = d[i++];
        if(a & 0x80){   // 11v: link a code to an entry, read it back both ways, unlink; or delete
          if(i + 1 >= n) return 0; const int ts = d[i++] % favilla::RK_MAX, ps = d[i++] % favilla::RK_MAX;
          const int r = favilla::rk_totp_link(ts, (a & 0x40) ? -1 : ps);
          if(r == 0 && !(a & 0x40)){
            if(favilla::rk_totp_linked_pw(ts) != ps || favilla::rk_pw_totp_slot(ps) != ts) do{ fprintf(stderr, "ABORT 6 at line %d\n", __LINE__); abort(); }while(0);
            favilla::RkRow* rows = (favilla::RkRow*)malloc(sizeof(favilla::RkRow) * favilla::RK_MAX);
            const int k = favilla::rk_pw_rows(rows, favilla::RK_MAX); bool seen = false;
            for(int j = 0; j < k; j++) if(rows[j].slot == ps){ seen = true; if(!(rows[j].health & favilla::RK_H_TOTP)) do{ fprintf(stderr, "ABORT 7 at line %d\n", __LINE__); abort(); }while(0); } else if(rows[j].health & favilla::RK_H_TOTP){ if(favilla::rk_pw_totp_slot(rows[j].slot) < 0) do{ fprintf(stderr, "ABORT 8 at line %d\n", __LINE__); abort(); }while(0); }
            free(rows); if(!seen) do{ fprintf(stderr, "ABORT 9 at line %d\n", __LINE__); abort(); }while(0);
          }
          if(r == 0 && (a & 0x40) && favilla::rk_totp_linked_pw(ts) >= 0) do{ fprintf(stderr, "ABORT 10 at line %d\n", __LINE__); abort(); }while(0);
        } else {
          const int s = a % favilla::RK_MAX; favilla::rk_delete(s);
          for(int ts = 0; ts < favilla::RK_MAX; ts++) if(favilla::rk_totp_linked_pw(ts) == s) do{ fprintf(stderr, "ABORT 11 at line %d\n", __LINE__); abort(); }while(0);   // a deleted entry keeps no link
          if(favilla::rk_pw_totp_slot(s) >= 0) do{ fprintf(stderr, "ABORT 12 at line %d\n", __LINE__); abort(); }while(0);
        }
        break; }
    }
  }
  return 0;
}
