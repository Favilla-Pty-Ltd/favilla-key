// =============================================================================
// pk_records.cpp - passwordless passkey records (2 Nov 2026). See pk_records.h.
// =============================================================================
#ifdef FAVILLA_PK_RESTORABLE
#include <Arduino.h>
#include <Preferences.h>
#include <string.h>
#include <time.h>
#include <mutex>
#include "nvs_flash.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"
#include "g0_signer.h"
#include "pk_records.h"
#ifdef ARDUINO
#include "esp_heap_caps.h"
#endif

namespace favilla {

static const char* RK_PART = "nvs_vault";
static const char* RK_NS   = "pkrec";
static constexpr size_t HDR = 13, TAGOFF = 13, CLEAR = 21;   // id8 upd4 kind1 | tag8

struct Idx { uint8_t used; uint8_t clear[CLEAR]; };
struct Tag { uint8_t used; char site[RK_SITE_MAX + 1]; uint8_t tag[8]; };
// 2 Nov 2026: the index, the site-tag cache and the two work buffers live in
// one PSRAM block taken at mount (about 3.5 KB), not in internal RAM: WiFi
// hotspot mode had only 2 KB of internal heap left with them static.
// 3 Nov 2026 (P4-1): RK_MAX 200, so the cache pointers moved in here too (800 B
// would otherwise sit in internal RAM).
// P4-10 (3 Nov 2026): one site-index entry, PSRAM, valid while slot id and updated match.
struct SiteE { uint8_t id8[8]; uint32_t upd; uint8_t tag8[8]; uint8_t flags; char site[RK_IDX_SITE + 1]; };
struct RkRam { Idx idx[RK_MAX]; Tag tags[4]; uint8_t blob[G0_VAULT_DATA_MAX], buf[G0_VAULT_DATA_MAX]; uint8_t tomb[512 * 12]; RkAcct* cache[RK_MAX]; RkLabel* labels[RK_MAX]; struct SiteE* sites[RK_MAX];
               // 11dr (RK_MAX 400): the per-slot tables below were static, in internal RAM (7.4 KB at 200, 14.8 KB at 400)
               uint8_t hlth[RK_MAX]; uint8_t hlthId[RK_MAX][8]; bool bucketHit[RK_MAX]; uint8_t tlnk[RK_MAX][16]; uint8_t rcnt[RK_MAX][11];
               bool takeS[RK_MAX], linkedS[RK_MAX]; };   // 11dr: scratch for rk_delete_many / rk_pw_rows (under s_mx), off the small task stacks   // labels: v15, freed at lock   // tomb: phase 3 tombstones (TOMB_MAX x 12), under s_mx
static RkRam*   R = nullptr;            // set by rk_mount; every caller is behind rk_ready()
#define s_cache (R->cache)              // opened passkey records, PSRAM, wiped at every lock (P3)
static uint8_t  s_tagNext = 0;
static bool     s_mounted = false, s_loaded = false;
static uint8_t  s_lastRes = 0;
static int      s_openLeft = -1;
static int      s_tagLeft = 32;         // 25 Nov 2026: counted here (rk_tag_left); the G0's per-sitting budget
static const int RK_SITTING = 32;       // the G0's VLT_PER_SITTING before v24
static int      s_limit = -1;           // 25 Nov 2026: the G0's vault limit now (0 none; -1 not read yet)
static int      s_labelLeft = -1;
static std::mutex s_mx;
static void siteSetLocked(int s, const char* site, size_t n);   // P4-10 (3 Nov 2026), below
static void siteDropLocked(int s);
static void labelDropLocked(int s);
static uint32_t s_lockEpoch = 0;   // P4-10 review (3): bumped by every lock
static void ixFlushLocked(bool force);
static uint8_t s_ixKey[32]; static bool s_ixHave = false, s_ixBatch = false; static uint8_t s_ixGen = 0; static int s_ixDirty = 0;

static void* rkAlloc(size_t n) {
#ifdef ARDUINO
  void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (p) return p;
#endif
  return malloc(n);
}
// Slot keys: "r00".."r99" as before (records written by older firmware keep
// their names), "r100".."r199" above that. Callers pass char[5].
static void key(int slot, char k[5]) {
  k[0] = 'r';
  if (slot < 100) { k[1] = (char)('0' + slot / 10); k[2] = (char)('0' + slot % 10); k[3] = 0; }
  else { k[1] = (char)('0' + slot / 100); k[2] = (char)('0' + (slot / 10) % 10); k[3] = (char)('0' + slot % 10); k[4] = 0; }
}
static bool kindHeld(uint8_t k) { return k == RK_KIND_PASSKEY || k == RK_KIND_PASSWORD || k == RK_KIND_TOTP || k == RK_KIND_RECOVERY; }   // 9i: TOTP records are held, merged and backed up too; 11aa: recovery codes
static uint32_t rd32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint32_t rd32le(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

// ---- Phase 3 (2 Nov 2026, Vault spec section 4): backup bookkeeping --------
// Tombstones: a deleted record leaves (id8, deleted-at4) so a restore does not
// bring it back, and the next backup carries it. Kept in the same namespace as
// the records, so a wallet wipe clears them too. "dirty": a change the relay
// backup does not have yet.
static constexpr int TOMB_MAX = 512;   // 11dr: more than RK_MAX (400), as below; was 256   // review: 64 let a delete come back once more than 64 had happened across KEYs.
// 4 Nov 2026 (bulk delete): 128 -> 256, more than RK_MAX (200), so deleting every record at once keeps every
// tombstone. At 128, a delete of 145 dropped the oldest 17 and the next merge of the relay backup brought them back.
static_assert(sizeof(RkRam::tomb) == TOMB_MAX * 12, "RkRam::tomb holds TOMB_MAX tombstones");
static uint32_t nowOr(uint32_t floor) { time_t t = time(nullptr); uint32_t n = (t > 1700000000) ? (uint32_t)t : 0; return n > floor ? n : floor; }
static int tombLoad(uint8_t* t) {
  Preferences p; size_t n = 0;
  if (p.begin(RK_NS, true, RK_PART)) {
    n = p.isKey("tomb") ? p.getBytesLength("tomb") : 0;
    if (n % 12 || n > (size_t)TOMB_MAX * 12 || (n && p.getBytes("tomb", t, n) != n)) n = 0;
    p.end();
  }
  return (int)(n / 12);
}
static bool tombSave(const uint8_t* t, int c) {
  Preferences p; bool ok = false;
  if (p.begin(RK_NS, false, RK_PART)) { ok = c ? p.putBytes("tomb", t, (size_t)c * 12) == (size_t)c * 12 : (p.remove("tomb"), true); p.end(); }
  return ok;
}
static void dirtySet(bool on) { Preferences p; if (p.begin(RK_NS, false, RK_PART)) { p.putUChar("dirty", on ? 1 : 0); p.end(); } }
// Review 2 Nov 2026: every change bumps this (under s_mx). A publish clears
// "dirty" only if nothing changed since its export, so a registration that
// lands while the backup is on its way is not marked as backed up.
static uint32_t s_changeGen = 0;
static void changed() { s_changeGen++; dirtySet(true); }
// Review: a time from the backup further ahead than this is not trusted (a
// forged or clock-skewed record or tombstone would win every later merge).
static bool tooFar(uint32_t t) { time_t n = time(nullptr); return n > 1700000000 && t > (uint32_t)n + 86400u; }
// Record (id, t) in tombstones t[0..c): newer time wins; when full the oldest goes.
static int tombPut(uint8_t* t, int c, const uint8_t id8[8], uint32_t when) {
  for (int i = 0; i < c; i++) if (!memcmp(t + i * 12, id8, 8)) { if (rd32(t + i * 12 + 8) < when) wr32(t + i * 12 + 8, when); return c; }
  int at = c;
  if (c == TOMB_MAX) { at = 0; for (int i = 1; i < c; i++) if (rd32(t + i * 12 + 8) < rd32(t + at * 12 + 8)) at = i; }
  else c++;
  memcpy(t + at * 12, id8, 8); wr32(t + at * 12 + 8, when);
  return c;
}
static uint32_t tombTime(const uint8_t* t, int c, const uint8_t id8[8]) {
  for (int i = 0; i < c; i++) if (!memcmp(t + i * 12, id8, 8)) return rd32(t + i * 12 + 8);
  return 0;
}

size_t rk_utf8_cut(const char* s, size_t n, size_t max) {
  if (n <= max) return n;
  size_t k = max;
  while (k > 0 && (((uint8_t)s[k]) & 0xC0) == 0x80) k--;   // s[k] is the first byte NOT kept: never split before a continuation byte
  return k;
}

// Review 2 Nov 2026: the partition holds vault records only, so it can heal
// itself. A full or newer-format partition is erased and mounted again, and
// the first mount erases whatever was there before (bench units that once ran
// the 384 KB nvs_game have its old pages at 0xFB0000), then writes a marker.
// ---- P4-1 (3 Nov 2026): nvs_vault grows from 64 KB to 128 KB in place ---------
// The new table keeps the start (0xFB0000) and doubles the size. Records
// written under the 64 KB table are all in the first half, which stays a valid
// store. The second half may still hold pages of the old 384 KB nvs_game
// (bench units), and NVS would load those as its own. So before the first
// mount at a size larger than any the vault has been used at, every page past
// 64 KB is erased. The marker "vsz" (the size the vault was last checked at)
// is a vault key, found by reading the page headers directly: no mount is
// needed to find it, and it is written right after the mount, before any
// record can land past 64 KB. A wipe rewrites it with "ver".
static constexpr uint32_t RK_OLD_SIZE = 0x10000;
// NVS page layout (ESP-IDF nvs_page.hpp): 32-byte header (state u32 first),
// a 32-byte entry-state bitmap (2 bits per entry, 0b10 = written), then 126
// entries of 32 bytes: nsIndex, type, span, chunkIndex, crc32, key[16], data[8].
static constexpr uint32_t NVS_PAGE = 4096, NVS_ENTRIES = 126, NVS_UNINIT = 0xFFFFFFFFu;
static constexpr uint8_t  NVS_TYPE_U32 = 0x04;
// Returns the size recorded in a live "vsz" entry (0 if none), and whether
// any page past RK_OLD_SIZE is in use.
static uint32_t rkScan(const esp_partition_t* part, bool* upperUsed, uint32_t base) {
  *upperUsed = false;
  uint8_t* pg = (uint8_t*)rkAlloc(NVS_PAGE);
  if (!pg) { *upperUsed = true; return 0; }   // cannot check: treat as dirty (the erase only touches pages past 64 KB)
  uint32_t vsz = 0;
  for (uint32_t off = 0; off + NVS_PAGE <= part->size; off += NVS_PAGE) {
    if (esp_partition_read(part, off, pg, NVS_PAGE) != ESP_OK) { if (off >= base) *upperUsed = true; continue; }
    if (rd32le(pg) == NVS_UNINIT) continue;
    if (off >= base) *upperUsed = true;
    for (uint32_t e = 0; e < NVS_ENTRIES; ) {
      uint8_t st = (pg[32 + e / 4] >> ((e % 4) * 2)) & 3;
      const uint8_t* it = pg + 64 + e * 32;
      if (st != 2) { e++; continue; }
      uint8_t span = it[2]; if (span == 0 || span > NVS_ENTRIES - e) span = 1;
      if (it[0] != 0 && it[1] == NVS_TYPE_U32 && span == 1 && !memcmp(it + 8, "vsz", 4)) { uint32_t v = rd32le(it + 24); if (v > vsz) vsz = v; }
      e += span;
    }
  }
  free(pg);
  return vsz;
}
static void rkMarkSize() {
  const esp_partition_t* part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, RK_PART);
  if (!part || part->size <= RK_OLD_SIZE) return;
  Preferences p; if (p.begin(RK_NS, false, RK_PART)) { if (p.getUInt("vsz", 0) != part->size) p.putUInt("vsz", part->size); p.end(); }
}
static void rkGrowCheck() {
  const esp_partition_t* part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, RK_PART);
  if (!part || part->size <= RK_OLD_SIZE) return;   // the 64 KB table: nothing to do
  // 11dr (128 KB -> 256 KB, RK_MAX 400): the same rule one size up. The pages
  // the vault has been checked at (vsz, or 64 KB with no marker) are its own;
  // anything past them may be old nvs_game pages (bench units: 0xFD0000 to
  // 0xFF0000 was the 384 KB nvs_game's tail) and is erased before the mount.
  bool upper = false;
  uint32_t vsz = rkScan(part, &upper, 0xFFFFFFFFu);   // first pass: the marker only
  if (vsz >= part->size) return;                      // already checked at this size
  const uint32_t base = (vsz > RK_OLD_SIZE && vsz < part->size && (vsz % NVS_PAGE) == 0) ? vsz : RK_OLD_SIZE;
  rkScan(part, &upper, base);
  if (upper) {
    esp_err_t e = esp_partition_erase_range(part, base, part->size - base);
    Serial.printf("[RK] nvs_vault is now %u KB: the pages past %u KB held old data, erased them (%s). Records in the first %u KB are kept.\n",
                  (unsigned)(part->size / 1024), (unsigned)(base / 1024), e == ESP_OK ? "ok" : "FAILED", (unsigned)(base / 1024));
  } else Serial.printf("[RK] nvs_vault is now %u KB (was checked at %u KB): the new pages are empty, records kept\n", (unsigned)(part->size / 1024), (unsigned)(base / 1024));
}

bool rk_mount() {
  if (!R) {
    R = (RkRam*)rkAlloc(sizeof(RkRam));
    if (!R) { Serial.println("[RK] no memory for the record index: no-username passkeys are off"); s_mounted = false; return false; }
    memset(R, 0, sizeof *R);
  }
  if (!s_mounted) rkGrowCheck();   // P4-1: before NVS sees the new pages
  esp_err_t e = nvs_flash_init_partition(RK_PART);
  if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.printf("[RK] nvs_vault: err 0x%x on mount, erasing it (vault records only)\n", (unsigned)e);
    nvs_flash_erase_partition(RK_PART); e = nvs_flash_init_partition(RK_PART);
  }
  s_mounted = (e == ESP_OK);
  if (!s_mounted) {
    Serial.printf("[RK] nvs_vault partition not usable (err 0x%x): no-username passkeys are off. Reflash the partition table from the Forge.\n", (unsigned)e);
    return false;
  }
  bool marked = false;
  { Preferences p; if (p.begin(RK_NS, true, RK_PART)) { marked = p.isKey("ver"); p.end(); } }
  if (!marked) {
    nvs_flash_deinit_partition(RK_PART); nvs_flash_erase_partition(RK_PART); e = nvs_flash_init_partition(RK_PART);
    s_mounted = (e == ESP_OK);
    Preferences p; if (s_mounted && p.begin(RK_NS, false, RK_PART)) { p.putUChar("ver", 1); p.end(); }
    Serial.printf("[RK] nvs_vault: first use, partition erased and marked (%s)\n", s_mounted ? "ok" : "FAILED");
  }
  if (s_mounted) rkMarkSize();   // P4-1: writes only when it is not already there
  // 11bw (issue #40 A3): how full nvs_vault is, at every boot. A record is one
  // sealed blob of up to G0_VAULT_DATA_MAX bytes, about 18 NVS entries at its
  // largest; RK_MAX is sized so that many records of the largest kind still
  // fit beside the index, health, tombstone and label blobs.
  if (s_mounted) { nvs_stats_t st;
    if (nvs_get_stats(RK_PART, &st) == ESP_OK)
      Serial.printf("[RK] nvs_vault: %u of %u entries used (%u%%), %u free, RK_MAX %d\n", (unsigned)st.used_entries, (unsigned)st.total_entries,
                    st.total_entries ? (unsigned)(st.used_entries * 100 / st.total_entries) : 0u, (unsigned)st.free_entries, RK_MAX); }
  s_loaded = false;
  return s_mounted;
}
bool rk_ready() { return s_mounted && g0_vault_present(); }
uint8_t rk_last_res() { return s_lastRes; }
int rk_open_left() { return s_openLeft; }
int rk_tag_left() { return s_tagLeft; }
void rk_budget_refilled() {
  if (s_limit == 0) { s_tagLeft = -1; s_openLeft = -1; return; }
  const int n = s_limit > 0 ? s_limit : RK_SITTING;
  s_tagLeft = n; s_openLeft = n;
}
static int vault(uint8_t op, const uint8_t* in, size_t n, uint8_t* out, size_t* on);   // below
static void limitApply(const uint8_t* b, RkLimit* o) {
  s_limit = b[0];
  s_openLeft = b[0] ? b[2] : -1; s_tagLeft = b[0] ? b[3] : -1;
  if (o) { o->now = b[0]; o->next = b[1]; o->openLeft = s_openLeft; o->tagLeft = s_tagLeft; o->refills = b[4]; o->refillsMax = b[5]; }
}
int rk_limit_read(RkLimit* o) {
  if (o) *o = { RK_SITTING, RK_SITTING, s_openLeft, s_tagLeft, 0, 4 };
  if (!rk_ready()) return RK_E_NOVAULT;
  if (!g0_limit_present()) { s_limit = RK_SITTING; return RK_OK; }   // the fixed 32 of an older G0
  std::lock_guard<std::mutex> g(s_mx);
  if (!R) return RK_E_NVS;
  size_t on = 0;
  int r = vault(G0_VAULT_LIMIT, nullptr, 0, R->buf, &on);
  if (r) return r;
  if (on < 6) return RK_E_G0;
  limitApply(R->buf, o);
  return RK_OK;
}
int rk_limit_set(uint8_t lim, RkLimit* o) {
  if (!rk_ready() || !g0_limit_present()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  if (!R) return RK_E_NVS;
  size_t on = 0;
  int r = vault(G0_VAULT_SETLIM, &lim, 1, R->buf, &on);
  if (r) return r;
  if (on < 6) return RK_E_G0;
  limitApply(R->buf, o);
  return RK_OK;
}
bool rk_save_room(int saves, int opens) {
  if (s_limit < 0 && rk_ready()) rk_limit_read(nullptr);   // first ask this life: what the G0 holds
  if (s_tagLeft >= 0 && s_tagLeft < saves) return false;
  if (s_openLeft >= 0 && s_openLeft < opens) return false;
  return true;
}
int rk_label_left() { return s_labelLeft; }
const char* rk_hint() {
  switch (s_lastRes) {
    case 0xE3: return "the passkey master is not readable here: log in once in VAULT mode, or allow the NOSTR gate there";
    case 0xEB: return "this power-on life's labels are used (800 from G0 v23): power cycle";
    case 0xEA: return "the import window was refused: it needs the PIN on the KEY just before, the NOSTR life, and one window per power-on";
    case 0xE6: return "the record did not pass the G0's check (not sealed by this vault, or altered)";
    default: return "";
  }
}
const char* rk_err_name(int e) {
  switch (e) {
    case RK_OK: return "ok";
    case RK_E_NOVAULT: return "no vault (partition table or G0 VAULT missing)";
    case RK_E_FULL: return "full";
    case RK_E_G0: return "the G0 refused or did not answer";
    case RK_E_BUDGET: return "this sitting's record opens are used: lock and unlock (4 refills per power-on, then power cycle)";
    case RK_E_SIZE: return "a field is too long";
    case RK_E_NVS: return "could not write the record";
    case RK_E_FORMAT: return "record does not parse";
    case RK_E_EXISTS: return "already on the KEY (kept)";
    default: return "unknown";
  }
}

static void loadLocked() {
  if (s_loaded) return;
  memset(R->idx, 0, sizeof R->idx);
  Preferences p;
  if (p.begin(RK_NS, true, RK_PART)) {
    for (int i = 0; i < RK_MAX; i++) {
      char k[5]; key(i, k);
      size_t n = p.isKey(k) ? p.getBytesLength(k) : 0;
      if (n < CLEAR + 16 + 16 + 32 || n > G0_VAULT_DATA_MAX) continue;
      if (p.getBytes(k, R->blob, n) != n) continue;
      R->idx[i].used = 1; memcpy(R->idx[i].clear, R->blob, CLEAR);
    }
    p.end();
  }
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  s_loaded = true;
}

static int countLocked() { int n = 0; for (int i = 0; i < RK_MAX; i++) n += R->idx[i].used; return n; }   // every kind: what RK_MAX limits
static bool isKind(int i, uint8_t k) { return R->idx[i].used && R->idx[i].clear[12] == k; }

// ---- 11s: password health -------------------------------------------------------
#define s_hlth (R->hlth)         // 11dr: PSRAM (RkRam)
#define s_hlthId (R->hlthId)
static bool s_hlthLoaded = false, s_hlthDirty = false;
struct PwHash { uint8_t id8[8]; uint8_t sha[20]; bool on; };
static PwHash* s_pwHash = nullptr;   // PSRAM, RAM only, wiped on lock
#define s_bucketHit (R->bucketHit)   // 11dr: PSRAM; 11bc: a hit in an earlier part of a bucket that comes in parts
static void hlthLoadLocked() {
  if (s_hlthLoaded) return;
  memset(s_hlth, 0, sizeof s_hlth); memset(s_hlthId, 0, sizeof s_hlthId);
  Preferences p;
  if (p.begin(RK_NS, true, RK_PART)) {
    const size_t hn = p.isKey("hlth") ? p.getBytesLength("hlth") : 0;
    if (hn == (size_t)RK_MAX * 9 || hn == (size_t)RK_OLD_MAX * 9) {   // 11dr: a 200-row table (RK_OLD_MAX) fills the first 200 slots
      const int rows = (int)(hn / 9);
      uint8_t* b = (uint8_t*)rkAlloc(hn);
      if (b && p.getBytes("hlth", b, hn) == hn) for (int i = 0; i < rows; i++) { memcpy(s_hlthId[i], b + i * 9, 8); s_hlth[i] = b[i * 9 + 8]; }
      free(b);
    }
    p.end();
  }
  s_hlthLoaded = true;
}
static void hlthFlushLocked() {
  if (!s_hlthDirty) return;
  uint8_t* b = (uint8_t*)rkAlloc(RK_MAX * 9); if (!b) return;
  for (int i = 0; i < RK_MAX; i++) { memcpy(b + i * 9, s_hlthId[i], 8); b[i * 9 + 8] = s_hlth[i]; }
  Preferences p; if (p.begin(RK_NS, false, RK_PART)) { if (p.putBytes("hlth", b, RK_MAX * 9) == (size_t)RK_MAX * 9) s_hlthDirty = false; p.end(); }
  free(b);
}
static uint8_t hlthGetLocked(int s) {
  hlthLoadLocked();
  if (s < 0 || s >= RK_MAX || !isKind(s, RK_KIND_PASSWORD) || memcmp(s_hlthId[s], R->idx[s].clear, 8)) return 0;
  return s_hlth[s];
}
static void hlthSetLocked(int s, uint8_t h) {
  hlthLoadLocked();
  if (s < 0 || s >= RK_MAX || !R->idx[s].used) return;
  memcpy(s_hlthId[s], R->idx[s].clear, 8); s_hlth[s] = h; s_hlthDirty = true;
}
static uint8_t strengthOf(const char* pw, size_t n) {
  if (!n) return 0;
  bool lo = false, up = false, di = false, sy = false;
  for (size_t i = 0; i < n; i++) { unsigned char c = pw[i]; if (c >= 'a' && c <= 'z') lo = true; else if (c >= 'A' && c <= 'Z') up = true; else if (c >= '0' && c <= '9') di = true; else sy = true; }
  const int cls = lo + up + di + sy;
  if (n < 10 || cls < 2) return 1;
  if (n >= 20 || (n >= 16 && cls >= 3) || (n >= 14 && cls == 4)) return 3;
  return 2;
}
// The password's SHA-1 into the RAM table (for reuse and the breach check), and the
// reuse bits of every entry that shares it. Called with the password in hand.
static void hashNoteLocked(int s, const char* pw, size_t n) {
  if (!s_pwHash) { s_pwHash = (PwHash*)rkAlloc(sizeof(PwHash) * RK_MAX); if (!s_pwHash) return; memset(s_pwHash, 0, sizeof(PwHash) * RK_MAX); }
  uint8_t sha[20]; mbedtls_sha1((const unsigned char*)pw, n, sha);
  PwHash& me = s_pwHash[s]; memcpy(me.id8, R->idx[s].clear, 8); memcpy(me.sha, sha, 20); me.on = true;
  s_bucketHit[s] = false;   // 11bc: a part seen for an older password says nothing about this one
  bool reused = false;
  for (int i = 0; i < RK_MAX; i++) {
    if (i == s || !s_pwHash[i].on || !isKind(i, RK_KIND_PASSWORD) || memcmp(s_pwHash[i].id8, R->idx[i].clear, 8)) continue;
    if (!memcmp(s_pwHash[i].sha, sha, 20)) { reused = true; uint8_t h = hlthGetLocked(i); if (!(h & RK_H_REUSED)) hlthSetLocked(i, h | RK_H_REUSED); }
  }
  uint8_t h = hlthGetLocked(s);
  const uint8_t nh = reused ? (h | RK_H_REUSED) : (h & ~RK_H_REUSED);
  if (nh != h) hlthSetLocked(s, nh);
  mbedtls_platform_zeroize(sha, sizeof sha);
}
static bool hashOnLocked(int s) { return s_pwHash && s_pwHash[s].on && isKind(s, RK_KIND_PASSWORD) && !memcmp(s_pwHash[s].id8, R->idx[s].clear, 8); }
static void hashForgetLocked() { if (s_pwHash) mbedtls_platform_zeroize(s_pwHash, sizeof(PwHash) * RK_MAX); if (R) memset(s_bucketHit, 0, sizeof s_bucketHit); }

static int countKind(uint8_t k) { int n = 0; for (int i = 0; i < RK_MAX; i++) n += isKind(i, k); return n; }
// ---- 11v: codes linked to password entries ("tlnk": RK_MAX x [code id8][entry id8], by code slot)
#define s_tlnk (R->tlnk)   // 11dr: PSRAM
static bool s_tlnkLoaded = false;
#define s_rcnt (R->rcnt)   // 11dr: PSRAM
static bool s_rcntLoaded = false;   // 11aa: [id8][n][used lo][used hi] by slot, the clear count table for recovery codes
static void tlnkLoadLocked() {
  if (s_tlnkLoaded) return;
  memset(s_tlnk, 0, sizeof s_tlnk);
  Preferences p;
  if (p.begin(RK_NS, true, RK_PART)) {
    const size_t tn = p.isKey("tlnk") ? p.getBytesLength("tlnk") : 0;
    if (tn == sizeof s_tlnk || tn == (size_t)RK_OLD_MAX * 16) p.getBytes("tlnk", s_tlnk, tn);   // 11dr: rows are by slot, so 200 rows are slots 0..199
    p.end();
  }
  s_tlnkLoaded = true;
}
static bool tlnkSaveLocked() {
  Preferences p; bool ok = false;
  if (p.begin(RK_NS, false, RK_PART)) { ok = p.putBytes("tlnk", s_tlnk, sizeof s_tlnk) == sizeof s_tlnk; p.end(); }
  return ok;
}
static const uint8_t ZERO8[8] = {0};
// the password slot a code slot is linked to, -1 if none (both ids must still match).
// 11aa: with no table row (a restore, or a code saved before 11v under the entry's
// own site), the site tag in the clear header decides: a code saved under exactly the
// entry's site has the entry's tag. One such entry links; two (two accounts on the
// site) do not, since the label would be needed to tell them apart.
// A table row with the code's id and a zero entry id means "unlinked on purpose":
// no tag fallback for that code.
static bool tlnkRowLocked(int ts) { return !memcmp(s_tlnk[ts], R->idx[ts].clear, 8); }
static int tlnkPwLocked(int ts) {
  tlnkLoadLocked();
  if (ts < 0 || ts >= RK_MAX || !isKind(ts, RK_KIND_TOTP)) return -1;
  if (tlnkRowLocked(ts)) {
    if (!memcmp(s_tlnk[ts] + 8, ZERO8, 8)) return -1;
    for (int s = 0; s < RK_MAX; s++) if (isKind(s, RK_KIND_PASSWORD) && !memcmp(R->idx[s].clear, s_tlnk[ts] + 8, 8)) return s;
    return -1;
  }
  int found = -1;
  for (int s = 0; s < RK_MAX; s++) if (isKind(s, RK_KIND_PASSWORD) && !memcmp(R->idx[s].clear + TAGOFF, R->idx[ts].clear + TAGOFF, 8)) { if (found >= 0) return -1; found = s; }
  return found;
}
// the entry's code: one linked by the table first, else one linked by the site tag
static int tlnkTotpOfPwLocked(int ps) {
  if (ps < 0 || ps >= RK_MAX || !isKind(ps, RK_KIND_PASSWORD)) return -1;
  tlnkLoadLocked();
  for (int ts = 0; ts < RK_MAX; ts++) if (isKind(ts, RK_KIND_TOTP) && tlnkRowLocked(ts) && tlnkPwLocked(ts) == ps) return ts;
  for (int ts = 0; ts < RK_MAX; ts++) if (isKind(ts, RK_KIND_TOTP) && !tlnkRowLocked(ts) && tlnkPwLocked(ts) == ps) return ts;
  return -1;
}
// every password slot with a code, in one pass (for the lists)
static void tlnkMarkLocked(bool linked[RK_MAX]) {
  memset(linked, 0, RK_MAX);
  for (int ts = 0; ts < RK_MAX; ts++) if (isKind(ts, RK_KIND_TOTP)) { const int ps = tlnkPwLocked(ts); if (ps >= 0) linked[ps] = true; }
}
static int slotOfKind(uint8_t k, int i) { for (int s = 0, c = 0; s < RK_MAX; s++) if (isKind(s, k) && c++ == i) return s; return -1; }
int rk_count() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return countKind(RK_KIND_PASSKEY);
}
int rk_count_all() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return countLocked();
}

// One G0 VAULT call; maps its result to an RK_E_* code.
static int vault(uint8_t op, const uint8_t* in, size_t n, uint8_t* out, size_t* on) {
  uint8_t res = 0xFF, left = 0xFF;
  if (!g0_vault(op, in, n, out, on, &res, &left)) { s_lastRes = 0xFF; return RK_E_G0; }
  s_lastRes = res; if (left != 0xFF) s_openLeft = left;
  else if (op != G0_VAULT_LIMIT && op != G0_VAULT_SETLIM) { s_limit = 0; s_openLeft = -1; s_tagLeft = -1; }   // v24: 0xFF = no limit
  if (res == 0 && (op == G0_VAULT_TAG || op == G0_VAULT_SEAL) && s_tagLeft > 0) s_tagLeft--;   // 25 Nov 2026: rk_tag_left
  if (res == 0xE8) s_tagLeft = 0;   // the G0 says the TAGs are spent
  if (res == 0) return RK_OK;
  if (res == 0xE7 || res == 0xE8) return RK_E_BUDGET;   // 2b: E8 = this sitting's TAG budget (C+)
  return RK_E_G0;
}

static int tagLocked(const char* site, size_t n, uint8_t tag[8]) {
  for (auto& t : R->tags) if (t.used && strlen(t.site) == n && !memcmp(t.site, site, n)) { memcpy(tag, t.tag, 8); return RK_OK; }
  size_t on = 0;
  int r = vault(G0_VAULT_TAG, (const uint8_t*)site, n, R->buf, &on);
  if (r) return r;
  if (on != 8) return RK_E_G0;
  memcpy(tag, R->buf, 8);
  auto& t = R->tags[s_tagNext++ % 4];
  t.used = 1; memcpy(t.site, site, n); t.site[n] = 0; memcpy(t.tag, tag, 8);
  return RK_OK;
}

// Parse an opened record (hdr13 || plaintext) into a.
static bool parse(const uint8_t* b, size_t n, RkAcct* a) {
  if (n < HDR + 1) return false;
  memset(a, 0, sizeof *a);
  a->updated = rd32(b + 8);
  if (b[12] != RK_KIND_PASSKEY) return false;
  size_t p = HDR;
  auto field = [&](size_t max, uint8_t* dst, size_t* dn) -> bool {
    if (p >= n) return false;
    size_t l = b[p++]; if (l > max || p + l > n) return false;
    memcpy(dst, b + p, l); *dn = l; p += l; return true;
  };
  size_t l;
  if (!field(RK_SITE_MAX, (uint8_t*)a->site, &l) || l == 0) return false;
  a->site[l] = 0;
  if (!field(RK_HANDLE_MAX, a->handle, &l) || l == 0) return false;
  a->handleN = (uint8_t)l;
  if (!field(RK_NAME_MAX, (uint8_t*)a->name, &l)) return false;
  a->name[l] = 0;
  if (!field(RK_NAME_MAX, (uint8_t*)a->disp, &l)) return false;
  a->disp[l] = 0;
  if (p + 32 + 4 != n) return false;
  a->id34[0] = 0x01; a->id34[1] = 0x01; memcpy(a->id34 + 2, b + p, 32);
  return true;
}

// Read slot i and have the G0 open it: RK_OK and the plaintext (hdr13 ||
// fields) in R->buf, *on bytes. The caller wipes R->buf.
static int openRawLocked(int i, size_t* on) {
  Preferences p; char k[5]; key(i, k); size_t n = 0;
  if (p.begin(RK_NS, true, RK_PART)) { n = p.isKey(k) ? p.getBytesLength(k) : 0; if (n && n <= sizeof R->blob) n = p.getBytes(k, R->blob, n); else n = 0; p.end(); }
  if (!n) return RK_E_NVS;
  *on = 0;
  int r = vault(G0_VAULT_OPEN, R->blob, n, R->buf, on);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  if (r) { mbedtls_platform_zeroize(R->buf, sizeof R->buf); return r; }
  return RK_OK;
}
// Open passkey slot i (cache first). RK_OK and *a filled, or an error.
static int openLocked(int i, RkAcct* a) {
  if (s_cache[i]) { *a = *s_cache[i]; return RK_OK; }
  if (!isKind(i, RK_KIND_PASSKEY)) return RK_E_FORMAT;
  size_t on = 0;
  int r = openRawLocked(i, &on);
  if (r) return r;
  bool ok = parse(R->buf, on, a);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (!ok) return RK_E_FORMAT;
  a->slot = i;
  RkAcct* c = (RkAcct*)rkAlloc(sizeof(RkAcct));
  if (c) { *c = *a; s_cache[i] = c; }
  return RK_OK;
}

// The slot holding this site's record for this user handle: >= 0 found, -1
// none, or an RK_E_* code if any of the site's records could not be opened
// (then a save must not guess: a duplicate would follow). Review 2 Nov 2026:
// every matching slot is checked, not the first 8.
static int matchLocked(const char* site, size_t n, const uint8_t* handle, size_t hn) {
  uint8_t tag[8];
  int r = tagLocked(site, n, tag);
  if (r) return r;
  for (int i = 0; i < RK_MAX; i++) {
    if (!isKind(i, RK_KIND_PASSKEY) || memcmp(R->idx[i].clear + TAGOFF, tag, 8)) continue;   // P4: password entries of the site are not passkeys
    RkAcct a; int e = openLocked(i, &a);
    if (e) { mbedtls_platform_zeroize(&a, sizeof a); return e; }
    bool same = strlen(a.site) == n && !memcmp(a.site, site, n) && a.handleN == hn && !memcmp(a.handle, handle, hn);
    mbedtls_platform_zeroize(&a, sizeof a);
    if (same) return i;
  }
  return -1;
}
static int findLocked(const char* site, size_t n, RkAcct* out, int max) {
  uint8_t tag[8];
  int r = tagLocked(site, n, tag);
  if (r) return r;
  int got = 0, err = RK_OK;
  for (int i = 0; i < RK_MAX && got < max; i++) {
    if (!isKind(i, RK_KIND_PASSKEY) || memcmp(R->idx[i].clear + TAGOFF, tag, 8)) continue;   // P4: never spend an OPEN on a password at sign-in
    RkAcct a; int e = openLocked(i, &a);
    if (e) { err = e; Serial.printf("[RK] slot %d not opened: %s\n", i, rk_err_name(e)); if (e == RK_E_BUDGET) break; continue; }
    if (strlen(a.site) != n || memcmp(a.site, site, n)) { mbedtls_platform_zeroize(&a, sizeof a); continue; }   // a tag collision (2^-64): not this site
    out[got++] = a;
    mbedtls_platform_zeroize(&a, sizeof a);
  }
  return got ? got : err;
}

int rk_find(const char* site, size_t n, RkAcct* out, int max) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (n == 0 || n > RK_SITE_MAX) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return findLocked(site, n, out, max);
}

int rk_save(const char* site, size_t siteN, const uint8_t* handle, size_t handleN,
            const char* name, size_t nameN, const char* disp, size_t dispN, const uint8_t id34[34]) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (siteN == 0 || siteN > RK_SITE_MAX || handleN == 0 || handleN > RK_HANDLE_MAX) return RK_E_SIZE;
  if (!name) nameN = 0;   // a site may leave name or displayName out
  if (!disp) dispN = 0;
  nameN = rk_utf8_cut(name, nameN, RK_NAME_MAX);
  dispN = rk_utf8_cut(disp, dispN, RK_NAME_MAX);
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  // The same site and user handle: replace (CTAP), keeping the record's id.
  int slot = matchLocked(site, siteN, handle, handleN);
  if (slot < -1) return slot;   // a record of this site could not be opened: do not risk a duplicate
  uint8_t id8[8];
  if (slot >= 0) memcpy(id8, R->idx[slot].clear, 8);
  else {
    for (int i = 0; i < RK_MAX; i++) if (!R->idx[i].used) { slot = i; break; }
    if (slot < 0) return RK_E_FULL;
    esp_fill_random(id8, 8);
  }
  uint32_t upd = 0;
  { time_t now = time(nullptr); if (now > 1700000000) upd = (uint32_t)now; }
  for (int i = 0; i < RK_MAX; i++) if (R->idx[i].used) { uint32_t u = rd32(R->idx[i].clear + 8); if (u >= upd) upd = u + 1; }
  // hdr13 || [siteLen][site][hLen][handle][nLen][name][dLen][display][nonce16][tag16][created4]
  size_t p = 0; uint8_t* b = R->buf;
  memcpy(b, id8, 8); wr32(b + 8, upd); b[12] = RK_KIND_PASSKEY; p = HDR;
  b[p++] = (uint8_t)siteN;   memcpy(b + p, site, siteN); p += siteN;
  b[p++] = (uint8_t)handleN; memcpy(b + p, handle, handleN); p += handleN;
  b[p++] = (uint8_t)nameN;   if (nameN) memcpy(b + p, name, nameN); p += nameN;
  b[p++] = (uint8_t)dispN;   if (dispN) memcpy(b + p, disp, dispN); p += dispN;
  memcpy(b + p, id34 + 2, 32); p += 32;
  wr32(b + p, upd); p += 4;
  size_t on = 0;
  int r = vault(G0_VAULT_SEAL, b, p, R->blob, &on);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (r) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return r; }
  if (on < CLEAR) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_G0; }
  Preferences pr; char k[5]; key(slot, k); size_t w = 0;
  if (pr.begin(RK_NS, false, RK_PART)) { w = pr.putBytes(k, R->blob, on); pr.end(); }
  if (w != on) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_NVS; }
  R->idx[slot].used = 1; memcpy(R->idx[slot].clear, R->blob, CLEAR);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  changed();   // phase 3: the relay backup does not have this yet
  // Cache what was just sealed (review 2 Nov 2026): the next sign-in on this
  // site then costs no OPEN for it.
  if (!s_cache[slot]) s_cache[slot] = (RkAcct*)rkAlloc(sizeof(RkAcct));
  if (s_cache[slot]) {
    RkAcct* c = s_cache[slot]; memset(c, 0, sizeof *c);
    c->slot = slot; c->updated = upd;
    memcpy(c->site, site, siteN); memcpy(c->handle, handle, handleN); c->handleN = (uint8_t)handleN;
    if (nameN) memcpy(c->name, name, nameN);
    if (dispN) memcpy(c->disp, disp, dispN);
    c->id34[0] = 0x01; c->id34[1] = 0x01; memcpy(c->id34 + 2, id34 + 2, 32);
  }
  Serial.printf("[RK] record saved in slot %d (%d of %d used)\n", slot, countLocked(), RK_MAX);
  return RK_OK;
}

int rk_room(const char* site, size_t siteN, const uint8_t* handle, size_t handleN) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (siteN == 0 || siteN > RK_SITE_MAX || handleN == 0 || handleN > RK_HANDLE_MAX) return RK_E_SIZE;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int m = matchLocked(site, siteN, handle, handleN);
  if (m < -1) return m;
  if (m >= 0 || countLocked() < RK_MAX) return RK_OK;
  return RK_E_FULL;
}
int rk_slot_at(int i) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSKEY, i);
  return s >= 0 ? s : RK_E_FORMAT;
}
int rk_at(int i, RkAcct* out) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSKEY, i);
  return s >= 0 ? openLocked(s, out) : RK_E_FORMAT;
}

int rk_delete(int slot) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (slot < 0 || slot >= RK_MAX) return RK_E_FORMAT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!R->idx[slot].used) return RK_OK;
  {   // phase 3: a tombstone, so a restore does not bring it back
    uint8_t* tb = R->tomb; int c = tombLoad(tb);
    c = tombPut(tb, c, R->idx[slot].clear, nowOr(rd32(R->idx[slot].clear + 8) + 1));
    if (!tombSave(tb, c)) return RK_E_NVS;
  }
  Preferences p; char k[5]; key(slot, k); bool ok = false;
  if (p.begin(RK_NS, false, RK_PART)) { ok = p.remove(k); p.end(); }
  if (!ok) return RK_E_NVS;
  memset(&R->idx[slot], 0, sizeof R->idx[slot]);
  if (s_cache[slot]) { mbedtls_platform_zeroize(s_cache[slot], sizeof(RkAcct)); free(s_cache[slot]); s_cache[slot] = nullptr; }
  siteDropLocked(slot); ixFlushLocked(false);   // P4-10
  changed();
  Serial.printf("[RK] record in slot %d deleted (%d left, all kinds)\n", slot, countLocked());
  return RK_OK;
}

// 4 Nov 2026: many deletes in one go (the phone's "Delete selected", the KEY's
// "Delete all passwords"). Each (slot, id) must still be the same password
// record; anything else is skipped and counted. All tombstones are written in
// ONE save before any record is removed (a cut power can then only leave
// records that are already tombstoned: the next merge drops them), and the
// site index is written once at the end. ids may be null: every slot as it is.
int rk_delete_many(const int* slots, const uint8_t (*ids)[8], int n, int* deleted, int* skipped) {
  if (deleted) *deleted = 0; if (skipped) *skipped = 0;
  if (!rk_ready()) return RK_E_NOVAULT;
  if (!slots || n <= 0 || n > RK_MAX) return RK_E_FORMAT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  bool* take = R->takeS; memset(take, 0, sizeof R->takeS); int want = 0, skip = 0;   // 11dr: PSRAM scratch
  for (int k = 0; k < n; k++) {
    int s = slots[k];
    if (s < 0 || s >= RK_MAX || !R->idx[s].used || R->idx[s].clear[12] != RK_KIND_PASSWORD || take[s] || (ids && memcmp(R->idx[s].clear, ids[k], 8))) { skip++; continue; }
    take[s] = true; want++;
  }
  if (skipped) *skipped = skip;
  if (!want) return RK_OK;
  {
    uint8_t* tb = R->tomb; int c = tombLoad(tb);
    for (int s = 0; s < RK_MAX; s++) if (take[s]) c = tombPut(tb, c, R->idx[s].clear, nowOr(rd32(R->idx[s].clear + 8) + 1));
    if (!tombSave(tb, c)) return RK_E_NVS;
  }
  int done = 0; bool nvsFail = false;
  Preferences p;
  if (!p.begin(RK_NS, false, RK_PART)) return RK_E_NVS;
  for (int s = 0; s < RK_MAX; s++) {
    if (!take[s]) continue;
    char k[5]; key(s, k);
    if (!p.remove(k)) { nvsFail = true; continue; }
    memset(&R->idx[s], 0, sizeof R->idx[s]);
    if (s_cache[s]) { mbedtls_platform_zeroize(s_cache[s], sizeof(RkAcct)); free(s_cache[s]); s_cache[s] = nullptr; }
    labelDropLocked(s); siteDropLocked(s);
    done++;
  }
  p.end();
  if (done) { ixFlushLocked(true); changed(); }
  if (deleted) *deleted = done;
  Serial.printf("[RK] %d password entries deleted in one go (%d skipped%s, %d records left)\n", done, skip, nvsFail ? ", some could not be removed" : "", countLocked());
  return nvsFail ? RK_E_NVS : RK_OK;
}

// ---- Phase 3: backup body (Vault spec section 4) -----------------------------
// nrec u16 || nrec x (len u16 || sealed record exactly as stored) ||
// ntomb u16 || ntomb x (id8 || deleted-at u32). Nothing is opened.
bool rk_dirty() {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx);
  Preferences p; uint8_t d = 0; if (p.begin(RK_NS, true, RK_PART)) { d = p.getUChar("dirty", 0); p.end(); }
  return d != 0;
}
bool rk_set_clean(uint32_t gen) {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx);
  if (gen != s_changeGen) return false;   // something changed after the export: stay dirty
  dirtySet(false); return true;
}
int rk_export(uint8_t* out, size_t cap, size_t* outN, int* nrec, int* ntomb, uint32_t* gen) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  if (gen) *gen = s_changeGen;
  loadLocked();
  size_t p = 2; int nr = 0;
  Preferences pr;
  if (!pr.begin(RK_NS, true, RK_PART)) return RK_E_NVS;
  int err = RK_OK;
  for (int i = 0; i < RK_MAX && !err; i++) {
    if (!R->idx[i].used) continue;
    char k[5]; key(i, k);
    size_t n = pr.getBytesLength(k);
    if (n < CLEAR + 16 + 16 + 32 || n > G0_VAULT_DATA_MAX) continue;
    if (p + 2 + n + 2 > cap) { err = RK_E_SIZE; break; }
    if (pr.getBytes(k, out + p + 2, n) != n) { err = RK_E_NVS; break; }
    out[p] = (uint8_t)(n >> 8); out[p + 1] = (uint8_t)n; p += 2 + n; nr++;
  }
  pr.end();
  if (err) return err;
  out[0] = (uint8_t)(nr >> 8); out[1] = (uint8_t)nr;
  uint8_t* tb = R->tomb; int c = tombLoad(tb);
  if (p + 2 + (size_t)c * 12 > cap) return RK_E_SIZE;
  out[p] = (uint8_t)(c >> 8); out[p + 1] = (uint8_t)c; p += 2;
  memcpy(out + p, tb, (size_t)c * 12); p += (size_t)c * 12;
  if (outN) *outN = p; if (nrec) *nrec = nr; if (ntomb) *ntomb = c;
  return RK_OK;
}
// Merge a backup body into this KEY: tombstones first, then newest "updated"
// wins per id. Records are written sealed, exactly as they came (the same
// words give the same K_vault, so they open here); a forged or altered one
// simply fails its MAC when it is first opened. Never opens anything.
int rk_import(const uint8_t* in, size_t n, RkImport* st) {
  if (!rk_ready()) return RK_E_NOVAULT;
  RkImport z = {}; if (!st) st = &z; *st = RkImport{};
  // Parse the whole body before changing anything.
  if (n < 4) return RK_E_FORMAT;
  size_t p = 2; int nr = (in[0] << 8) | in[1];
  if (nr > 4 * RK_MAX) return RK_E_FORMAT;   // P4-1: was 255 (RK_MAX 50); a KEY never exports more than RK_MAX
  for (int i = 0; i < nr; i++) {
    if (p + 2 > n) return RK_E_FORMAT;
    size_t l = ((size_t)in[p] << 8) | in[p + 1];
    if (l < CLEAR + 16 + 16 + 32 || l > G0_VAULT_DATA_MAX || p + 2 + l > n) return RK_E_FORMAT;
    p += 2 + l;
  }
  if (p + 2 > n) return RK_E_FORMAT;
  int nt = (in[p] << 8) | in[p + 1]; size_t tp = p + 2;
  if (nt > 4 * TOMB_MAX || tp + (size_t)nt * 12 != n) return RK_E_FORMAT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  uint8_t* tb = R->tomb; int c = tombLoad(tb);
  bool changed = false;
  auto dropSlot = [&](int s) -> bool {
    Preferences pr; char k[5]; key(s, k); bool ok = false;
    if (pr.begin(RK_NS, false, RK_PART)) { ok = pr.remove(k); pr.end(); }
    if (!ok) return false;
    memset(&R->idx[s], 0, sizeof R->idx[s]);
    if (s_cache[s]) { mbedtls_platform_zeroize(s_cache[s], sizeof(RkAcct)); free(s_cache[s]); s_cache[s] = nullptr; }
    labelDropLocked(s); siteDropLocked(s);   // P4-10 review (2): a restore never leaves a name behind
    return true;
  };
  // 1. tombstones from the backup
  for (int i = 0; i < nt; i++) {
    const uint8_t* t = in + tp + i * 12; uint32_t when = rd32(t + 8);
    if (tooFar(when)) { st->future++; continue; }
    if (tombTime(tb, c, t) < when) { c = tombPut(tb, c, t, when); changed = true; }
    for (int s = 0; s < RK_MAX; s++)
      if (R->idx[s].used && !memcmp(R->idx[s].clear, t, 8) && rd32(R->idx[s].clear + 8) <= when) {
        if (dropSlot(s)) { st->removed++; changed = true; } else st->failed++;
      }
  }
  // 2. records
  p = 2;
  Preferences pr;
  if (!pr.begin(RK_NS, false, RK_PART)) { tombSave(tb, c); return RK_E_NVS; }
  for (int i = 0; i < nr; i++) {
    size_t l = ((size_t)in[p] << 8) | in[p + 1]; const uint8_t* r = in + p + 2; p += 2 + l;
    uint32_t upd = rd32(r + 8);
    if (!kindHeld(r[12])) { st->foreign++; continue; }   // a kind this firmware does not hold: the caller must not publish over it (P4: passwords are held)
    if (tooFar(upd)) { st->future++; continue; }
    if (tombTime(tb, c, r) >= upd && tombTime(tb, c, r) != 0) { st->skipped++; continue; }   // deleted here (or there) after this version
    int slot = -1, freeSlot = -1;
    for (int s = 0; s < RK_MAX; s++) {
      if (R->idx[s].used && !memcmp(R->idx[s].clear, r, 8)) { slot = s; break; }
      if (!R->idx[s].used && freeSlot < 0) freeSlot = s;
    }
    if (slot >= 0) {
      uint32_t lu = rd32(R->idx[slot].clear + 8);
      if (lu > upd) { st->same++; continue; }   // this KEY's copy is newer
      if (lu == upd) {   // review: the same time on two KEYs: the larger sealed bytes win everywhere, so all KEYs agree
        char k0[5]; key(slot, k0); size_t ln = pr.getBytesLength(k0);
        bool keep = ln < 1 || ln > G0_VAULT_DATA_MAX || pr.getBytes(k0, R->buf, ln) != ln;
        int c2 = keep ? 1 : memcmp(R->buf, r, ln < l ? ln : l); if (!keep && c2 == 0) c2 = (ln >= l) ? 1 : -1;
        mbedtls_platform_zeroize(R->buf, sizeof R->buf);
        if (c2 >= 0) { st->same++; continue; }
      }
    }
    if (slot < 0) slot = freeSlot;
    if (slot < 0) { st->full++; continue; }   // the caller must not publish over a backup it could not hold
    char k[5]; key(slot, k);
    if (pr.putBytes(k, r, l) != l) { st->failed++; continue; }
    if (s_cache[slot]) { mbedtls_platform_zeroize(s_cache[slot], sizeof(RkAcct)); free(s_cache[slot]); s_cache[slot] = nullptr; }
    labelDropLocked(slot); siteDropLocked(slot);   // P4-10 review (2): an equal (id, updated) with other bytes must not keep the old name
    R->idx[slot].used = 1; memcpy(R->idx[slot].clear, r, CLEAR);
    st->added++; changed = true;
  }
  pr.end();
  if (!tombSave(tb, c)) st->failed++;
  // Anything here that the backup lacks (a newer record, an extra one, a
  // tombstone) means the next backup should carry it.
  bool extra = false;
  for (int s = 0; s < RK_MAX && !extra; s++) {
    if (!R->idx[s].used) continue;
    bool found = false; size_t q = 2;
    for (int i = 0; i < nr; i++) { size_t l = ((size_t)in[q] << 8) | in[q + 1]; const uint8_t* r = in + q + 2; q += 2 + l;
      if (!memcmp(r, R->idx[s].clear, 8) && rd32(r + 8) >= rd32(R->idx[s].clear + 8)) { found = true; break; } }
    if (!found) extra = true;
  }
  for (int i = 0; i < c && !extra; i++) {
    bool found = false;
    for (int j = 0; j < nt; j++) if (!memcmp(in + tp + j * 12, tb + i * 12, 8) && rd32(in + tp + j * 12 + 8) >= rd32(tb + i * 12 + 8)) { found = true; break; }
    if (!found) extra = true;
  }
  if (extra) dirtySet(true);
  (void)changed;
  if (extra) s_changeGen++;
  Serial.printf("[RK] backup merged: %d added or updated, %d removed by tombstones, %d already here, %d skipped, %d no room, %d other kinds, %d dated ahead, %d failed (%d records now)%s\n",
                st->added, st->removed, st->same, st->skipped, st->full, st->foreign, st->future, st->failed, countLocked(), extra ? " - this KEY has changes the backup lacks" : "");
  return st->failed ? RK_E_NVS : RK_OK;
}

// ---- Phase 4 (3 Nov 2026, Vault spec 7f): password entries (kind 2) ----------
int rk_pw_check(size_t siteN, size_t userN, size_t passN, size_t noteN) {
  if (siteN == 0 || siteN > RK_SITE_MAX || passN == 0 || userN > RK_PW_FIELD_MAX || passN > RK_PW_FIELD_MAX || noteN > RK_PW_FIELD_MAX) return RK_E_SIZE;
  if (1 + siteN + 1 + userN + 1 + passN + 1 + noteN + 12 > RK_PT_MAX) return RK_E_SIZE;
  return RK_OK;
}
void rk_pw_wipe(RkPass* p) { if (p) mbedtls_platform_zeroize(p, sizeof *p); }
// Parse an opened kind-2 record (hdr13 || plaintext) into a.
static bool parsePw(const uint8_t* b, size_t n, RkPass* a) {
  if (n < HDR + 1 || b[12] != RK_KIND_PASSWORD) return false;
  memset(a, 0, sizeof *a);
  size_t p = HDR, l = 0;
  auto field = [&](size_t max, char* dst) -> bool {
    if (p >= n) return false;
    l = b[p++]; if (l > max || p + l > n) return false;
    memcpy(dst, b + p, l); dst[l] = 0; p += l; return true;
  };
  if (!field(RK_SITE_MAX, a->site) || l == 0) return false;
  if (!field(RK_PW_FIELD_MAX, a->user)) return false;
  if (!field(RK_PW_FIELD_MAX, a->pass) || l == 0) return false;
  if (!field(RK_PW_FIELD_MAX, a->note)) return false;
  if (p + 12 != n) return false;
  a->policy = rd32(b + p); a->created = rd32(b + p + 4); a->updated = rd32(b + 8);   // the header's time is the one merges trust
  return true;
}
static int pwOpenLocked(int s, RkPass* out) {
  if (!isKind(s, RK_KIND_PASSWORD)) return RK_E_FORMAT;
  size_t on = 0;
  int r = openRawLocked(s, &on);
  if (r) return r;
  bool ok = parsePw(R->buf, on, out);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (!ok) { rk_pw_wipe(out); return RK_E_FORMAT; }
  out->slot = s;
  { // 11s: an OPEN is a free look at the password: strength if unknown, the hash for reuse and the breach check
    const size_t pn = strnlen(out->pass, sizeof out->pass);
    uint8_t h = hlthGetLocked(s);
    if (!(h & RK_H_STRENGTH)) { h = (uint8_t)((h & ~RK_H_STRENGTH) | strengthOf(out->pass, pn)); hlthSetLocked(s, h); }
    hashNoteLocked(s, out->pass, pn);
    hlthFlushLocked();
  }
  return RK_OK;
}
int rk_pw_count() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return countKind(RK_KIND_PASSWORD);
}
int rk_pw_slot_at(int i) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  return s >= 0 ? s : RK_E_FORMAT;
}
int rk_pw_open(int i, RkPass* out) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  return s >= 0 ? pwOpenLocked(s, out) : RK_E_FORMAT;
}
// The slot of this site's entry for this username: >= 0, -1 none, or an
// RK_E_* code if one of the site's entries could not be opened (a save must
// not guess then: a duplicate would follow). Each candidate costs an OPEN;
// only entries with the site's tag are candidates.
static int labelLocked(int s, RkLabel* out);   // v15, below
// labelOnly (11bh, imports): a match by LABEL is enough; the record is not
// opened (an import keeps the KEY's entry, so its created date is not needed,
// and an OPEN would come out of the sitting's 32).
static int pwMatchLocked(const char* site, size_t n, const char* user, size_t un, uint32_t* created, bool labelOnly = false) {
  uint8_t tag[8];
  int r = tagLocked(site, n, tag);
  if (r) return r;
  for (int i = 0; i < RK_MAX; i++) {
    if (!isKind(i, RK_KIND_PASSWORD) || memcmp(R->idx[i].clear + TAGOFF, tag, 8)) continue;
    // v15: the same site with another username costs a LABEL (400 per life),
    // not an OPEN (32 per sitting), so an import of several accounts on one
    // site does not spend the OPENs. A match is then opened once for its
    // created date.
    if (g0_v15_present()) {
      RkLabel L;
      int e = labelLocked(i, &L);
      if (e) return e;
      bool same = strlen(L.site) == n && !memcmp(L.site, site, n) && strlen(L.user) == un && !memcmp(L.user, user, un);
      mbedtls_platform_zeroize(&L, sizeof L);
      if (!same) continue;
      if (labelOnly) return i;
    }
    RkPass* a = (RkPass*)rkAlloc(sizeof(RkPass));
    if (!a) return RK_E_NVS;
    int e = pwOpenLocked(i, a);
    bool same = !e && strlen(a->site) == n && !memcmp(a->site, site, n) && strlen(a->user) == un && !memcmp(a->user, user, un);
    if (same) *created = a->created;
    rk_pw_wipe(a); free(a);
    if (e) return e;
    if (same) return i;
  }
  return -1;
}
int rk_pw_save(const RkPass* in, int* slotOut) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (!in) return RK_E_SIZE;
  size_t siteN = strnlen(in->site, sizeof in->site), userN = strnlen(in->user, sizeof in->user),
         passN = strnlen(in->pass, sizeof in->pass), noteN = strnlen(in->note, sizeof in->note);
  if (siteN > RK_SITE_MAX || userN > RK_PW_FIELD_MAX || passN > RK_PW_FIELD_MAX || noteN > RK_PW_FIELD_MAX) return RK_E_SIZE;   // not NUL-terminated
  if (rk_pw_check(siteN, userN, passN, noteN)) return RK_E_SIZE;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int slot = -1; uint32_t oldCreated = 0;
  if (in->slot >= 0 && in->slot < RK_MAX && isKind(in->slot, RK_KIND_PASSWORD)) slot = in->slot;   // an edit: keep the id
  else {
    // 11bh (bench 17 Nov 2026): an import never replaces an entry already on the
    // KEY (its password may be the newer one), and finding it costs a LABEL, not
    // an OPEN: 32 duplicates in an export had spent the sitting's opens.
    const bool imp = in->origin == RK_ORIGIN_IMPORT && g0_v15_present();
    slot = pwMatchLocked(in->site, siteN, in->user, userN, &oldCreated, imp);   // a replace keeps the id and when it was first made
    if (slot < -1) return slot;
    if (imp && slot >= 0) return RK_E_EXISTS;
  }
  uint8_t id8[8];
  if (slot >= 0) memcpy(id8, R->idx[slot].clear, 8);
  else {
    for (int i = 0; i < RK_MAX; i++) if (!R->idx[i].used) { slot = i; break; }
    if (slot < 0) return RK_E_FULL;
    esp_fill_random(id8, 8);
  }
  uint32_t upd = 0;
  { time_t now = time(nullptr); if (now > 1700000000) upd = (uint32_t)now; }
  for (int i = 0; i < RK_MAX; i++) if (R->idx[i].used) { uint32_t u = rd32(R->idx[i].clear + 8); if (u >= upd) upd = u + 1; }
  uint32_t created = in->created ? in->created : oldCreated ? oldCreated : upd;
  // hdr13 || [siteLen][site][uLen][user][pLen][pass][nLen][note][policy4][created4][updated4]
  size_t p = 0; uint8_t* b = R->buf;
  memcpy(b, id8, 8); wr32(b + 8, upd); b[12] = RK_KIND_PASSWORD; p = HDR;
  b[p++] = (uint8_t)siteN; memcpy(b + p, in->site, siteN); p += siteN;
  b[p++] = (uint8_t)userN; if (userN) memcpy(b + p, in->user, userN); p += userN;
  b[p++] = (uint8_t)passN; memcpy(b + p, in->pass, passN); p += passN;
  b[p++] = (uint8_t)noteN; if (noteN) memcpy(b + p, in->note, noteN); p += noteN;
  wr32(b + p, in->policy); wr32(b + p + 4, created); wr32(b + p + 8, upd); p += 12;
  size_t on = 0;
  int r = vault(G0_VAULT_SEAL, b, p, R->blob, &on);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (r) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return r; }
  if (on < CLEAR) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_G0; }
  Preferences pr; char k[5]; key(slot, k); size_t w = 0;
  if (pr.begin(RK_NS, false, RK_PART)) { w = pr.putBytes(k, R->blob, on); pr.end(); }
  if (w != on) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_NVS; }
  R->idx[slot].used = 1; memcpy(R->idx[slot].clear, R->blob, CLEAR);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  changed();
  if (slotOut) *slotOut = slot;
  { // 11s: health at seal time. A replaced entry starts its breach verdict over.
    const uint8_t old = hlthGetLocked(slot);
    uint8_t h = (uint8_t)(strengthOf(in->pass, passN) | ((in->origin ? (in->origin & 3) : ((old & RK_H_ORIGIN) >> 2)) << 2));   // an edit that says nothing keeps the origin
    hlthSetLocked(slot, h);
    hashNoteLocked(slot, in->pass, passN);
    hlthFlushLocked();
  }
  siteSetLocked(slot, in->site, siteN);   // P4-10: the index follows every save
  ixFlushLocked(false);
  Serial.printf("[RK] password entry saved in slot %d (%d passwords, %d of %d records used)\n", slot, countKind(RK_KIND_PASSWORD), countLocked(), RK_MAX);
  return RK_OK;
}

int rk_pw_order(int* idx, int max) {
  if (!rk_ready() || !idx || max <= 0) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  uint32_t* t = (uint32_t*)rkAlloc(sizeof(uint32_t) * RK_MAX);   // 11dr: PSRAM (1.6 KB at RK_MAX 400 was too much stack)
  if (!t) return 0;
  struct FreeT { uint32_t* p; ~FreeT() { free(p); } } ft{t};
  int n = 0;
  for (int s = 0, i = 0; s < RK_MAX; s++) {
    if (!isKind(s, RK_KIND_PASSWORD)) continue;
    if (n < max) {   // insertion by time, newest first; equal times keep slot order
      uint32_t u = rd32(R->idx[s].clear + 8); int j = n++;
      while (j > 0 && t[j - 1] < u) { idx[j] = idx[j - 1]; t[j] = t[j - 1]; j--; }
      idx[j] = i; t[j] = u;
    }
    i++;
  }
  return n;
}

// ---- v15 (3 Nov 2026, Vault spec 7f P4-8): labels -----------------------------
bool rk_pw_label_cached(int i) {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  if (s < 0) return false;
  RkLabel* c = R->labels[s];
  return c && c->slot == s && c->updated == rd32(R->idx[s].clear + 8) && !memcmp(c->id8, R->idx[s].clear, 8);
}
// One LABEL of slot s (cache first). Caller holds the mutex and loaded the index.
static int labelLocked(int s, RkLabel* out) {
  uint32_t upd = rd32(R->idx[s].clear + 8);
  RkLabel* c = R->labels[s];
  if (c && c->slot == s && c->updated == upd && !memcmp(c->id8, R->idx[s].clear, 8)) { *out = *c; return RK_OK; }   // the same id and time: the same record
  Preferences p; char k[5]; key(s, k); size_t n = 0;
  if (p.begin(RK_NS, true, RK_PART)) { n = p.isKey(k) ? p.getBytesLength(k) : 0; if (n && n <= sizeof R->blob) n = p.getBytes(k, R->blob, n); else n = 0; p.end(); }
  if (!n) return RK_E_NVS;
  size_t on = 0;
  int r = vault(G0_VAULT_LABEL, R->blob, n, R->buf, &on);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  if (r) { mbedtls_platform_zeroize(R->buf, sizeof R->buf); return r; }
  // left16 || hdr13 || [sLen][site] || [uLen][user]
  const uint8_t* b = R->buf; bool ok = on >= 2 + HDR + 2;
  RkLabel L; memset(&L, 0, sizeof L);
  if (ok) {
    s_labelLeft = (b[0] << 8) | b[1];
    ok = !memcmp(b + 2, R->idx[s].clear, HDR) && (b[2 + 12] == RK_KIND_PASSWORD || b[2 + 12] == RK_KIND_TOTP);   // 9i: kind 3 too (same site and account shape)   // the label is for the record asked about
    size_t q = 2 + HDR;
    if (ok) { size_t l = b[q++]; ok = l >= 1 && l <= RK_SITE_MAX && q + l < on; if (ok) { memcpy(L.site, b + q, l); q += l; } }
    if (ok) { size_t l = b[q++]; ok = l <= RK_PW_FIELD_MAX && q + l == on; if (ok) memcpy(L.user, b + q, l); }
  }
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (!ok) return RK_E_FORMAT;
  L.slot = s; L.updated = upd; memcpy(L.id8, R->idx[s].clear, 8);
  *out = L;
  if (!c) c = R->labels[s] = (RkLabel*)rkAlloc(sizeof(RkLabel));
  if (c) *c = L;
  siteSetLocked(s, L.site, strlen(L.site));   // P4-10: a label heals the index
  if (s_ixDirty >= 10) ixFlushLocked(false);   // heals are written ten at a time
  return RK_OK;
}
int rk_pw_label(int i, RkLabel* out) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (!g0_v15_present()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  if (s < 0) return RK_E_FORMAT;
  return labelLocked(s, out);
}
bool rk_pw_id_of(int slot, uint8_t id8[8]) {
  if (!rk_ready() || slot < 0 || slot >= RK_MAX) return false;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!isKind(slot, RK_KIND_PASSWORD)) return false;
  memcpy(id8, R->idx[slot].clear, 8);   // the id is in the clear header: no G0 call
  return true;
}
int rk_pw_index_of(int slot, const uint8_t id8[8]) {
  if (!rk_ready() || slot < 0 || slot >= RK_MAX) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!isKind(slot, RK_KIND_PASSWORD) || (id8 && memcmp(R->idx[slot].clear, id8, 8))) return -1;
  int i = 0; for (int s = 0; s < slot; s++) i += isKind(s, RK_KIND_PASSWORD);
  return i;
}
// VAULT op 5: the import window. The G0 takes it only as the very next VAULT op
// after a right UVCHECK, in the NOSTR life, once per power-on life.
int rk_pw_import_window(int* sealsLeft, int* tagsLeft) {
  if (!rk_ready() || !g0_v15_present()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!R) return RK_E_NVS;
  size_t on = 0;
  int r = vault(G0_VAULT_IMPORT, nullptr, 0, R->buf, &on);
  if (r) return r;
  if (on < 4) return RK_E_G0;
  if (sealsLeft) *sealsLeft = (R->buf[0] << 8) | R->buf[1];
  if (tagsLeft) *tagsLeft = (R->buf[2] << 8) | R->buf[3];
  return RK_OK;
}

static void ixCloseLocked();
void rk_forget_cache() {
  std::lock_guard<std::mutex> g(s_mx);
  s_lockEpoch++;     // P4-10 review (3): an unwrap that began before this lock cannot install its key after it
  ixCloseLocked();   // P4-10: the index key and the names go with the lock
  // 11ae (11 Nov 2026): s_cache is R->cache, and R is null until rk_mount
  // (an onboarding life never mounts). UV_FORGET after a seed restore came
  // through here and the KEY reset with LoadProhibited at the fingerprint
  // screen, every time (bench, decoded with addr2line). Guard like the rest.
  if (R) for (int i = 0; i < RK_MAX; i++) if (s_cache[i]) { mbedtls_platform_zeroize(s_cache[i], sizeof(RkAcct)); free(s_cache[i]); s_cache[i] = nullptr; }
  if (R) for (int i = 0; i < RK_MAX; i++) if (R->labels[i]) { mbedtls_platform_zeroize(R->labels[i], sizeof(RkLabel)); free(R->labels[i]); R->labels[i] = nullptr; }   // v15
  if (R) mbedtls_platform_zeroize(R->tags, sizeof R->tags);
  s_tagNext = 0;
  hashForgetLocked();   // 11s: the password hashes go with the lock
}

void rk_wipe_all() {
  if (!s_mounted && !rk_mount()) { Serial.println("[RK] wipe: nvs_vault could not be mounted - records (if any) stay until the next wipe"); return; }
  {
    std::lock_guard<std::mutex> g(s_mx);
    Preferences p; if (p.begin(RK_NS, false, RK_PART)) { p.clear(); p.putUChar("ver", 1); p.end(); }
    rkMarkSize();   // P4-1: clear() removed the size marker too
    memset(R->idx, 0, sizeof R->idx); s_loaded = true;
    memset(s_tlnk, 0, sizeof s_tlnk); s_tlnkLoaded = false;   // 11v: the links went with the namespace
    memset(s_rcnt, 0, sizeof s_rcnt); s_rcntLoaded = false;   // 11aa
  }
  rk_forget_cache();
  Serial.println("[RK] every vault record (passkeys and passwords) wiped with the wallet");
}

// ---- P4-10 (3 Nov 2026, Vault spec): the sealed site index -------------------
// nvs_vault key "six": nonce12 || AES-256-GCM(K_IDX, plaintext) || tag16, AAD
// "FAVILLA-SIDX-v1" || SE object generation. Plaintext: ver 1 || count u16 ||
// count x (slot u8 || id8 || updated u32 || flags u8 || len u8 || site bytes).
// flags: 1 = pending ("New entry N"), 2 = cut (the name is longer than 64
// bytes; the full name comes from a LABEL). An entry is used only while its
// slot still holds the same id and updated time; anything else falls back to
// LABEL and heals the entry. K_IDX is never stored: callers unwrap it (SE) and
// hand it in at unlock; the lock wipes it with the names.
static const char* IX_KEY = "six";
static const uint8_t IX_AAD[] = "FAVILLA-SIDX-v1";
static constexpr size_t IX_ENT = 2 + 8 + 4 + 8 + 1 + 1 + RK_IDX_SITE, IX_PT_MAX = 3 + RK_MAX * IX_ENT, IX_BLOB_MAX = 12 + IX_PT_MAX + 16;   // 11dr: v3, slot u16

static bool siteValidLocked(int s) {
  SiteE* e = R ? R->sites[s] : nullptr;
  return e && R->idx[s].used && R->idx[s].clear[12] == RK_KIND_PASSWORD && !memcmp(e->id8, R->idx[s].clear, 8) && e->upd == rd32(R->idx[s].clear + 8)
           && !memcmp(e->tag8, R->idx[s].clear + TAGOFF, 8);   // review (2): the site tag in the clear header must agree too
}
static void siteSetLocked(int s, const char* site, size_t n) {
  if (!R || s < 0 || s >= RK_MAX || !R->idx[s].used || R->idx[s].clear[12] != RK_KIND_PASSWORD) return;
  size_t m = rk_utf8_cut(site, n, RK_IDX_SITE);
  uint8_t flags = (n > m ? 2 : 0) | (n >= 10 && !memcmp(site, "New entry ", 10) ? 1 : 0);
  SiteE* e = R->sites[s];
  if (siteValidLocked(s) && e->flags == flags && strlen(e->site) == m && !memcmp(e->site, site, m)) return;   // no change
  if (!e) e = R->sites[s] = (SiteE*)rkAlloc(sizeof(SiteE));
  if (!e) return;
  memset(e, 0, sizeof *e); memcpy(e->id8, R->idx[s].clear, 8); e->upd = rd32(R->idx[s].clear + 8); memcpy(e->tag8, R->idx[s].clear + TAGOFF, 8); e->flags = flags; memcpy(e->site, site, m);
  s_ixDirty++;
}
static void labelDropLocked(int s) {
  if (!R || s < 0 || s >= RK_MAX || !R->labels[s]) return;
  mbedtls_platform_zeroize(R->labels[s], sizeof(RkLabel)); free(R->labels[s]); R->labels[s] = nullptr;
}
static void siteDropLocked(int s) {
  if (!R || s < 0 || s >= RK_MAX || !R->sites[s]) return;
  mbedtls_platform_zeroize(R->sites[s], sizeof(SiteE)); free(R->sites[s]); R->sites[s] = nullptr; s_ixDirty++;
}
static void ixAad(uint8_t aad[16]) { memcpy(aad, IX_AAD, 15); aad[15] = s_ixGen; }
// 3 Nov 2026 (bench, 145-entry import): one-shot GCM over the whole index failed
// on the KEY once the index grew past about 2 KB ("seal FAILED" from the 59th
// name on). The ESP port runs the whole length as one AES DMA job, which past
// ~2 KB switches to interrupt mode and needs internal DMA bounce buffers for
// PSRAM data, with ~9 KB of internal heap left. This runs GCM in 512-byte
// pieces through two small internal buffers: no single DMA job is large, and
// the bytes are the same as the one-shot call (same key, nonce, AAD, tag).
// Returns 0, or the mbedTLS error; IX_TAG_BAD (decrypt only) = wrong tag.
static constexpr int IX_TAG_BAD = 1;
#ifdef ARDUINO
static void* ixIntAlloc(size_t n) { return heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA); }
static void ixIntFree(void* p) { heap_caps_free(p); }
static unsigned ixIntHeap() { return (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL); }
#else
static void* ixIntAlloc(size_t n) { return malloc(n); }
static void ixIntFree(void* p) { free(p); }
static unsigned ixIntHeap() { return 0; }
#endif
static int ixGcm(bool enc, const uint8_t iv[12], const uint8_t aad[16], const uint8_t* in, size_t len, uint8_t* out, uint8_t tag[16]) {
  const size_t CH = 512;
  uint8_t* ib = (uint8_t*)ixIntAlloc(CH);
  uint8_t* ob = (uint8_t*)ixIntAlloc(CH);
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_ixKey, 256);
  if (!rc) rc = mbedtls_gcm_starts(&g, enc ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT, iv, 12);
  if (!rc) rc = mbedtls_gcm_update_ad(&g, aad, 16);
  for (size_t o = 0; !rc && o < len; ) {
    size_t n = len - o < CH ? len - o : CH, w = 0;
    if (ib && ob) { memcpy(ib, in + o, n); rc = mbedtls_gcm_update(&g, ib, n, ob, CH, &w); if (!rc && w) memcpy(out + o, ob, w); }
    else rc = mbedtls_gcm_update(&g, in + o, n, out + o, len - o, &w);   // no internal room: the same pieces, straight from PSRAM
    if (!rc && w != n) rc = -2;   // both ports return every byte of a piece at once
    o += n;
  }
  uint8_t t[16]; size_t w = 0;
  if (!rc) rc = mbedtls_gcm_finish(&g, nullptr, 0, &w, t, 16);
  mbedtls_gcm_free(&g);
  if (ib) { mbedtls_platform_zeroize(ib, CH); ixIntFree(ib); }
  if (ob) { mbedtls_platform_zeroize(ob, CH); ixIntFree(ob); }
  if (!rc) {
    if (enc) memcpy(tag, t, 16);
    else { uint8_t d = 0; for (int i = 0; i < 16; i++) d |= t[i] ^ tag[i]; if (d) rc = IX_TAG_BAD; }
  }
  mbedtls_platform_zeroize(t, 16);
  return rc;
}
// force: write now. Otherwise saves and deletes write at once (unless an import
// batches them) and heals by LABEL every 10.
static void ixFlushLocked(bool force) {
  if (!s_ixHave || !R || !s_ixDirty) return;
  if (!force && s_ixBatch && s_ixDirty < 10) return;   // an import: every 10 entries (and at the end)
  uint8_t* pt = (uint8_t*)rkAlloc(IX_PT_MAX); uint8_t* blob = (uint8_t*)rkAlloc(IX_BLOB_MAX);
  if (!pt || !blob) { free(pt); free(blob); return; }
  size_t p = 3; int n = 0;
  for (int s = 0; s < RK_MAX; s++) {
    if (!siteValidLocked(s)) continue;
    SiteE* e = R->sites[s]; size_t l = strlen(e->site);
    pt[p++] = (uint8_t)(s >> 8); pt[p++] = (uint8_t)s; memcpy(pt + p, e->id8, 8);   // 11dr: v3, slot u16 (slots past 255)
    p += 8; wr32(pt + p, e->upd); p += 4; memcpy(pt + p, e->tag8, 8); p += 8; pt[p++] = e->flags; pt[p++] = (uint8_t)l; memcpy(pt + p, e->site, l); p += l; n++;
  }
  pt[0] = 3; pt[1] = (uint8_t)(n >> 8); pt[2] = (uint8_t)n;   // 11dr: v3 (v2 had a one-byte slot)
  esp_fill_random(blob, 12);
  uint8_t aad[16]; ixAad(aad);
  int grc = ixGcm(true, blob, aad, pt, p, blob + 12, blob + 12 + p);
  bool ok = grc == 0;
  mbedtls_platform_zeroize(pt, IX_PT_MAX); free(pt);
  size_t w = 0, bn = 12 + p + 16;
  bool room = true;
  if (ok) { Preferences pr; if (pr.begin(RK_NS, false, RK_PART)) {
      // review (7): records come first. NVS needs room for the new copy before the old
      // one is freed, so the index is written only if, after it, a full-size record
      // could still be saved (32-byte entries; a record is at most 512 bytes).
      size_t need = (bn + 31) / 32 + 2, floor = (G0_VAULT_DATA_MAX + 31) / 32 + 8;
      // re-review (1): Preferences::freeEntries() reads the default "nvs" partition,
      // so ask nvs_vault itself, and do not count the spare page NVS keeps for GC.
      nvs_stats_t st; size_t fe = 0;
      if (nvs_get_stats(RK_PART, &st) == ESP_OK) fe = st.free_entries > 126 ? st.free_entries - 126 : 0;
      room = fe >= need + floor;
      if (room) w = pr.putBytes(IX_KEY, blob, bn);
      pr.end(); } }
  free(blob);
  if (ok && w == bn) { s_ixDirty = 0; Serial.printf("[RK] site index: written (%d names, %u bytes)\n", n, (unsigned)bn); }
  else if (!ok) Serial.printf("[RK] site index: seal FAILED (mbedtls %d, %u bytes, internal heap %u) - names fall back to labels\n", grc, (unsigned)p, ixIntHeap());
  else Serial.printf("[RK] site index: %s - names fall back to labels\n", !room ? "not written: nvs_vault is too full to keep a record's room" : "write FAILED");
}
static void ixCloseLocked() {
  mbedtls_platform_zeroize(s_ixKey, sizeof s_ixKey); s_ixHave = false; s_ixBatch = false; s_ixDirty = 0;
  if (R) for (int i = 0; i < RK_MAX; i++) if (R->sites[i]) { mbedtls_platform_zeroize(R->sites[i], sizeof(SiteE)); free(R->sites[i]); R->sites[i] = nullptr; }
}
uint32_t rk_lock_epoch() { std::lock_guard<std::mutex> g(s_mx); return s_lockEpoch; }
int rk_idx_open(const uint8_t k[32], uint8_t gen, uint32_t epoch) {
  if (!rk_ready()) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  if (epoch != s_lockEpoch) { Serial.println("[RK] site index: the KEY locked during the unwrap - key dropped"); return -1; }
  loadLocked();
  if (!R) return -1;
  const bool batch = s_ixBatch;
  ixCloseLocked();
  s_ixBatch = batch;
  memcpy(s_ixKey, k, 32); s_ixGen = gen; s_ixHave = true;
  size_t n = 0; uint8_t* blob = (uint8_t*)rkAlloc(IX_BLOB_MAX); uint8_t* pt = (uint8_t*)rkAlloc(IX_PT_MAX);
  if (!blob || !pt) { free(blob); free(pt); return -1; }
  { Preferences p; if (p.begin(RK_NS, true, RK_PART)) { n = p.isKey(IX_KEY) ? p.getBytesLength(IX_KEY) : 0; if (n >= 12 + 3 + 16 && n <= IX_BLOB_MAX) n = p.getBytes(IX_KEY, blob, n); else n = 0; p.end(); } }
  int got = 0, stale = 0;
  if (!n) { s_ixDirty = 1; free(blob); free(pt); Serial.println("[RK] site index: none yet (it fills as names are read)"); return 0; }
  size_t cl = n - 12 - 16; uint8_t aad[16]; ixAad(aad);
  int grc = ixGcm(false, blob, aad, blob + 12, cl, pt, blob + 12 + cl);
  bool ok = grc == 0;
  free(blob);
  if (!ok) { mbedtls_platform_zeroize(pt, IX_PT_MAX); free(pt); s_ixDirty = 1;
    if (grc == IX_TAG_BAD) Serial.println("[RK] site index: did not open (another key or setup, or altered) - rebuilt from labels");
    else Serial.printf("[RK] site index: could not be opened here (mbedtls %d, %u bytes, internal heap %u) - names read again by label\n", grc, (unsigned)cl, ixIntHeap());
    return 0; }
  size_t q = 3; const uint8_t ver = cl >= 3 ? pt[0] : 0; int cnt = (ver == 2 || ver == 3) ? ((pt[1] << 8) | pt[2]) : -1;
  const size_t sb = ver == 3 ? 2 : 1;   // 11dr: v3 writes the slot in two bytes; v2 (written before) in one
  for (int i = 0; i < cnt && q + 22 + sb <= cl; i++) {
    int s = sb == 2 ? ((pt[q] << 8) | pt[q + 1]) : pt[q]; q += sb - 1;
    const uint8_t* id = pt + q + 1; uint32_t upd = rd32(pt + q + 9); const uint8_t* tg = pt + q + 13; uint8_t fl = pt[q + 21]; size_t l = pt[q + 22]; q += 23;
    if (l > RK_IDX_SITE || q + l > cl) { cnt = -1; break; }
    if (s < RK_MAX && R->idx[s].used && R->idx[s].clear[12] == RK_KIND_PASSWORD && !memcmp(R->idx[s].clear, id, 8) && rd32(R->idx[s].clear + 8) == upd && !memcmp(R->idx[s].clear + TAGOFF, tg, 8)) {
      SiteE* e = R->sites[s] ? R->sites[s] : (R->sites[s] = (SiteE*)rkAlloc(sizeof(SiteE)));
      if (e) { memset(e, 0, sizeof *e); memcpy(e->id8, id, 8); e->upd = upd; memcpy(e->tag8, tg, 8); e->flags = fl; memcpy(e->site, pt + q, l); got++; }
    } else stale++;
    q += l;
  }
  mbedtls_platform_zeroize(pt, IX_PT_MAX); free(pt);
  if (cnt < 0) { ixCloseLocked(); memcpy(s_ixKey, k, 32); s_ixHave = true; s_ixDirty = 1; Serial.println("[RK] site index: malformed - rebuilt from labels"); return 0; }
  if (stale) s_ixDirty++;   // drop them at the next write
  Serial.printf("[RK] site index: %d names ready, %d out of date (read again by label)\n", got, stale);
  return got;
}
bool rk_idx_have_key() { std::lock_guard<std::mutex> g(s_mx); return s_ixHave; }
bool rk_idx_get_key(uint8_t out[32]) { std::lock_guard<std::mutex> g(s_mx); if (!s_ixHave) return false; memcpy(out, s_ixKey, 32); return true; }
void rk_idx_batch(bool on) { std::lock_guard<std::mutex> g(s_mx); s_ixBatch = on; if (!on) ixFlushLocked(true); }
void rk_idx_flush() { if (!rk_ready()) return; std::lock_guard<std::mutex> g(s_mx); ixFlushLocked(true); }
static const char* ixWrapKey(char which) { return which == 'N' ? "ixN" : "ixP"; }
bool rk_idx_wrap_get(char which, uint8_t out64[RK_IDX_WRAP]) {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx);
  Preferences p; size_t n = 0;
  if (p.begin(RK_NS, true, RK_PART)) { if (p.isKey(ixWrapKey(which)) && p.getBytesLength(ixWrapKey(which)) == RK_IDX_WRAP) n = p.getBytes(ixWrapKey(which), out64, RK_IDX_WRAP); p.end(); }
  return n == RK_IDX_WRAP;
}
bool rk_idx_wrap_put(char which, const uint8_t in64[RK_IDX_WRAP]) {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx);
  Preferences p; size_t w = 0;
  if (p.begin(RK_NS, false, RK_PART)) { w = p.putBytes(ixWrapKey(which), in64, RK_IDX_WRAP); p.end(); }
  return w == RK_IDX_WRAP;
}
void rk_idx_wrap_del(char which) {
  if (!rk_ready()) return;
  std::lock_guard<std::mutex> g(s_mx);
  Preferences p; if (p.begin(RK_NS, false, RK_PART)) { if (p.isKey(ixWrapKey(which))) p.remove(ixWrapKey(which)); p.end(); }
}
// P4-10 review (4): a check value stored with each wrap, so an unwrap of bytes
// that were not made from K_IDX (CBC always "decrypts") is refused instead of
// adopted and re-exported under another key. HMAC, so it reveals nothing.
void rk_idx_kcv(const uint8_t k[32], uint8_t out16[16]) {
  uint8_t h[32]; static const uint8_t L[] = "FAVILLA-SIDX-KCV";
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, 32, L, 16, h);
  memcpy(out16, h, 16); mbedtls_platform_zeroize(h, 32);
}
bool rk_idx_kcv_ok(const uint8_t k[32], const uint8_t kcv16[16]) {
  uint8_t c[16]; rk_idx_kcv(k, c); uint8_t d = 0; for (int i = 0; i < 16; i++) d |= (uint8_t)(c[i] ^ kcv16[i]);
  mbedtls_platform_zeroize(c, 16); return d == 0;
}
// ---- Usernames book (4 Nov 2026, Josh: PASSKEY > Settings > Usernames) ----------
// The owner's own short list of usernames and emails, for the New password picker
// (instant, instead of reading the newest entries' labels from the G0). Sealed with
// K_IDX like the site index: nonce12 || AES-256-GCM(ver1 || n || n x (len, bytes)) ||
// tag16, AAD "FAVILLA-UBOOK-1" || generation. Not linked to any site; passwords and
// notes stay G0-only. No K_IDX (locked, or the index key not opened): -1.
static const char* UB_KEY = "ubk";
static constexpr size_t UB_PT_MAX = 2 + RK_UB_MAX * (1 + RK_PW_FIELD_MAX), UB_BLOB_MAX = 12 + UB_PT_MAX + 16;
static void ubAad(uint8_t aad[16]) { memcpy(aad, "FAVILLA-UBOOK-1", 15); aad[15] = s_ixGen; }
static int ubLoadLocked(char (*out)[RK_PW_FIELD_MAX + 1], int max) {
  if (!s_ixHave) return -1;
  uint8_t* blob = (uint8_t*)rkAlloc(UB_BLOB_MAX); uint8_t* pt = (uint8_t*)rkAlloc(UB_PT_MAX);
  if (!blob || !pt) { free(blob); free(pt); return -1; }
  size_t n = 0;
  { Preferences p; if (p.begin(RK_NS, true, RK_PART)) { n = p.isKey(UB_KEY) ? p.getBytesLength(UB_KEY) : 0; if (n >= 12 + 2 + 16 && n <= UB_BLOB_MAX) n = p.getBytes(UB_KEY, blob, n); else n = 0; p.end(); } }
  int k = 0;
  if (n) {
    size_t cl = n - 28; uint8_t aad[16]; ubAad(aad);
    if (ixGcm(false, blob, aad, blob + 12, cl, pt, blob + 12 + cl) == 0 && pt[0] == 1) {
      int cnt = pt[1]; size_t q = 2;
      for (int i = 0; i < cnt && k < max && q < cl; i++) {
        size_t l = pt[q++]; if (l == 0 || l > RK_PW_FIELD_MAX || q + l > cl) break;
        memcpy(out[k], pt + q, l); out[k][l] = 0; q += l; k++;
      }
    } else Serial.println("[RK] usernames book: did not open (another key or setup) - starts empty");
  }
  mbedtls_platform_zeroize(pt, UB_PT_MAX); free(pt); free(blob);
  return k;
}
static bool ubSaveLocked(char (*in)[RK_PW_FIELD_MAX + 1], int n) {
  if (!s_ixHave) return false;
  uint8_t* blob = (uint8_t*)rkAlloc(UB_BLOB_MAX); uint8_t* pt = (uint8_t*)rkAlloc(UB_PT_MAX);
  if (!blob || !pt) { free(blob); free(pt); return false; }
  size_t p = 2; pt[0] = 1; pt[1] = (uint8_t)n;
  for (int i = 0; i < n; i++) { size_t l = strnlen(in[i], RK_PW_FIELD_MAX); pt[p++] = (uint8_t)l; memcpy(pt + p, in[i], l); p += l; }
  esp_fill_random(blob, 12); uint8_t aad[16]; ubAad(aad);
  bool ok = ixGcm(true, blob, aad, pt, p, blob + 12, blob + 12 + p) == 0;
  mbedtls_platform_zeroize(pt, UB_PT_MAX); free(pt);
  if (ok) { Preferences pr; ok = false; if (pr.begin(RK_NS, false, RK_PART)) { ok = pr.putBytes(UB_KEY, blob, 12 + p + 16) == 12 + p + 16; pr.end(); } }
  free(blob);
  return ok;
}
int rk_ub_list(char (*out)[RK_PW_FIELD_MAX + 1], int max) {
  if (!rk_ready() || !out || max <= 0) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  return ubLoadLocked(out, max);
}
int rk_ub_add(const char* u) {
  if (!rk_ready() || !u) return RK_E_NOVAULT;
  size_t l = strnlen(u, RK_PW_FIELD_MAX + 1);
  if (l == 0 || l > RK_PW_FIELD_MAX) return RK_E_SIZE;
  std::lock_guard<std::mutex> g(s_mx);
  char (*b)[RK_PW_FIELD_MAX + 1] = (char (*)[RK_PW_FIELD_MAX + 1])rkAlloc(sizeof(char[RK_PW_FIELD_MAX + 1]) * RK_UB_MAX);
  if (!b) return RK_E_NVS;
  int n = ubLoadLocked(b, RK_UB_MAX), r = RK_OK; bool added = false;
  if (n < 0) r = RK_E_NOVAULT;
  else {
    bool have = false; for (int i = 0; i < n; i++) if (!strcmp(b[i], u)) have = true;
    if (!have) {
      if (n == RK_UB_MAX) r = RK_E_FULL;
      else { for (int i = n; i > 0; i--) memcpy(b[i], b[i - 1], RK_PW_FIELD_MAX + 1); snprintf(b[0], RK_PW_FIELD_MAX + 1, "%s", u); n++;   // newest first
             if (!ubSaveLocked(b, n)) r = RK_E_NVS; else added = true; }
    }
  }
  mbedtls_platform_zeroize(b, sizeof(char[RK_PW_FIELD_MAX + 1]) * RK_UB_MAX); free(b);
  if (added) Serial.printf("[RK] usernames book: saved (%d)\n", n);
  return r;
}
int rk_ub_del(int i) {
  if (!rk_ready()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  char (*b)[RK_PW_FIELD_MAX + 1] = (char (*)[RK_PW_FIELD_MAX + 1])rkAlloc(sizeof(char[RK_PW_FIELD_MAX + 1]) * RK_UB_MAX);
  if (!b) return RK_E_NVS;
  int n = ubLoadLocked(b, RK_UB_MAX), r = RK_OK;
  if (n < 0) r = RK_E_NOVAULT;
  else if (i < 0 || i >= n) r = RK_E_FORMAT;
  else { for (int k = i; k < n - 1; k++) memcpy(b[k], b[k + 1], RK_PW_FIELD_MAX + 1); n--; if (!ubSaveLocked(b, n)) r = RK_E_NVS; }
  mbedtls_platform_zeroize(b, sizeof(char[RK_PW_FIELD_MAX + 1]) * RK_UB_MAX); free(b);
  return r;
}

// A name for entry i: the full one from a cached label, else the index's (maybe cut).
bool rk_pw_site(int i, char* out, size_t cap, bool* pending, bool* cut) {
  if (!rk_ready() || !out || !cap) return false;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  if (s < 0) return false;
  RkLabel* c = R->labels[s];
  if (c && c->slot == s && c->updated == rd32(R->idx[s].clear + 8) && !memcmp(c->id8, R->idx[s].clear, 8)) {
    snprintf(out, cap, "%s", c->site);
    if (pending) *pending = !strncmp(c->site, "New entry ", 10);
    if (cut) *cut = false;
    return true;
  }
  if (!siteValidLocked(s)) return false;
  snprintf(out, cap, "%s", R->sites[s]->site);
  if (pending) *pending = R->sites[s]->flags & 1;
  if (cut) *cut = (R->sites[s]->flags & 2) != 0;
  return true;
}
// P4-10 review (1): one locked read of everything a list row shows, so the name,
// the slot, the id and the username always belong to the same record.
bool rk_pw_row(int i, RkRow* out) {
  if (!rk_ready() || !out) return false;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  if (s < 0) return false;
  memset(out, 0, sizeof *out);
  out->slot = s; memcpy(out->id8, R->idx[s].clear, 8); out->health = hlthGetLocked(s);
  RkLabel* c = R->labels[s];
  if (c && c->slot == s && c->updated == rd32(R->idx[s].clear + 8) && !memcmp(c->id8, R->idx[s].clear, 8)) {
    snprintf(out->site, sizeof out->site, "%s", c->site); snprintf(out->user, sizeof out->user, "%s", c->user);
    out->nameKnown = out->userKnown = true; out->pending = !strncmp(c->site, "New entry ", 10);
    return true;
  }
  if (!siteValidLocked(s)) return true;   // bench 3 Nov: the record is listed even before its name is read, never left out
  snprintf(out->site, sizeof out->site, "%s", R->sites[s]->site);
  out->nameKnown = true; out->pending = R->sites[s]->flags & 1; out->cut = (R->sites[s]->flags & 2) != 0;
  return true;
}
// Bench 3 Nov 2026: the phone's list in ONE lock. Row by row, each call waited for
// the background LABEL (which holds the lock through its G0 call, ~0.47 s), and a
// 60-entry list took 10 s on the web server task. Newest first, as rk_pw_order.
int rk_pw_rows(RkRow* out, int max) {
  if (!rk_ready() || !out || max <= 0) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  uint32_t* t = (uint32_t*)rkAlloc(sizeof(uint32_t) * RK_MAX); int* sl = (int*)rkAlloc(sizeof(int) * RK_MAX); int n = 0;   // PSRAM: the web server task's stack is small
  if (!t || !sl) { free(t); free(sl); return 0; }
  for (int s = 0; s < RK_MAX; s++) {
    if (!isKind(s, RK_KIND_PASSWORD) || n >= max) continue;
    uint32_t u = rd32(R->idx[s].clear + 8); int j = n++;
    while (j > 0 && t[j - 1] < u) { t[j] = t[j - 1]; sl[j] = sl[j - 1]; j--; }
    t[j] = u; sl[j] = s;
  }
  bool* linked = R->linkedS; tlnkMarkLocked(linked);   // 11v; 11dr: PSRAM scratch
  for (int k = 0; k < n; k++) {
    int s = sl[k]; RkRow* o = &out[k]; memset(o, 0, sizeof *o);
    o->slot = s; memcpy(o->id8, R->idx[s].clear, 8); o->health = hlthGetLocked(s);
    if (linked[s]) o->health |= RK_H_TOTP;
    RkLabel* c = R->labels[s];
    if (c && c->slot == s && c->updated == rd32(R->idx[s].clear + 8) && !memcmp(c->id8, R->idx[s].clear, 8)) {
      snprintf(o->site, sizeof o->site, "%s", c->site); snprintf(o->user, sizeof o->user, "%s", c->user);
      o->nameKnown = o->userKnown = true; o->pending = !strncmp(c->site, "New entry ", 10);
    } else if (siteValidLocked(s)) {
      snprintf(o->site, sizeof o->site, "%s", R->sites[s]->site);
      o->nameKnown = true; o->pending = R->sites[s]->flags & 1; o->cut = (R->sites[s]->flags & 2) != 0;
    }
  }
  free(t); free(sl);
  return n;
}
bool rk_pw_site_known(int i) { char t[2]; return rk_pw_site(i, t, sizeof t, nullptr, nullptr); }

// ---- 9i (7 Nov 2026, G0 v17): one-time codes (kind 3) ---------------------------
int rk_totp_count() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return countKind(RK_KIND_TOTP);
}
int rk_totp_save(const char* site, const char* acct, const uint8_t* secret, size_t secretN, uint8_t digits, uint8_t period, int* slotOut) {
  if (slotOut) *slotOut = -1;
  if (!rk_ready() || !g0_v17_present()) return RK_E_NOVAULT;
  const size_t sn = site ? strnlen(site, RK_SITE_MAX + 1) : 0, an = acct ? strnlen(acct, RK_PW_FIELD_MAX + 1) : 0;
  if (sn == 0 || sn > RK_SITE_MAX || an > RK_PW_FIELD_MAX || secretN == 0 || secretN > RK_TOTP_SECRET_MAX || digits < 6 || digits > 8 || period == 0) return RK_E_SIZE;
  if (HDR + 1 + sn + 1 + an + 1 + secretN + 2 > RK_PT_MAX + HDR) return RK_E_SIZE;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int slot = -1; for (int i = 0; i < RK_MAX; i++) if (!R->idx[i].used) { slot = i; break; }
  if (slot < 0) return RK_E_FULL;
  uint8_t id8[8]; esp_fill_random(id8, 8);
  uint32_t upd = 0;
  { time_t now = time(nullptr); if (now > 1700000000) upd = (uint32_t)now; }
  for (int i = 0; i < RK_MAX; i++) if (R->idx[i].used) { uint32_t u = rd32(R->idx[i].clear + 8); if (u >= upd) upd = u + 1; }
  size_t p = 0; uint8_t* b = R->buf;
  memcpy(b, id8, 8); wr32(b + 8, upd); b[12] = RK_KIND_TOTP; p = HDR;
  b[p++] = (uint8_t)sn; memcpy(b + p, site, sn); p += sn;
  b[p++] = (uint8_t)an; if (an) memcpy(b + p, acct, an); p += an;
  b[p++] = (uint8_t)secretN; memcpy(b + p, secret, secretN); p += secretN;
  b[p++] = digits; b[p++] = period;
  size_t on = 0;
  int r = vault(G0_VAULT_SEAL, b, p, R->blob, &on);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (r) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return r; }
  if (on < CLEAR) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_G0; }
  Preferences pr; char k[5]; key(slot, k); size_t w = 0;
  if (pr.begin(RK_NS, false, RK_PART)) { w = pr.putBytes(k, R->blob, on); pr.end(); }
  if (w != on) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_NVS; }
  R->idx[slot].used = 1; memcpy(R->idx[slot].clear, R->blob, CLEAR);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  changed();
  if (slotOut) *slotOut = slot;
  Serial.printf("[RK] one-time code saved in slot %d (%d codes, %d of %d records used)\n", slot, countKind(RK_KIND_TOTP), countLocked(), RK_MAX);
  return RK_OK;
}
// 11v
int rk_totp_link(int totpSlot, int pwSlot) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (totpSlot < 0 || totpSlot >= RK_MAX || pwSlot >= RK_MAX) return RK_E_FORMAT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked(); tlnkLoadLocked();
  if (!isKind(totpSlot, RK_KIND_TOTP)) return RK_E_FORMAT;
  if (pwSlot >= 0 && !isKind(pwSlot, RK_KIND_PASSWORD)) return RK_E_FORMAT;
  if (pwSlot >= 0) for (int ts = 0; ts < RK_MAX; ts++) if (ts != totpSlot && tlnkRowLocked(ts) && tlnkPwLocked(ts) == pwSlot) memset(s_tlnk[ts], 0, 16);   // one table-linked code per entry
  for (int ts = 0; ts < RK_MAX; ts++) if (!isKind(ts, RK_KIND_TOTP) || !tlnkRowLocked(ts)) memset(s_tlnk[ts], 0, 16);   // drop rows of records that are gone
  memcpy(s_tlnk[totpSlot], R->idx[totpSlot].clear, 8);
  if (pwSlot < 0) memset(s_tlnk[totpSlot] + 8, 0, 8);   // unlinked on purpose: no tag fallback
  else memcpy(s_tlnk[totpSlot] + 8, R->idx[pwSlot].clear, 8);
  if (!tlnkSaveLocked()) return RK_E_NVS;
  Serial.printf("[RK] code in slot %d %s\n", totpSlot, pwSlot < 0 ? "unlinked" : "linked to a password entry");
  return RK_OK;
}
int rk_totp_linked_pw(int totpSlot) {
  if (!rk_ready()) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return tlnkPwLocked(totpSlot);
}
int rk_pw_totp_slot(int pwSlot) {
  if (!rk_ready()) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return tlnkTotpOfPwLocked(pwSlot);
}
int rk_totp_rows(RkTotp* out, int max) {
  if (!rk_ready() || !out || max <= 0 || !g0_v15_present()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int n = 0;
  for (int s = 0; s < RK_MAX && n < max; s++) {
    if (!isKind(s, RK_KIND_TOTP)) continue;
    RkTotp& o = out[n++]; memset(&o, 0, sizeof o); o.slot = s;
    RkLabel L;
    if (labelLocked(s, &L) == RK_OK) { snprintf(o.site, sizeof o.site, "%s", L.site); snprintf(o.acct, sizeof o.acct, "%s", L.user); o.known = true; }
    mbedtls_platform_zeroize(&L, sizeof L);
  }
  return n;
}
int rk_totp_find(const char* site, size_t n, int* slots, int max) {
  if (!rk_ready() || !site || !slots || max <= 0 || !g0_v15_present()) return 0;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  int k = 0;
  for (int s = 0; s < RK_MAX && k < max; s++) {
    if (!isKind(s, RK_KIND_TOTP)) continue;
    RkLabel L;
    if (labelLocked(s, &L) == RK_OK && strlen(L.site) == n && !strncasecmp(L.site, site, n)) slots[k++] = s;
    mbedtls_platform_zeroize(&L, sizeof L);
  }
  return k;
}
int rk_totp_code(int slot, uint64_t t, uint32_t* code, uint8_t* digits, uint8_t* period) {
  if (!rk_ready() || !g0_v17_present()) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (slot < 0 || slot >= RK_MAX || !isKind(slot, RK_KIND_TOTP)) return RK_E_FORMAT;
  Preferences p; char k[5]; key(slot, k); size_t n = 0;
  if (p.begin(RK_NS, true, RK_PART)) { n = p.isKey(k) ? p.getBytesLength(k) : 0; if (n && n + 8 <= sizeof R->buf) n = p.getBytes(k, R->buf + 8, n); else n = 0; p.end(); }
  if (!n) return RK_E_NVS;
  for (int i = 0; i < 8; i++) R->buf[i] = (uint8_t)(t >> (56 - 8 * i));
  size_t on = 0;
  int r = vault(G0_VAULT_TOTP, R->buf, 8 + n, R->blob, &on);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (r == RK_OK && on == 6) { *code = rd32(R->blob); *digits = R->blob[4]; if (period) *period = R->blob[5]; }
  else if (r == RK_OK) r = RK_E_FORMAT;
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  return r;
}


// ---- 11s: health, public -----------------------------------------------------------
// ---- 11aa: site recovery codes (kind 4) ------------------------------------------
static void rcntLoadLocked() {
  if (s_rcntLoaded) return;
  memset(s_rcnt, 0, sizeof s_rcnt);
  Preferences p;
  if (p.begin(RK_NS, true, RK_PART)) { const size_t cn = p.isKey("rcnt") ? p.getBytesLength("rcnt") : 0;
    if (cn == sizeof s_rcnt || cn == (size_t)RK_OLD_MAX * 11) p.getBytes("rcnt", s_rcnt, cn);   // 11dr: as tlnk
    p.end(); }
  s_rcntLoaded = true;
}
static void rcntSetLocked(int s, int n, uint16_t used) {
  rcntLoadLocked();
  memcpy(s_rcnt[s], R->idx[s].clear, 8); s_rcnt[s][8] = (uint8_t)n; s_rcnt[s][9] = (uint8_t)used; s_rcnt[s][10] = (uint8_t)(used >> 8);
  Preferences p; if (p.begin(RK_NS, false, RK_PART)) { p.putBytes("rcnt", s_rcnt, sizeof s_rcnt); p.end(); }
}
static bool parseRc(const uint8_t* b, size_t n, RkRecovery* out) {
  memset(out, 0, sizeof *out);
  size_t p = HDR; if (n < HDR + 5) return false;
  size_t sl = b[p++]; if (sl < 1 || sl > RK_SITE_MAX || p + sl > n) return false; memcpy(out->site, b + p, sl); p += sl;
  size_t ul = b[p++]; if (ul > RK_PW_FIELD_MAX || p + ul > n) return false; memcpy(out->user, b + p, ul); p += ul;
  if (p + 3 > n) return false;
  int cnt = b[p++]; if (cnt < 1 || cnt > RK_RC_MAX) return false;
  out->used = (uint16_t)(b[p] | (b[p + 1] << 8)); p += 2;
  for (int i = 0; i < cnt; i++) { if (p >= n) return false; size_t l = b[p++]; if (l < 1 || l > RK_RC_LEN || p + l > n) return false; memcpy(out->code[i], b + p, l); p += l; }
  out->n = cnt;
  return p == n;
}
void rk_rc_wipe(RkRecovery* r) { if (r) mbedtls_platform_zeroize(r, sizeof *r); }
static int rcSealLocked(int slot, const uint8_t id8[8], const char* site, size_t sn, const char* user, size_t un, const char (*codes)[RK_RC_LEN + 1], int n, uint16_t used) {
  uint32_t upd = 0;
  { time_t now = time(nullptr); if (now > 1700000000) upd = (uint32_t)now; }
  for (int i = 0; i < RK_MAX; i++) if (R->idx[i].used) { uint32_t u = rd32(R->idx[i].clear + 8); if (u >= upd) upd = u + 1; }
  size_t p = 0; uint8_t* b = R->buf;
  memcpy(b, id8, 8); wr32(b + 8, upd); b[12] = RK_KIND_RECOVERY; p = HDR;
  b[p++] = (uint8_t)sn; memcpy(b + p, site, sn); p += sn;
  b[p++] = (uint8_t)un; if (un) memcpy(b + p, user, un); p += un;
  b[p++] = (uint8_t)n; b[p++] = (uint8_t)used; b[p++] = (uint8_t)(used >> 8);
  for (int i = 0; i < n; i++) { size_t l = strnlen(codes[i], RK_RC_LEN + 1); if (l < 1 || l > RK_RC_LEN) { mbedtls_platform_zeroize(R->buf, sizeof R->buf); return RK_E_SIZE; } b[p++] = (uint8_t)l; memcpy(b + p, codes[i], l); p += l; }
  if (p > RK_PT_MAX + HDR) { mbedtls_platform_zeroize(R->buf, sizeof R->buf); return RK_E_SIZE; }
  size_t on = 0;
  int r = vault(G0_VAULT_SEAL, b, p, R->blob, &on);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (r) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return r; }
  if (on < CLEAR) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_G0; }
  Preferences pr; char k[5]; key(slot, k); size_t w = 0;
  if (pr.begin(RK_NS, false, RK_PART)) { w = pr.putBytes(k, R->blob, on); pr.end(); }
  if (w != on) { mbedtls_platform_zeroize(R->blob, sizeof R->blob); return RK_E_NVS; }
  R->idx[slot].used = 1; memcpy(R->idx[slot].clear, R->blob, CLEAR);
  mbedtls_platform_zeroize(R->blob, sizeof R->blob);
  changed();
  rcntSetLocked(slot, n, used);
  return RK_OK;
}
int rk_rc_save(const char* site, const char* user, const char (*codes)[RK_RC_LEN + 1], int n, int* slotOut) {
  if (slotOut) *slotOut = -1;
  if (!rk_ready()) return RK_E_NOVAULT;
  const size_t sn = site ? strnlen(site, RK_SITE_MAX + 1) : 0, un = user ? strnlen(user, RK_PW_FIELD_MAX + 1) : 0;
  if (sn < 1 || sn > RK_SITE_MAX || un > RK_PW_FIELD_MAX || n < 1 || n > RK_RC_MAX || !codes) return RK_E_SIZE;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  uint8_t tag[8]; int r = tagLocked(site, sn, tag); if (r) return r;
  int slot = -1;
  for (int i = 0; i < RK_MAX; i++) if (isKind(i, RK_KIND_RECOVERY) && !memcmp(R->idx[i].clear + TAGOFF, tag, 8)) { slot = i; break; }   // the site's set is replaced, keeping its id
  uint8_t id8[8];
  if (slot >= 0) memcpy(id8, R->idx[slot].clear, 8);
  else { for (int i = 0; i < RK_MAX; i++) if (!R->idx[i].used) { slot = i; break; } if (slot < 0) return RK_E_FULL; esp_fill_random(id8, 8); }
  r = rcSealLocked(slot, id8, site, sn, user, un, codes, n, 0);
  if (r == RK_OK) { if (slotOut) *slotOut = slot; Serial.printf("[RK] recovery codes saved in slot %d (%d codes)\n", slot, n); }
  return r;
}
int rk_rc_slot_for_pw(int pwSlot) {
  if (!rk_ready() || pwSlot < 0 || pwSlot >= RK_MAX) return -1;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!isKind(pwSlot, RK_KIND_PASSWORD)) return -1;
  for (int i = 0; i < RK_MAX; i++) if (isKind(i, RK_KIND_RECOVERY) && !memcmp(R->idx[i].clear + TAGOFF, R->idx[pwSlot].clear + TAGOFF, 8)) return i;
  return -1;
}
bool rk_rc_counts(int slot, int* n, int* used) {
  if (!rk_ready() || slot < 0 || slot >= RK_MAX) return false;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked(); rcntLoadLocked();
  if (!isKind(slot, RK_KIND_RECOVERY) || memcmp(s_rcnt[slot], R->idx[slot].clear, 8)) return false;
  const int cnt = s_rcnt[slot][8]; const uint16_t u = (uint16_t)(s_rcnt[slot][9] | (s_rcnt[slot][10] << 8));
  int k = 0; for (int i = 0; i < cnt; i++) if (u & (1u << i)) k++;
  if (n) *n = cnt; if (used) *used = k;
  return true;
}
static int rcOpenLocked(int slot, RkRecovery* out) {
  if (!isKind(slot, RK_KIND_RECOVERY)) return RK_E_FORMAT;
  size_t on = 0;
  int r = openRawLocked(slot, &on);
  if (r) return r;
  const bool ok = parseRc(R->buf, on, out);
  mbedtls_platform_zeroize(R->buf, sizeof R->buf);
  if (!ok) { rk_rc_wipe(out); return RK_E_FORMAT; }
  out->slot = slot;
  rcntSetLocked(slot, out->n, out->used);   // the clear count follows the record (a restore starts it over)
  return RK_OK;
}
int rk_rc_open(int slot, RkRecovery* out) {
  if (!rk_ready() || !out || slot < 0 || slot >= RK_MAX) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  return rcOpenLocked(slot, out);
}
int rk_rc_mark_used(RkRecovery* rc, int i) {
  if (!rk_ready() || !rc || rc->slot < 0 || rc->slot >= RK_MAX || i < 0 || i >= rc->n || rc->n > RK_RC_MAX) return RK_E_NOVAULT;
  std::lock_guard<std::mutex> g(s_mx);
  loadLocked();
  if (!isKind(rc->slot, RK_KIND_RECOVERY)) return RK_E_FORMAT;
  const uint16_t used = (uint16_t)(rc->used | (1u << i));
  uint8_t id8[8]; memcpy(id8, R->idx[rc->slot].clear, 8);
  const int r = rcSealLocked(rc->slot, id8, rc->site, strlen(rc->site), rc->user, strlen(rc->user), rc->code, rc->n, used);
  if (r == RK_OK) rc->used = used;
  return r;
}

uint8_t rk_pw_health(int i) {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int s = slotOfKind(RK_KIND_PASSWORD, i);
  return s >= 0 ? hlthGetLocked(s) : 0;
}
uint8_t rk_pw_health_slot(int slot) {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  return hlthGetLocked(slot);
}
int rk_pw_index_of_id(const uint8_t id8[8]) {
  if (!rk_ready() || !id8) return -1;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int k = 0;
  for (int s = 0; s < RK_MAX; s++) { if (!isKind(s, RK_KIND_PASSWORD)) continue; if (!memcmp(R->idx[s].clear, id8, 8)) return k; k++; }
  return -1;
}
int rk_health_unseen() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int n = 0;
  for (int s = 0; s < RK_MAX; s++) {
    if (!isKind(s, RK_KIND_PASSWORD)) continue;
    const uint8_t h = hlthGetLocked(s);
    if ((h & RK_H_STRENGTH) && (hashOnLocked(s) || (h & RK_H_CHECKED))) continue;
    n++;
  }
  return n;
}
int rk_health_pending() {
  if (!rk_ready()) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int n = 0;
  for (int s = 0; s < RK_MAX; s++) if (hashOnLocked(s) && !(hlthGetLocked(s) & RK_H_CHECKED)) n++;
  return n;
}
int rk_health_prefixes(uint8_t (*out)[3], int max) {
  if (!rk_ready() || !out || max <= 0) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int n = 0;
  for (int s = 0; s < RK_MAX && n < max; s++) {
    if (!hashOnLocked(s) || (hlthGetLocked(s) & RK_H_CHECKED)) continue;
    uint8_t p[3] = { s_pwHash[s].sha[0], s_pwHash[s].sha[1], (uint8_t)(s_pwHash[s].sha[2] & 0xF0) };   // 20 bits = 5 hex digits
    bool dup = false; for (int k = 0; k < n; k++) if (!memcmp(out[k], p, 3)) { dup = true; break; }
    if (!dup) memcpy(out[n++], p, 3);
  }
  return n;
}
// 24 Nov 2026 (bench): an app sent an EMPTY bucket and every entry with that
// prefix was marked "checked, not breached": a failed fetch read as clean. A
// real Have I Been Pwned range holds hundreds of suffixes (padding lines with
// a count of 0 are dropped by the phone), so a whole bucket, all its parts
// together, under RK_HEALTH_MIN_BUCKET is refused: no verdict is recorded,
// the entries stay pending, and the caller answers with a refusal.
static uint8_t  s_bkPrefix[3] = {0, 0, 0};
static uint32_t s_bkCount = 0;
static bool     s_bkOpen = false;
int rk_health_bucket(const uint8_t prefix[3], const uint8_t* suffixes, int n, bool last) {
  if (!rk_ready() || !prefix || n < 0) return 0;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  const uint8_t p2 = (uint8_t)(prefix[2] & 0xF0);
  if (!s_bkOpen || s_bkPrefix[0] != prefix[0] || s_bkPrefix[1] != prefix[1] || s_bkPrefix[2] != p2) {
    // a new bucket (or parts of an older one were abandoned): count from here
    s_bkPrefix[0] = prefix[0]; s_bkPrefix[1] = prefix[1]; s_bkPrefix[2] = p2; s_bkCount = 0; s_bkOpen = true;
  }
  s_bkCount += (uint32_t)n;
  const bool tooSmall = last && s_bkCount < RK_HEALTH_MIN_BUCKET;
  if (last) s_bkOpen = false;
  int decided = 0;
  for (int s = 0; s < RK_MAX; s++) {
    if (!hashOnLocked(s)) continue;
    const uint8_t* sha = s_pwHash[s].sha;
    if (sha[0] != prefix[0] || sha[1] != prefix[1] || (sha[2] & 0xF0) != (prefix[2] & 0xF0)) continue;
    // our suffix: the low nibble of byte 2 then bytes 3..19 (35 hex digits), packed as the phone packs it
    uint8_t mine[18]; mine[0] = (uint8_t)((sha[2] & 0x0F) << 4 | (sha[3] >> 4));
    for (int i = 1; i < 17; i++) mine[i] = (uint8_t)((sha[i + 2] & 0x0F) << 4 | (sha[i + 3] >> 4));
    mine[17] = (uint8_t)((sha[19] & 0x0F) << 4);
    if (tooSmall) { mbedtls_platform_zeroize(mine, sizeof mine); s_bucketHit[s] = false; continue; }   // no verdict from a bucket this small
    bool hit = false;
    for (int k = 0; k < n && !hit; k++) hit = !memcmp(suffixes + k * 18, mine, 18);
    mbedtls_platform_zeroize(mine, sizeof mine);
    if (!last) { if (hit) s_bucketHit[s] = true; continue; }   // a part: the verdict waits for the last one
    hit = hit || s_bucketHit[s]; s_bucketHit[s] = false;
    uint8_t h = hlthGetLocked(s);
    uint8_t nh = (uint8_t)((h | RK_H_CHECKED) & ~RK_H_BREACHED); if (hit) nh |= RK_H_BREACHED;
    if (nh != h) hlthSetLocked(s, nh);
    decided++;
  }
  if (tooSmall) return -1;
  hlthFlushLocked();
  return decided;
}
// 24 Nov 2026 (bench): send every "checked, not breached" entry back to pending,
// for the verdicts an empty bucket recorded before the floor above existed. A
// breached verdict is kept: it can only have come from a real bucket.
int rk_health_recheck_clean() {
  if (!rk_ready()) return -1;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  int n = 0;
  for (int s = 0; s < RK_MAX; s++) {
    if (!isKind(s, RK_KIND_PASSWORD)) continue;
    const uint8_t h = hlthGetLocked(s);
    if ((h & RK_H_CHECKED) && !(h & RK_H_BREACHED)) { hlthSetLocked(s, (uint8_t)(h & ~RK_H_CHECKED)); n++; }
  }
  hlthFlushLocked();
  return n;
}
bool rk_health_backfill_one() {
  if (!rk_ready()) return false;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  for (int s = 0; s < RK_MAX; s++) {
    if (!isKind(s, RK_KIND_PASSWORD)) continue;
    const uint8_t h = hlthGetLocked(s);
    if ((h & RK_H_STRENGTH) && (hashOnLocked(s) || (h & RK_H_CHECKED))) continue;
    RkPass* a = (RkPass*)rkAlloc(sizeof(RkPass)); if (!a) return false;
    int e = pwOpenLocked(s, a);   // notes strength and the hash itself
    rk_pw_wipe(a); free(a);
    if (e) return false;   // the budget is spent, or the record is unreadable: stop for this sitting
    return true;
  }
  return false;
}
int rk_health_prefix_of(int slot, uint8_t prefix[3]) {
  if (!rk_ready() || slot < 0 || slot >= RK_MAX) return -1;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  if (!isKind(slot, RK_KIND_PASSWORD)) return -1;
  if (hlthGetLocked(slot) & RK_H_CHECKED) return 2;
  if (!hashOnLocked(slot)) return 0;
  prefix[0] = s_pwHash[slot].sha[0]; prefix[1] = s_pwHash[slot].sha[1]; prefix[2] = (uint8_t)(s_pwHash[slot].sha[2] & 0xF0);
  return 1;
}
int rk_health_assess_slot(int slot) {
  if (!rk_ready()) return RK_E_NOVAULT;
  if (slot < 0 || slot >= RK_MAX) return -1;
  std::lock_guard<std::mutex> g(s_mx); loadLocked();
  if (!isKind(slot, RK_KIND_PASSWORD)) return -1;
  const uint8_t h = hlthGetLocked(slot);
  if ((h & RK_H_STRENGTH) && (hashOnLocked(slot) || (h & RK_H_CHECKED))) return 0;
  RkPass* a = (RkPass*)rkAlloc(sizeof(RkPass)); if (!a) return RK_E_NVS;
  int e = pwOpenLocked(slot, a);   // notes strength and the hash, as the backfill does
  rk_pw_wipe(a); free(a);
  return e ? e : 1;
}
}  // namespace favilla
#endif  // FAVILLA_PK_RESTORABLE
