// ═══════════════════════════════════════════════════════════════════════════
// NV_DOMAINS — storage isolation for FAVILLA KEY (Isolation Doctrine R3/R4/R6)
// ═══════════════════════════════════════════════════════════════════════════
// Three NVS domains, three partitions (see partitions_favilla_8mb.csv):
//
//   NVSPART_SEC  ("nvs_sec")  — seed blobs, pairing, device mode, NWC.
//                               Near-zero writes post-provisioning. A failure
//                               to mount is a LOUD failure, never auto-erased.
//   NVSPART_GAME ("nvs_game") — CIPHER + steps. May churn/fill/corrupt with
//                               zero shared fate. Auto-erased on corruption:
//                               game failure degrades to game failure (R6).
//   default "nvs"             — WiFi lib state, PHY calib, relays, feedback.
//                               Untouched; the WiFi stack owns its location.
//
// USAGE
//   setup():   if (!nvInitPartitions()) { /* nvs_sec mount failed: show
//                fatal storage error; do NOT continue to signing UI */ }
//   loop():    if (nvGameFlushDue()) { cipherFlushHot(); nvGameFlushed(); }
//   sleep:     nvGameFlushNow() immediately before esp_deep_sleep_start()
//              (calls cipherFlushHot() unconditionally, ignoring deferral —
//              the security UX cannot be active while entering sleep).
//   security:  securityUxBegin() on entry to PIN entry / SAS confirm /
//              PSBT signing / pairing screens; securityUxEnd() on exit.
//              While active, NO game NVS commits happen (R4).
//
//   Preferences opens gain a third arg:
//     p.begin("cipher", false, NVSPART_GAME);
//     p.begin("favilla_se", false, NVSPART_SEC);
//   (migrate_ns.py rewrites existing call sites mechanically.)
// ═══════════════════════════════════════════════════════════════════════════
#pragma once
#include <nvs_flash.h>
#include <Preferences.h>

#define NVSPART_SEC   "nvs_sec"
#define NVSPART_GAME  "nvs_game"

// ── Init ────────────────────────────────────────────────────────────────────
// Mount both extra partitions. Returns false ONLY on nvs_sec failure —
// that is a ship-stopper condition for the boot path (device must not
// pretend to be a functioning signer without its security store).
// nvs_game corruption is self-healed by erase: the game loses its save,
// the signer loses nothing.
static bool nvInitPartitions() {
  // Security partition: init, never auto-erase. NVS_ERR -> fail loud.
  esp_err_t e = nvs_flash_init_partition(NVSPART_SEC);
  if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    // Even these "recoverable" states are NOT auto-erased for the security
    // partition — erasing here could destroy a seed blob. Surface it.
    return false;
  }
  if (e != ESP_OK) return false;

  // Game partition: init; on corruption, erase and re-init (Rule 6).
  e = nvs_flash_init_partition(NVSPART_GAME);
  if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND ||
      e == ESP_ERR_NVS_INVALID_STATE) {
    nvs_flash_erase_partition(NVSPART_GAME);
    e = nvs_flash_init_partition(NVSPART_GAME);
  }
  // Even total nvs_game failure is non-fatal: the game runs from RAM
  // defaults and simply doesn't persist. Signer unaffected.
  (void)e;

  // Boot-time visibility: NVS keeps per-entry bookkeeping in INTERNAL heap,
  // so a stuffed game partition silently taxes the signer's RAM (~8KB when
  // the 128KB partition is full — enough to push bunker mode under its
  // NIP-46 heap floor). This line makes that tax visible on every boot
  // instead of ambushing us as "bunker refuses requests".
  {
    nvs_stats_t st;
    if (nvs_get_stats(NVSPART_GAME, &st) == ESP_OK)
      Serial.printf("[NVSTAX] nvs_game: used=%d/%d entries (heap tax scales with used)\n",
                    st.used_entries, st.total_entries);
    if (nvs_get_stats(NVSPART_SEC, &st) == ESP_OK)
      Serial.printf("[NVSTAX] nvs_sec:  used=%d/%d entries\n",
                    st.used_entries, st.total_entries);
  }
  return true;
}

// ── Rule 4: security UX owns the device ─────────────────────────────────────
// Reference-counted so nested flows (e.g. SAS modal over a pairing screen)
// compose correctly.
static volatile int _secUxDepth = 0;
static inline void securityUxBegin() { _secUxDepth = _secUxDepth + 1; }
static inline void securityUxEnd()   { if (_secUxDepth > 0) _secUxDepth = _secUxDepth - 1; }
static inline bool securityUxActive(){ return _secUxDepth > 0; }

// ── Game dirty-flag flush engine (wear fix) ─────────────────────────────────
// Hot game state (embers, step counters) accumulates in RAM and is flushed:
//   * at most once per NV_GAME_FLUSH_MS while dirty (default 5 min)
//   * never while a security flow is on screen (deferred, not dropped)
//   * unconditionally on sleep entry / game exit / death via nvGameFlushNow()
// Cold writes (mints, inventory, skill purchases, run stats) stay immediate
// at their existing call sites — they are rare and matter.
//
// Crash-loss budget: at most NV_GAME_FLUSH_MS of steps. Because stepsHwBase
// is persisted with the same flush, a crash can also DOUBLE-credit up to the
// same window (base stale -> delta re-credited on next boot). Both directions
// are bounded, local-only, and cost nothing but embers. Acceptable for V1.
#ifndef NV_GAME_FLUSH_MS
#define NV_GAME_FLUSH_MS 300000UL   // 5 minutes
#endif

static volatile bool _nvGameDirty = false;
static unsigned long _nvGameLastFlush = 0;

static inline void nvMarkGameDirty() { _nvGameDirty = true; }

// True when a flush should run now. Pair with cipherFlushHot() + nvGameFlushed().
static inline bool nvGameFlushDue() {
  if (!_nvGameDirty) return false;
  if (securityUxActive()) return false;                       // R4: defer
  return (millis() - _nvGameLastFlush) >= NV_GAME_FLUSH_MS;
}
static inline void nvGameFlushed() {
  _nvGameDirty = false;
  _nvGameLastFlush = millis();
}

// Forward-declared writer, defined in cipher_steps.h (it can see both the
// game globals and the steps state). Writes embers/walked + step counters.
void cipherFlushHot();

// Unconditional flush for sleep entry / shutdown paths. Ignores the interval
// (but still honors an active security flow, which cannot occur on the sleep
// path by construction — sleep gesture is a game/global UX, not a signing UX).
static inline void nvGameFlushNow() {
  if (!_nvGameDirty) return;
  cipherFlushHot();
  nvGameFlushed();
}

// ── Seed migration: REMOVED ─────────────────────────────────────────────────
// nvMigrateSeedOnce() (dev-unit relocation of seed_blob from the default
// partition into nvs_sec) was deleted 2026-07. It was a boot-time write path
// INTO nvs_sec sourced FROM the untrusted default partition — an inverted
// trust direction and a seed-substitution vector if it ever shipped. All dev
// units that booted any post-split build have already migrated (the function
// was idempotent and deleted its source key); any unit that never did will
// present as un-provisioned and should be re-onboarded from its BIP-39 backup.
// Do not reintroduce boot-time writers into nvs_sec.
