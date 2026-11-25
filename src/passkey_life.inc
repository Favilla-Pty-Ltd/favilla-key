#ifdef FAVILLA_BLE_KBD
static bool g_pkCamBack = false;   // 8u: the camera reserve is held again after Bluetooth is up (life start and after each scan)
#endif
// =============================================================================
// passkey_life.inc — the PASSKEY life on the ESP32 (30 Oct 2026, step 3b)
// =============================================================================
// Passkey door spec v1.0, section 6. Included by main.cpp after the FIDO glue
// (FAVILLA_PASSKEY_DOOR builds only). Owns the device from the end of setup()
// in a life the G0 holds as PASSKEY:
//   * no radio, ever: deviceMode forced OFFLINE before any radio decision (as
//     in a Bitcoin session), the radio guard refuses, and a tripwire checks
//     the WiFi driver is still uninitialised every 2 s;
//   * the passkey PIN is asked once, on the KEY, before any sign-in. The SE
//     checks it (one of its 10 attempts; this side stops at 9). It is held in
//     RAM for the life and wiped on auto-lock and on sleep;
//   * a website's request shows the prompt (site name, ENTER / BACK); every
//     signature still goes through the passkey-PIN session, the G0's mint and
//     the burn (passkey_door.inc), so the PIN in RAM opens nothing by itself.
// Bench: the USB serial port stays up next to the FIDO interface (the
// shipping passkey life has none). In this life it answers TWO commands only,
// `fido status` and `fido bootloader` (the way back to the Forge). Everything
// else - the whole bench console, wipes and probes included - is ignored: the
// computer you sign in on is exactly the party this life does not trust.
// =============================================================================

#include <functional>
#include "login_qr.h"   // 4 Nov 2026: Vault phase 5, the login QR (site + username in one scan)
#include "chan_proto.h"  // 11az: the NEW_LOGIN form bits (chan::FORM_*), in every build
#ifdef FAVILLA_PK_RESTORABLE
static void pwBgTick();   // background site names (below): every PASSKEY-life loop calls pkSerialTick
#endif
#if defined(FAVILLA_BENCH_PROBES) && defined(FAVILLA_PK_RESTORABLE)
// 3 Nov 2026: bench check for the sealed site index (P4-10). The boards are
// Secure Boot eFused with secure download mode on, so esptool cannot read the
// flash; this reads the WHOLE flash chip raw, the bytes a chip-off dump would
// give (flash encryption is off), and searches it for every site name the
// unlocked index knows. It prints counts, where each hit sits, and the name
// of a hit only. Bench builds only, like `bench pkprobe`.
#include "esp_flash.h"
#include "esp_partition.h"
#include "esp_task_wdt.h"
static const char* pkScanWhere(uint32_t a, uint32_t* off){
  esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, nullptr);
  const char* r = a < 0x8000 ? "bootloader/table" : "unpartitioned"; *off = a;
  for(; it; it = esp_partition_next(it)){
    const esp_partition_t* q = esp_partition_get(it);
    if(a >= q->address && a < q->address + q->size){ r = q->label; *off = a - q->address; break; }
  }
  if(it) esp_partition_iterator_release(it);
  return r;
}
static void pkSiteScan(){
  if(!g_pkPinHeld || !favilla::rk_idx_have_key()){ Serial.println("[SCAN] enter the passkey PIN first (the index must be open)"); return; }
  const int MAXN = 200, W = 65;
  char* names = (char*)heap_caps_calloc(MAXN, W, MALLOC_CAP_SPIRAM);
  uint8_t* lens = (uint8_t*)calloc(MAXN, 1);
  uint16_t* hits = (uint16_t*)calloc(MAXN, 2);
  uint8_t* pre = (uint8_t*)calloc(8192, 1);            // 2-byte prefix bitmap
  const size_t CH = 4096, OV = 64;
  uint8_t* buf = (uint8_t*)heap_caps_malloc(CH + OV, MALLOC_CAP_SPIRAM);
  if(!names || !lens || !hits || !pre || !buf){ Serial.println("[SCAN] out of memory"); goto out; }
  {
    int n = 0, shortN = 0, total = favilla::rk_pw_count();
    for(int i = 0; i < total && n < MAXN; i++){
      char* d = names + n * W;
      if(!favilla::rk_pw_site(i, d, W, nullptr, nullptr)) continue;
      size_t L = strlen(d);
      if(L < 4){ shortN++; continue; }                     // too short to mean anything in 16 MB
      lens[n] = (uint8_t)L; uint16_t k = ((uint8_t)d[0] << 8) | (uint8_t)d[1];
      pre[k >> 3] |= 1 << (k & 7); n++;
    }
    uint32_t size = 0; esp_flash_get_size(nullptr, &size);
    Serial.printf("[SCAN] %d site names (of %d entries, %d too short to search); reading all %u KB of flash raw...\n", n, total, shortN, (unsigned)(size / 1024));
    uint32_t t0 = millis(), found = 0, readErr = 0; size_t have = 0;
    for(uint32_t a = 0; a < size; a += CH){
      size_t len = (size - a) < CH ? (size - a) : CH;
      if(esp_flash_read(nullptr, buf + have, a, len) != ESP_OK){ readErr++; have = 0; continue; }
      size_t tot = have + len; uint32_t base = a - have;
      for(size_t i = 0; i + 1 < tot; i++){
        uint16_t k = (buf[i] << 8) | buf[i + 1];
        if(!(pre[k >> 3] & (1 << (k & 7)))) continue;
        for(int j = 0; j < n; j++){
          size_t L = lens[j];
          if(i + L > tot || memcmp(buf + i, names + j * W, L)) continue;
          if(i + L <= have) continue;                        // already counted in the last chunk's tail
          hits[j]++; found++;
          if(found <= 40){ uint32_t off; const char* w = pkScanWhere(base + i, &off);
            Serial.printf("[SCAN]   HIT \"%s\" at 0x%06x (%s +0x%x)\n", names + j * W, (unsigned)(base + i), w, (unsigned)off); }
        }
      }
      have = tot < OV ? tot : OV; memmove(buf, buf + tot - have, have);
      if(((a / CH) & 63) == 0){ if(esp_task_wdt_status(nullptr) == ESP_OK) esp_task_wdt_reset(); vTaskDelay(1); }
    }
    int namesHit = 0; for(int j = 0; j < n; j++) if(hits[j]) namesHit++;
    if(found == 0) Serial.printf("[SCAN] RESULT: none of the %d names is anywhere in flash (%u ms, %u read errors)\n", n, (unsigned)(millis() - t0), (unsigned)readErr);
    else Serial.printf("[SCAN] RESULT: %u hits for %d of %d names (%u ms, %u read errors)%s\n", (unsigned)found, namesHit, n, (unsigned)(millis() - t0), (unsigned)readErr, found > 40 ? "; first 40 shown" : "");
  }
out:
  if(names){ memset(names, 0, MAXN * W); heap_caps_free(names); }
  free(lens); free(hits); free(pre);
  if(buf){ memset(buf, 0, CH + OV); heap_caps_free(buf); }
}
#endif
static void chanExpire();   // below
static bool g_btPreferPhone = false;   // 8p: bench only (bt phone / bt auto): typing to the phone with the cable in
extern uint32_t g_pwrBoostMs;   // main.cpp (defined further down)
static void pkSerialTick(){
  // 9n (power): this life never runs loop(), so the light-sleep locks are driven
  // from here: no naps while the screen is lit, on USB (a PC or power) or in the
  // first 60 s. Both do nothing on the stock core.
  pmBacklightTick(); pmUsbSerialTick();
#ifdef FAVILLA_PK_RESTORABLE
  pwBgTick();
#endif
  // 9m (power): a QR scan raises the CPU to 240 MHz and nothing in this life
  // brought it back (the main loop's safety net does not run here). Back to
  // 80 MHz 3 s after the last boost, once the camera is off (pwrIdle keeps any hold).
  { static uint32_t lastChk = 0; const uint32_t now = millis();
    if(now - lastChk > 1000){ lastChk = now; if(!cameraRunning && now - g_pwrBoostMs > 3000 && getCpuFrequencyMhz() > 80){ pwrIdle(); LOG_BOOT("[PWR] CPU back to %u MHz after the scan\n", (unsigned)getCpuFrequencyMhz()); } } }
  chanExpire();
#ifdef FAVILLA_BLE_KBD
  blek::tick();   // 8m: advertising only when needed; the link dropped 10 s after typing
  // 8t: a scan paused Bluetooth; once the camera has been off for 2 s, hand its
  // memory back and start Bluetooth again (as at the start of the life).
  if(blek::s_paused && !cameraRunning && millis() - lastCameraStopMs > 2000){
    cameraRelease(); camReserveRelease("Bluetooth back after the scan");
    g_pkCamBack = false;   // 8u: the camera's block is taken again once Bluetooth is up
    blek::resumeAfterCamera();
  }
  // 11ai: the scan ran with Bluetooth up (the block was there). The resident
  // driver still holds ~20 KB of internal RAM the link needs for its answers:
  // let it go the same 2 s after the scan, with nothing to restart.
  else if(blek::s_up && cameraHwReady && !cameraRunning && millis() - lastCameraStopMs > 2000){
    cameraRelease(); camReserveRelease("Bluetooth kept the RAM");
    g_pkCamBack = false;
  }
#endif
  static char line[32]; static size_t n = 0;
  while(CON_AVAILABLE()){
    int c = CON_READ();
    if(c == '\r' || c == '\n'){
      line[n] = 0;
      if(n){
        if(!strcmp(line, "fido status"))          fido::status();
        else if(!strcmp(line, "pm"))         pmCensusPrint();   // 9w: the power census
#ifdef FAVILLA_BENCH_PROBES
        else if(!strncmp(line, "time ", 5)){   // 9j bench: set the clock by hand until the app sends TIME (bench builds only)
          long long t = atoll(line + 5);
          if(t > 1700000000LL && t < 4102444800LL){ struct timeval tv = { (time_t)t, 0 }; settimeofday(&tv, nullptr); Serial.printf("[OTP] bench: clock set to %lld\n", t); }
          else Serial.println("[OTP] bench: give the Unix time in seconds, e.g. time 1794028000");
        }
#endif
#ifdef FAVILLA_BLE_KBD
        else if(!strcmp(line, "bt status"))       blek::status();
#ifdef FAVILLA_BENCH_PROBES
        else if(!strcmp(line, "bt test"))         blek::benchTest();   // 8g: a fixed word, never a password
        else if(!strcmp(line, "bt gatt"))         blek::benchGatt();   // 8i: the attribute table, for the iPhone subscription
        else if(!strcmp(line, "bt phone"))        { g_btPreferPhone = true;  Serial.println("[BT] bench: typing goes to the phone, cable or not (bt auto to undo)"); }
        else if(!strcmp(line, "bt auto"))         { g_btPreferPhone = false; Serial.println("[BT] bench: typing goes to the computer when the cable is in, else the phone"); }
#endif
#endif
        else if(!strcmp(line, "fido bootloader")) fido::restartToUsjLoader();
#ifdef FAVILLA_BENCH_PROBES
        // 2 Nov 2026: Vault spec 1b, the L2 policy probe. Bench builds only;
        // the shipping passkey life has no serial port at all.
        // 4 Nov 2026: the heap reading for the Bluetooth phase (P5-4 B): what the
        // PASSKEY life leaves in internal RAM, unlocked, at rest.
        else if(!strcmp(line, "bench heap")){
          heapCheckpoint(g_pkPinHeld ? "passkey unlocked" : "passkey locked");
          Serial.printf("[HEAPCK] internal low-water mark since boot: %u\n", (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
        }
#ifdef FAVILLA_PK_RESTORABLE
        else if(!strcmp(line, "vault size")) vaultSizeReport();   // 11dr: the RK_MAX 400 bench (main.cpp)
        else if(!strcmp(line, "vault unfill")) vaultUnfill();     // 11dr bench: only the "fill-" test entries
        else if(!strcmp(line, "vault recheck")){   // 24 Nov 2026 bench: undo the verdicts empty buckets recorded
          const int n = favilla::rk_health_recheck_clean();
          if(n < 0) Serial.println("[PW] recheck: the vault is not mounted yet, try again in a few seconds");
          else Serial.printf("[PW] recheck: %d entr%s marked clean are pending again (breached ones kept); check them again from the app\n", n, n == 1 ? "y" : "ies");
        }
#endif
        else if(!strcmp(line, "bench pkprobe")){
          if(!g_pkPinHeld) Serial.println("[PKPROBE] enter the passkey PIN first");
          else { I2C_LOCK(); favilla::se_pkprobe(g_pkPin); I2C_UNLOCK(); }
        }
#ifdef FAVILLA_PK_RESTORABLE
        else if(!strcmp(line, "bench sitescan")) pkSiteScan();
#endif
#endif
        else Serial.println("[PASSKEY] serial: ignored (passkey mode answers only 'fido status', 'bt status' and 'fido bootloader')");
      }
      n = 0;
    } else if(n < sizeof(line) - 1) line[n++] = (char)c;
    else n = 0;   // over-long line: drop it
  }
}
// Radio tripwire, the same check a Bitcoin session runs; called from every
// loop in this life, PIN pad and hold screens included.
static void passkeyLock(const char* why);
static void (*g_pkLockHook)() = nullptr;   // 9h: the app channel forgets its LIST permission on every lock
static void pkTripwire(){
  static uint32_t last = 0;
  if(millis() - last < 2000) return;
  last = millis();
  wifi_mode_t wm = WIFI_MODE_NULL;
  esp_err_t werr = esp_wifi_get_mode(&wm);
  if(werr != ESP_ERR_WIFI_NOT_INIT || WiFi.getMode() != WIFI_OFF){
    LOG_BOOT("[PASSKEY] RADIO TRIPWIRE: WiFi driver present in a PASSKEY life (err %s, mode %d) - stopping\n", esp_err_to_name(werr), (int)wm);
    WiFi.disconnect(true, true); WiFi.mode(WIFI_OFF); esp_wifi_deinit();
    passkeyLock("radio tripwire");
    dispRestartForever("RESTART NEEDED", "A radio started in passkey mode.", "Restart the key.");   // never returns
  }
}

static const uint32_t PK_AUTOLOCK_MS = 10UL * 60UL * 1000UL;   // no press and no sign-in for 10 min -> PIN again
static const int      PK_SEND_MAX    = 9;                      // never send the SE's 10th attempt (brick guard rule)
static int  g_pkFails = 0;

static void pkFailsLoad(){ Preferences p; if(p.begin("pkdoor", true, NVSPART_SEC)){ g_pkFails = p.getInt("fails", 0); p.end(); } if(g_pkFails < 0) g_pkFails = 0; }
static void pkFailsSave(){ Preferences p; if(p.begin("pkdoor", false, NVSPART_SEC)){ p.putInt("fails", g_pkFails); p.end(); } }

static void passkeyEnterInPlace(const char* why){
  g_passkeyLife = true;
  deviceMode = MODE_OFFLINE; effectiveMode = MODE_OFFLINE;   // every radio bring-up branch keys off this
  g_doorChoice = DOOR_PASSKEY; doorSave(DOOR_PASSKEY);
  LOG_BOOT("[PASSKEY] passkey life entered (%s) - radios will not be initialised this boot\n", why);
}

// 9d (the app's ask, 6 Nov 2026): the last login sent to the app, for the
// 60 s "send again" shortcut on two-page sign-ins. RAM only; forgotten on lock,
// on restart, once used and after 60 s. Holds no password, only which entry.
struct LastFill { bool on; int idx; uint8_t peer[7]; uint32_t at; char site[101]; char user[48]; };
static LastFill g_lastFill = {};
static int g_pwAskIdx = -1;            // the entry the current FILL ask sent (set by pwSendToApp)
static int g_pwTypedIdx = -1; static uint32_t g_pwTypedAt = 0;   // 11z: the last entry typed to the computer, for the code that follows it
// 11aw: what the page showed for the ask being served (chan FIELDS_*: 0 both,
// 1 username box only, 2 password box only), and whether the username step
// pressed Enter, so the password step on the next page does the same.
static uint8_t g_pwFields = 0; static bool g_pwTypedSubmit = false; static uint8_t g_pwTypedFields = 0;
static void lastFillForget(){ mbedtls_platform_zeroize(&g_lastFill, sizeof g_lastFill); }

static void passkeyLock(const char* why){
  if(g_pkLockHook) g_pkLockHook();
  lastFillForget();   // 9d
  uvForgetPin();
  I2C_LOCK();                                   // a login in flight finishes first (fidoBeSign holds this lock)
  memset(g_pkPin, 0, sizeof(g_pkPin));
  g_pkPinHeld = false;
  I2C_UNLOCK();
  LOG_BOOT("[PASSKEY] locked (%s): passkey PIN wiped from RAM\n", why);
}

// ── screens ──────────────────────────────────────────────────────────────────
// Page language as onboarding: tracked label, ember mark, one Archivo Bold 28
// headline, Archivo 13 grey lines, tracked footer.
static const char* g_pkNote = nullptr; static uint16_t g_pkNoteCol = 0;   // drawn by pkPage when set (only pkHome sets it)
static const char* g_pkAskNo = nullptr; static const char* g_pkAskYes = nullptr;   // 11cw: pkAsk's corner answers
static void pkPage(const char* label, const char* head, const char* l1, const char* l2, const char* foot, uint16_t footCol = C_EB_BRASS){
  wp::stop();   // 11cg: a moving wait page ends when any VAULT page replaces it
  spr.fillSprite(C_BG);
  uiTrackLabel(label, 120, 14, C_EB_BRASS);
  ebMarkSmall(101, 38, 6, 2);
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
  if(spr.textWidth(head) <= 224) spr.drawString(head, 120 - spr.textWidth(head)/2, 92);
  else { fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_INK); uiWrapCentre(head, 94, 216, 18, 2); fEnd(); }   // 5v: never past the edges
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  if(l1) spr.drawString(l1, 120 - spr.textWidth(l1)/2, 134);
  if(l2) spr.drawString(l2, 120 - spr.textWidth(l2)/2, 152);
  fEndHard();
  if(g_pkNote) uiTrackLabel(g_pkNote, 120, 176, g_pkNoteCol);   // 4 Nov 2026 (phase 6): the home screen's Bluetooth line
  // 11cy: a lone "ENTER TO ..." / "ENTER FOR ..." footer becomes the word alone in
  // ENTER's corner (bottom-right), like every other screen's answers.
  if(foot && !strncmp(foot, "ENTER TO ", 9)) uiCornerAnswers(nullptr, foot + 9);
  else if(foot && !strncmp(foot, "ENTER FOR ", 10)) uiCornerAnswers(nullptr, foot + 10);
  else if(foot) uiTrackLabel(foot, 120, 202, footCol);
  if(g_pkAskYes) uiCornerAnswers(g_pkAskNo, g_pkAskYes);
  dispPush();
}
// 11cw (Josh, 22 Nov 2026): a question page, its two answers in the corners over
// their buttons (BACK bottom-left, ENTER bottom-right) instead of a footer hint.
static void pkAsk(const char* label, const char* head, const char* l1, const char* l2, const char* no, const char* yes){
  g_pkAskNo = no; g_pkAskYes = yes;
  pkPage(label, head, l1, l2, nullptr);
  g_pkAskNo = g_pkAskYes = nullptr;
}
// 11cg (22 Nov 2026, UX drop 1): pkPage's layout with the small ember
// flickering, for the second or two the KEY works (the G0 opening an entry,
// the phone's keyboard waking). The next pkPage or pkPageMsg ends it.
static void pkWorking(const char* label, const char* head, const char* l1, const char* l2, const char* foot = nullptr, uint16_t footCol = C_EB_GREY){
  wp::Page& p = wp::small(label, head);
  snprintf(p.line1, sizeof p.line1, "%s", l1 ? l1 : ""); snprintf(p.line2, sizeof p.line2, "%s", l2 ? l2 : "");
  snprintf(p.foot, sizeof p.foot, "%s", foot ? foot : ""); p.footCol = footCol;
  wp::show();
}
static void pkHome(){
  char l2[40];
  int n = favilla::rk_count();   // 11dq: the passkeys the Passkeys page lists (was the old FIDO index slots, often 0)
  snprintf(l2, sizeof l2, n == 1 ? "1 passkey on this key." : "%d passkeys on this key.", n);
#ifdef FAVILLA_BLE_KBD
  // 4 Nov 2026 (phase 6): a Bluetooth life says so on the home screen, always.
  struct NoteGuard { ~NoteGuard(){ g_pkNote = nullptr; } } ng;
  if(g_btLife){ const bool c = blek::ready(); g_pkNote = c ? "PHONE CONNECTED" : blek::s_up ? "BLUETOOTH ON" : blek::s_paused ? "BLUETOOTH PAUSED" : blek::starting() ? "BLUETOOTH STARTING" : "BLUETOOTH FAILED"; g_pkNoteCol = c ? C_EB_BRASS : C_EB_GREY; }
  else if(g_passkeyLife && g_btCrumbs.stage > 100){ g_pkNote = "BLUETOOTH SKIPPED"; g_pkNoteCol = C_EB_GREY; }
#endif
#ifdef FAVILLA_PK_RESTORABLE
  if(g0_pk2b_present()){ pkPage("VAULT", "Ready", "Sign in on your computer.", l2, "ENTER FOR MENU", C_EB_GREY); return; }
#endif
  pkPage("VAULT", "Ready", "Sign in on your computer.", l2, "HOLD BOTH LEFT TO SLEEP", C_EB_GREY);
}
// Hold a screen with nothing to do but sleep (setup problems, PIN locked).
static void pkHoldForever(){
  clearButtonPending();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); tickSleepGesture(); pkSerialTick(); pkTripwire(); delay(20); }
}

#ifdef FAVILLA_PK_RESTORABLE
// ── Vault phase 2b (2 Nov 2026): passkey windows, first-login copies, the gate ──
// Every G0 PKSIGN / VAULT in this life runs in its own window (ruling S2).
// v19 (13 Nov 2026, docs/DOOR_KEY_RULE.md): the window's passkey session also
// reads the PASSKEY copy and strips K_PK, and the 64 bytes (inner || tag) go to
// the G0 before each op (g0_pkm_set). The G0 uses them only at V_3, in a PASSKEY
// life, with its own tag checking. The close hook clears them first.
static bool pkWinOpenHook(){
  I2C_LOCK();
  bool ok = g_pkPinHeld && favilla::se_pk_window_open(g_pkPin, true);
  if(ok){
    uint8_t m[G0_PKM_LEN];
    if(favilla::se_pk_master_read(m)) g0_pkm_set(m); else g0_pkm_clear();   // no copy yet (first login) or refused: the G0 then refuses the op
    mbedtls_platform_zeroize(m, sizeof m);
    favilla::se_pin_session_close();   // the G0 runs its own session; the close reopens one to burn
  }
  I2C_UNLOCK();
  return ok;
}
static void pkWinCloseHook(){ g0_pkm_clear(); I2C_LOCK(); favilla::se_pk_window_close(g_pkPinHeld ? g_pkPin : nullptr); I2C_UNLOCK(); }   // review (H1): no PIN, no SE attempt: wedge instead
// S4 = A: the copy is written at the first PASSKEY login after setup.
// v19: one copy only, the PASSKEY one (no NOSTR copy, no question).
static void pk2bFirstLogin(){
  if(!g0_pk2b_present()) return;
  uint8_t pkm[G0_PKM_LEN];
  if(!pk2bPendingLoad(pkm)) return;
  bool keys; { I2C_LOCK(); keys = favilla::se_pk2b_keys_present(); I2C_UNLOCK(); }
  if(!keys){ mbedtls_platform_zeroize(pkm, sizeof pkm); LOG_BOOT("[PK2B] first login: K_PK missing - set the KEY up again\n"); return; }
  pkPage("VAULT", "Setting up", "Storing your passkey key", "for this mode.", nullptr);
  uint32_t t0 = millis();
  I2C_LOCK();
  bool ok = favilla::se_pk_window_open(g_pkPin, true);
  if(ok) ok = favilla::se_pk2b_write_copies(pkm);
  bool burned = favilla::se_pk_window_close(g_pkPin);
  I2C_UNLOCK();
  mbedtls_platform_zeroize(pkm, sizeof pkm);
  if(ok && burned){ pk2bPendingErase(); g_pkrMasterSeen = -1; g_pkrMasterSeenP = -1; }
  LOG_BOOT("[PK2B] first PASSKEY login: PASSKEY copy %s, %lu ms\n", ok ? "written" : "NOT written (kept for the next login)", (unsigned long)(millis() - t0));
}
// Phase 3 (2 Nov 2026): the vault backup publishing key copy. Made once, in
// one window, at a PASSKEY login: the G0 derives k_pub from the master
// (PUBSEAL) and hands back only k_pub sealed under K_G0, its public key and the
// check value. v19: the sealed bytes wait in nvs_sec ("vseal") until the next
// NOSTR life, which wraps them under the daily key into SE_OBJ_VPUB inside the
// daily session (vpubPendingWrite in main.cpp). The PASSKEY life never
// holds the daily PIN, and the daily PIN never opens the master.
static void vpubEnsure(){
  if(!g0_vpub_present() || !g0_pk2b_present() || !g_pkPinHeld) return;
  bool have, master; { I2C_LOCK(); have = favilla::se_vpub_present(); master = favilla::se_pkr_ready_passkey(); I2C_UNLOCK(); }
  uint8_t p[32], c[8]; bool keys = vbKeysLoad(p, c);
  bool fix = vbFixPending();
  if(vpubSealPending() && keys && !fix) return;   // v19: waiting for the NOSTR life
  if((have && keys && !fix) || !master) return;
  if(fix) have = false;   // review: re-make the copy (se_vpub_write replaces the old object)
  uint32_t t0 = millis(); uint8_t out[80]; size_t on = 0; uint8_t res = 0xFF; bool ok;
  pkPage("VAULT", "Setting up", "Preparing relay backups", "for your passkeys.", nullptr);
  g0_window_batch_begin();   // one window for PUBSEAL
  ok = g0_vault(G0_VAULT_PUBSEAL, nullptr, 0, out, &on, &res, nullptr) && res == 0 && on == 72;
  g0_window_batch_end();     // the close hook burns V_3
  if(ok && !have) ok = vpubSealSave(out);   // v19: the NOSTR life writes SE_OBJ_VPUB from it
  if(ok){
    if(keys && (memcmp(p, out + 32, 32) || memcmp(c, out + 64, 8))) LOG_BOOT("[VAULT] WARN: the stored backup key differed from the G0's - replaced with the G0's\n");
    vbKeysSave(out + 32, out + 64);
    if(fix) vbFixSet(false);
  }
  mbedtls_platform_zeroize(out, sizeof out);
  LOG_BOOT("[VAULT] publishing key %s (%s), %lu ms\n", ok ? "ready" : "NOT made (tried again at the next login)", have ? "public key only" : "sealed, written to the SE at the next NOSTR unlock", (unsigned long)(millis() - t0));
}
// Menu from the home screen: ENTER. Same page language as the picker: tracked
// label at the top, house list cards at y 52 with a pitch of 46, footer labels.
// Review (M6): every menu loop leaves for a site's request, a wedged door, or
// 60 s with no press, so the home loop's auto-lock, dim and checks resume.
static bool chanPending();   // 4 Nov 2026 (stage 2): a browser asked to sign in or save a login (below; false without the channel)
static void chanExpire();    // drop an automatic ask the home screen has not reached in 10 s
// 8z7 (6 Nov 2026): the iPhone app's Favilla sheet asked to sign in (ble_kbd.h).
// Like a browser's explicit ask, it takes over from any menu.
#if defined(FAVILLA_BLE_KBD) && defined(FAVILLA_PK_RESTORABLE)
static inline bool phoneAskPending(){ return blek::reqQueued(); }
#else
static inline bool phoneAskPending(){ return false; }
#endif
static bool pkMenuLeave(uint32_t& lastPress){
  if(btn1.stable == LOW || btn2.stable == LOW || btn3.stable == LOW || btn4.stable == LOW) lastPress = millis();
  return fido::g_up.state == 1 || chanPending() || phoneAskPending() || favilla::se_passkey_wedged() || millis() - lastPress > 60000UL;
}
// 6c (4 Nov 2026, Josh: the passwords menu flashed before the passkey prompt):
// a site is asking, so every menu above returns WITHOUT painting itself first.
static inline bool pkLeaveNow(){ return fido::g_up.state == 1 || chanPending() || phoneAskPending() || favilla::se_passkey_wedged(); }

// ── Vault phase 4 (3 Nov 2026, Vault spec 7f): PASSWORDS ──────────────────────
// The list shows site and username from the G0's LABEL (never the password),
// most recently changed first, three to a screen, labelled as they come into
// view (about 0.5 s each the first time, then from the cache until the lock).
// ENTER on a row opens it; on the entry, a tap of ENTER types the username,
// Tab and the password into the field the computer has selected, and a 1.5 s
// hold adds Enter (submits). UP shows the note (never typed) and the delete.
// Nothing is typed without a press made on this screen, and each typing is one
// OPEN of that record; the opened entry is wiped as soon as it is typed.
static bool pwWarnSeen(){ Preferences p; uint8_t v = 0; if(p.begin("pkdoor", true, NVSPART_SEC)){ v = p.getUChar("pwwarn", 0); p.end(); } return v == 1; }
static void pwWarnSet(){ Preferences p; if(p.begin("pkdoor", false, NVSPART_SEC)){ p.putUChar("pwwarn", 1); p.end(); } }
static void pwWaitBack(uint32_t& lp){ clearButtonPending(); for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(tickSleepGesture() || pkMenuLeave(lp)) return; if(btn2.isPressed() || btn4.isPressed()) return; delay(10); } }
static const char* pwOpenErr(int e){
  if(e == favilla::RK_E_BUDGET) return "The vault limit needs your PIN. Lock the KEY and unlock it to type more.";
  const char* h = favilla::rk_hint(); if(h && *h) return h;
  return favilla::rk_err_name(e);
}
// First use (D4 rider): the KEY types into whatever the computer has selected.
static bool pwFirstUse(uint32_t& lp){
  if(pwWarnSeen()) return true;
  pkPage("BEFORE YOU TYPE", "Check the site", "The KEY cannot see the website.", "Look at the address bar first.", nullptr);
  uiCornerAnswers("LEAVE", "I WILL CHECK");   // 11cw
  dispPush(); clearButtonPending();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    if(btn2.isPressed()){ pwWarnSet(); return true; }
    delay(10); }
}
// ── where the KEY types (4 Nov 2026, Vault phase 6) ─────────────────────────
// USB, or a paired phone over Bluetooth. With both able to type, the one that
// connected last: plugging into a computer after the phone types there, and
// connecting the phone after the cable types on the phone.
namespace typer {
enum { NONE = 0, USB = 1, BT = 2 };
static inline int pick(){
  const bool u = kbd::ready();
#ifdef FAVILLA_BLE_KBD
  const bool b = blek::ready();
  if(b && g_btPreferPhone) return BT;
  if(u && b) return (int32_t)(blek::s_readyAt - kbd::s_mountedAt) > 0 ? BT : USB;
  if(b) return BT;
  // 8m: the phone link is made only to type, so a paired phone counts as a
  // target while not connected; the computer comes first when it is plugged in.
  // 8p, bench only: "bt phone" sends typing to the phone even with the cable in
  // (to read the serial log while testing the phone); "bt auto" undoes it.
  if((!u || g_btPreferPhone) && g_btLife && blek::s_up && blek::kbOn() && blek::peersCount() > 0) return BT;   // 9c: only with the keyboard on
#endif
  return u ? USB : NONE;
}
static inline bool ready(){ return pick() != NONE; }
// The phone link the press chose (re-review: a Bluetooth destination is that
// phone's link, not any phone that happens to be connected by the time it types).
static uint32_t s_btAt = 0; static uint16_t s_btH = 0xFFFF;
static inline int choose(){
  const int d = pick();
#ifdef FAVILLA_BLE_KBD
  if(d == BT){ s_btAt = blek::s_readyAt; s_btH = blek::s_h; }
#endif
  return d;
}
// Review (4 Nov 2026): the destination is chosen ONCE, when the owner presses,
// shown on screen, and passed in. If it is gone by the time the record is
// open, nothing is typed: it never switches to the other one on its own.
static inline int typeTo(int dest, const char* s, size_t len, char* bad, size_t badCap){
#ifdef FAVILLA_BLE_KBD
  if(dest == BT){ int n = kbd::untypable(s, len, bad, badCap); if(n) return n; if(!(blek::ready() && blek::s_readyAt == s_btAt && blek::s_h == s_btH)) return -1; int r = blek::type(s, len, bad, badCap); blek::noteTyped(); return r; }
#endif
  if(dest == USB){ int n = kbd::untypable(s, len, bad, badCap); if(n) return n; return kbd::ready() ? kbd::type(s, len, bad, badCap) : -1; }
  return -1;
}
static inline const char* whereOf(int dest){ return dest == BT ? "on the phone." : "on the computer."; }
static inline const char* noneHead(){ return g_btLife ? "Nothing is using the KEY as a keyboard." : "The computer is not using the KEY as a keyboard."; }
static inline const char* noneHint(){ return g_btLife ? "Plug the KEY in, or connect a paired phone." : "Plug the KEY into the computer you want to type on."; }
static inline const char* stoppedOf(int dest){ return dest == BT ? "The phone stopped listening, or disconnected. Clear the field and try again." : "The computer stopped listening part way. Clear the field and try again."; }
}  // namespace typer
#ifdef FAVILLA_BLE_KBD
// 8m: the phone link is made to type. Wake it and wait for the phone to come
// back and subscribe (up to 10 s; BACK stops). True when the phone can type.
static bool pkBtConnect(uint32_t& lp){
  blek::wake(12000);
  pkWorking("PASSWORD", "Connecting", "Waking the phone's", "Bluetooth keyboard.", "BACK TO STOP", C_EB_GREY);   // 11cg
  const uint32_t t0 = millis(); clearButtonPending();
  while(millis() - t0 < 10000UL){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(btn4.isPressed()){ wp::stop(); lp = millis(); return false; }
    if(blek::ready()){ delay(250); lp = millis(); return true; }   // a moment for the phone to settle after it subscribes (the next page ends the flicker)
    delay(20);
  }
  lp = millis(); wp::stop();
  LOG_BOOT("[BT] the phone did not connect within 10 s\n");
  return false;
}
#endif
static uint32_t g_pwTypedCount = 0;   // 4 Nov 2026: every completed typing (the channel reports "typed" from this)
static bool g_pwToApp = false;        // 9c: the phone's FILL ask is running: the login goes back to the app, never typed
static bool g_pwNewSaved = false;     // pwNew saved an entry (the channel reports "saved")
#ifdef FAVILLA_BLE_KBD
// 9c: the owner picked entry i for the app's FILL ask: send the username and
// password to the app (iOS AutoFill fills the form), over the link the ask came
// on. One OPEN, wiped after. Counted as a sign-in like a typing.
static void pwSendToApp(int i, const favilla::RkLabel& L, uint32_t& lp){
  pkWorking("PASSWORD", "Sending", "To the Favilla app", "on the phone.");   // 11cg
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e){ pkPageMsg("PASSWORDS", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;   // the record changed under the label: send nothing
  const bool sent = (r == 0) && blek::fillSend(0, e->user, e->pass);
  favilla::rk_pw_wipe(e); free(e);
  LOG_BOOT("[PW] slot %d to the app for AutoFill: %s\n", L.slot, r ? favilla::rk_err_name(r) : sent ? "sent" : "the app's link is gone");
  if(r){ pkPageMsg("PASSWORDS", "Not sent.", pwOpenErr(r)); pwWaitBack(lp); return; }
  if(!sent){ pkPageMsg("PASSWORDS", "Not sent.", "The phone disconnected. Try again from the phone."); pwWaitBack(lp); return; }
  g_pwTypedCount++; g_pwAskIdx = i;   // 9d: remembered by phoneAskRun for the 60 s shortcut
  pkPage("PASSWORD", "Sent", "The phone fills it in.", nullptr, nullptr);
  uint32_t t0 = millis(); clearButtonPending();
  while(millis() - t0 < 1200){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(btn2.isPressed() || btn4.isPressed()) break; delay(10); }
}
#endif
// Type entry i: username, Tab, password (+ Enter). One OPEN.
static void pwType(int i, const favilla::RkLabel& L, bool submit, uint32_t& lp){
#ifdef FAVILLA_BLE_KBD
  if(g_pwToApp){ (void)submit; pwSendToApp(i, L, lp); return; }   // 9c
#endif
  if(!pwFirstUse(lp)) return;
  int dest = typer::choose();
  if(dest == typer::NONE){ pkPageMsg("PASSWORDS", typer::noneHead(), typer::noneHint()); pwWaitBack(lp); return; }
#ifdef FAVILLA_BLE_KBD
  if(dest == typer::BT && !blek::ready()){
    if(!pkBtConnect(lp)){ pkPageMsg("PASSWORDS", "The phone did not connect.", "Check Bluetooth is on and Favilla KEY is in its list, then try again."); pwWaitBack(lp); return; }
    dest = typer::choose();
    if(dest != typer::BT){ pkPageMsg("PASSWORDS", "Nothing was typed.", "The keyboard target changed. Try again."); pwWaitBack(lp); return; }
  }
#endif
  pkWorking("PASSWORD", "Typing", "Keep the field selected", typer::whereOf(dest));   // 11cg
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  char* buf = (char*)heap_caps_malloc(2 * favilla::RK_PW_FIELD_MAX + 4, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e || !buf){ if(e) free(e); if(buf) free(buf); pkPageMsg("PASSWORDS", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;   // the record changed under the label: type nothing
  int res = -9; char bad[24] = {0};
  if(r == 0 && g_pwFields == 1 && !e->user[0]) r = favilla::RK_E_FORMAT;   // 11aw: the page wants a username and this entry has none
  if(r == 0){
    size_t un = strlen(e->user), pn = strlen(e->pass), n = 0;
    // 11aw: a two-page sign-in gets one half per page: the username and Enter
    // on the page with only a username box, the password on the page with
    // only a password box. A page with both gets username, Tab, password.
    if(g_pwFields == 1){ memcpy(buf, e->user, un); n = un; }
    else if(g_pwFields == 2){ memcpy(buf, e->pass, pn); n = pn; }
    else {
      if(un){ memcpy(buf, e->user, un); n = un; buf[n++] = '\t'; }
      memcpy(buf + n, e->pass, pn); n += pn;
    }
    if(submit) buf[n++] = '\n';
    res = typer::typeTo(dest, buf, n, bad, sizeof bad);   // checks every character first: nothing is typed if one cannot be
    mbedtls_platform_zeroize(buf, 2 * favilla::RK_PW_FIELD_MAX + 4);
  }
  favilla::rk_pw_wipe(e); free(e); free(buf);
  LOG_BOOT("[PW] type slot %d to the %s (username %s, enter %d): %s\n", L.slot, dest == typer::BT ? "phone" : "computer", L.user[0] ? "yes" : "none", (int)submit,
           r ? favilla::rk_err_name(r) : res == 0 ? "typed" : res > 0 ? "refused: characters the layout cannot type" : "the computer stopped listening");
  if(r == favilla::RK_E_FORMAT && g_pwFields == 1){ pkPageMsg("PASSWORDS", "Not typed.", "The page asks for a username and this entry has none."); pwWaitBack(lp); return; }
  if(r){ pkPageMsg("PASSWORDS", "Not typed.", pwOpenErr(r)); pwWaitBack(lp); return; }
  if(res > 0){
    char l2[96]; snprintf(l2, sizeof l2, "It cannot type: %s  Edit this entry in the app, or type it yourself.", bad);
    for(char* q = l2; *q; q++) if((uint8_t)*q < 0x20 || (uint8_t)*q == 0x7F) *q = '?';
    pkPageMsg("PASSWORDS", "Nothing was typed.", l2); pwWaitBack(lp); return;
  }
  if(res < 0){ pkPageMsg("PASSWORDS", "Typing stopped.", typer::stoppedOf(dest)); pwWaitBack(lp); return; }
  g_pwTypedCount++;
  if(dest == typer::USB){ g_pwTypedIdx = i; g_pwTypedAt = millis(); g_pwTypedSubmit = submit; g_pwTypedFields = g_pwFields; }   // 11z, 11aw
#ifdef FAVILLA_BLE_KBD
  if(dest == typer::BT && submit) blek::release();   // 8n: submitted: the phone's own keyboard back at once
#endif
  pkPage("PASSWORD", "Typed", g_pwFields == 1 ? "Username typed." : g_pwFields == 2 ? "Password typed." : L.user[0] ? "Username, Tab and password." : "Password typed.", submit ? "Enter pressed." : (dest == typer::BT ? "Press Enter on the phone." : "Press Enter on the computer."), nullptr);
  uint32_t t0 = millis(); clearButtonPending();
  while(millis() - t0 < 1500){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(btn2.isPressed() || btn4.isPressed()) break; delay(10); }
}
// ── 11aa (11 Nov 2026, Josh: recovery codes): the site's one-time backup strings ──
// Kept as a kind-4 record sealed by the G0 and found by the entry's site tag.
// Added by scanning a favilla:recovery QR (the PWA, the extension popup or the
// app make it from the codes the site shows). Shown one at a time; ENTER WHEN
// USED crosses it off (a re-seal, no second OPEN).
#include "recovery_qr.h"
#include "otpauth.h"          // siteMatch (the codes page includes it again below; pragma once)
static bool totpYesNo(uint32_t& lp);   // below
static void pwHead(const char* label, const char* detail);   // below
static int rcScan(recoveryqr::Out* o){   // 0 scanned, -1 left
  for(;;){
    spr.fillSprite(C_BG);
    pwHead("RECOVERY CODES", "Hold the codes QR to the camera");
    dispPush(); delay(400);
    pwrBoost(); camHoldWake();
    cameraStart(); qrFound = false;
    if(!cameraRunning) return -1;
    for(int f = 0; f < 4; f++){ camera_fb_t* sf = esp_camera_fb_get(); if(sf) esp_camera_fb_return(sf); vTaskDelay(pdMS_TO_TICKS(25)); }
    qrResultBuf[0] = 0; qrDiagReset(); qrDumpReset();
    g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
    unsigned long qs = millis(), lastQR = 0; bool got = false;
    while(millis() - qs < 30000){
      btn4.poll();
      if(btn4.isPressed()) break;
      if(!qrFound && (millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)){ qrScanOnce(); lastQR = millis(); delay(5); }
      if(qrFound){ qrFound = false; got = true; break; }
      pkTripwire(); delay(10);
    }
    g_airgapLivePreview = false; cameraStop(); clearButtonPending();
    if(!got) return -1;
    size_t len = strnlen(qrResultBuf, QR_RESULT_SZ);
    while(len && (qrResultBuf[len - 1] == '\n' || qrResultBuf[len - 1] == '\r' || qrResultBuf[len - 1] == ' ')) len--;
    const int r = recoveryqr::parse(qrResultBuf, len, o);
    mbedtls_platform_zeroize(qrResultBuf, QR_RESULT_SZ);
    LOG_BOOT("[RC] recovery QR scanned: %s\n", r == recoveryqr::OK ? "ok" : recoveryqr::errText(r));
    if(r == recoveryqr::OK) return 0;
    dispError(recoveryqr::errText(r)); errorPause();
  }
}
static bool rcAdd(const favilla::RkLabel& L, uint32_t& lp){
  recoveryqr::Out* o = (recoveryqr::Out*)heap_caps_malloc(sizeof(recoveryqr::Out), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!o) return false;
  struct Free { recoveryqr::Out* o; ~Free(){ mbedtls_platform_zeroize(o, sizeof *o); free(o); } } fr{o};
  if(rcScan(o) != 0){ lp = millis(); return false; }
  lp = millis();
  char l1[64], l2[64];
  if(!otpauth::siteMatch(L.site, o->site) && !otpauth::siteMatch(o->site, L.site)){
    snprintf(l1, sizeof l1, "The QR names %s", o->site); snprintf(l2, sizeof l2, "This entry is %s. Save anyway?", L.site);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); pkFitText(l1, sizeof l1, 216, false); pkFitText(l2, sizeof l2, 216, false); fEndHard();
    pkAsk("RECOVERY CODES", "Different site", l1, l2, "CANCEL", "SAVE HERE");
  } else {
    if(o->n == 1) snprintf(l1, sizeof l1, "1 code for %s", L.site); else snprintf(l1, sizeof l1, "%d codes for %s", o->n, L.site);
    snprintf(l2, sizeof l2, "%s", "Replaces any saved before.");
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); pkFitText(l1, sizeof l1, 216, false); fEndHard();
    pkAsk("RECOVERY CODES", "Save them?", l1, l2, "CANCEL", "SAVE");
  }
  if(!totpYesNo(lp)) return false;
  pkPage("RECOVERY CODES", "Working", "Sealing the codes", "in the signer chip.", nullptr);
  int slot = -1, r; r = RK_PIN(favilla::rk_rc_save(L.site, L.user, o->code, o->n, &slot));
  LOG_BOOT("[RC] recovery codes saved for slot %d: %s\n", L.slot, r == 0 ? "ok" : favilla::rk_err_name(r));
  pkPageMsg("RECOVERY CODES", r == 0 ? "Saved." : "Not saved.", r == 0 ? "Delete the codes from the site's page or the file you saved them in." : favilla::rk_err_name(r));
  pwWaitBack(lp);
  return r == 0;
}
static void pwRecovery(int i, const favilla::RkLabel& L, uint32_t& lp){
  for(;;){
    const int slot = favilla::rk_rc_slot_for_pw(L.slot);
    if(slot < 0){
      pkPage("RECOVERY CODES", "None saved", "The site's backup codes can", "live on this KEY, sealed.", "ENTER TO ADD BY QR");
      clearButtonPending();
      for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
        if(btn2.isPressed()) break; delay(10); }
      rcAdd(L, lp); continue;
    }
    int n = 0, used = 0; const bool known = favilla::rk_rc_counts(slot, &n, &used);
    char l1[48]; if(known) snprintf(l1, sizeof l1, "%d of %d left for %s", n - used, n, L.site); else snprintf(l1, sizeof l1, "Codes saved for %s", L.site);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); pkFitText(l1, sizeof l1, 216, false); fEndHard();
    pkPage("RECOVERY CODES", "Codes on this KEY", l1, "Showing one uses a record open.", "ENTER TO SHOW THE NEXT");
    uiTrackLabel("UP TO REPLACE BY QR", 120, 186, C_EB_GREY); dispPush();   // 11cy: above the corner answer
    clearButtonPending(); int act = 0;
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn2.isPressed()){ act = 1; break; } if(btn3.isPressed()){ act = 2; break; } delay(10); }
    if(act == 2){ rcAdd(L, lp); continue; }
    favilla::RkRecovery* rc = (favilla::RkRecovery*)heap_caps_malloc(sizeof(favilla::RkRecovery), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(!rc){ pkPageMsg("RECOVERY CODES", "Out of memory.", nullptr); pwWaitBack(lp); return; }
    struct Free { favilla::RkRecovery* r; ~Free(){ favilla::rk_rc_wipe(r); free(r); } } fr{rc};
    pkPage("RECOVERY CODES", "Opening", "Reading the codes from", "the record.", nullptr);
    int r; r = RK_PIN(favilla::rk_rc_open(slot, rc));
    if(r){ pkPageMsg("RECOVERY CODES", "Could not open them.", pwOpenErr(r)); pwWaitBack(lp); return; }
    int cur = -1; for(int k = 0; k < rc->n; k++) if(!(rc->used & (1u << k))){ cur = k; break; }
    for(;;){
      if(cur < 0){ pkPageMsg("RECOVERY CODES", "All used.", "Make new codes on the site and scan them here."); pwWaitBack(lp); return; }
      int left = 0; for(int k = 0; k < rc->n; k++) if(!(rc->used & (1u << k))) left++;
      fEnd(); spr.fillSprite(C_BG);
      uiTrackLabel("RECOVERY CODE", 120, 14, C_EB_BRASS);
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { char l[72]; snprintf(l, sizeof l, "%s", L.site); pkFitText(l, sizeof l, 216, false); spr.drawString(l, 120 - spr.textWidth(l) / 2, 40); }
      fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
      if(spr.textWidth(rc->code[cur]) <= 220) spr.drawString(rc->code[cur], 120 - spr.textWidth(rc->code[cur]) / 2, 88);
      else { fEndHard(); fSet(F_MONO); spr.setTextColor(C_EB_INK); uiWrapCentre(rc->code[cur], 84, 216, 18, 2); fEnd(); }
      fEndHard();
      { char l[32]; snprintf(l, sizeof l, "%d OF %d LEFT", left, rc->n); uiTrackLabel(l, 120, 140, C_EB_GREY); }
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { const char* l = "DOWN for another unused code"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 162); }
      fEndHard();
      uiCornerAnswers("LEAVE", "USED");   // 11cw
      dispPush(); clearButtonPending();
      int a = 0;
      for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
        if(btn2.isPressed()){ a = 1; break; } if(btn1.isPressed()){ a = 2; break; } delay(10); }
      lp = millis();
      if(a == 2){ int nx = -1; for(int k = 1; k <= rc->n; k++){ const int j = (cur + k) % rc->n; if(!(rc->used & (1u << j))){ nx = j; break; } } cur = nx; continue; }
      pkPage("RECOVERY CODES", "Working", "Crossing it off", "in the signer chip.", nullptr);
      int mr; { g0_window_batch_begin(); mr = favilla::rk_rc_mark_used(rc, cur); g0_window_batch_end(); }
      LOG_BOOT("[RC] code %d marked used: %s\n", cur, mr == 0 ? "ok" : favilla::rk_err_name(mr));
      if(mr){ pkPageMsg("RECOVERY CODES", "Not crossed off.", favilla::rk_err_name(mr)); pwWaitBack(lp); return; }
      cur = -1; for(int k = 0; k < rc->n; k++) if(!(rc->used & (1u << k))){ cur = k; break; }
    }
  }
}
// ── 11az (13 Nov 2026, Josh's approved mock "KEY password screens", 9 to 11) ──
// The account screen: ENTER types, UP is the linked one-time code (a hold shows
// the password on the KEY), DOWN opens MORE: change password, one-time code,
// note, edit name or user, recovery codes, delete. An old copy kept by CHANGE
// PASSWORD ("site (old)") gets its own MORE: the new one works, or put it back.
static const char PW_OLD_TAG[] = " (old)";
static bool pwIsOld(const char* site){ size_t n = strlen(site), t = sizeof PW_OLD_TAG - 1; return n > t && !strcmp(site + n - t, PW_OLD_TAG); }
static void pwOldBase(const char* site, char* out, size_t cap){ size_t n = strlen(site); if(pwIsOld(site)) n -= sizeof PW_OLD_TAG - 1; snprintf(out, cap, "%.*s", (int)n, site); }
static void totpShow(const favilla::RkTotp& t, uint32_t& lp);   // below (the CODES page)
static bool pwChange(int i, const favilla::RkLabel& L, uint32_t& lp);   // below (after the generator)
static bool pwPickUser(char* user, size_t cap, uint32_t& lp);           // below
#ifdef FAVILLA_BLE_KBD
static bool pwFillOptions(int i, const favilla::RkLabel& L, uint32_t& lp);   // 11bi: below (after CHANGE PASSWORD)
static bool pwFillNew(const char* site, const char* user0, uint32_t& lp);
static char g_fillSite[chan::FIELD_MAX + 1] = {0}, g_fillUser[chan::FIELD_MAX + 1] = {0};   // the FILL ask's site and username (for NEW LOGIN)
#endif
static bool pwTypeOrScan(const char* title, const char* what, char* out, size_t cap, uint32_t& lp, char* userOut = nullptr);   // below (TYPE or SCAN QR; userOut: a login QR's username)
// The code linked to this entry, shown (UP, or MORE > ONE-TIME CODE).
static void pwShowCode(const favilla::RkLabel& L, uint32_t& lp){
  const int ts = favilla::rk_pw_totp_slot(L.slot);
  if(ts < 0){ pkPageMsg("ONE-TIME CODE", "No code is linked to this login.", "Add it in CODES (ADD A CODE), then pick this account."); pwWaitBack(lp); return; }
  if(!g0_v17_present()){ pkPageMsg("ONE-TIME CODE", "The signer chip needs the v17 firmware.", "It computes the codes so the secret never leaves it."); pwWaitBack(lp); return; }
  favilla::RkTotp* T = (favilla::RkTotp*)heap_caps_malloc(sizeof(favilla::RkTotp) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!T){ pkPageMsg("ONE-TIME CODE", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  const int n = favilla::rk_totp_rows(T, favilla::RK_MAX); int k = -1;
  for(int j = 0; j < n; j++) if(T[j].slot == ts){ k = j; break; }
  if(k >= 0){ favilla::RkTotp t = T[k]; mbedtls_platform_zeroize(T, sizeof(favilla::RkTotp) * favilla::RK_MAX); free(T); totpShow(t, lp); mbedtls_platform_zeroize(&t, sizeof t); return; }
  mbedtls_platform_zeroize(T, sizeof(favilla::RkTotp) * favilla::RK_MAX); free(T);
  pkPageMsg("ONE-TIME CODE", "The code cannot be read.", "Open it from CODES."); pwWaitBack(lp);
}
// Reveal (approved 13 Nov 2026): the password on the KEY's screen only. One
// OPEN; groups of four in JetBrains Mono, digits in brass, a space as a grey dot.
// Hidden after 30 s or by any button. Logged without the value.
static void pwReveal(int i, const favilla::RkLabel& L, uint32_t& lp){
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e){ pkPageMsg("PASSWORD", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct WipeE { favilla::RkPass* e; ~WipeE(){ favilla::rk_pw_wipe(e); free(e); } } we{e};
  pkPage("PASSWORD", "Opening", "Reading it from", "the record.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;
  LOG_BOOT("[PW] slot %d shown on the KEY: %s\n", L.slot, r ? favilla::rk_err_name(r) : "shown");
  if(r){ pkPageMsg("PASSWORD", "Not shown.", pwOpenErr(r)); pwWaitBack(lp); return; }
  const int n = (int)strlen(e->pass);
  const bool big = n <= 48;                     // Bold 24: 12 to a line, four lines; else Regular 12: 24 to a line
  const int per = big ? 12 : 24, cw = big ? 14 : 7, gap = big ? 10 : 5, lh = big ? 30 : 16;
  const int lines = (n + per - 1) / per;
  const int lineW = per * cw + (per / 4 - 1) * gap;
  const int y0 = big ? 56 + (4 - (lines < 4 ? lines : 4)) * lh / 2 : 60;
  auto draw = [&](int left){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("PASSWORD", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_BRASS);
    { char s[96]; snprintf(s, sizeof s, "%s%s%s", L.site, L.user[0] ? ", " : "", L.user); pkFitText(s, sizeof s, 216, false); spr.drawString(s, 120 - spr.textWidth(s) / 2, 34); }
    fEndHard(); spr.loadFont(big ? FONT_JetBrainsMono_Bold_24 : FONT_JetBrainsMono_Regular_12);
    for(int k = 0; k < n; k++){
      const int ln = k / per, col = k % per;
      const int x = 120 - lineW / 2 + col * cw + (col / 4) * gap, y = y0 + ln * lh;
      const char c = e->pass[k];
      if(c == ' '){ spr.fillRect(x + cw / 2 - 1, y + (big ? 12 : 6), 3, 3, C_EB_GREY); continue; }
      char s[2] = {c, 0}; spr.setTextColor(c >= '0' && c <= '9' ? C_EB_BRASS : C_EB_INK); spr.drawString(s, x, y);
    }
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { char s[48]; snprintf(s, sizeof s, n == 1 ? "1 character, digits in brass" : "%d characters, digits in brass", n);
      const int yb = y0 + lines * lh + 8; spr.drawString(s, 120 - spr.textWidth(s) / 2, yb < 178 ? yb : 178); }
    fEndHard();
    { char t[24]; snprintf(t, sizeof t, "HIDES IN %d S", left); uiTrackLabel(t, 120, 196, C_EB_BRASS); }
    spr.fillRect(32, 210, 176, 2, C_EB_LINE); spr.fillRect(32, 210, 176 * left / 30, 2, C_EB_BRASS);
    uiTrackLabel("ANY BUTTON HIDES IT", 120, 216, C_EB_GREY);
    dispPush();
  };
  while(btn3.stable == LOW){ btn3.poll(); delay(5); }   // the hold that opened it is not the press that hides it
  clearButtonPending();
  const uint32_t t0 = millis(); int shown = -1;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp)) break;
    if(btn1.isPressed() || btn2.isPressed() || btn3.isPressed() || btn4.isPressed()) break;
    const int left = 30 - (int)((millis() - t0) / 1000);
    if(left <= 0) break;
    if(left != shown){ shown = left; lastActivity = millis(); draw(left); }
    delay(20);
  }
  spr.fillSprite(C_BG); dispPush();   // off the panel at once
  lp = millis();
}
// One list row screen for MORE and EDIT: five rows of 28 px, the PASSWORDS list's
// style. names[k] in caps; greyRow (or -1) is drawn grey when not selected (DELETE).
static int pwRowsPick(const char* title, const char* const* names, int n, int greyRow, int sel, uint32_t& lp){
  const int VIS = 5, CH = 28, PITCH = 31, Y0 = 36;
  for(;;){
    if(pkLeaveNow()) return -1;
    int off = 0; if(n > VIS){ off = sel - 2; if(off < 0) off = 0; if(off > n - VIS) off = n - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    { char t[40]; uiUpper(title, t, sizeof t); fSet(F_BRAND_B12); pkFitText(t, sizeof t, 216, true); fEnd(); uiTrackLabel(t, 120, 14, C_EB_BRASS, uiTrackWidth(t, 3) > 228 ? 1 : 3); }
    for(int r = 0; r < VIS && off + r < n; r++){ const int row = off + r;
      uiListCard(12, Y0 + r * PITCH, 216, CH, row == sel, C_EB_BRASS, names[row], nullptr, 24, row == greyRow && row != sel ? C_EB_GREY : 0); }
    if(n > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 6; int thumb = TH * VIS / n; int ty = TY + (TH - thumb) * off / (n - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    uiTrackLabel("ENTER TO CHOOSE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return -1;
      if(btn1.isPressed()){ sel = (sel + 1) % n; act = 1; } else if(btn3.isPressed()){ sel = (sel + n - 1) % n; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 2) return sel;
  }
}
// The note (one OPEN, never typed).
static void pwShowNote(int i, const favilla::RkLabel& L, uint32_t& lp){
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e) return;
  struct WipeE { favilla::RkPass* e; ~WipeE(){ favilla::rk_pw_wipe(e); free(e); } } we{e};
  pkPage("NOTE", "Opening", "Reading the note from", "the record.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && e->slot != L.slot) r = favilla::RK_E_FORMAT;
  fEnd(); spr.fillSprite(C_BG);
  uiTrackLabel("NOTE", 120, 14, C_EB_BRASS);
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13);
  { char s[72]; snprintf(s, sizeof s, "%s", L.site); pkFitText(s, sizeof s, 210, false); spr.setTextColor(C_EB_GREY); spr.drawString(s, 120 - spr.textWidth(s) / 2, 36); }
  spr.setTextColor(C_EB_INK);
  uiWrapCentre(r ? pwOpenErr(r) : e->note[0] ? e->note : "No note.", 70, 210, 18, 6);
  fEndHard();
  uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
  dispPush();
  pwWaitBack(lp);
}
// DELETE: a 2 s hold, as before.
static bool pwDeleteOne(const favilla::RkLabel& L, uint32_t& lp){
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("DELETE", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
    if(spr.textWidth(L.site) <= 216) spr.drawString(L.site, 120 - spr.textWidth(L.site) / 2, 62);
    else { fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_INK); uiWrapCentre(L.site, 66, 210, 18, 2); }
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13);
    { char u[72]; snprintf(u, sizeof u, "%s", L.user[0] ? L.user : "(no username)"); pkFitText(u, sizeof u, 210, false); spr.setTextColor(C_EB_INK); spr.drawString(u, 120 - spr.textWidth(u) / 2, 110); }
    spr.setTextColor(C_EB_GREY);
    { const char* t = "The site keeps this password:"; spr.drawString(t, 120 - spr.textWidth(t) / 2, 142); }
    { const char* t = "change it there if you stop using it."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 160); }
    fEndHard();
    uiHoldFooter("HOLD ENTER TO DELETE", "BACK keeps it", hold, C_EB_BRASS);
    dispPush();
  };
  draw(0); clearButtonPending();
  const uint32_t shownAt = millis(); float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    const float h = holdSince(btn2, shownAt, 2000);
    if(h >= 1.0f){
      int de; { g0_window_batch_begin(); de = favilla::rk_delete(L.slot); g0_window_batch_end(); }
      LOG_BOOT("[PW] delete slot %d: %s\n", L.slot, favilla::rk_err_name(de));
      while(btn2.stable == LOW){ btn2.poll(); delay(5); }
      pkPageMsg("PASSWORDS", de == 0 ? "Deleted from this KEY." : "Could not delete it.", de == 0 ? nullptr : favilla::rk_err_name(de));
      pwWaitBack(lp); return de == 0;
    } else if((h > 0) != (last > 0) || (h - last) > 0.04f){ last = h; draw(h); }
    btn2.isPressed(); btn1.isPressed(); btn3.isPressed();
    delay(10);
  }
}
// EDIT NAME OR USER: the site name on the passphrase reel, the username from the
// picker. One OPEN and one save each; the record keeps its id (and its code link).
static bool pwEditField(int i, const favilla::RkLabel& L, bool name, uint32_t& lp){
  char nv[PP_MAX + 1] = {0}; bool got;
  if(name){ int nl = 0; got = ppPicker("NAME", C_EB_BRASS, nv, &nl) && nl > 0; }
  else { snprintf(nv, sizeof nv, "%s", L.user); got = pwPickUser(nv, sizeof nv, lp) && strcmp(nv, L.user); }
  lp = millis();
  if(!got){ mbedtls_platform_zeroize(nv, sizeof nv); return false; }
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e){ mbedtls_platform_zeroize(nv, sizeof nv); return false; }
  struct WipeE { favilla::RkPass* e; ~WipeE(){ favilla::rk_pw_wipe(e); free(e); } } we{e};
  pkPage(name ? "NAME" : "USERNAME", "Saving", "Sealing it on the signer", name ? "with the new name." : "with the new username.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;
  if(r == 0){
    if(name) snprintf(e->site, sizeof e->site, "%s", nv); else snprintf(e->user, sizeof e->user, "%s", nv);
    e->policy &= ~pwgen::POLICY_PENDING; e->slot = L.slot;
    int slot = -1; r = RK_PIN(favilla::rk_pw_save(e, &slot));
  }
  LOG_BOOT("[PW] %s of slot %d changed: %s\n", name ? "name" : "username", L.slot, favilla::rk_err_name(r));
  mbedtls_platform_zeroize(nv, sizeof nv);
  pkPageMsg(name ? "NAME" : "USERNAME", r == 0 ? "Saved." : "Not saved.", r == 0 ? nullptr : pwOpenErr(r));
  pwWaitBack(lp); return r == 0;
}
// The live entry an old copy belongs to: same name without " (old)", same username.
static int pwLiveOf(const favilla::RkLabel& L){
  char base[favilla::RK_SITE_MAX + 1]; pwOldBase(L.site, base, sizeof base);
  const int n = favilla::rk_pw_count(); int hit = -1;
  g0_window_batch_begin();
  for(int k = 0; k < n && hit < 0; k++){
    char s[favilla::RK_SITE_MAX + 1]; bool pend = false;
    if(!favilla::rk_pw_site(k, s, sizeof s, &pend, nullptr) || strcmp(s, base)) continue;
    favilla::RkLabel M; if(favilla::rk_pw_label(k, &M) == 0 && !strcmp(M.user, L.user)) hit = k;
    mbedtls_platform_zeroize(&M, sizeof M);
  }
  g0_window_batch_end();
  return hit;
}
// An old copy's two answers. works: delete the copy. Else put its password back
// in the live entry (which keeps its id, its code link and its note), then
// delete the copy. Two OPENs for the put-back.
static bool pwOldResolve(int i, const favilla::RkLabel& L, bool works, uint32_t& lp){
  const char* T = works ? "NEW ONE WORKS" : "PUT THIS ONE BACK";
  if(works){
    pkAsk(T, "Delete the old one?", "The new password stays", "on the login.", "KEEP", "DELETE");
    if(!totpYesNo(lp)) return false;
    int de; { g0_window_batch_begin(); de = favilla::rk_delete(L.slot); g0_window_batch_end(); }
    LOG_BOOT("[PW] change confirmed later: old copy in slot %d deleted: %s\n", L.slot, favilla::rk_err_name(de));
    pkPageMsg(T, de == 0 ? "Done. The old one is gone." : "Could not delete it.", de == 0 ? nullptr : favilla::rk_err_name(de));
    pwWaitBack(lp); return de == 0;
  }
  const int live = pwLiveOf(L);
  if(live < 0){ pkPageMsg(T, "The new login is not on this KEY.", "Rename this one with EDIT NAME OR USER instead."); pwWaitBack(lp); return false; }
  pkAsk(T, "Put it back?", "The site kept the old password:", "the login gets it back.", "CANCEL", "PUT BACK");
  if(!totpYesNo(lp)) return false;
  favilla::RkPass* o = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  favilla::RkPass* m = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  struct W2 { favilla::RkPass* a; favilla::RkPass* b; ~W2(){ if(a){ favilla::rk_pw_wipe(a); free(a); } if(b){ favilla::rk_pw_wipe(b); free(b); } } } w2{o, m};
  if(!o || !m){ pkPageMsg(T, "Out of memory.", nullptr); pwWaitBack(lp); return false; }
  pkPage(T, "Saving", "Sealing the old password", "on the login.", nullptr);
  int r; { g0_window_batch_begin(); r = favilla::rk_pw_open(i, o); if(r == 0) r = favilla::rk_pw_open(live, m); g0_window_batch_end(); }
  if(r == 0 && (o->slot != L.slot || strcmp(o->site, L.site))) r = favilla::RK_E_FORMAT;
  if(r == 0){
    memcpy(m->pass, o->pass, sizeof m->pass); m->policy = o->policy & ~pwgen::POLICY_PENDING; m->origin = o->origin;
    int slot = -1; r = RK_PIN(favilla::rk_pw_save(m, &slot));
    if(r == 0){ int de; { g0_window_batch_begin(); de = favilla::rk_delete(L.slot); g0_window_batch_end(); } LOG_BOOT("[PW] change undone: old password back in slot %d, copy deleted: %s\n", m->slot, favilla::rk_err_name(de)); }
  }
  if(r) LOG_BOOT("[PW] change undo: %s\n", favilla::rk_err_name(r));
  pkPageMsg(T, r == 0 ? "Put back." : "Not put back.", r == 0 ? "The login has the old password again." : pwOpenErr(r));
  pwWaitBack(lp); return r == 0;
}
// MORE. Returns true when the entry changed or went (the list reads it again).
static bool pwMore(int i, const favilla::RkLabel& L, uint32_t& lp){
  const bool old = pwIsOld(L.site);
  // 11es (Josh, 25 Nov 2026): SEND PASSWORD first: the password alone into the
  // box that is selected, for a page the KEY read as something else (a change
  // form whose current-password box wanted it, a sign-in it took for two pages).
  static const char* const NORMAL[] = { "SEND PASSWORD", "CHANGE PASSWORD", "ONE-TIME CODE", "NOTE", "EDIT NAME OR USER", "RECOVERY CODES", "DELETE" };
  static const char* const OLDROWS[] = { "NEW ONE WORKS", "PUT THIS ONE BACK", "NOTE", "DELETE" };
  int sel = 0;
  for(;;){
    const int k = old ? pwRowsPick(L.site, OLDROWS, 4, 3, sel, lp) : pwRowsPick(L.site, NORMAL, 7, 6, sel, lp);
    if(k < 0) return false;
    sel = k;
    if(old){
      if(k == 0 || k == 1){ if(pwOldResolve(i, L, k == 0, lp)) return true; continue; }
      if(k == 2){ pwShowNote(i, L, lp); continue; }
      if(pwDeleteOne(L, lp)) return true;
      continue;
    }
    switch(k){
      case 0: { const uint8_t f0 = g_pwFields; g_pwFields = 2; const uint32_t tc = g_pwTypedCount;
                pwType(i, L, false, lp); g_pwFields = f0;
                if(g_pwTypedCount != tc) return false;   // typed: back to the entry
                break; }
      case 1: if(pwChange(i, L, lp)) return true; break;
      case 2: pwShowCode(L, lp); break;
      case 3: pwShowNote(i, L, lp); break;
      case 4: { static const char* const ED[] = { "NAME", "USERNAME" }; const int f = pwRowsPick("EDIT NAME OR USER", ED, 2, -1, 0, lp);
                if(f >= 0 && pwEditField(i, L, f == 0, lp)) return true;
                break; }
      case 5: pwRecovery(i, L, lp); break;
      default: if(pwDeleteOne(L, lp)) return true; break;
    }
    lp = millis();
  }
}
// 11ec (24 Nov 2026, Josh: "users will want a clear and simple way to enter and
// visually see which account they are using"): every sign-in screen is the same.
// The site is the hero (Bold 28; Bold 20 if it does not fit; two lines at Bold 20
// broken after a dot, so the real domain stays whole on the second line), the
// username in brass under it, the block centred between the header and the
// corners. Returns the y just under the username. The site is also the
// phishing check: it must be readable at a glance.
// 11er: no header. tag: a grey word above the site when the same screen means
// something else (OLD COPY, SEND AGAIN, USERNAME, PASSWORD), else null. The
// block sits centred between the top and bottom corner words.
static int pwSignInHero(const char* site, const char* user, const char* tag, int lift = 0){   // lift: px higher (11et: room for two lines under it)
  const char* s = site && site[0] ? site : "(no site)";
  char l1[104] = {0}, l2[104] = {0}; const uint8_t* face = FONT_Archivo_Bold_28_full; int pitch = 32; bool two = false;
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full);
  if(spr.textWidth(s) > 216){
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_20_full); face = FONT_Archivo_Bold_20_full; pitch = 24;
    if(spr.textWidth(s) > 216){
      // break after the first label(s), so the rest (the domain that matters) fits whole
      const char* cut = nullptr;
      for(const char* q = strchr(s, '.'); q && q[1]; q = strchr(q + 1, '.')){ cut = q + 1; if(spr.textWidth(cut) <= 216) break; }
      if(cut){ size_t n = (size_t)(cut - s); if(n > sizeof l1 - 1) n = sizeof l1 - 1; memcpy(l1, s, n); snprintf(l2, sizeof l2, "%s", cut); two = true; }
    }
  }
  if(!two) snprintf(l1, sizeof l1, "%s", s);
  pkFitText(l1, sizeof l1, 216, false); if(two) pkFitText(l2, sizeof l2, 216, false);
  const int block = (two ? 2 : 1) * pitch + 12 + 16;
  const int y0 = 122 - block / 2 - lift;
  if(tag){ fEndHard(); uiTrackLabel(tag, 120, y0 - 30, C_EB_GREY); }
  fEndHard(); spr.loadFont(face); spr.setTextColor(C_EB_INK);
  spr.drawString(l1, 120 - spr.textWidth(l1) / 2, y0);
  if(two) spr.drawString(l2, 120 - spr.textWidth(l2) / 2, y0 + pitch);
  const int uy = y0 + (two ? 2 : 1) * pitch + 12;
  fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_BRASS);
  { char u[72]; snprintf(u, sizeof u, "%s", user && user[0] ? user : "(no username)"); pkFitText(u, sizeof u, 210, false);
    spr.drawString(u, 120 - spr.textWidth(u) / 2, uy); }
  fEnd(); fEndHard(); spr.loadFont(FONT_Archivo_Regular_13);
  return uy + 18;
}
// One entry: site, username, ENTER types. Returns 0 back, 1 changed or deleted
// (the list reads it again), 2 next (only while the phone's ask runs).
static int pwEntry(int i, int pos, int n, uint32_t& lp){
  favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(i, &L); g0_window_batch_end(); }
  if(r){ pkPageMsg("PASSWORDS", "This entry cannot be read.", pwOpenErr(r)); pwWaitBack(lp); return 0; }
  const bool code = favilla::rk_pw_totp_slot(L.slot) >= 0, old = pwIsOld(L.site);   // 11v: a linked code
  (void)pos;   // 11er: no "N OF M" line
  char shown[favilla::RK_SITE_MAX + 1]; pwOldBase(L.site, shown, sizeof shown);

  auto draw = [&](float hold, float upHold){
    // 11ec: header, count, the site and account, the corner answers; nothing else.
    // The header names what ENTER types (SIGN IN, or USERNAME / PASSWORD on a
    // two-page sign-in). 11er: UP is SHOW (a tap the code, a 1 s hold the
    // password on screen), DOWN is MORE; when the phone asks, UP is NEXT and DOWN MORE.
    // 11er (Josh, 25 Nov 2026): no header and no count; a grey tag only when the
    // screen means something else; the four buttons' words in their corners.
    fEnd(); spr.fillSprite(C_BG);
    const char* tag = old ? "OLD COPY" : !g_pwToApp && g_pwFields == 1 ? "USERNAME" : !g_pwToApp && g_pwFields == 2 ? "PASSWORD" : nullptr;
    const int below = pwSignInHero(shown, L.user, tag);
    if(upHold > 0){ const int w = (int)(120 * (upHold > 1 ? 1 : upHold)); spr.fillRect(60, below + 6, 120, 2, C_EB_LINE); spr.fillRect(60, below + 6, w, 2, C_EB_BRASS); }
    fEndHard();
    if(hold > 0){ const int w = (int)(76 * (hold > 1 ? 1 : hold)); spr.fillRect(152, 208, 76, 2, C_EB_LINE); spr.fillRect(152, 208, w, 2, C_EB_BRASS); }
    uiCornerAnswers("BACK", hold > 0 ? "SUBMIT" : "SEND");
#ifdef FAVILLA_BLE_KBD
    if(g_pwToApp) uiCornerTop(n > 1 ? "NEXT" : nullptr, "MORE");
#else
    if(g_pwToApp) uiCornerTop(n > 1 ? "NEXT" : nullptr, nullptr);
#endif
    else uiCornerTop("SHOW", "MORE");
    dispPush();
  };
  draw(0, 0); clearButtonPending();
  uint32_t shownAt = millis(); bool down = false, upDown = false; float last = 0, upLast = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return 0;
    if(g_pwToApp){   // 9c: no code, reveal or MORE during a phone's ask
#ifdef FAVILLA_BLE_KBD
      if(btn1.isPressed()){   // 11bi (issue #38): NEW PASSWORD on this login, or NEW LOGIN for the site; 11er: MORE, top-right
        const uint32_t tc = g_pwTypedCount; const bool sent = pwFillOptions(i, L, lp); lp = millis();
        if(sent || g_pwTypedCount != tc) return 0;
        draw(0, 0); clearButtonPending(); shownAt = millis(); delay(10); continue;
      }
#else
      btn1.isPressed();
#endif
      if(btn3.isPressed() && n > 1) return 2;   // 11er: NEXT, top-left
      if(btn2.isPressed()){ const uint32_t tc = g_pwTypedCount; pwType(i, L, false, lp); lp = millis(); if(g_pwTypedCount != tc) return 0; draw(0, 0); clearButtonPending(); shownAt = millis(); }
      delay(10); continue;
    }
    if(btn1.isPressed()){ if(pwMore(i, L, lp)) return 1; lp = millis(); draw(0, 0); clearButtonPending(); shownAt = millis(); continue; }
    // UP: a tap is the code, a 1 s hold shows the password (Reveal)
    if(btn3.stable == LOW && btn3.pressStart >= shownAt){
      upDown = true; const float h = btn3.holdProgress(1000);
      if(h >= 1.0f){ pwReveal(i, L, lp); lp = millis(); draw(0, 0); clearButtonPending(); shownAt = millis(); upDown = false; upLast = 0; continue; }
      if(h - upLast > 0.04f){ upLast = h; draw(0, h); }
    } else if(upDown){
      upDown = false; upLast = 0;
      if(code){ pwShowCode(L, lp); lp = millis(); clearButtonPending(); shownAt = millis(); }
      draw(0, 0);
    }
    btn3.isPressed();
    if(btn2.stable == LOW && btn2.pressStart >= shownAt){
      down = true;
      float h = btn2.holdProgress(500);
      if(h >= 1.0f){ pwType(i, L, true, lp); while(btn2.stable == LOW){ btn2.poll(); delay(5); } lp = millis(); draw(0, 0); clearButtonPending(); shownAt = millis(); down = false; last = 0; continue; }
      if((h - last) > 0.04f){ last = h; draw(h, 0); }
    } else if(down){   // released before the hold finished: a tap
      down = false; last = 0;
      pwType(i, L, false, lp); lp = millis(); draw(0, 0); clearButtonPending(); shownAt = millis();
    }
    btn2.isPressed();
    delay(10);
  }
}
// ── the generator (3 Nov 2026, Vault spec 7f and 6) ───────────────────────────
// Seed = SHA-256("FAVILLA-PWGEN-V1" || SE TRNG 32 || ESP32 RNG 32): the seed
// path's pattern; fails closed if the SE does not answer. The password is never
// shown: it is typed into the site's new-password field and saved on the first
// typing (before the keys go out, so an account can never get a password the
// KEY did not keep). It is saved as "New entry N" with the pending bit; the
// owner picks a username from those already in the vault, and the PWA asks for
// the site later.
static bool pwGenSeed(uint8_t seed[32]);
// P4-10 (3 Nov 2026, Vault spec): the site index at a PASSKEY unlock. One passkey
// window (about 0.8 s): K_IDX unwrapped under K_PK (or made, the first time,
// and wrapped). v19: no NOSTR copy; an older 'N' wrap and K_IXN are removed.
// Then the ESP32 opens the index itself and every name it holds is known at once.
static void pkIdxUnlock(){
  if(!g_pkPinHeld || !favilla::rk_ready() || !g0_pk2b_present()) return;
  uint32_t t0 = millis();
  uint8_t wp[favilla::RK_IDX_WRAP], wn[favilla::RK_IDX_WRAP], k[32], fresh[32];
  // Everything that takes pk_records' lock happens outside the bus lock (re-review 3).
  const bool haveP = favilla::rk_idx_wrap_get('P', wp);
  const bool haveN = favilla::rk_idx_wrap_get('N', wn); mbedtls_platform_zeroize(wn, sizeof wn);
  const uint32_t epoch = favilla::rk_lock_epoch();
  const bool canFresh = pwGenSeed(fresh);   // ready before the window, in case the wrap is missing or unreadable
  bool made = false, ixDeleted = false, ok;
  I2C_LOCK();
  ok = favilla::se_pk_window_open(g_pkPin, true);
  if(ok){
    // review (4): a key is adopted only if its check value matches. Bytes planted in
    // "ixP" decrypt to something under K_PK, but never to a key with the right check
    // value, so they are replaced.
    bool unwrapped = haveP && favilla::se_idx_unwrap(favilla::SE_OBJ_K_PK, wp, k) && favilla::rk_idx_kcv_ok(k, wp + 48);
    if(!unwrapped){
      if(canFresh){ memcpy(k, fresh, 32); ok = favilla::se_idx_wrap(favilla::SE_OBJ_K_PK, k, wp); if(ok) favilla::rk_idx_kcv(k, wp + 48); made = ok; }
      else ok = false;
    }
    if(favilla::se_idx_kixn_present()) ixDeleted = favilla::se_idx_kixn_delete_in_session();   // v19: from an older build
  }
  favilla::se_pk_window_close(g_pkPin);
  I2C_UNLOCK();
  if(made && !favilla::rk_idx_wrap_put('P', wp)) ok = false;
  if(made && haveP) LOG_BOOT("[IDX] the PASSKEY wrap did not check out (or was from an earlier build) - a new site index key was made\n");
  if(ixDeleted || haveN) favilla::rk_idx_wrap_del('N');
  if(ok) ok = favilla::rk_idx_open(k, favilla::se_generation(), epoch) >= 0;
  mbedtls_platform_zeroize(k, 32); mbedtls_platform_zeroize(fresh, 32); mbedtls_platform_zeroize(wp, sizeof wp); mbedtls_platform_zeroize(wn, sizeof wn);
  LOG_BOOT("[IDX] PASSKEY unlock: site index key %s, %lu ms\n", !ok ? "NOT available (names come from labels)" : made ? "made" : "unwrapped",
           (unsigned long)(millis() - t0));
}
static bool pwGenSeed(uint8_t seed[32]){
  uint8_t se[32], esp[32]; bool ok;
  { I2C_LOCK(); ok = favilla::se_random(se, 32); I2C_UNLOCK(); }
  if(!ok){ mbedtls_platform_zeroize(se, 32); return false; }
  esp_fill_random(esp, 32);
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const uint8_t*)"FAVILLA-PWGEN-V1", 16); mbedtls_sha256_update(&c, se, 32); mbedtls_sha256_update(&c, esp, 32);
  mbedtls_sha256_finish(&c, seed); mbedtls_sha256_free(&c);
  mbedtls_platform_zeroize(se, 32); mbedtls_platform_zeroize(esp, 32);
  return true;
}
static int pwNewNumber(){ Preferences p; int n = 1; if(p.begin("pkdoor", false, NVSPART_SEC)){ n = p.getInt("pwnew", 0) + 1; p.putInt("pwnew", n); p.end(); } return n; }
// Usernames already in the vault (from the labels of the 12 most recent
// entries), for the picker. Returns how many, deduplicated, at most max.
// 4 Nov 2026 (bench, Josh): a cold read is ~0.47 s per entry on the G0, ~7 s for
// twelve. Usernames stay G0-only (ruled), so the wait stays; prog(done, total) is
// called before each read the G0 has to do, so the card shows it moving.
static int pwKnownUsers(char (*out)[favilla::RK_PW_FIELD_MAX + 1], int max, const std::function<void(int, int)>& prog = nullptr){
  int ord[12]; int n = favilla::rk_pw_order(ord, 12), k = 0;
  favilla::RkLabel L;
  // 3 Nov 2026 (bench, Josh: "takes ages to load the usernames"): one passkey
  // window for all twelve reads. Each read opened and closed its own window
  // (SE session + the door latch minted again, ~1 s a time); the batches nest,
  // so the outer one keeps a single window open across the loop.
  g0_window_batch_begin();
  for(int i = 0; i < n && k < max; i++){
    if(prog && !favilla::rk_pw_label_cached(ord[i])) prog(i, n);
    int r = favilla::rk_pw_label(ord[i], &L);
    if(r || !L.user[0]) continue;
    bool dup = false; for(int j = 0; j < k; j++) if(!strcmp(out[j], L.user)) dup = true;
    if(!dup) strcpy(out[k++], L.user);
  }
  g0_window_batch_end();
  mbedtls_platform_zeroize(&L, sizeof L);
  return k;
}
static bool pwScanText(const char* what, char* out, size_t cap, char* userOut = nullptr, bool review = true);   // below (8w: also an own password)
// ── 11az (13 Nov 2026, Josh's approved mock, screens 1 to 6) ──────────────────
// Presets (ruled 13 Nov): 24 characters by default (154 bits with the each-class
// rule), 32 (206), 22 without symbols (131), 16 for sites with a 16 limit (103),
// or the owner's own, typed on the reel or scanned.
struct PwPreset { int len; uint32_t cls; const char* name; const char* desc; };
static constexpr uint32_t PW_ALL = pwgen::CL_LOWER | pwgen::CL_UPPER | pwgen::CL_DIGIT | pwgen::CL_SYMBOL;
static constexpr uint32_t PW_NOSYM = pwgen::CL_LOWER | pwgen::CL_UPPER | pwgen::CL_DIGIT;
static const PwPreset PW_PRESETS[] = {
  {24, PW_ALL,   "24 CHARACTERS",  "154 bits, letters, digits, symbols"},
  {32, PW_ALL,   "32 CHARACTERS",  "206 bits, letters, digits, symbols"},
  {22, PW_NOSYM, "22, NO SYMBOLS", "131 bits, for sites that refuse them"},
  {16, PW_ALL,   "16 CHARACTERS",  "103 bits, for sites with a 16 limit"},
  {0, 0,         "TYPE IT",        "Your own, with the buttons"},
  {0, 0,         "SCAN QR",        "Your own, from a QR"},
};
static const int PW_NPRESET = 6, PW_TYPE_IT = 4;
static uint8_t g_pwForm = 0;   // NEW_LOGIN's form byte (chan::FORM_*), 0 = the page was not looked at
static int pwPickPreset(int cur, char* own, int* ownLen, uint32_t& lp){
  int sel = cur;
  for(;;){
    const int VIS = 3, CH = 42, PITCH = 46, Y0 = 34;
    int off = sel - 1; if(off < 0) off = 0; if(off > PW_NPRESET - VIS) off = PW_NPRESET - VIS;
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("PASSWORD", 120, 14, C_EB_BRASS);
    for(int r = 0; r < VIS; r++) uiListCard(12, Y0 + r * PITCH, 216, CH, off + r == sel, C_EB_BRASS, PW_PRESETS[off + r].name, PW_PRESETS[off + r].desc, 24);
    { const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 8; int thumb = TH * VIS / PW_NPRESET; int ty = TY + (TH - thumb) * off / (PW_NPRESET - VIS); spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { char t[24]; snprintf(t, sizeof t, "%d of %d", sel + 1, PW_NPRESET); spr.drawString(t, 120 - spr.textWidth(t) / 2, 174); }
    fEndHard();
    uiTrackLabel("ENTER TO CHOOSE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return -1;
      if(btn1.isPressed()){ sel = (sel + 1) % PW_NPRESET; act = 1; } else if(btn3.isPressed()){ sel = (sel + PW_NPRESET - 1) % PW_NPRESET; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
    if(PW_PRESETS[sel].len) return sel;
    mbedtls_platform_zeroize(own, PP_MAX + 1); *ownLen = 0;   // 8w: the owner's own, on the reel or from a QR
    const bool got = sel == PW_TYPE_IT ? (ppPicker("PASSWORD", C_EB_BRASS, own, ownLen) && *ownLen > 0) : pwScanText("password", own, PP_MAX + 1);
    lp = millis();
    if(got){ *ownLen = (int)strnlen(own, PP_MAX); if(*ownLen > 0) return sel; }
    mbedtls_platform_zeroize(own, PP_MAX + 1); *ownLen = 0;
  }
}
static void pwPresetDesc(int sel, int ownLen, char* out, size_t cap){
  if(PW_PRESETS[sel].len) snprintf(out, cap, "%d characters, made", PW_PRESETS[sel].len);
  else snprintf(out, cap, ownLen == 1 ? "1 character, yours" : "%d characters, yours", ownLen);
}
// The password for a preset into e->pass, with its policy and origin. false: the SE's RNG did not answer.
static bool pwMakePass(int sel, const char* own, int ownLen, favilla::RkPass* e){
  if(!PW_PRESETS[sel].len){
    if(ownLen <= 0 || ownLen > (int)favilla::RK_PW_FIELD_MAX) return false;
    memcpy(e->pass, own, ownLen); e->pass[ownLen] = 0; e->policy = pwgen::policy(ownLen, 0); e->origin = favilla::RK_ORIGIN_OWN; return true;
  }
  uint8_t seed[32]; bool ok = pwGenSeed(seed);
  if(ok) ok = pwgen::generate(seed, PW_PRESETS[sel].len, PW_PRESETS[sel].cls, e->pass);
  mbedtls_platform_zeroize(seed, 32);
  if(!ok){ LOG_BOOT("[PW] generate: SE TRNG failed - refused\n"); return false; }
  e->policy = pwgen::policy(PW_PRESETS[sel].len, PW_PRESETS[sel].cls); e->origin = favilla::RK_ORIGIN_KEY;
  return true;
}
// Where to type, chosen at the press (the phone woken if it is the target). -1: nowhere (said on screen).
static int pwDest(const char* title, uint32_t& lp){
  int dest = typer::choose();
  if(dest == typer::NONE){ pkPageMsg(title, typer::noneHead(), typer::noneHint()); pwWaitBack(lp); return -1; }
#ifdef FAVILLA_BLE_KBD
  if(dest == typer::BT && !blek::ready()){
    if(!pkBtConnect(lp)){ pkPageMsg(title, "The phone did not connect.", "Check Bluetooth is on and Favilla KEY is in its list, then try again."); pwWaitBack(lp); return -1; }
    dest = typer::choose();
    if(dest != typer::BT){ pkPageMsg(title, "Nothing was typed.", "The keyboard target changed. Try again."); pwWaitBack(lp); return -1; }
  }
#endif
  return dest;
}
// Types buf (wiped by the caller). Every character is checked first: nothing is typed if one cannot be.
static bool pwTypeBuf(const char* title, int dest, const char* buf, size_t n, uint32_t& lp){
  char bad[24] = {0};
  const int res = typer::typeTo(dest, buf, n, bad, sizeof bad);
  if(res == 0){ g_pwTypedCount++; return true; }
  if(res > 0){
    char l2[96]; snprintf(l2, sizeof l2, "It cannot type: %s  Type it yourself, or change it.", bad);
    for(char* q = l2; *q; q++) if((uint8_t)*q < 0x20 || (uint8_t)*q == 0x7F) *q = '?';
    pkPageMsg(title, "Nothing was typed.", l2);
  } else pkPageMsg(title, "Typing stopped.", typer::stoppedOf(dest));
  pwWaitBack(lp); return false;
}
// 11az: what a sign-up or change form gets, in order: the first box (username or
// current password), the new password, the confirm box. Pieces the Tab reaches go
// in one typing, joined by Tab; between split ones the KEY asks the owner to click
// the next box (DOWN types it, BACK stops). Returns how many pieces were typed.
struct PwPiece { const char* s; const char* box; bool split; };   // split: a click before this one
static int pwTypePieces(const char* title, int dest, const PwPiece* p, int n, char* buf, size_t cap, uint32_t& lp){
  int k = 0;
  while(k < n){
    if(k > 0){   // a split: the owner clicks the next box first
      char l1[48]; snprintf(l1, sizeof l1, "Click the %s box", p[k].box);
      g_pkAskNo = "STOP"; g_pkAskYes = "TYPE";   // 11er: one word in each corner (DOWN types too)
      pkPage(title, "Next box", l1, "on the site.", nullptr);
      g_pkAskNo = g_pkAskYes = nullptr;
      clearButtonPending(); int a = 0;
      while(!a){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) a = 2; else if(btn1.isPressed() || btn2.isPressed()) a = 1;
        btn3.isPressed(); delay(10); }
      lp = millis();
      if(a == 2) return k;
    }
    size_t m = 0; int j = k;
    do {
      if(j > k){ if(m + 1 >= cap) break; buf[m++] = '\t'; }
      const size_t l = strlen(p[j].s); if(m + l >= cap) break;
      memcpy(buf + m, p[j].s, l); m += l; j++;
    } while(j < n && !p[j].split);
    pkPage(title, "Typing", "Keep the field selected", typer::whereOf(dest), nullptr);
    const bool ok = pwTypeBuf(title, dest, buf, m, lp);
    mbedtls_platform_zeroize(buf, cap);
    if(!ok) return k;
    k = j;
  }
  return k;
}
// The usernames for a picker: the book (newest first), then those of the 12
// newest passwords that the book does not have. Returns how many.
static int pwUserList(char (*users)[favilla::RK_PW_FIELD_MAX + 1], int max){
  int nu = favilla::rk_ub_list(users, max < favilla::RK_UB_MAX ? max : favilla::RK_UB_MAX); if(nu < 0) nu = 0;
  char (*more)[favilla::RK_PW_FIELD_MAX + 1] = (char (*)[favilla::RK_PW_FIELD_MAX + 1])heap_caps_calloc(12, favilla::RK_PW_FIELD_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(more){
    pkPage("USERNAME", "Reading", "The usernames on", "this KEY.", nullptr);
    const int nm = pwKnownUsers(more, 12);
    for(int i = 0; i < nm && nu < max; i++){ bool dup = false; for(int j = 0; j < nu; j++) if(!strcmp(users[j], more[i])) dup = true; if(!dup) strcpy(users[nu++], more[i]); }
    mbedtls_platform_zeroize(more, 12 * (favilla::RK_PW_FIELD_MAX + 1)); free(more);
  }
  return nu;
}
// The username picker: NONE, the usernames on the KEY, ADD A NEW ONE (typed or
// scanned, and kept in the book). true with the choice in user.
static bool pwPickUser(char* user, size_t cap, uint32_t& lp){
  const int MAXU = favilla::RK_UB_MAX + 12;
  char (*users)[favilla::RK_PW_FIELD_MAX + 1] = (char (*)[favilla::RK_PW_FIELD_MAX + 1])heap_caps_calloc(MAXU, favilla::RK_PW_FIELD_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!users){ pkPageMsg("USERNAME", "Out of memory.", nullptr); pwWaitBack(lp); return false; }
  struct FreeU { char* p; size_t n; ~FreeU(){ mbedtls_platform_zeroize(p, n); free(p); } } fu{(char*)users, (size_t)MAXU * (favilla::RK_PW_FIELD_MAX + 1)};
  const int nu = pwUserList(users, MAXU);
  const int rows = nu + 2;
  int sel = 0; for(int k = 0; k < nu; k++) if(!strcmp(users[k], user)) sel = k + 1;
  const int VIS = 5, CH = 28, PITCH = 31, Y0 = 36;
  for(;;){
    if(pkLeaveNow()) return false;
    int off = 0; if(rows > VIS){ off = sel - 2; if(off < 0) off = 0; if(off > rows - VIS) off = rows - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("USERNAME", 120, 14, C_EB_BRASS);
    for(int r = 0; r < VIS && off + r < rows; r++){
      const int row = off + r; char nm[64];
      if(row == 0) snprintf(nm, sizeof nm, "%s", "NONE"); else if(row == rows - 1) snprintf(nm, sizeof nm, "%s", "ADD A NEW ONE"); else snprintf(nm, sizeof nm, "%s", users[row - 1]);
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
      uiListCard(12, Y0 + r * PITCH, 216, CH, row == sel, C_EB_BRASS, nm, nullptr, 24, (row == 0 || row == rows - 1) && row != sel ? C_EB_BRASS : 0);
      mbedtls_platform_zeroize(nm, sizeof nm);
    }
    if(rows > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 6; int thumb = TH * VIS / rows; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (rows - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    uiTrackLabel("ENTER TO CHOOSE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
      if(btn1.isPressed()){ sel = (sel + 1) % rows; act = 1; } else if(btn3.isPressed()){ sel = (sel + rows - 1) % rows; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
    if(sel == 0){ user[0] = 0; return true; }
    if(sel < rows - 1){ snprintf(user, cap, "%s", users[sel - 1]); return true; }
    char nu2[PP_MAX + 1] = {0};
    if(pwTypeOrScan("NEW USERNAME", "username", nu2, sizeof nu2, lp) && nu2[0]){
      const int ar = favilla::rk_ub_add(nu2); LOG_BOOT("[PW] usernames book: add from the picker: %s\n", favilla::rk_err_name(ar));
      snprintf(user, cap, "%s", nu2); mbedtls_platform_zeroize(nu2, sizeof nu2); return true;
    }
    mbedtls_platform_zeroize(nu2, sizeof nu2); lp = millis();
  }
}
// A saved login with exactly this site name and username, or -1.
static int pwFindExact(const char* site, const char* user){
  const int n = favilla::rk_pw_count(); int hit = -1;
  g0_window_batch_begin();
  for(int k = 0; k < n && hit < 0; k++){
    char s[favilla::RK_SITE_MAX + 1]; bool pend = false;
    if(!favilla::rk_pw_site(k, s, sizeof s, &pend, nullptr) || strcasecmp(s, site)) continue;
    favilla::RkLabel M; if(favilla::rk_pw_label(k, &M) == 0 && !strcmp(M.user, user)) hit = k;
    mbedtls_platform_zeroize(&M, sizeof M);
  }
  g0_window_batch_end();
  return hit;
}
// The confirm line after a typing, by what the extension saw (0: nothing seen).
static const char* pwConfirmLine(bool typedConfirm){
  if(typedConfirm) return "Typed, and the confirm box filled.";
  if((g_pwForm & chan::FORM_KNOWN) && (g_pwForm & chan::FORM_CONFIRM)) return "Confirm box: click it, DOWN types it.";
  if(g_pwForm & chan::FORM_KNOWN) return "Typed.";
  return "Confirm box? DOWN types it again.";
}
// The result screens (Saved, Accepted?): the ember, a word, two lines.
static void pwResultPage(const char* head, const char* word, const char* l1, const char* l2, const char* foot, const char* sub, const char* l3 = nullptr){
  fEnd(); spr.fillSprite(C_BG);
  uiTrackLabel(head, 120, 14, C_EB_BRASS, uiTrackWidth(head, 3) > 228 ? 1 : 3);
  ebMarkSmall(101, 38, 6, 2);
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK); spr.drawString(word, 120 - spr.textWidth(word) / 2, 88);
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  if(l1){ char s[80]; snprintf(s, sizeof s, "%s", l1); pkFitText(s, sizeof s, 228, false); spr.drawString(s, 120 - spr.textWidth(s) / 2, 132); }
  if(l2){ char s[80]; snprintf(s, sizeof s, "%s", l2); pkFitText(s, sizeof s, 228, false); spr.drawString(s, 120 - spr.textWidth(s) / 2, 150); }
  if(l3){ char s[80]; snprintf(s, sizeof s, "%s", l3); pkFitText(s, sizeof s, 228, false); spr.drawString(s, 120 - spr.textWidth(s) / 2, 168); }
  fEndHard();
  uiTrackLabel(foot, 120, 196, C_EB_BRASS);
  if(sub){ int tr = 3; while(tr > 1 && uiTrackWidth(sub, tr) > 228) tr--; uiTrackLabel(sub, 120, strncmp(sub, "BACK", 4) ? 186 : 216, C_EB_GREY, tr); }   // 11cz: a non-BACK line sits above the corners
  dispPush();
}
// NEW ACCOUNT (screens 1 to 3). One form: SITE (read-only when the browser
// asked), USERNAME, PASSWORD. UP and DOWN move between the cards, ENTER changes
// the one selected, a hold of ENTER saves and types: the username, Tab, the
// password, and Tab and the password again when the extension saw the confirm
// box right after it. Saved before it is typed, so a site never gets a password
// the KEY did not keep. "Site refused it" (UP on Saved) picks another kind and
// replaces the password in the same entry.
static void pwNew(uint32_t& lp, const char* presetSite = nullptr, const char* presetUser = nullptr){   // presets: a browser asked (stage 2)
  if(!pwFirstUse(lp)) return;
  char siteTyped[PP_MAX + 1] = {0};
  char own[PP_MAX + 1] = {0}; int ownLen = 0, sel = 0;
  struct WipeOwn { char* p; char* s; ~WipeOwn(){ mbedtls_platform_zeroize(p, PP_MAX + 1); mbedtls_platform_zeroize(s, PP_MAX + 1); } } wo{own, siteTyped};
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_calloc(1, sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  const size_t BUFN = 3 * favilla::RK_PW_FIELD_MAX + 4;   // username, Tab, password, Tab, password
  char* buf = (char*)heap_caps_malloc(BUFN, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e || !buf){ if(e) free(e); if(buf) free(buf); pkPageMsg("NEW ACCOUNT", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct Wipe { favilla::RkPass* e; char* b; size_t n; ~Wipe(){ favilla::rk_pw_wipe(e); free(e); mbedtls_platform_zeroize(b, n); free(b); } } wp{e, buf, BUFN};
  const bool siteRo = presetSite && presetSite[0];
  if(siteRo) snprintf(siteTyped, sizeof siteTyped, "%s", presetSite);
  if(presetUser && presetUser[0]) snprintf(e->user, sizeof e->user, "%s", presetUser);
  else {   // the newest username in the book, shown on the card (ENTER changes it)
    char (*u1)[favilla::RK_PW_FIELD_MAX + 1] = (char (*)[favilla::RK_PW_FIELD_MAX + 1])heap_caps_calloc(favilla::RK_UB_MAX, favilla::RK_PW_FIELD_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(u1){ if(favilla::rk_ub_list(u1, favilla::RK_UB_MAX) > 0) snprintf(e->user, sizeof e->user, "%s", u1[0]); mbedtls_platform_zeroize(u1, favilla::RK_UB_MAX * (favilla::RK_PW_FIELD_MAX + 1)); free(u1); }
  }
  int focus = 1, slot = -1; bool made = false; char name[PP_MAX + 1] = {0};
  const int RX = 12, RW = 216, RH = 42, RP = 46, RY = 34;
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("NEW ACCOUNT", 120, 14, C_EB_BRASS);
    char v[72];
    if(siteTyped[0]) snprintf(v, sizeof v, "%s", siteTyped); else snprintf(v, sizeof v, "%s", focus == 0 ? "Name it later, ENTER to name" : "Name it later");
    fSet(F_BODY); pkFitText(v, sizeof v, RW - 36, false); fEnd();
    uiListCard(RX, RY, RW, RH, focus == 0, C_EB_BRASS, "SITE", v, 24);
    if(e->user[0]) snprintf(v, sizeof v, "%s%s", e->user, focus == 1 ? ", ENTER to change" : ""); else snprintf(v, sizeof v, "%s", focus == 1 ? "None, ENTER to pick" : "None");
    fSet(F_BODY); pkFitText(v, sizeof v, RW - 36, false); fEnd();
    uiListCard(RX, RY + RP, RW, RH, focus == 1, C_EB_BRASS, "USERNAME", v, 24);
    { char d[40]; pwPresetDesc(sel, ownLen, d, sizeof d); snprintf(v, sizeof v, "%s%s", d, focus == 2 ? ", ENTER" : ""); }
    uiListCard(RX, RY + 2 * RP, RW, RH, focus == 2, C_EB_BRASS, "PASSWORD", v, 24);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const bool u = e->user[0] && (!(g_pwForm & chan::FORM_KNOWN) || (g_pwForm & chan::FORM_USER));
      const char* t = u ? "Start in the username box on the site." : "Start in the password box on the site."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 176); }
    fEndHard();
    uiHoldFooter("HOLD ENTER: SAVE, TYPE", "Saved on the signer before it is typed", hold, C_EB_BRASS);
    dispPush();
  };
  // Save (or replace the password in the entry saved already), then type. 0 not done, 1 typed.
  auto saveType = [&](bool& confirmTyped) -> int {
    if(slot < 0 && siteTyped[0]){   // the same site and username saved already: that is a change, not a new account
      const int ex = pwFindExact(siteTyped, e->user);
      if(ex >= 0){
        pkAsk("NEW ACCOUNT", "Already saved", "This KEY has a login for this", "site with that username.", "CANCEL", "CHANGE IT");
        if(totpYesNo(lp)){ favilla::RkLabel M; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(ex, &M); g0_window_batch_end(); }
          if(r == 0) pwChange(ex, M, lp);
          mbedtls_platform_zeroize(&M, sizeof M); return 2; }
        return 0;
      }
    }
    const int dest = pwDest("NEW ACCOUNT", lp); if(dest < 0) return 0;
    if(!made){
      if(!pwMakePass(sel, own, ownLen, e)){ pkPageMsg("NEW ACCOUNT", "Could not make a password.", "The secure element's random number generator did not answer. Nothing was made."); pwWaitBack(lp); return 0; }
      made = true;
    }
    if(slot < 0){
      if(siteTyped[0]) snprintf(name, sizeof name, "%s", siteTyped); else snprintf(name, sizeof name, "New entry %d", pwNewNumber());
      snprintf(e->site, sizeof e->site, "%s", name);
    }
    e->policy = (e->policy & ~pwgen::POLICY_PENDING) | (siteTyped[0] ? 0 : pwgen::POLICY_PENDING);
    e->slot = slot;
    pkPage("NEW ACCOUNT", "Saving", "Sealing it on the signer", "before it is typed.", nullptr);
    int r; r = RK_PIN(favilla::rk_pw_save(e, &slot));
    LOG_BOOT("[PW] new account: %s (%s, %d characters), %s slot %d: %s\n", sel >= PW_TYPE_IT ? "own password" : "made", PW_PRESETS[sel].name, (int)strlen(e->pass), e->slot < 0 ? "saved in" : "replaced in", slot, favilla::rk_err_name(r));
    if(r){ if(e->slot < 0) slot = -1; pkPageMsg("NEW ACCOUNT", "Not saved, so not typed.", pwOpenErr(r)); pwWaitBack(lp); return 0; }
    e->slot = slot; g_pwNewSaved = true;
    if(e->user[0]){ const int ar = favilla::rk_ub_add(e->user); if(ar && ar != favilla::RK_E_FULL) LOG_BOOT("[PW] usernames book: %s\n", favilla::rk_err_name(ar)); }
    const bool known = g_pwForm & chan::FORM_KNOWN;
    const bool withUser = e->user[0] && (!known || (g_pwForm & chan::FORM_USER));
    const bool conf = known && (g_pwForm & chan::FORM_CONFIRM);
    PwPiece pc[3]; int np = 0;
    if(withUser) pc[np++] = { e->user, "username", false };
    pc[np++] = { e->pass, "new password", withUser && (g_pwForm & chan::FORM_SPLIT1) };
    if(conf) pc[np++] = { e->pass, "confirm", (g_pwForm & chan::FORM_SPLIT2) != 0 };
    const int done = pwTypePieces("NEW ACCOUNT", dest, pc, np, buf, BUFN, lp);
    const bool ok = done > (withUser ? 1 : 0);   // the password reached the site
    confirmTyped = conf && done == np;
    LOG_BOOT("[PW] new account slot %d typed %d of %d pieces (%s%s): %s\n", slot, done, np, withUser ? "username, password" : "password", conf ? ", confirm" : "", ok ? "ok" : "not typed");
    if(!ok){ confirmTyped = false; return 0; }
    return 1;
  };
  draw(0); clearButtonPending();
  uint32_t shownAt = millis(); bool down = false; float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp)) return;
    if(btn4.isPressed()){ if(slot < 0) LOG_BOOT("[PW] new account left before it was saved: nothing kept\n"); return; }
    { const bool dn = btn1.isPressed(), up = !dn && btn3.isPressed();
      if(dn || up){ const int lo = siteRo ? 1 : 0; focus += dn ? 1 : -1; if(focus > 2) focus = lo; if(focus < lo) focus = 2; lp = millis(); draw(0); continue; } }
    if(btn2.stable == LOW && btn2.pressStart >= shownAt){
      down = true; const float h = btn2.holdProgress(600);
      if(h >= 1.0f){
        while(btn2.stable == LOW){ btn2.poll(); delay(5); }
        bool confirmTyped = false; const int got = saveType(confirmTyped); lp = millis();
        if(got == 2) return;   // went to CHANGE PASSWORD
        if(got == 1){   // Saved (screen 3)
          char l2[96]; snprintf(l2, sizeof l2, "%s%s%s", name, e->user[0] ? ", " : "", e->user);
          for(;;){
            pwResultPage("NEW ACCOUNT", "Saved", pwConfirmLine(confirmTyped), l2, "ENTER: DONE", "SITE REFUSED IT? PRESS UP");
            clearButtonPending(); int a = 0;
            while(!a){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
              if(tickSleepGesture() || pkMenuLeave(lp)) return;
              if(btn2.isPressed() || btn4.isPressed()) return;   // done: the entry is kept
              if(btn3.isPressed()) a = 1; else if(btn1.isPressed()) a = 2;
              delay(10); }
            lp = millis();
            if(a == 2){   // the password again, for a confirm box the Tab did not reach
              const int dest = pwDest("NEW ACCOUNT", lp);
              if(dest >= 0){ const size_t pn = strlen(e->pass); memcpy(buf, e->pass, pn); const bool ok = pwTypeBuf("NEW ACCOUNT", dest, buf, pn, lp); mbedtls_platform_zeroize(buf, BUFN); if(ok) confirmTyped = true; }
              continue;
            }
            const int ns = pwPickPreset(sel, own, &ownLen, lp);   // the site refused it: another kind, same entry
            if(ns >= 0){ sel = ns; made = false; focus = 2; }
            break;
          }
        }
        draw(0); clearButtonPending(); shownAt = millis(); down = false; last = 0; continue;
      }
      if((h - last) > 0.04f){ last = h; draw(h); }
    } else if(down){   // a tap: change the card selected
      down = false; last = 0;
      if(focus == 0){ char st[PP_MAX + 1] = {0}, us[PP_MAX + 1] = {0};
        if(pwTypeOrScan("SITE OR APP", "site or app", st, sizeof st, lp, us)){ snprintf(siteTyped, sizeof siteTyped, "%s", st); if(us[0]) snprintf(e->user, sizeof e->user, "%s", us); }
        mbedtls_platform_zeroize(st, sizeof st); mbedtls_platform_zeroize(us, sizeof us); }
      else if(focus == 1){ char u[favilla::RK_PW_FIELD_MAX + 1]; snprintf(u, sizeof u, "%s", e->user); if(pwPickUser(u, sizeof u, lp)) snprintf(e->user, sizeof e->user, "%s", u); mbedtls_platform_zeroize(u, sizeof u); }
      else { const int ns = pwPickPreset(sel, own, &ownLen, lp); if(ns >= 0){ sel = ns; made = false; } }
      lp = millis(); draw(0); clearButtonPending(); shownAt = millis();
    }
    btn2.isPressed();
    delay(10);
  }
}
// CHANGE PASSWORD (screens 4 to 6). Keeps the old one until the owner says the
// site took the new one: the old password is copied to "<site> (old)" first, the
// new one goes into the login itself (which keeps its id, so its code link and
// note stay), then the KEY types the old one, Tab, the new one (and Tab and the
// new one again when the extension saw the confirm box right after it).
// Accepted: the copy is deleted. Not yet: both stay, and MORE on the OLD copy
// finishes it later. Nothing typed: the change is undone.
// 25 Nov 2026: before a password is made, room to save it (and the old copy),
// or the PIN first, so a site never takes a password the KEY could not keep.
static void pwNoRoom(const char* T, uint32_t& lp){ pkPageMsg(T, "Nothing was changed.", "The vault limit needs your PIN. Lock and unlock the KEY, or power it off and on once the 4 refills are used."); pwWaitBack(lp); }
static bool pwChange(int i, const favilla::RkLabel& L, uint32_t& lp){
  if(!vaultRoomOrPin(2, 1, "Room to save the new password")){ pwNoRoom("CHANGE PASSWORD", lp); return false; }
  if(pwIsOld(L.site)){ pkPageMsg("CHANGE PASSWORD", "This is the old copy.", "Change the login itself."); pwWaitBack(lp); return false; }
  { char os[favilla::RK_SITE_MAX + 1]; snprintf(os, sizeof os, "%.*s%s", (int)(favilla::RK_SITE_MAX - (sizeof PW_OLD_TAG - 1)), L.site, PW_OLD_TAG);
    if(pwFindExact(os, L.user) >= 0){ pkPageMsg("CHANGE PASSWORD", "A change is waiting.", "Open the OLD copy in PASSWORDS: NEW ONE WORKS, or PUT THIS ONE BACK."); pwWaitBack(lp); return false; } }
  if(!pwFirstUse(lp)) return false;
  char own[PP_MAX + 1] = {0}; int ownLen = 0, sel = 0;
  struct WipeOwn { char* p; ~WipeOwn(){ mbedtls_platform_zeroize(p, PP_MAX + 1); } } wo{own};
  const bool cur = !(g_pwForm & chan::FORM_KNOWN) || (g_pwForm & chan::FORM_CURRENT);
  // 11et (Josh, 25 Nov 2026): the sign-in screen's shape. CHANGE PASSWORD as the
  // grey tag, the site and account, the kind of password it will make, one line
  // saying which box to click. MORE (DOWN, top-right) picks the kind; hold ENTER
  // (CHANGE) changes it; a tap of ENTER does nothing.
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    { const int below = pwSignInHero(L.site, L.user, "CHANGE PASSWORD", 8);
      char d[48], v[64]; pwPresetDesc(sel, ownLen, d, sizeof d);
      if(PW_PRESETS[sel].len) snprintf(v, sizeof v, "New: %s", PW_PRESETS[sel].name); else snprintf(v, sizeof v, "New: %s", d);
      for(char* q = v + 5; *q; q++) if(*q >= 'A' && *q <= 'Z') *q = (char)(*q - 'A' + 'a');   // "New: 24 characters"
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY); spr.drawString(v, 120 - spr.textWidth(v) / 2, below + 8);
      spr.setTextColor(C_EB_INK);
      const char* t = cur ? "Click the current password box" : "Click the new password box";
      spr.drawString(t, 120 - spr.textWidth(t) / 2, 178); fEndHard(); }
    uiCornerTop(nullptr, "MORE");
    uiCornerAnswers("BACK", "CHANGE");
    if(hold > 0){ fSet(F_BRAND_B12); int w = 0; for(const char* q = "CHANGE"; *q; q++){ char c[2] = {*q, 0}; w += spr.textWidth(c) + 3; } w -= 3; fEnd();
      spr.fillRect(228 - w, 208, w, 2, C_EB_LINE); spr.fillRect(228 - w, 208, (int)(w * (hold > 1 ? 1 : hold)), 2, C_EB_BRASS); }
    dispPush();
  };
  draw(0); clearButtonPending();
  uint32_t shownAt = millis(); bool down = false; float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    if(btn1.isPressed()){   // MORE: the kind of password
      const int ns = pwPickPreset(sel, own, &ownLen, lp); if(ns >= 0) sel = ns;
      lp = millis(); draw(0); clearButtonPending(); shownAt = millis(); continue; }
    btn3.isPressed();
    if(btn2.stable == LOW && btn2.pressStart >= shownAt){
      down = true; const float h = btn2.holdProgress(600);
      if(h >= 1.0f){ while(btn2.stable == LOW){ btn2.poll(); delay(5); } break; }
      if((h - last) > 0.04f){ last = h; draw(h); }
    } else if(down){ down = false; last = 0; draw(0); }   // let go early: nothing
    btn2.isPressed();
    delay(10);
  }
  lp = millis();
  const int dest = pwDest("CHANGE PASSWORD", lp); if(dest < 0) return false;
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  favilla::RkPass* c = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  const size_t BUFN = 3 * favilla::RK_PW_FIELD_MAX + 4;
  char* buf = (char*)heap_caps_malloc(BUFN, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  struct W3 { favilla::RkPass* a; favilla::RkPass* b; char* f; size_t n; ~W3(){ if(a){ favilla::rk_pw_wipe(a); free(a); } if(b){ favilla::rk_pw_wipe(b); free(b); } if(f){ mbedtls_platform_zeroize(f, n); free(f); } } } w3{e, c, buf, BUFN};
  if(!e || !c || !buf){ pkPageMsg("CHANGE PASSWORD", "Out of memory.", nullptr); pwWaitBack(lp); return false; }
  pkPage("CHANGE PASSWORD", "Keeping the old one", "Sealing a copy of it", "on the signer.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;
  if(r){ pkPageMsg("CHANGE PASSWORD", "Not changed.", pwOpenErr(r)); pwWaitBack(lp); return false; }
  memcpy(c, e, sizeof *c);
  c->slot = -1;
  snprintf(c->site, sizeof c->site, "%.*s%s", (int)(favilla::RK_SITE_MAX - (sizeof PW_OLD_TAG - 1)), e->site, PW_OLD_TAG);
  snprintf(c->note, sizeof c->note, "%s", "Kept by CHANGE PASSWORD until the site takes the new one.");
  int oslot = -1; r = RK_PIN(favilla::rk_pw_save(c, &oslot));
  LOG_BOOT("[PW] change: old password of slot %d copied to slot %d: %s\n", L.slot, oslot, favilla::rk_err_name(r));
  if(r){ pkPageMsg("CHANGE PASSWORD", "Not changed.", "The old one could not be kept, so nothing was changed."); pwWaitBack(lp); return false; }
  c->slot = oslot;
  const uint32_t pol0 = e->policy; const uint8_t org0 = e->origin;
  if(!pwMakePass(sel, own, ownLen, e)){
    { g0_window_batch_begin(); favilla::rk_delete(oslot); g0_window_batch_end(); }
    pkPageMsg("CHANGE PASSWORD", "Could not make a password.", "The secure element's random number generator did not answer. Nothing was changed."); pwWaitBack(lp); return true;
  }
  e->policy &= ~pwgen::POLICY_PENDING; e->slot = L.slot;
  pkPage("CHANGE PASSWORD", "Saving", "Sealing the new one", "before it is typed.", nullptr);
  { int s2 = -1; r = RK_PIN(favilla::rk_pw_save(e, &s2)); }
  LOG_BOOT("[PW] change: new password (%s, %d characters) into slot %d: %s\n", PW_PRESETS[sel].name, (int)strlen(e->pass), L.slot, favilla::rk_err_name(r));
  if(r){ { g0_window_batch_begin(); favilla::rk_delete(oslot); g0_window_batch_end(); }
    pkPageMsg("CHANGE PASSWORD", "Not changed.", pwOpenErr(r)); pwWaitBack(lp); return true; }
  const bool conf = (g_pwForm & chan::FORM_KNOWN) && (g_pwForm & chan::FORM_CONFIRM);
  PwPiece pc[3]; int np = 0;
  if(cur) pc[np++] = { c->pass, "current password", false };
  pc[np++] = { e->pass, "new password", cur && (g_pwForm & chan::FORM_SPLIT1) };
  if(conf) pc[np++] = { e->pass, "confirm", (g_pwForm & chan::FORM_SPLIT2) != 0 };
  const int done = pwTypePieces("CHANGE PASSWORD", dest, pc, np, buf, BUFN, lp);
  const bool ok = done > (cur ? 1 : 0);   // the new one reached the site
  const bool confirmTyped = conf && done == np;
  const size_t pn = strlen(e->pass);
  LOG_BOOT("[PW] change slot %d typed %d of %d pieces: %s\n", L.slot, done, np, ok ? "ok" : "the new one was not typed");
  if(!ok){   // nothing reached the site: put the old one back
    memcpy(e->pass, c->pass, sizeof e->pass); e->policy = pol0; e->origin = org0; e->slot = L.slot;
    int s2 = -1, ur; { g0_window_batch_begin(); ur = favilla::rk_pw_save(e, &s2); if(ur == 0) favilla::rk_delete(oslot); g0_window_batch_end(); }
    LOG_BOOT("[PW] change undone after the typing failed: %s\n", favilla::rk_err_name(ur));
    if(ur){ pkPageMsg("CHANGE PASSWORD", "Both are kept.", "The old one is the OLD copy in PASSWORDS."); pwWaitBack(lp); }
    return true;
  }
  (void)confirmTyped;
  for(;;){   // Accepted? (screen 5)
    // 11es (Josh, 25 Nov 2026): TYPE (DOWN, top-right) types the new one again,
    // as often as needed (a confirm box the KEY did not know of, a page that
    // cleared it). No header: the site sits under the ember, in brass.
    fEnd(); spr.fillSprite(C_BG);
    ebMarkSmall(101, 38, 6, 2);
    fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_BRASS);
    { char s[72]; snprintf(s, sizeof s, "%s", L.site); pkFitText(s, sizeof s, 216, false); spr.drawString(s, 120 - spr.textWidth(s) / 2, 84); }
    fEnd(); fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
    { const char* w = "Accepted?"; spr.drawString(w, 120 - spr.textWidth(w) / 2, 106); }
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* t = "Yes: the new one replaces the old."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 146); }
    { const char* t = "Later: both are kept."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 164); }
    fEndHard();
    uiCornerTop(nullptr, "TYPE");
    uiCornerAnswers("LATER", "YES");
    dispPush();
    clearButtonPending(); int a = 0;
    while(!a){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp)){ a = 3; break; }
      if(btn2.isPressed()) a = 1; else if(btn4.isPressed()) a = 3; else if(btn1.isPressed()) a = 2;
      btn3.isPressed(); delay(10); }
    lp = millis();
    if(a == 2){ const int d2 = pwDest("CHANGE PASSWORD", lp); if(d2 >= 0){ memcpy(buf, e->pass, pn); pwTypeBuf("CHANGE PASSWORD", d2, buf, pn, lp); mbedtls_platform_zeroize(buf, BUFN); } continue; }
    if(a == 1){
      int de; { g0_window_batch_begin(); de = favilla::rk_delete(oslot); g0_window_batch_end(); }
      LOG_BOOT("[PW] change accepted: old copy in slot %d deleted: %s\n", oslot, favilla::rk_err_name(de));
      pkPageMsg("CHANGE PASSWORD", de == 0 ? "Changed." : "Changed. The old copy is still listed.", de == 0 ? "The old password is gone from this KEY." : favilla::rk_err_name(de));
      pwWaitBack(lp); return true;
    }
    LOG_BOOT("[PW] change not confirmed yet: both kept (old copy in slot %d)\n", oslot);
    pkPageMsg("CHANGE PASSWORD", "Both are kept.", "The old one is listed as OLD. Open it to finish: NEW ONE WORKS, or PUT THIS ONE BACK.");
    pwWaitBack(lp); return true;
  }
}
#ifdef FAVILLA_BLE_KBD
// ── 11bi (17 Nov 2026, issue #38): new passwords from iPhone AutoFill ─────────
// The app's FILL ask (a phone's sign-in sheet) can now end in a password the
// KEY makes: NEW LOGIN FOR <site> (the last row of the matches, and on the No
// saved login screen) and NEW PASSWORD in a login's options (UP during the ask).
// Both are saved on the KEY before anything goes to the phone, then sent like a
// picked login (0xB3 [0][user][password]), so iOS fills them in. NEW PASSWORD
// is CHANGE PASSWORD (11az) without the typing: the old password stays as
// "<site> (old)" until the owner says the site took the new one.
// Sends e's login to the app and says so on the screen. true: sent.
static bool pwFillSend(const favilla::RkPass* e, int slot, const char* T, uint32_t& lp){
  const bool sent = blek::fillSend(0, e->user, e->pass);
  LOG_BOOT("[PW] %s slot %d to the app for AutoFill: %s\n", T, slot, sent ? "sent" : "the app's link is gone");
  if(!sent){ pkPageMsg(T, "Saved, not sent.", "The phone disconnected. The login is on this KEY: pick it next time."); pwWaitBack(lp); return false; }
  g_pwTypedCount++;
  uint8_t id[8]; g_pwAskIdx = favilla::rk_pw_id_of(slot, id) ? favilla::rk_pw_index_of(slot, id) : -1;   // 9d: the 60 s shortcut
  return true;
}
// NEW LOGIN FOR <site>: a strong 20-character password (the issue's ruling, as
// iOS suggests), the FILL's username if it sent one (a tap picks another), held
// ENTER saves it, then it goes to the phone. true: sent.
static bool pwFillNew(const char* site, const char* user0, uint32_t& lp){
  static const char* T = "NEW LOGIN";
  if(!vaultRoomOrPin(1, 0, "Room to save the new login")){ pwNoRoom(T, lp); return false; }
  if(favilla::rk_count_all() >= favilla::RK_MAX){ pkPageMsg(T, "This KEY is full.", "Delete a login in PASSWORDS first."); pwWaitBack(lp); return false; }
  char user[favilla::RK_PW_FIELD_MAX + 1]; snprintf(user, sizeof user, "%s", user0 ? user0 : "");
  struct WipeU { char* p; size_t n; ~WipeU(){ mbedtls_platform_zeroize(p, n); } } wu{user, sizeof user};
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel(T, 120, 14, C_EB_BRASS);
    char v[96]; snprintf(v, sizeof v, "%s", site); fSet(F_BODY); pkFitText(v, sizeof v, 180, false); fEnd();
    uiListCard(12, 34, 216, 42, false, C_EB_BRASS, "SITE", v, 24);
    snprintf(v, sizeof v, "%s", user[0] ? user : "none, ENTER to pick"); fSet(F_BODY); pkFitText(v, sizeof v, 180, false); fEnd();
    uiListCard(12, 80, 216, 42, true, C_EB_BRASS, "USERNAME", v, 24);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* t = "A 20-character password,"; spr.drawString(t, 120 - spr.textWidth(t) / 2, 134); }
    { const char* t = "made and saved on this KEY."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 152); }
    fEndHard();
    uiHoldFooter("HOLD ENTER: SAVE IT", "Then the phone fills it in", hold, C_EB_BRASS);
    dispPush();
  };
  draw(0); clearButtonPending();
  uint32_t shownAt = millis(); bool down = false; float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    btn1.isPressed(); btn3.isPressed();
    if(btn2.stable == LOW && btn2.pressStart >= shownAt){
      down = true; const float h = btn2.holdProgress(600);
      if(h >= 1.0f){ while(btn2.stable == LOW){ btn2.poll(); delay(5); } break; }
      if((h - last) > 0.04f){ last = h; draw(h); }
    } else if(down){ down = false; last = 0;   // a tap: pick the username
      char u[favilla::RK_PW_FIELD_MAX + 1]; snprintf(u, sizeof u, "%s", user); if(pwPickUser(u, sizeof u, lp)) snprintf(user, sizeof user, "%s", u); mbedtls_platform_zeroize(u, sizeof u);
      lp = millis(); draw(0); clearButtonPending(); shownAt = millis(); }
    btn2.isPressed();
    delay(10);
  }
  lp = millis();
  if(pwFindExact(site, user) >= 0){ pkPageMsg(T, "This login is already here.", "Pick it in the list, or use UP > NEW PASSWORD on it."); pwWaitBack(lp); return false; }
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_calloc(1, sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e){ pkPageMsg(T, "Out of memory.", nullptr); pwWaitBack(lp); return false; }
  struct WipeE { favilla::RkPass* e; ~WipeE(){ favilla::rk_pw_wipe(e); free(e); } } we{e};
  uint8_t seed[32]; bool ok = pwGenSeed(seed);
  if(ok) ok = pwgen::generate(seed, 20, PW_ALL, e->pass);
  mbedtls_platform_zeroize(seed, sizeof seed);
  if(!ok){ LOG_BOOT("[PW] fill new login: SE TRNG failed - refused\n"); pkPageMsg(T, "Could not make a password.", "The secure element's random number generator did not answer. Nothing was saved."); pwWaitBack(lp); return false; }
  e->slot = -1; e->policy = pwgen::policy(20, PW_ALL); e->origin = favilla::RK_ORIGIN_KEY;
  snprintf(e->site, sizeof e->site, "%s", site); snprintf(e->user, sizeof e->user, "%s", user);
  pkPage(T, "Saving", "Sealing it on the signer", "before it is sent.", nullptr);
  int slot = -1, r; r = RK_PIN(favilla::rk_pw_save(e, &slot));
  LOG_BOOT("[PW] fill new login (20 characters, made): slot %d: %s\n", slot, favilla::rk_err_name(r));
  if(r){ pkPageMsg(T, "Not saved, so not sent.", pwOpenErr(r)); pwWaitBack(lp); return false; }
  if(e->user[0]){ const int ar = favilla::rk_ub_add(e->user); if(ar && ar != favilla::RK_E_FULL) LOG_BOOT("[PW] usernames book: %s\n", favilla::rk_err_name(ar)); }
  if(!pwFillSend(e, slot, T, lp)) return false;
  pkPage("NEW LOGIN", "Sent", "The phone fills it in.", nullptr, nullptr);
  uint32_t t0 = millis(); clearButtonPending();
  while(millis() - t0 < 1200){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(btn2.isPressed() || btn4.isPressed()) break; delay(10); }
  return true;
}
// NEW PASSWORD on login i: CHANGE PASSWORD (11az) answered to the phone. The
// old password is copied to "<site> (old)" first, the new one goes into the
// login (same id, code link and note), then it is sent. Both stay until the
// owner opens the OLD copy: NEW ONE WORKS, or PUT THIS ONE BACK. true: sent.
static bool pwFillNewPass(int i, const favilla::RkLabel& L, uint32_t& lp){
  static const char* T = "NEW PASSWORD";
  if(!vaultRoomOrPin(2, 1, "Room to save the new password")){ pwNoRoom(T, lp); return false; }
  if(pwIsOld(L.site)){ pkPageMsg(T, "This is the old copy.", "Change the login itself."); pwWaitBack(lp); return false; }
  char os[favilla::RK_SITE_MAX + 1]; snprintf(os, sizeof os, "%.*s%s", (int)(favilla::RK_SITE_MAX - (sizeof PW_OLD_TAG - 1)), L.site, PW_OLD_TAG);
  if(pwFindExact(os, L.user) >= 0){ pkPageMsg(T, "A change is waiting.", "Open the OLD copy in PASSWORDS: NEW ONE WORKS, or PUT THIS ONE BACK."); pwWaitBack(lp); return false; }
  if(favilla::rk_count_all() >= favilla::RK_MAX){ pkPageMsg(T, "This KEY is full.", "The old password needs a place. Delete a login in PASSWORDS first."); pwWaitBack(lp); return false; }
  char own[PP_MAX + 1] = {0}; int ownLen = 0, sel = 0;
  struct WipeOwn { char* p; ~WipeOwn(){ mbedtls_platform_zeroize(p, PP_MAX + 1); } } wo{own};
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel(T, 120, 14, C_EB_BRASS);
    char v[96]; snprintf(v, sizeof v, "%s%s%s", L.site, L.user[0] ? ", " : "", L.user); fSet(F_BODY); pkFitText(v, sizeof v, 180, false); fEnd();
    uiListCard(12, 34, 216, 42, false, C_EB_BRASS, "ACCOUNT", v, 24);
    { char d[40]; pwPresetDesc(sel, ownLen, d, sizeof d); snprintf(v, sizeof v, "%s, ENTER", d); }
    uiListCard(12, 80, 216, 42, true, C_EB_BRASS, "NEW PASSWORD", v, 24);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* t = "Keeps the old one until"; spr.drawString(t, 120 - spr.textWidth(t) / 2, 134); }
    { const char* t = "the site takes the new one."; spr.drawString(t, 120 - spr.textWidth(t) / 2, 152); }
    fEndHard();
    uiHoldFooter("HOLD ENTER: CHANGE IT", "Then the phone fills it in", hold, C_EB_BRASS);
    dispPush();
  };
  draw(0); clearButtonPending();
  uint32_t shownAt = millis(); bool down = false; float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    btn1.isPressed(); btn3.isPressed();
    if(btn2.stable == LOW && btn2.pressStart >= shownAt){
      down = true; const float h = btn2.holdProgress(600);
      if(h >= 1.0f){ while(btn2.stable == LOW){ btn2.poll(); delay(5); } break; }
      if((h - last) > 0.04f){ last = h; draw(h); }
    } else if(down){ down = false; last = 0;
      const int ns = pwPickPreset(sel, own, &ownLen, lp); if(ns >= 0) sel = ns;
      lp = millis(); draw(0); clearButtonPending(); shownAt = millis(); }
    btn2.isPressed();
    delay(10);
  }
  lp = millis();
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  favilla::RkPass* c = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  struct W2 { favilla::RkPass* a; favilla::RkPass* b; ~W2(){ if(a){ favilla::rk_pw_wipe(a); free(a); } if(b){ favilla::rk_pw_wipe(b); free(b); } } } w2{e, c};
  if(!e || !c){ pkPageMsg(T, "Out of memory.", nullptr); pwWaitBack(lp); return false; }
  pkPage(T, "Keeping the old one", "Sealing a copy of it", "on the signer.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(i, e));
  if(r == 0 && (e->slot != L.slot || strcmp(e->site, L.site) || strcmp(e->user, L.user))) r = favilla::RK_E_FORMAT;
  if(r){ pkPageMsg(T, "Not changed.", pwOpenErr(r)); pwWaitBack(lp); return false; }
  memcpy(c, e, sizeof *c); c->slot = -1;
  snprintf(c->site, sizeof c->site, "%s", os);
  snprintf(c->note, sizeof c->note, "%s", "Kept by CHANGE PASSWORD until the site takes the new one.");
  int oslot = -1; r = RK_PIN(favilla::rk_pw_save(c, &oslot));
  LOG_BOOT("[PW] fill new password: old password of slot %d copied to slot %d: %s\n", L.slot, oslot, favilla::rk_err_name(r));
  if(r){ pkPageMsg(T, "Not changed.", "The old one could not be kept, so nothing was changed."); pwWaitBack(lp); return false; }
  if(!pwMakePass(sel, own, ownLen, e)){
    { g0_window_batch_begin(); favilla::rk_delete(oslot); g0_window_batch_end(); }
    pkPageMsg(T, "Could not make a password.", "The secure element's random number generator did not answer. Nothing was changed."); pwWaitBack(lp); return false;
  }
  e->policy &= ~pwgen::POLICY_PENDING; e->slot = L.slot;
  pkPage(T, "Saving", "Sealing the new one", "before it is sent.", nullptr);
  { int s2 = -1; r = RK_PIN(favilla::rk_pw_save(e, &s2)); }
  LOG_BOOT("[PW] fill new password (%s, %d characters) into slot %d: %s\n", PW_PRESETS[sel].name, (int)strlen(e->pass), L.slot, favilla::rk_err_name(r));
  if(r){ { g0_window_batch_begin(); favilla::rk_delete(oslot); g0_window_batch_end(); }
    pkPageMsg(T, "Not changed.", pwOpenErr(r)); pwWaitBack(lp); return false; }
  if(!pwFillSend(e, L.slot, T, lp)) return false;   // saved: both kept, and the OLD copy finishes it
  pkPageMsg(T, "Sent. Both are kept.", "When the site takes it, open the OLD copy in PASSWORDS: NEW ONE WORKS.");
  pwWaitBack(lp);
  return true;
}
// UP on a login during the phone's FILL ask. true: a new password went to the phone.
static bool pwFillOptions(int i, const favilla::RkLabel& L, uint32_t& lp){
  char nl[48]; snprintf(nl, sizeof nl, "%s", "NEW LOGIN FOR THIS SITE");
  const char* rows[2] = { "NEW PASSWORD", nl };
  const int k = pwRowsPick(L.site, rows, 2, -1, 0, lp);
  if(k == 0) return pwFillNewPass(i, L, lp);
  if(k == 1) return pwFillNew(g_fillSite, g_fillUser, lp);
  return false;
}
#endif  // FAVILLA_BLE_KBD
// A browser asked from a change-password page: the saved login for that site
// (and username, when the page showed one). 1 typed, 2 not, 3 none saved.
static int pwChangeFor(const char* site, const char* user, uint32_t& lp, bool quietNone = false){   // quietNone (11eq): no page when none, the caller makes a new one
  const int n = favilla::rk_pw_count();
  int* hit = (int*)heap_caps_calloc(n > 0 ? n : 1, sizeof(int), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  const char** names = (const char**)heap_caps_calloc(n > 0 ? n : 1, sizeof(char*), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  char (*users)[48] = (char (*)[48])heap_caps_calloc(n > 0 ? n : 1, 48, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  struct F3 { void* a; void* b; void* c; size_t cn; ~F3(){ free(a); free(b); if(c){ mbedtls_platform_zeroize(c, cn); free(c); } } } f3{hit, names, users, (size_t)(n > 0 ? n : 1) * 48};
  if(!hit || !names || !users){ pkPageMsg("CHANGE PASSWORD", "Out of memory.", nullptr); pwWaitBack(lp); return 2; }
  int nh = 0;
  pkPage("CHANGE PASSWORD", "Finding it", "The saved login", "for this site.", nullptr);
  g0_window_batch_begin();
  for(int k = 0; k < n; k++){
    char s[favilla::RK_SITE_MAX + 1]; bool pend = false;
    if(!favilla::rk_pw_site(k, s, sizeof s, &pend, nullptr) || pwIsOld(s) || loginqr::siteMatch(s, site) < 2) continue;
    favilla::RkLabel M; if(favilla::rk_pw_label(k, &M)) continue;
    hit[nh] = k; snprintf(users[nh], 48, "%s", M.user[0] ? M.user : "(no username)"); names[nh] = users[nh]; nh++;
    mbedtls_platform_zeroize(&M, sizeof M);
  }
  g0_window_batch_end();
  // 11bb (13 Nov 2026, bench): the page's username narrows the list only when a
  // login has it. A page that names another account (or a different spelling
  // of the email) still offers this site's logins to pick from.
  if(user[0] && nh > 1){ int w = 0; for(int k = 0; k < nh; k++) if(!strcmp(users[k], user)){ hit[w] = hit[k]; if(w != k) memcpy(users[w], users[k], 48); names[w] = users[w]; w++; } if(w > 0) nh = w; }
  LOG_BOOT("[PW] change from a browser: %d saved login%s for this site%s\n", nh, nh == 1 ? "" : "s", user[0] ? ", the page named a username" : "");
  if(nh == 0 && quietNone) return 3;
  if(nh == 0){ pkPageMsg("CHANGE PASSWORD", "No saved login to change.", "This KEY has no login for this site. Save one with NEW ACCOUNT."); pwWaitBack(lp); return 3; }
  int pick = 0;
  if(nh > 1){ pick = pwRowsPick("WHICH LOGIN", names, nh, -1, 0, lp); if(pick < 0) return 2; }
  favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(hit[pick], &L); g0_window_batch_end(); }
  if(r){ pkPageMsg("CHANGE PASSWORD", "This entry cannot be read.", pwOpenErr(r)); pwWaitBack(lp); return 2; }
  const uint32_t t0 = g_pwTypedCount;
  pwChange(hit[pick], L, lp);
  mbedtls_platform_zeroize(&L, sizeof L);
  return g_pwTypedCount != t0 ? 1 : 2;
}

// ── Background labels (3 Nov 2026, bench) ─────────────────────────────────────
// A site name costs one G0 LABEL (~0.47 s, a secure-element session each), and
// the cache empties at every lock. So from the PIN on, the PASSKEY life reads
// the names in the background, one per loop pass, only after the buttons have
// been quiet for a moment (a press is never kept waiting by more than one).
// prefer: entry indices to read first (the rows on screen), may be null.
static bool g_pwBgDone = false; static uint32_t g_pwBgT0 = 0, g_pwBgDoneAt = 0, g_pwBgHold = 5000; static int g_pwBgCount = 0;
static void pwBgReset(){ g_pwBgDone = false; g_pwBgT0 = 0; g_pwBgCount = 0; }
static bool pwBgLabel(uint32_t quietSince, const int* prefer, int np){
  if(g_pwBgDone && millis() - g_pwBgDoneAt < g_pwBgHold) return false;   // look again now and then: a lock empties the cache, an entry may be new
  g_pwBgDone = false; g_pwBgHold = 5000;
  // Bench 3 Nov 2026: a LABEL holds the I2C bus (G0 and secure element) for
  // about 0.47 s, and the press click (haptic) is on that bus too, so a press
  // that lands during one waits for it. So: rows on the list screen are read
  // after 0.6 s without a press; everything else only after 3 s without one,
  // which keeps menu scrolling clear.
  const uint32_t q = millis() - quietSince;
  if(q < 600) return false;
  if(!g_pkPinHeld || !favilla::rk_ready() || !g0_v15_present()) return false;
  int left = favilla::rk_label_left(); if(left >= 0 && left < 20) { g_pwBgDone = true; g_pwBgDoneAt = millis(); return false; }   // keep the last labels for the screens
  int pick = -1;
  for(int k = 0; k < np && pick < 0; k++) if(prefer[k] >= 0 && !favilla::rk_pw_site_known(prefer[k])) pick = prefer[k];
  const int n = favilla::rk_pw_count();
  if(pick < 0 && q < 3000){ bool any = false; for(int i = 0; i < n && !any; i++) any = !favilla::rk_pw_site_known(i); if(any) return false; }   // off screen: wait for a longer pause
  for(int i = 0; i < n && pick < 0; i++) if(!favilla::rk_pw_site_known(i)) pick = i;
  // 4 Nov 2026 (bench, Josh: the username list for a new password still took ~7 s):
  // each LABEL is ~0.47 s on the G0 and the picker reads the 12 most recent
  // entries. With every name known, the reader goes on to those 12 in the same
  // quiet moments, so the picker finds them cached (no G0 call) when it opens.
  if(pick < 0 && q >= 3000){
    int ord[12]; const int no = favilla::rk_pw_order(ord, 12); favilla::RkRow rw;
    for(int k = 0; k < no && pick < 0; k++) if(favilla::rk_pw_row(ord[k], &rw) && !rw.userKnown) pick = ord[k];
  }
  if(pick < 0){
    if(g_pwBgCount) favilla::rk_idx_flush();   // P4-10: the names just read go into the index
    if(g_pwBgCount) LOG_BOOT("[PW] background labels: %d read in %lu ms, all %d ready | labels left this life %d\n", g_pwBgCount, (unsigned long)(millis() - g_pwBgT0), n, favilla::rk_label_left());
    g_pwBgDone = true; g_pwBgDoneAt = millis(); g_pwBgCount = 0; g_pwBgT0 = 0; return false;
  }
  if(!g_pwBgT0) g_pwBgT0 = millis();
  favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(pick, &L); g0_window_batch_end(); }
  mbedtls_platform_zeroize(&L, sizeof L);
  if(r){ LOG_BOOT("[PW] background labels stopped: %s, G0 0x%02X %s\n", favilla::rk_err_name(r), favilla::rk_last_res(), favilla::rk_hint()); g_pwBgDone = true; g_pwBgDoneAt = millis(); g_pwBgHold = 60000; return false; }   // a refusal: try again in a minute, not every pass
  g_pwBgCount++;
  return true;
}

// Bench 3 Nov 2026: reading only from the home loop missed the menus (the
// owner goes straight from the PIN into the menu). So every PASSKEY-life loop
// reads through pkSerialTick: whichever screen is up, once the buttons have
// been quiet, never while a website is asking. The list sets the rows it shows
// as the ones to read first and repaints when g_pwBgGen moves.
static int g_pwPrefer[5] = {-1, -1, -1, -1, -1}; static int g_pwPreferN = 0;
static uint32_t g_pwBgGen = 0, g_pwLastPress = 0;
static bool g_pwBgBusy = false;
static void pwBgTick(){
  if(g_pwBgBusy || !g_passkeyLife) return;
  if(btn1.stable == LOW || btn1.pending || btn2.stable == LOW || btn2.pending || btn3.stable == LOW || btn3.pending || btn4.stable == LOW || btn4.pending) { g_pwLastPress = millis(); return; }
  if(fido::g_up.state == 1) return;
  g_pwBgBusy = true;
  if(pwBgLabel(g_pwLastPress, g_pwPreferN ? g_pwPrefer : nullptr, g_pwPreferN)) g_pwBgGen++;
  g_pwBgBusy = false;
}

// ── PASSWORDS list (3 Nov 2026, Josh): site names only, five to a screen.
// New entries from the generator first (newest first), then A to Z by site;
// entries not read yet sit at the end as "Reading" and move into place as the
// background reader gets to them. The selection follows its entry, not its row.
// ENTER opens an entry: username, typing, note and delete are on that screen.
struct PwRow { int16_t idx, slot; uint8_t lab, pend; int pendN; char site[64]; };
static int pwRowCmp(const PwRow& a, const PwRow& b){
  if(a.lab != b.lab) return a.lab ? -1 : 1;
  if(!a.lab) return a.idx - b.idx;
  if(a.pend != b.pend) return a.pend ? -1 : 1;
  if(a.pend) return b.pendN - a.pendN;
  int c = strcasecmp(a.site, b.site); return c ? c : a.idx - b.idx;
}
static int pwBuildRows(PwRow* rows){
  const int n = favilla::rk_pw_count();
  for(int i = 0; i < n; i++){
    PwRow& w = rows[i]; memset(&w, 0, sizeof w); w.idx = (int16_t)i; w.slot = (int16_t)favilla::rk_pw_slot_at(i);
    bool pend = false;
    if(favilla::rk_pw_site(i, w.site, sizeof w.site, &pend, nullptr)){   // P4-10: the index or a cached label, no G0 call
      w.lab = 1;
      if(pend){ w.pend = 1; w.pendN = atoi(w.site + 10); }
    }
  }
  for(int i = 1; i < n; i++){ PwRow t = rows[i]; int j = i; while(j > 0 && pwRowCmp(t, rows[j - 1]) < 0){ rows[j] = rows[j - 1]; j--; } rows[j] = t; }   // insertion sort, n <= 200
  return n;
}
// ── TYPE or SCAN QR (4 Nov 2026, Josh: "same as passphrase for BTC") ──────────
// A site name or a username, typed on the passphrase reel or read from a QR (the
// camera path of ppScan: same entry sequence, same 30 s window). The text is not
// secret, so there is no pre-scan warning; it is shown in full to accept.
// 5v (4 Nov 2026, Josh): the vault's page head on these too, the brass tracked
// label like every other PASSKEY page, with a grey line under it.
static void pwHead(const char* label, const char* detail){
  char up[32]; size_t i = 0; for(; label[i] && i + 1 < sizeof up; i++) up[i] = (label[i] >= 'a' && label[i] <= 'z') ? label[i] - 32 : label[i]; up[i] = 0;
  uiTrackLabel(up, 120, 14, C_EB_BRASS);
  if(detail){ fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY); spr.drawString(detail, 120 - spr.textWidth(detail) / 2, 32); fEndHard(); }
}
// Count the lines uiWrapCentre would draw for t at maxW in the loaded font.
static int pwWrapLines(const char* t, int maxW){
  char line[64]; int lines = 0; const char* p = t;
  while(*p){
    int n = 0; const char* lastBreak = nullptr; int lastN = 0; const char* q = p;
    while(*q && n < (int)sizeof(line) - 1){ line[n] = *q; line[n+1] = 0; if(spr.textWidth(line) > maxW && n > 0) break; if(*q == ' '){ lastBreak = q; lastN = n; } n++; q++; }
    if(*q && lastBreak){ q = lastBreak + 1; }
    lines++; p = q; while(*p == ' ') p++;
  }
  return lines;
}
// Phase 5 (4 Nov 2026): a login QR's review. LOGIN head; the site large, the
// username under it in brass. Every character is shown: Bold 28 / Bold 14 when
// they fit, else Regular 13; if both near 100 still overflow, the page says so.
static void pwDrawLoginReview(const char* site, const char* user, int sel){
  spr.fillSprite(C_BG);
  pwHead("login", "Scanned. Save a login for this?");
  const int TOP = 50, BOT = 134;
  bool cut = false;
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full);
  bool siteBig = spr.textWidth(site) <= 216; fEndHard();
  int y = TOP;
  // pick the font that shows both whole in the band
  int fontPick = 0, sl = 1, ul = 0, lh = 18;   // 0: Bold 14, 1: Regular 13
  for(fontPick = 0; fontPick < 2; fontPick++){
    if(fontPick == 0) fSet(F_BRAND_B14); else spr.loadFont(FONT_Archivo_Regular_13);
    lh = fontPick == 0 ? 18 : 15;
    sl = siteBig ? 0 : pwWrapLines(site, 210); ul = user[0] ? pwWrapLines(user, 210) : 1;
    int h = (siteBig ? 32 : sl * lh) + 6 + ul * lh;
    if(fontPick == 0) fEnd(); else fEndHard();
    if(h <= BOT - TOP) break;
  }
  if(fontPick == 2){ fontPick = 1; lh = 15; cut = true; }
  int avail = (BOT - TOP - (siteBig ? 32 : 0) - 6) / lh;
  int sMax = siteBig ? 0 : (cut ? (avail + 1) / 2 : sl), uMax = cut ? avail - sMax : ul;
  int total = (siteBig ? 32 : sMax * lh) + 6 + uMax * lh;
  y = TOP + (BOT - TOP - total) / 2;
  if(siteBig){ spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK); spr.drawString(site, 120 - spr.textWidth(site) / 2, y); fEndHard(); y += 32; }
  else { if(fontPick == 0) fSet(F_BRAND_B14); else spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_INK); y = uiWrapCentre(site, y, 210, lh, sMax); if(fontPick == 0) fEnd(); else fEndHard(); }
  y += 6;
  if(fontPick == 0) fSet(F_BRAND_B14); else spr.loadFont(FONT_Archivo_Regular_13);
  if(user[0]){ spr.setTextColor(C_EB_BRASS); uiWrapCentre(user, y, 210, lh, uMax); }
  else { spr.setTextColor(C_EB_GREY); const char* nu = "No username"; spr.drawString(nu, 120 - spr.textWidth(nu) / 2, y); }
  if(fontPick == 0) fEnd(); else fEndHard();
  if(cut){ fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_RED); const char* m = "Too long to show whole"; spr.drawString(m, 120 - spr.textWidth(m) / 2, 136); fEndHard(); }
  ppCard(cut ? 152 : 140, cut ? 38 : 44, "USE IT",     "Site and username read right", sel == 0, C_EB_BRASS, ppIconTick);
  ppCard(cut ? 194 : 188, cut ? 38 : 44, "SCAN AGAIN", "Wrong or cut off",             sel == 1, C_EB_BRASS, ppIconRedo);
}
static bool pwScanText(const char* what, char* out, size_t cap, char* userOut, bool review){   // review false: sign in by QR (the entry screen is the check)
  for(;;){
    spr.fillSprite(C_BG);
    pwHead(what, "Hold the QR to the camera");
    dispPush(); delay(400);
    pwrBoost(); camHoldWake();   // 10u: the scan's own hold, and its record
    cameraStart(); qrFound = false;
    if(!cameraRunning) return false;   // start failed: the error screen is already shown
    for(int f = 0; f < 4; f++){ camera_fb_t* sf = esp_camera_fb_get(); if(sf) esp_camera_fb_return(sf); vTaskDelay(pdMS_TO_TICKS(25)); }
    qrResultBuf[0] = 0; qrDiagReset(); qrDumpReset();
    g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
    unsigned long qs = millis(), lastQR = 0; bool got = false;
    while(millis() - qs < 30000){
      btn4.poll();
      if(btn4.isPressed()){ break; }
      if(!qrFound && (millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)){ qrScanOnce(); lastQR = millis(); delay(5); }
      if(qrFound){ qrFound = false; got = true; break; }
      pkTripwire(); delay(10);
    }
    g_airgapLivePreview = false; cameraStop(); clearButtonPending();
    if(!got) return false;   // BACK or 30 s: back to TYPE / SCAN QR
    size_t len = strnlen(qrResultBuf, QR_RESULT_SZ);
    while(len && (qrResultBuf[len - 1] == '\n' || qrResultBuf[len - 1] == '\r' || qrResultBuf[len - 1] == ' ')) len--;   // a trailing newline from a QR app
    if(loginqr::isLogin(qrResultBuf, len)){   // phase 5: favilla:login?v=1&s=..&u=.. (login_qr.h)
      char ls[loginqr::FIELD_MAX + 1], lu[loginqr::FIELD_MAX + 1];
      int lr = userOut ? loginqr::parse(qrResultBuf, len, ls, lu) : loginqr::NOT_LOGIN;
      mbedtls_platform_zeroize(qrResultBuf, QR_RESULT_SZ);
      LOG_BOOT("[PW] login QR scanned for %s: %s\n", what, !userOut ? "refused (not here)" : lr == loginqr::OK ? "ok" : loginqr::errText(lr));
      if(!userOut){ dispError("A login QR: scan it at Name the site"); errorPause(); continue; }
      if(lr != loginqr::OK){ dispError(loginqr::errText(lr)); errorPause(); continue; }
      int sel = 0; bool decided = !review, accept = !review;
      while(!decided){
        pwDrawLoginReview(ls, lu, sel); dispPush();
        for(;;){ btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
          if(btn1.isPressed() || btn3.isPressed()){ sel ^= 1; break; }
          if(btn2.isPressed()){ accept = sel == 0; decided = true; break; }
          if(btn4.isPressed()){ accept = false; decided = true; break; }
          esp_task_wdt_reset(); delay(10); }
        delay(150);
      }
      clearButtonPending();
      if(accept && strlen(ls) < cap){ memcpy(out, ls, strlen(ls) + 1); snprintf(userOut, PP_MAX + 1, "%s", lu); }
      mbedtls_platform_zeroize(ls, sizeof ls); mbedtls_platform_zeroize(lu, sizeof lu);
      if(accept) return true;
      if(sel == 1) continue;
      return false;
    }
    bool ok = len > 0 && len < cap;
    for(size_t i = 0; ok && i < len; i++) if((uint8_t)qrResultBuf[i] < 0x20 || (uint8_t)qrResultBuf[i] > 0x7E) ok = false;   // what the KEY can type
    char tmp[PP_MAX + 1] = {0};
    if(ok && len <= PP_MAX){ memcpy(tmp, qrResultBuf, len); tmp[len] = 0; } else ok = false;
    mbedtls_platform_zeroize(qrResultBuf, QR_RESULT_SZ);
    LOG_BOOT("[PW] %s QR scanned (%d characters): %s\n", what, (int)len, ok ? "ok" : "refused");
    if(!ok){ dispError(len ? "Only plain US keyboard text, up to 100" : "The QR was empty"); errorPause(); continue; }
    if(!review){ memcpy(out, tmp, len + 1); return true; }   // sign in by QR: a bare site name
    int sel = 0; bool decided = false, accept = false;
    while(!decided){
      // 5u (4 Nov 2026, Josh: "looks a bit shit"): not the passphrase's mono grid
      // (that exists to show spaces in a wallet secret). The value is the page:
      // Bold 28 when it fits one line, else Bold 14 (Regular 13 when long) wrapped
      // and centred in the band above the cards, with its length under it.
      spr.fillSprite(C_BG);
      pwHead(what, "Scanned. Use it?");
      {
        const int TOP = 48, BOT = 124;               // the band between the question and the cards
        fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full);
        int y;
        if(spr.textWidth(tmp) <= 216){
          y = (TOP + BOT) / 2 - 22;
          spr.setTextColor(C_EB_INK); spr.drawString(tmp, 120 - spr.textWidth(tmp) / 2, y);
          y += 34; fEndHard();
        } else {
          fEndHard();
          bool small = len > 60;
          int lh = small ? 16 : 18, lines = 0;
          if(small) spr.loadFont(FONT_Archivo_Regular_13); else fSet(F_BRAND_B14);
          { // count the lines uiWrapCentre will draw, so the block sits centred
            int x = 0; for(size_t i = 0; i < len; i++){ char c[2] = { tmp[i], 0 }; int cw = spr.textWidth(c); if(x + cw > 210){ lines++; x = 0; } x += cw; }
            lines++; if(lines > 5) lines = 5; }
          y = (TOP + BOT) / 2 - (lines * lh + 18) / 2;
          spr.setTextColor(C_EB_INK); y = uiWrapCentre(tmp, y, 210, lh, 5) + 2;
          if(small) fEndHard(); else fEnd();
        }
        fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
        char c[24]; snprintf(c, sizeof c, len == 1 ? "1 character" : "%d characters", (int)len);
        spr.drawString(c, 120 - spr.textWidth(c) / 2, y); fEndHard();
      }
      ppCard(132, 48, "USE IT",     "It reads right",   sel == 0, C_EB_BRASS, ppIconTick);
      ppCard(184, 48, "SCAN AGAIN", "Wrong or cut off", sel == 1, C_EB_BRASS, ppIconRedo);
      dispPush();
      for(;;){ btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
        if(btn1.isPressed() || btn3.isPressed()){ sel ^= 1; break; }
        if(btn2.isPressed()){ accept = sel == 0; decided = true; break; }
        if(btn4.isPressed()){ accept = false; decided = true; break; }
        esp_task_wdt_reset(); delay(10); }
      delay(150);
    }
    clearButtonPending();
    if(accept){ memcpy(out, tmp, len + 1); return true; }
    if(sel == 1) continue;   // SCAN AGAIN
    return false;
  }
}
// TYPE / SCAN QR, as the passphrase's "Enter the passphrase" screen. true with
// the text in out (cap >= PP_MAX + 1); false on BACK.
static bool pwTypeOrScan(const char* title, const char* what, char* out, size_t cap, uint32_t& lp, char* userOut){
  int sel = 0;
  for(;;){
    spr.fillSprite(C_BG);
    pwHead(title, "Type it, or scan a QR");
    ppCard(46,  62, "TYPE",    "With the buttons",          sel == 0, C_EB_BRASS, ppIconKeys);
    ppCard(114, 62, "SCAN QR", "From your phone or a page", sel == 1, C_EB_BRASS, ppIconQr);
    dispPush();
    clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
      if(btn1.isPressed() || btn3.isPressed()){ sel ^= 1; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    if(act == 1) continue;
    memset(out, 0, cap); int n = 0;
    bool ok = sel == 0 ? (ppPicker(title, C_EB_BRASS, out, &n) && n > 0) : pwScanText(what, out, cap, userOut);
    lp = millis();
    if(ok) return true;
    mbedtls_platform_zeroize(out, cap);
  }
}
static bool pkPinPad(char out[9], bool canCancel = false);   // below
// 4 Nov 2026 (Josh: an easier way to delete accounts): every password on this KEY
// at once. Behind the passkey PIN again (checked here against the PIN this life
// already holds: no secure-element attempt is spent) and a 3 s hold. Passkeys are
// not touched. One tombstone write and one index write (rk_delete_many).
static void pwDeleteAll(uint32_t& lp){
  const int n = favilla::rk_pw_count();
  if(n <= 0) return;
  { char l1[40]; snprintf(l1, sizeof l1, n == 1 ? "The 1 password on this KEY." : "All %d passwords on this KEY.", n);   // 5v: the count moved here, the head fits
    pkAsk("DELETE ALL", "Delete all?", l1, "Passkeys are kept.", "KEEP", "GO ON"); }
  clearButtonPending();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
    if(btn2.isPressed()) break; delay(10); }
  char pin[9] = {0};
  if(!pkPinPad(pin, true)){ mbedtls_platform_zeroize(pin, sizeof pin); return; }   // BACK on the first digit
  uint8_t d = 0; for(int i = 0; i < PIN_NEW_LEN; i++) d |= (uint8_t)(g_pkPin[i] ^ pin[i]);
  mbedtls_platform_zeroize(pin, sizeof pin);
  if(d || !g_pkPinHeld){ LOG_BOOT("[PW] delete all: wrong PIN, nothing deleted\n"); pkPageMsg("DELETE ALL", "Wrong PIN.", "Nothing was deleted."); pwWaitBack(lp); return; }
  auto draw = [&](float hold){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("DELETE ALL", 120, 14, C_EB_BRASS);
    char t[24]; snprintf(t, sizeof t, n == 1 ? "1 password" : "%d passwords", n);
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK); spr.drawString(t, 120 - spr.textWidth(t) / 2, 70);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* l = "The sites still have them: change"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 124); }
    { const char* l = "them there if you stop using them."; spr.drawString(l, 120 - spr.textWidth(l) / 2, 142); }
    fEndHard();
    { const char* t = "HOLD ENTER TO DELETE ALL"; int tr = 3; while(tr > 1 && uiTrackWidth(t, tr) > 228) tr--; uiTrackLabel(t, 120, 196, C_EB_BRASS, tr); }   // tightens, never clips
    if(hold > 0){ int w = (int)(176 * (hold > 1 ? 1 : hold)); spr.fillRect(32, 210, 176, 2, C_EB_LINE); spr.fillRect(32, 210, w, 2, C_EB_BRASS); }
    else uiTrackLabel("BACK TO KEEP THEM", 120, 216, C_EB_GREY);
    dispPush();
  };
  draw(0); clearButtonPending();
  uint32_t shownAt = millis(); float last = 0;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
    float h = holdSince(btn2, shownAt, 3000);
    if(h >= 1.0f){
      int* sl = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
      int m = 0, done = 0, skipped = 0, r = favilla::RK_E_NVS;
      if(sl){ const int c = favilla::rk_pw_count(); for(int i = 0; i < c && m < favilla::RK_MAX; i++){ int s = favilla::rk_pw_slot_at(i); if(s >= 0) sl[m++] = s; }
        pkPage("DELETE ALL", "Deleting", "Removing them from", "this KEY.", nullptr);
        r = favilla::rk_delete_many(sl, nullptr, m, &done, &skipped); free(sl); }
      LOG_BOOT("[PW] delete all: %d of %d deleted: %s\n", done, m, favilla::rk_err_name(r));
      char l1[40]; snprintf(l1, sizeof l1, done == 1 ? "1 password deleted." : "%d passwords deleted.", done);
      pkPageMsg("DELETE ALL", r == 0 ? l1 : "Not all were deleted.", r == 0 ? "Passkeys are kept." : favilla::rk_err_name(r));
      while(btn2.stable == LOW){ btn2.poll(); delay(5); }
      pwWaitBack(lp); return;
    } else if((h > 0) != (last > 0) || (h - last) > 0.04f){ last = h; draw(h); }
    btn2.isPressed();   // a tap is not a delete
    delay(10);
  }
}
// ── Sign in by QR (Vault phase 5 stage 1, 4 Nov 2026, Josh) ──────────────────
// The extension's login QR (or any QR of a site name), scanned from the top of
// PASSWORDS: the KEY finds the saved entries for that site in the sealed index
// (no G0 call) and opens the one to type. One exact or domain match opens
// straight away; several (or a username in the QR that picks one) show a short
// list; close names ("GitHub" for github.com) are listed, never opened alone;
// no match says so, which is what a lookalike site gets.
// Find and open the saved login for site (user picks among several). Returns
// 1 typed, 2 nothing typed (BACK), 3 no saved login. Shared by the QR and the
// browser channel (stage 2).
static int pwSignInFor(PwRow* R, int n, char* site, char* user, uint32_t& lp, bool autoAsk = false, bool offerSave = false);   // offerSave: the site came from the browser's address bar   // autoAsk: a browser asked on its own (no screen unless a strong match)
static void pwSignInByQr(PwRow* R, int n, uint32_t& lp){
  if(n == 0){ pkPageMsg("SIGN IN", "No passwords on this KEY yet.", "Make one with NEW ACCOUNT."); pwWaitBack(lp); return; }
  char site[PP_MAX + 1] = {0}, user[PP_MAX + 1] = {0};
  if(!pwScanText("sign in", site, sizeof site, user, false)){ lp = millis(); return; }
  lp = millis();
  pwSignInFor(R, n, site, user, lp);
  mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user);
}
// 7f (Josh's bench): a login saved under a close name ("Cloudflare") never
// lights the KEY up by itself. After it is typed from a browser ask, offer to
// save the site's address on it, so the next visit is a strong match.
static void pwOfferSaveSite(int idx, const char* site, uint32_t& lp){
  char nm[favilla::RK_SITE_MAX + 1]; loginqr::savedName(site, nm, sizeof nm);
  if(!nm[0] || !strchr(nm, '.')) return;
  auto draw = [&](){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("SAVE ADDRESS", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* l = "Save this address on the login?"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 58); }
    fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_INK);
    int y = uiWrapCentre(nm, 90, 210, 18, 2); fEnd();
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* l = "Then it comes up by itself here."; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 14); }
    { const char* l = "Only if this is the real site."; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 32); }
    fEndHard();
    uiCornerAnswers("SKIP", "SAVE");   // 11cw
    dispPush();
  };
  draw(); clearButtonPending();
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()){ lp = millis(); return; }
    if(btn2.isPressed()) break;
    btn1.isPressed(); btn3.isPressed();
    delay(10);
  }
  favilla::RkPass* e = (favilla::RkPass*)heap_caps_malloc(sizeof(favilla::RkPass), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!e){ pkPageMsg("SAVE ADDRESS", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct WipeE { favilla::RkPass* e; ~WipeE(){ favilla::rk_pw_wipe(e); free(e); } } we{e};
  pkPage("SAVE ADDRESS", "Saving", "Sealing it on the signer", "with the address.", nullptr);
  int r; r = RK_PIN(favilla::rk_pw_open(idx, e));
  if(r == 0){
    snprintf(e->site, sizeof e->site, "%s", nm);
    e->policy &= ~pwgen::POLICY_PENDING;
    int slot = -1; r = RK_PIN(favilla::rk_pw_save(e, &slot));
  }
  LOG_BOOT("[PW] save address on a close match: %s\n", r ? favilla::rk_err_name(r) : "saved");
  pkPageMsg("SAVE ADDRESS", r == 0 ? "Saved." : "Not saved.", r == 0 ? "Next time it comes up by itself." : pwOpenErr(r));
  pwWaitBack(lp); lp = millis();
}
static int pwSignInFor(PwRow* R, int n, char* site, char* user, uint32_t& lp, bool autoAsk, bool offerSave){
  // 11aw: the second page of a two-page sign-in. The username went to this
  // site within the last 60 s; the page now shows only a password box: type
  // that entry's password without a list, pressing Enter if the first step did.
  if(g_pwFields == 2 && g_pwTypedFields == 1 && g_pwTypedIdx >= 0 && millis() - g_pwTypedAt < 60000){
    for(int k = 0; k < n; k++){
      if(R[k].idx != g_pwTypedIdx || !R[k].lab) continue;
      if(loginqr::siteMatch(R[k].site, site) < 1) break;
      favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(R[k].idx, &L); g0_window_batch_end(); }
      if(r) break;
      const uint32_t t0 = g_pwTypedCount;
      if(dimActive) idleDimWake();
      LOG_BOOT("[PW] two-page sign-in: the password step for %s\n", site);
      pwType(R[k].idx, L, g_pwTypedSubmit, lp); lp = millis();
      g_pwTypedIdx = -1;   // one password step per username step
      return g_pwTypedCount != t0 ? 1 : 2;
    }
  }
  if(n == 0 && autoAsk) return 3;
  if(n == 0){ pkPageMsg("SIGN IN", "No passwords on this KEY yet.", "Make one with NEW ACCOUNT."); pwWaitBack(lp); return 3; }
  const uint32_t typed0 = g_pwTypedCount;
  struct Hit { int16_t idx; int8_t score; char site[64]; char user[48]; };
  Hit* hits = (Hit*)heap_caps_calloc(n, sizeof(Hit), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!hits){ pkPageMsg("SIGN IN", "Out of memory.", nullptr); pwWaitBack(lp); return 2; }
  struct Free { Hit* h; int n; ~Free(){ mbedtls_platform_zeroize(h, n * sizeof(Hit)); free(h); } } fr{hits, n};
  int nh = 0, best = 0, unread = 0;
  for(int k = 0; k < n; k++){
    if(!R[k].lab){ unread++; continue; }
    int sc = loginqr::siteMatch(R[k].site, site);
    if(!sc) continue;
    hits[nh].idx = R[k].idx; hits[nh].score = (int8_t)sc; snprintf(hits[nh].site, sizeof hits[nh].site, "%s", R[k].site); nh++;
    if(sc > best) best = sc;
  }
  { int w = 0; for(int k = 0; k < nh; k++) if(best >= 2 ? hits[k].score >= 2 : true) hits[w++] = hits[k]; nh = w; }   // strong matches hide close ones
  if(autoAsk && best < 2) return 3;   // asked on its own: close names never light the KEY up, and no match stays silent
  if(autoAsk && dimActive) idleDimWake();   // a login to offer: wake the screen for it
  // usernames for the list (and to let the QR's username pick one); LABELs, cached after the first
  const int LBL = nh < 12 ? nh : 12;
  if(nh > 1 || user[0]){
    pkPage("SIGN IN", "Finding it", "Reading the usernames", "for this site.", nullptr);
    g0_window_batch_begin();
    for(int k = 0; k < LBL; k++){ favilla::RkLabel L; if(!favilla::rk_pw_label(hits[k].idx, &L)) snprintf(hits[k].user, sizeof hits[k].user, "%s", L.user); mbedtls_platform_zeroize(&L, sizeof L); }
    g0_window_batch_end();
    if(user[0]){ int same = 0; for(int k = 0; k < LBL; k++) same += !strcasecmp(hits[k].user, user);
      if(same){ int w = 0; for(int k = 0; k < LBL; k++) if(!strcasecmp(hits[k].user, user)) hits[w++] = hits[k]; nh = w; } }
  }
  LOG_BOOT("[PW] sign in by QR: %d match%s (%s)%s%s\n", nh, nh == 1 ? "" : "es", best >= 3 ? "exact" : best == 2 ? "domain" : best == 1 ? "close" : "none",
           user[0] ? ", username in the QR" : "", unread ? ", some names not read yet" : "");
#ifdef FAVILLA_BLE_KBD
  const bool pickOffer = g_pwToApp || offerSave;   // 11av: the browser's ask too, not only the app's
#else
  const bool pickOffer = offerSave;
#endif
  if(nh == 0 && pickOffer){   // 9d: an app or a name iOS gave (not a domain), 11av: or a browser ask with nothing matching: offer the whole list
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("SIGN IN", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
    { const char* h = "No saved login"; spr.drawString(h, 120 - spr.textWidth(h) / 2, 62); }
    fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_BRASS);
    int y = uiWrapCentre(site, 104, 210, 18, 2); fEnd();
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* l = "Pick one of your logins?"; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 10); }
#ifdef FAVILLA_BLE_KBD
    if(g_pwToApp){   // 11bi (issue #38): or a new login for this site, made on the KEY
      const char* a = "DOWN"; const char* b = " for a new login"; const int x = 120 - (spr.textWidth(a) + spr.textWidth(b)) / 2;
      spr.setTextColor(C_EB_BRASS); spr.drawString(a, x, y + 28); spr.setTextColor(C_EB_GREY); spr.drawString(b, x + spr.textWidth(a), y + 28);
    }
#endif
    fEndHard();
    uiTrackLabel("ENTER TO PICK", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    bool pick = false, fresh = false;
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) break;
#ifdef FAVILLA_BLE_KBD
      if(g_pwToApp && btn1.isPressed()){ fresh = true; break; }
#endif
      if(btn2.isPressed()){ pick = true; break; } delay(10); }
    lp = millis();
#ifdef FAVILLA_BLE_KBD
    if(fresh) return pwFillNew(site, user, lp) ? 1 : 2;   // 11bi
#else
    (void)fresh;
#endif
    if(!pick) return 3;
    for(int k = 0; k < n; k++){ if(!R[k].lab) continue; hits[nh].idx = R[k].idx; hits[nh].score = 0; snprintf(hits[nh].site, sizeof hits[nh].site, "%s", R[k].site); nh++; }
    if(nh == 0){ pkPageMsg("SIGN IN", "The names are still being read.", "Try again in a moment."); pwWaitBack(lp); return 3; }
    const int L2 = nh < 12 ? nh : 12;   // usernames for the first rows (the rest show the site)
    pkPage("SIGN IN", "Finding them", "Reading the usernames.", nullptr, nullptr);
    g0_window_batch_begin();
    for(int k = 0; k < L2; k++){ favilla::RkLabel L; if(!favilla::rk_pw_label(hits[k].idx, &L)) snprintf(hits[k].user, sizeof hits[k].user, "%s", L.user); mbedtls_platform_zeroize(&L, sizeof L); }
    g0_window_batch_end();
    best = 0;   // the list below; leave() offers to save this name on the chosen entry
  } else
  if(nh == 0){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("SIGN IN", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
    { const char* h = "No saved login"; spr.drawString(h, 120 - spr.textWidth(h) / 2, 62); }
    fEndHard(); fSet(F_BRAND_B14); spr.setTextColor(C_EB_BRASS);
    int y = uiWrapCentre(site, 104, 210, 18, 2); fEnd();
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { const char* l = unread ? "Some names are still being read." : "Check the address bar: a lookalike"; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 10); }
    { const char* l = unread ? "Try again in a moment." : "site has no login on this KEY."; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 28); }
    fEndHard();
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); pwWaitBack(lp); return 3;
  }
  if(nh == 1 && best >= 2){ pwEntry(hits[0].idx, 0, 1, lp); lp = millis(); return g_pwTypedCount != typed0 ? 1 : 2; }
  int sel = 0, typedIdx = -1;
  auto leave = [&]() -> int {   // 7f: a close match typed from a browser ask: offer to save the address
    if(offerSave && best < 2 && typedIdx >= 0 && !pkLeaveNow()) pwOfferSaveSite(typedIdx, site, lp);
    return g_pwTypedCount != typed0 ? 1 : 2;
  };
  const int VIS = 3, CH = 42, PITCH = 46, Y0 = 52;
#ifdef FAVILLA_BLE_KBD
  const int extra = g_pwToApp ? 1 : 0;   // 11bi (issue #38): NEW LOGIN FOR <site>, the last row during the phone's FILL ask
#else
  const int extra = 0;
#endif
  const int rows = nh + extra;
  for(;;){
    if(pkLeaveNow()) return leave();   // 6c: no flash of this menu on the way out
    int off = 0; if(rows > VIS){ off = sel - 1; if(off < 0) off = 0; if(off > rows - VIS) off = rows - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel(best >= 2 ? "SIGN IN" : "CLOSE MATCHES", 120, 14, C_EB_BRASS);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    { char t[72]; snprintf(t, sizeof t, "for %s", site); pkFitText(t, sizeof t, 216, false); spr.drawString(t, 120 - spr.textWidth(t) / 2, 32); }
    fEndHard();
    for(int r = 0; r < VIS && off + r < rows; r++){
      if(off + r >= nh){   // 11bi: NEW LOGIN
        char fs[64]; snprintf(fs, sizeof fs, "for %s", site); fSet(F_BODY); pkFitText(fs, sizeof fs, 216 - 24 - 14, false); fEnd();
        uiListCard(12, Y0 + r * PITCH, 216, CH, off + r == sel, C_EB_BRASS, "NEW LOGIN", fs, 24);
        continue;
      }
      const Hit& h = hits[off + r]; char nm[64], us[64];
      snprintf(nm, sizeof nm, "%s", h.site); snprintf(us, sizeof us, "%s", h.user[0] ? h.user : (off + r < LBL ? "(no username)" : ""));
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
      fSet(F_BODY); pkFitText(us, sizeof us, 216 - 24 - 14, false); fEnd();
      uiListCard(12, Y0 + r * PITCH, 216, CH, off + r == sel, C_EB_BRASS, nm, us, 24);
    }
    if(rows > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 8; int thumb = TH * VIS / rows; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (rows - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    if(best < 2){ fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY); const char* l = "Not an exact match: check the site."; spr.drawString(l, 120 - spr.textWidth(l) / 2, 192 - 16); fEndHard(); }
    uiTrackLabel("ENTER TO OPEN", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return leave();
      if(btn1.isPressed()){ sel = (sel + 1) % rows; act = 1; } else if(btn3.isPressed()){ sel = (sel + rows - 1) % rows; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
#ifdef FAVILLA_BLE_KBD
    if(sel >= nh){ if(pwFillNew(site, user, lp)) return leave(); lp = millis(); continue; }   // 11bi: NEW LOGIN
#endif
    for(;;){ const uint32_t tc = g_pwTypedCount; int r = pwEntry(hits[sel].idx, sel, nh, lp); lp = millis(); if(g_pwTypedCount != tc) typedIdx = hits[sel].idx; if(r == 2){ sel = (sel + 1) % nh; continue; } break; }
    if(g_pwToApp && g_pwTypedCount != typed0) return leave();   // 9c: sent to the app: the ask is answered
  }
}
static void runPasswordsPage(uint32_t& lp){
  if(!g_pkPinHeld || !favilla::rk_ready()){ pkPageMsg("PASSWORDS", "Unlock the KEY to see them.", nullptr); pwWaitBack(lp); return; }
  if(!g0_v15_present()){ pkPageMsg("PASSWORDS", "The signer chip needs the v15 firmware.", "Listing passwords uses its LABEL operation."); pwWaitBack(lp); return; }
  PwRow* R = (PwRow*)heap_caps_malloc(sizeof(PwRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);   // PSRAM: site names, wiped on the way out
  if(!R){ pkPageMsg("PASSWORDS", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct Free { PwRow* p; ~Free(){ mbedtls_platform_zeroize(p, sizeof(PwRow) * favilla::RK_MAX); free(p); } } fr{R};
  int sel = 0, selSlot = -1; bool reopen = false; uint32_t quiet = 0;   // row 0 "Sign in by QR", row 1 "New password"; entries are rows H..n+H-1
  const int H = 2;   // 4 Nov 2026: header rows (phase 5 stage 1 added SIGN IN BY QR)
  const int VIS = 5, CH = 28, PITCH = 31, Y0 = 36;
  // 11az (13 Nov 2026, approved mock screen 9): fast scroll. A tap moves one row.
  // Held, UP or DOWN repeats after 0.4 s (8 rows a second), 25 a second after
  // 1.5 s (ruled 13 Nov: no letter step, the speed-up is enough). The repeat
  // stops at the ends (a tap still wraps round). Letting go stops on that row. The rows are not read again while a hold runs.
  int hDir = 0; uint32_t hT0 = 0, hLast = 0; bool hRep = false; int n = 0;
  for(;;){
    if(pkLeaveNow()) return;   // 6c: no flash of this menu on the way out
    if(!hRep) n = pwBuildRows(R);
    const int rows = n + H + (n > 0 ? 1 : 0);   // 4 Nov 2026: the last row is DELETE ALL
    const int delRow = n > 0 ? n + H : -1;
    if(selSlot >= 0 && !hRep){ for(int k = 0; k < n; k++) if(R[k].slot == selSlot){ sel = k + H; break; } }   // follow the entry as rows move
    if(sel >= rows) sel = rows - 1;
    selSlot = (sel >= H && sel < n + H) ? R[sel - H].slot : -1;
    if(reopen && sel >= H && sel < n + H){   // DOWN on an entry: straight to the next one in this order
      int r = pwEntry(R[sel - H].idx, sel - H, n, lp); lp = millis(); quiet = millis();
      if(r == 2){ sel = (sel - H + 1) % n + H; selSlot = R[sel - H].slot; continue; }
      reopen = false; continue;
    }
    int off = 0; if(rows > VIS){ off = sel - 2; if(off < 0) off = 0; if(off > rows - VIS) off = rows - VIS; }
    int unread = 0; for(int k = 0; k < n; k++) unread += !R[k].lab;
    // paint
    fEnd(); spr.fillSprite(C_BG);
    { char t[32]; if(unread) snprintf(t, sizeof t, "%d PASSWORDS, READING %d", n, unread); else snprintf(t, sizeof t, n == 1 ? "1 PASSWORD" : "%d PASSWORDS", n);
      uiTrackLabel(t, 120, 14, C_EB_BRASS, uiTrackWidth(t, 3) > 228 ? 1 : 3); }
    const uint16_t kRowDim = ebMix(C_BG, C_EB_GREY, 115);   // the other rows while a hold runs (mock: 45 %)
    for(int r = 0; r < VIS && off + r < rows; r++){
      int row = off + r; char nm[64]; uint16_t col = 0; bool old = false;
      if(row == 0){ snprintf(nm, sizeof nm, "%s", "SIGN IN BY QR"); col = row == sel ? 0 : C_EB_BRASS; }
      else if(row == 1){ snprintf(nm, sizeof nm, "%s", "NEW ACCOUNT"); col = row == sel ? 0 : C_EB_BRASS; }
      else if(row == delRow){ snprintf(nm, sizeof nm, "%s", "DELETE ALL"); col = row == sel ? 0 : C_EB_GREY; }
      else if(!R[row - H].lab){ snprintf(nm, sizeof nm, "%s", "Reading..."); col = C_EB_GREY; }
      else { old = pwIsOld(R[row - H].site); pwOldBase(R[row - H].site, nm, sizeof nm); if(R[row - H].pend && row != sel) col = C_EB_BRASS; }
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14 - (old ? 34 : 0), true); fEnd();
      if(hRep && row != sel) col = kRowDim;
      uiListCard(12, Y0 + r * PITCH, 216, CH, row == sel, C_EB_BRASS, nm, nullptr, 24, col);
      if(old){ fSet(F_BRAND_B12); spr.setTextColor(hRep && row != sel ? kRowDim : C_EB_BRASS); spr.drawString("OLD", 12 + 216 - 14 - spr.textWidth("OLD"), Y0 + r * PITCH + 8); fEnd(); }   // 11az: kept by CHANGE PASSWORD
    }
    if(rows > VIS){
      const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 6;
      int thumb = TH * VIS / rows; if(thumb < 8) thumb = 8;
      int ty = TY + (TH - thumb) * off / (rows - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS);
    }
    if(hRep){
      uiTrackLabel("LET GO TO STOP", 120, 196, C_EB_BRASS);
      char t[32];
      if(sel >= H && sel < n + H) snprintf(t, sizeof t, "%d OF %d", sel - H + 1, n); else t[0] = 0;
      if(t[0]) uiTrackLabel(t, 120, 216, C_EB_GREY);
    } else {
      uiTrackLabel("ENTER TO OPEN", 120, 196, C_EB_BRASS);
      uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    }
    dispPush();
    // wait: buttons first; when they are quiet, read one more name (visible rows first)
    for(int r = 0; r < VIS; r++){ int row = off + r; g_pwPrefer[r] = (row >= H && row < n + H) ? R[row - H].idx : -1; }
    g_pwPreferN = VIS;
    const uint32_t gen = g_pwBgGen;
    int act = 0;   // 1 moved, 2 open, 3 a name arrived, -1 leave
    while(!act){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) act = -1;
      else if(btn1.isPressed()){ if(rows > 1){ sel = (sel + 1) % rows; act = 1; hDir = 1; hT0 = btn1.pressStart; hLast = millis(); } }
      else if(btn3.isPressed()){ if(rows > 1){ sel = (sel + rows - 1) % rows; act = 1; hDir = -1; hT0 = btn3.pressStart; hLast = millis(); } }
      else if(btn2.isPressed()){ act = 2; hDir = 0; }
      else if(hDir){   // the hold
        Button& b = hDir > 0 ? btn1 : btn3;
        if(b.stable != LOW || b.pressStart != hT0){ hDir = 0; if(hRep){ hRep = false; act = 1; } }   // let go: stop on this row
        else {
          const uint32_t el = millis() - hT0;
          if(el >= 400){
            const uint32_t gap = el >= 1500 ? 40 : 125;
            if(millis() - hLast >= gap){
              hLast = millis();
              int ns = sel + hDir;
              if(ns < 0) ns = 0;
              if(ns > rows - 1) ns = rows - 1;
              if(ns != sel || !hRep){ sel = ns; hRep = true; act = 1; }
            }
          }
        }
      }
      else if(unread && g_pwBgGen != gen) act = 3;   // pkSerialTick read one more name
      delay(10);
    }
    g_pwPreferN = 0;
    if(act < 0) return;
    if(act != 1){ hDir = 0; hRep = false; }
    if(act == 1){ lp = millis(); quiet = millis(); selSlot = (sel >= H && sel < n + H) ? R[sel - H].slot : -1; continue; }
    if(act == 3) continue;
    if(sel == 0){ pwSignInByQr(R, n, lp); lp = millis(); quiet = millis(); pwBgReset(); continue; }
    if(sel == 1){ pwNew(lp); lp = millis(); quiet = millis(); pwBgReset(); continue; }
    if(sel == delRow){ pwDeleteAll(lp); lp = millis(); quiet = millis(); pwBgReset(); sel = 0; selSlot = -1; continue; }
    if(!R[sel - H].lab){ continue; }   // not read yet: it will be in a moment
    { int r = pwEntry(R[sel - H].idx, sel - H, n, lp); lp = millis(); quiet = millis(); pwBgReset();
      if(r == 2){ sel = (sel - H + 1) % n + H; selSlot = R[sel - H].slot; reopen = true; } }
  }
}

// 4 Nov 2026 (Josh): PASSKEY > Settings holds "In NOSTR mode" and the usernames book.
static void runUsernamesPage(uint32_t& lp);
static void runOpenLimitPage(uint32_t& lp);   // 11ep
#if defined(FAVILLA_VCHAN)
static void runBrowsersPage(uint32_t& lp);
static int chanPairedCount();
#endif
#ifdef FAVILLA_BLE_KBD
static void runBluetoothPage(uint32_t& lp);
#endif
// ── 9i (7 Nov 2026, G0 v17): one-time codes ───────────────────────────────────
// Josh's ruling B: the secret never leaves the G0. ADD BY QR reads an
// otpauth://totp/ QR (otpauth.h); the secret passes through the ESP32 once, to
// be sealed, and is wiped. A code is computed by the G0 (VAULT TOTP) from the
// KEY's clock; each costs one of the sitting's record opens. The phone app can
// ask for one over the app channel with its own time (ble_app.inc).
#include "otpauth.h"
static bool totpTimeKnown(){ return time(nullptr) > 1700000000; }
static bool totpYesNo(uint32_t& lp){
  clearButtonPending();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    if(btn2.isPressed()) return true;
    delay(10); }
}
// The camera, for a code QR (up to the QR buffer): pwScanText caps text at 100.
static int totpScan(otpauth::Entry* e){
  for(;;){
    spr.fillSprite(C_BG);
    pwHead("ADD A CODE", "Hold the setup QR to the camera");
    dispPush(); delay(400);
    pwrBoost(); camHoldWake();   // 10u: the scan's own hold, and its record
    cameraStart(); qrFound = false;
    if(!cameraRunning) return -1;
    for(int f = 0; f < 4; f++){ camera_fb_t* sf = esp_camera_fb_get(); if(sf) esp_camera_fb_return(sf); vTaskDelay(pdMS_TO_TICKS(25)); }
    qrResultBuf[0] = 0; qrDiagReset(); qrDumpReset();
    g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
    unsigned long qs = millis(), lastQR = 0; bool got = false;
    while(millis() - qs < 30000){
      btn4.poll();
      if(btn4.isPressed()) break;
      if(!qrFound && (millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)){ qrScanOnce(); lastQR = millis(); delay(5); }
      if(qrFound){ qrFound = false; got = true; break; }
      pkTripwire(); delay(10);
    }
    g_airgapLivePreview = false; cameraStop(); clearButtonPending();
    if(!got) return -1;
    size_t len = strnlen(qrResultBuf, QR_RESULT_SZ);
    while(len && (qrResultBuf[len - 1] == '\n' || qrResultBuf[len - 1] == '\r' || qrResultBuf[len - 1] == ' ')) len--;
    const int r = otpauth::parse(qrResultBuf, len, e);
    mbedtls_platform_zeroize(qrResultBuf, QR_RESULT_SZ);
    LOG_BOOT("[OTP] setup QR scanned: %s\n", r == otpauth::OK ? "ok" : otpauth::errText(r));
    if(r == otpauth::OK) return 0;
    dispError(otpauth::errText(r)); errorPause();
  }
}
// The code, grouped for reading: 123 456, 1234 5678, 1234 567.
static void totpFormat(uint32_t code, uint8_t digits, char* out, size_t cap){
  char d[12]; snprintf(d, sizeof d, "%0*lu", (int)digits, (unsigned long)code);
  const int cut = digits == 6 ? 3 : 4;
  snprintf(out, cap, "%.*s %s", cut, d, d + cut);
}
// ── 11v (11 Nov 2026, Josh: "how do we make 2fa link to an account") ────────
// Which password entry a code belongs to. Scored from what the setup QR says:
// the account label against usernames (an email is near-unique: +4), the
// issuer against site names ("ProtonMail" and proton.me: +2). One clear best
// gets a yes/no page; otherwise the list, best first, with NO ACCOUNT last.
// Returns 1 linked (pw slot, site and username copied out), 0 no account, -1 left.
static void totpNorm(const char* in, char* out, size_t cap){
  size_t n = 0; for(const char* c = in; *c && n + 1 < cap; c++){ char x = *c; if(x == ' ') continue; if(x >= 'A' && x <= 'Z') x += 32; out[n++] = x; } out[n] = 0;
}
static int totpScore(const char* issuer, const char* acct, const favilla::RkRow& r){
  int sc = 0;
  if(acct && acct[0] && r.userKnown && r.user[0] && !strcasecmp(acct, r.user)) sc += 4;
  if(issuer && issuer[0] && r.nameKnown && r.site[0]){
    if(otpauth::siteMatch(issuer, r.site) || otpauth::siteMatch(r.site, issuer)) sc += 2;
    else {
      char a[72], b[72]; totpNorm(issuer, a, sizeof a); totpNorm(r.site, b, sizeof b);
      const char* d = b; if(!strncmp(d, "www.", 4)) d += 4;
      char lab[72]; size_t ln = 0; for(const char* c = d; *c && *c != '.' && *c != '/' && ln + 1 < sizeof lab; c++) lab[ln++] = *c; lab[ln] = 0;
      if(ln >= 3 && strstr(a, lab)) sc += 2;                 // "protonmail" holds "proton"
      else if(strlen(a) >= 3 && strstr(b, a)) sc += 2;       // the site name holds the issuer
    }
  }
  return sc;
}
static int totpPickAccount(const char* issuer, const char* acct, int* pwSlot, char* siteOut, size_t siteCap, char* userOut, size_t userCap, uint32_t& lp){
  *pwSlot = -1;
  favilla::RkRow* rows = (favilla::RkRow*)heap_caps_malloc(sizeof(favilla::RkRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  int* ord = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  int* scs = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!rows || !ord || !scs){ free(rows); free(ord); free(scs); return 0; }
  struct Free { favilla::RkRow* r; int* o; int* c; ~Free(){ mbedtls_platform_zeroize(r, sizeof(favilla::RkRow) * favilla::RK_MAX); free(r); free(o); free(c); } } fr{rows, ord, scs};
  const int n = favilla::rk_pw_rows(rows, favilla::RK_MAX);
  if(n == 0) return 0;   // nothing to link to: saved under the QR's own name
  for(int i = 0; i < n; i++){ scs[i] = totpScore(issuer, acct, rows[i]); ord[i] = i; }
  for(int i = 1; i < n; i++){ int k = ord[i], j = i; while(j > 0 && scs[ord[j - 1]] < scs[k]){ ord[j] = ord[j - 1]; j--; } ord[j] = k; }   // best first, stable
  const int best = scs[ord[0]];
  const bool clear = best >= 2 && (n == 1 || scs[ord[1]] < best);
  auto take = [&](int i){
    *pwSlot = rows[i].slot;
    snprintf(siteOut, siteCap, "%s", rows[i].nameKnown && rows[i].site[0] ? rows[i].site : (issuer && issuer[0] ? issuer : "site"));
    snprintf(userOut, userCap, "%s", rows[i].userKnown && rows[i].user[0] ? rows[i].user : (acct ? acct : ""));
    return 1;
  };
  int sel = 0; bool list = !clear;
  if(clear){
    char l1[64], l2[64];
    snprintf(l1, sizeof l1, "%s", rows[ord[0]].site); snprintf(l2, sizeof l2, "%s", rows[ord[0]].userKnown && rows[ord[0]].user[0] ? rows[ord[0]].user : "(username not read yet)");
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); pkFitText(l1, sizeof l1, 216, false); pkFitText(l2, sizeof l2, 216, false); fEndHard();
    g_pkAskNo = "LEAVE"; g_pkAskYes = "LINK";   // 11cw: corners; DOWN still offers another account
    pkPage("ADD A CODE", "This account?", l1, l2, nullptr); g_pkAskNo = g_pkAskYes = nullptr;
    uiTrackLabel("DOWN FOR ANOTHER", 120, 186, C_EB_GREY); dispPush();
    clearButtonPending();
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp)) return -1;
      if(btn4.isPressed()) return 0;
      if(btn2.isPressed()) return take(ord[0]);
      if(btn1.isPressed()){ list = true; break; }
      delay(10); }
  }
  // the list: entries best first, NO ACCOUNT last
  const int rowsN = n + 1, VIS = 3, CH = 42, PITCH = 46, Y0 = 34;
  for(;;){
    int off = 0; if(rowsN > VIS){ off = sel - 1; if(off < 0) off = 0; if(off > rowsN - VIS) off = rowsN - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("WHICH ACCOUNT?", 120, 14, C_EB_BRASS);
    for(int r = 0; r < VIS && off + r < rowsN; r++){
      const int row = off + r, y = Y0 + r * PITCH;
      if(row == n){ uiListCard(12, y, 216, CH, row == sel, C_EB_BRASS, "NO ACCOUNT", "Keep the QR's own name", 24, row == sel ? 0 : C_EB_BRASS); continue; }
      const favilla::RkRow& w = rows[ord[row]];
      char nm[48], sb[48];
      snprintf(nm, sizeof nm, "%s", w.nameKnown && w.site[0] ? w.site : "(not read yet)"); snprintf(sb, sizeof sb, "%s", w.userKnown ? w.user : "");
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
      fSet(F_BODY); pkFitText(sb, sizeof sb, 216 - 24 - 14, false); fEnd();
      uiListCard(12, y, 216, CH, row == sel, C_EB_BRASS, nm, sb[0] ? sb : nullptr, 24);
    }
    if(rowsN > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 8; int thumb = TH * VIS / rowsN; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (rowsN - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    uiCornerAnswers("LEAVE", sel == n ? "NO ACCOUNT" : "LINK");   // 11cw
    dispPush();
    clearButtonPending();
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp)) return -1;
      if(btn4.isPressed()) return 0;
      if(btn1.isPressed()){ sel = (sel + 1) % rowsN; break; }
      if(btn3.isPressed()){ sel = (sel + rowsN - 1) % rowsN; break; }
      if(btn2.isPressed()){ lp = millis(); return sel == n ? 0 : take(ord[sel]); }
      delay(10); }
  }
}
// A code for one entry, on the KEY's screen. ENTER for a new one, DOWN to delete, UP to link it to an account.
// 11y (11 Nov 2026, Josh: "make it auto change the code every 30 secs"): when the
// countdown ends the next code is fetched by itself, up to TOTP_AUTO times in a row
// (each code is one of the sitting's record opens), then ENTER again.
static constexpr int TOTP_AUTO = 3;
static void totpShow(const favilla::RkTotp& t, uint32_t& lp){
  if(!totpTimeKnown()){ pkPageMsg("CODES", "The KEY does not know the time.", "Open the Favilla app on your paired iPhone: the KEY takes the time when it connects."); pwWaitBack(lp); return; }
  int autoLeft = TOTP_AUTO;
  for(;;){
    pkPage("CODES", "Working", "Computing the code", "in the signer chip.", nullptr);
    const uint64_t now = (uint64_t)time(nullptr);
    uint32_t code = 0; uint8_t dg = 0, per = 30;
    const int r = rkWithPin([&]()->int{ return favilla::rk_totp_code(t.slot, now, &code, &dg, &per); }, nullptr);   // 25 Nov 2026: the PIN if the limit stopped it
    LOG_BOOT("[OTP] code on the KEY for slot %d: %s | record opens left this sitting: %d\n", t.slot, r == 0 ? "ok" : favilla::rk_err_name(r), favilla::rk_open_left());
    if(r){ pkPageMsg("CODES", "No code.", r == favilla::RK_E_BUDGET ? "The vault limit needs your PIN: lock and unlock the KEY." : favilla::rk_err_name(r)); pwWaitBack(lp); return; }
    char c[16]; totpFormat(code, dg, c, sizeof c); code = 0;
    const uint32_t period = per ? per : 30;   // the record's own period, from the G0
    int shown = -1; bool again = false, del = false, link = false;
    const int linkedPw = favilla::rk_totp_linked_pw(t.slot);   // 11v
    const uint64_t slot0 = (uint64_t)time(nullptr) / period;   // the period this code is for
    clearButtonPending();
    for(;;){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()){ mbedtls_platform_zeroize(c, sizeof c); return; }
      if(btn2.isPressed()){ again = true; autoLeft = TOTP_AUTO; break; }
      if(btn1.isPressed()){ del = true; break; }
      if(btn3.isPressed()){ link = true; break; }
      // 11y: the period ended: the next code by itself, while the automatic refreshes last
      if(autoLeft > 0 && (uint64_t)time(nullptr) / period != slot0 && favilla::rk_open_left() != 0 && favilla::rk_open_left() != 1){ autoLeft--; again = true; lp = millis(); break; }
      const int left = (int)(period - ((uint64_t)time(nullptr) % period));
      if(left != shown){
        shown = left; lastActivity = millis();
        fEnd(); spr.fillSprite(C_BG);
        uiTrackLabel("CODE", 120, 14, C_EB_BRASS);
        fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
        { char l[96]; snprintf(l, sizeof l, "%s", t.site); pkFitText(l, sizeof l, 216, false); spr.drawString(l, 120 - spr.textWidth(l) / 2, 40); }
        if(t.acct[0]){ char l[96]; snprintf(l, sizeof l, "%s", t.acct); pkFitText(l, sizeof l, 216, false); spr.drawString(l, 120 - spr.textWidth(l) / 2, 58); }
        fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
        spr.drawString(c, 120 - spr.textWidth(c) / 2, 96); fEndHard();
        // 11ae (11 Nov 2026, Josh): the countdown says it all, so no "comes by
        // itself" line (it overflowed the width anyway); the opens budget only
        // when it is nearly spent; ENTER only once the automatic refreshes end.
        { char l[40]; const int ol = favilla::rk_open_left();
          if(ol >= 0 && ol <= 3) snprintf(l, sizeof l, "%d S LEFT, %d OPENS LEFT", left, ol); else snprintf(l, sizeof l, "%d S LEFT", left);
          uiTrackLabel(l, 120, 140, C_EB_GREY); }
        fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
        { const char* l = linkedPw >= 0 ? "UP to unlink, DOWN to delete" : "UP to link an account, DOWN to delete"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 162); }
        fEndHard();
        if(autoLeft <= 0) uiTrackLabel("ENTER FOR A NEW CODE", 120, 196, C_EB_BRASS);
        uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
        dispPush();
      }
      delay(20);
    }
    mbedtls_platform_zeroize(c, sizeof c);
    lp = millis();
    if(again) continue;
    if(link){   // 11v
      if(linkedPw >= 0){
        pkAsk("CODES", "Unlink it?", "The code stays on the KEY;", "it just belongs to no account.", "KEEP", "UNLINK");
        if(totpYesNo(lp)){ const int r = favilla::rk_totp_link(t.slot, -1); pkPageMsg("CODES", r == 0 ? "Unlinked." : "Not unlinked.", r == 0 ? nullptr : favilla::rk_err_name(r)); pwWaitBack(lp); }
        return;
      }
      int pw = -1; char st[favilla::RK_SITE_MAX + 1], us[favilla::RK_PW_FIELD_MAX + 1];
      const int pr = totpPickAccount(t.site, t.acct, &pw, st, sizeof st, us, sizeof us, lp);
      if(pr == 1){ const int r = favilla::rk_totp_link(t.slot, pw); LOG_BOOT("[OTP] code linked to an account: %s\n", r == 0 ? "ok" : favilla::rk_err_name(r));
        pkPageMsg("CODES", r == 0 ? "Linked." : "Not linked.", r == 0 ? "Sign-ins for that account now offer this code." : favilla::rk_err_name(r)); pwWaitBack(lp); }
      mbedtls_platform_zeroize(st, sizeof st); mbedtls_platform_zeroize(us, sizeof us);
      return;
    }
    if(del){
      pkAsk("CODES", "Delete it?", "The site still asks for codes:", "turn them off there first.", "KEEP", "DELETE");
      if(!totpYesNo(lp)) continue;
      const int de = favilla::rk_delete(t.slot);
      pkPageMsg("CODES", de == 0 ? "Deleted from this KEY." : "Could not delete it.", de == 0 ? "Keep the site's backup codes until two-step is moved." : favilla::rk_err_name(de));
      pwWaitBack(lp); return;
    }
  }
}
static void runCodesPage(uint32_t& lp){
  if(!g_pkPinHeld || !favilla::rk_ready()){ pkPageMsg("CODES", "Unlock the KEY to see them.", nullptr); pwWaitBack(lp); return; }
  if(!g0_v17_present()){ pkPageMsg("CODES", "The signer chip needs the v17 firmware.", "It computes the codes so the secret never leaves it."); pwWaitBack(lp); return; }
  favilla::RkTotp* T = (favilla::RkTotp*)heap_caps_malloc(sizeof(favilla::RkTotp) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!T){ pkPageMsg("CODES", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct Free { favilla::RkTotp* p; ~Free(){ mbedtls_platform_zeroize(p, sizeof(favilla::RkTotp) * favilla::RK_MAX); free(p); } } fr{T};
  int sel = 0;
  const int VIS = 3, CH = 42, PITCH = 46, Y0 = 34;   // the picker's cards: name and account
  for(;;){
    if(pkLeaveNow()) return;
    const int n = favilla::rk_totp_rows(T, favilla::RK_MAX);
    const int rows = n + 1;
    if(sel >= rows) sel = rows - 1;
    int off = 0; if(rows > VIS){ off = sel - 1; if(off < 0) off = 0; if(off > rows - VIS) off = rows - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    { char h[24]; snprintf(h, sizeof h, n == 1 ? "1 CODE" : "%d CODES", n); uiTrackLabel(h, 120, 14, C_EB_BRASS); }
    for(int r = 0; r < VIS && off + r < rows; r++){
      const int row = off + r, y = Y0 + r * PITCH;
      if(row == 0){ uiListCard(12, y, 216, CH, row == sel, C_EB_BRASS, "ADD A CODE", "Scan the setup QR or type its key", 24, row == sel ? 0 : C_EB_BRASS); continue; }
      const favilla::RkTotp& t = T[row - 1];
      char nm[48], sb[48];
      snprintf(nm, sizeof nm, "%s", t.known ? t.site : "(not read yet)"); snprintf(sb, sizeof sb, "%s", t.known ? t.acct : "");
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
      fSet(F_BODY); pkFitText(sb, sizeof sb, 216 - 24 - 14, false); fEnd();
      uiListCard(12, y, 216, CH, row == sel, C_EB_BRASS, nm, sb[0] ? sb : nullptr, 24);
    }
    if(rows > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 8; int thumb = TH * VIS / rows; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (rows - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    uiTrackLabel(sel == 0 ? "ENTER TO ADD ONE" : "ENTER TO SHOW", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush();
    int act = 0;
    clearButtonPending();
    while(!act){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % rows; act = 1; }
      else if(btn3.isPressed()){ sel = (sel + rows - 1) % rows; act = 1; }
      else if(btn2.isPressed()) act = 2;
      delay(10);
    }
    lp = millis();
    if(act == 1) continue;
    if(sel > 0){ totpShow(T[sel - 1], lp); lp = millis(); continue; }
    otpauth::Entry* e = (otpauth::Entry*)heap_caps_malloc(sizeof(otpauth::Entry), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(!e){ pkPageMsg("CODES", "Out of memory.", nullptr); pwWaitBack(lp); continue; }
    // 11x (11 Nov 2026, Josh: "some sites dont do QR they have words"): SCAN QR or
    // TYPE the setup key (base32, 6 digits every 30 s; other settings need a QR,
    // which the PWA and the extension can make from the key).
    int how = -1;
    { int sel = 0;
      for(;;){
        spr.fillSprite(C_BG);
        pwHead("ADD A CODE", "Scan the setup QR, or type its key");
        ppCard(46,  62, "SCAN QR", "The site's setup QR",       sel == 0, C_EB_BRASS, ppIconQr);
        ppCard(114, 62, "TYPE",    "The key shown as letters",  sel == 1, C_EB_BRASS, ppIconKeys);
        dispPush(); clearButtonPending();
        int act = 0;
        while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
          if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()){ act = 3; break; }
          if(btn1.isPressed() || btn3.isPressed()){ sel ^= 1; act = 1; } else if(btn2.isPressed()) act = 2;
          delay(10); }
        if(act == 1) continue;
        if(act == 2) how = sel;
        break;
      } }
    bool got = false;
    if(how == 0) got = totpScan(e) == 0;
    else if(how == 1){
      memset(e, 0, sizeof *e); e->digits = 6; e->period = 30;
      char key[PP_MAX + 1]; int kn = 0;
      for(;;){
        memset(key, 0, sizeof key); kn = 0;
        if(!ppPicker("SETUP KEY", C_EB_BRASS, key, &kn) || kn <= 0) break;
        const int r = otpauth::b32(key, (size_t)kn, e->secret, otpauth::SECRET_MAX, &e->secretN);
        mbedtls_platform_zeroize(key, sizeof key);
        if(r == otpauth::OK && e->secretN >= 5){ got = true; break; }
        pkPageMsg("SETUP KEY", "That is not a setup key.", r == otpauth::BAD_SECRET ? "Only the letters A to Z and the digits 2 to 7." : "It is too short. Check it against the site.");
        pwWaitBack(lp);
      }
      mbedtls_platform_zeroize(key, sizeof key);
      lp = millis();
    }
    if(got){
      // 11v: which account it belongs to, picked from the QR's issuer and account label
      int pw = -1; char st[favilla::RK_SITE_MAX + 1], us[favilla::RK_PW_FIELD_MAX + 1];
      int pr = totpPickAccount(e->site, e->acct, &pw, st, sizeof st, us, sizeof us, lp);
      if(pr == 0 && !e->site[0]){   // typed, no account picked: the site has to be named
        char nm[PP_MAX + 1] = {0}; int nn = 0;
        if(ppPicker("NAME THE SITE", C_EB_BRASS, nm, &nn) && nn > 0) snprintf(e->site, sizeof e->site, "%.*s", (int)(nn < (int)otpauth::FIELD_MAX ? nn : (int)otpauth::FIELD_MAX), nm);
        else pr = -1;
        lp = millis();
      }
      if(pr >= 0){
        const char* site = pr == 1 ? st : e->site; const char* acct = pr == 1 ? us : e->acct;
        char l1[64], l2[64]; snprintf(l1, sizeof l1, "%s", site); snprintf(l2, sizeof l2, "%s", acct[0] ? acct : "no account name");
        fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); pkFitText(l1, sizeof l1, 216, false); pkFitText(l2, sizeof l2, 216, false); fEndHard();   // the font pkPage draws its lines in
        pkAsk("ADD A CODE", "Save it?", l1, l2, "CANCEL", "SAVE");
        if(totpYesNo(lp)){
          pkPage("ADD A CODE", "Working", "Sealing the secret", "in the signer chip.", nullptr);
          int ts = -1;
          const int r = favilla::rk_totp_save(site, acct, e->secret, e->secretN, e->digits, e->period, &ts);
          LOG_BOOT("[OTP] code saved: %s (%d digits, %d s)\n", r == 0 ? "ok" : favilla::rk_err_name(r), (int)e->digits, (int)e->period);
          if(r == 0 && pr == 1 && ts >= 0){ const int lr = favilla::rk_totp_link(ts, pw); LOG_BOOT("[OTP] linked to the account: %s\n", lr == 0 ? "ok" : favilla::rk_err_name(lr)); }
          pkPageMsg("ADD A CODE", r == 0 ? "Saved." : "Not saved.", r == 0 ? "Enter a code from it on the site to finish turning two-step on." : favilla::rk_err_name(r));
          pwWaitBack(lp);
        }
      }
      mbedtls_platform_zeroize(st, sizeof st); mbedtls_platform_zeroize(us, sizeof us);
    } else if(cameraRunning == false){ /* BACK or 30 s, or the camera error was shown */ }
    mbedtls_platform_zeroize(e, sizeof *e); free(e);
    lp = millis();
  }
}
static void pkSettings(uint32_t& lp){
  // 4 Nov 2026 (phase 6): rows built per build; three on screen, the list
  // scrolls (same cards and type as before, a thumb when there are more).
  enum { R_USERS, R_LIMIT, R_BROWSERS, R_BT, R_BATT, R_FLASH };   // v19: the "In NOSTR mode" row is gone (one door, one PIN); 11ct: R_BATT; 11ep: R_LIMIT
  int rows[6], nr = 0;
  rows[nr++] = R_USERS;
  rows[nr++] = R_LIMIT;   // 11ep: the vault limit (G0 v24)
#if defined(FAVILLA_VCHAN)
  rows[nr++] = R_BROWSERS;
#endif
#ifdef FAVILLA_BLE_KBD
  rows[nr++] = R_BT;
#endif
#ifdef FAVILLA_BENCH_PROBES
  rows[nr++] = R_BATT;    // 11ct: the Battery page and its dark view in this life too (bench builds only)
#endif
  rows[nr++] = R_FLASH;   // 11u: the flashing port from this life too (the channel builds have no serial port for esptool)
  int sel = 0;
  for(;;){
    if(pkLeaveNow()) return;   // 6c: no flash of this menu on the way out
    int nub = -1;
    { char (*ub)[favilla::RK_PW_FIELD_MAX + 1] = (char (*)[favilla::RK_PW_FIELD_MAX + 1])heap_caps_calloc(favilla::RK_UB_MAX, favilla::RK_PW_FIELD_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
      if(ub){ nub = favilla::rk_ub_list(ub, favilla::RK_UB_MAX); mbedtls_platform_zeroize(ub, favilla::RK_UB_MAX * (favilla::RK_PW_FIELD_MAX + 1)); free(ub); } }
    favilla::RkLimit lim; favilla::rk_limit_read(&lim);   // 11ep
    const int VIS = 3;
    auto draw = [&](){   // 11cy: plain rows
      static int off = 0;
      const char* nm[6]; const char* vl[6]; static char dv[6][32];
      for(int r = 0; r < nr; r++){
        char* d = dv[r]; d[0] = 0;
        switch(rows[r]){
          case R_USERS: nm[r] = "Usernames";
            if(nub < 0) snprintf(d, 32, "%s", "Locked"); else snprintf(d, 32, nub == 0 ? "None yet" : nub == 1 ? "1 saved" : "%d saved", nub); break;
          case R_LIMIT: nm[r] = "Open limit";
            if(lim.next != lim.now) snprintf(d, 32, lim.next ? "%d, next restart" : "None, next restart", lim.next);
            else snprintf(d, 32, lim.now ? "%d per sitting" : "No limit", lim.now); break;
#if defined(FAVILLA_VCHAN)
          case R_BROWSERS: { nm[r] = "Browsers"; int nb = chanPairedCount(); snprintf(d, 32, nb == 0 ? "None paired" : nb == 1 ? "1 paired" : "%d paired", nb); } break;
#endif
#ifdef FAVILLA_BLE_KBD
          case R_BT: { nm[r] = "Bluetooth"; const bool set = blek::settingOn();
            if(g_btLife) snprintf(d, 32, "%s", !set ? "Off from next start" : blek::ready() ? "Connected" : "On");
            else snprintf(d, 32, "%s", set ? "On from next start" : "Off"); } break;
#endif
#ifdef FAVILLA_BENCH_PROBES
          case R_BATT: nm[r] = "Battery"; break;   // 11cy: actions carry no status
#endif
          case R_FLASH: nm[r] = "Flash mode"; break;
        }
        vl[r] = d;
      }
      uiRows("SETTINGS", nm, vl, nr, sel, off);
      dispPush();
    };
    draw(); clearButtonPending();
    int choice = -1;
    while(choice < 0){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % nr; draw(); }
      else if(btn3.isPressed()){ sel = (sel + nr - 1) % nr; draw(); }
      if(btn2.isPressed()) choice = rows[sel];
      delay(10);
    }
    if(choice == R_USERS) runUsernamesPage(lp);
    else if(choice == R_LIMIT) runOpenLimitPage(lp);
#if defined(FAVILLA_VCHAN)
    else if(choice == R_BROWSERS) runBrowsersPage(lp);
#endif
#ifdef FAVILLA_BLE_KBD
    else if(choice == R_BT) runBluetoothPage(lp);
#endif
#ifdef FAVILLA_BENCH_PROBES
    else if(choice == R_BATT){ g_lifeMenuTick = [](){ pkSerialTick(); pkTripwire(); }; lastActivity = millis(); runBatteryPage(); g_lifeMenuTick = nullptr; }   // 11cu: the dim timer starts at the open
#endif
    else if(choice == R_FLASH) runFlashModePage();
    lp = millis();
  }
}
// 11ep (25 Nov 2026): Settings > Open limit. How many records a sitting may open
// and how many site tags it may make (every save makes one) before the KEY asks
// for the PIN again. No limit is the default. The G0 holds it: a stricter one
// applies at once, a looser one (or none) from the next restart, so code on the
// main chip cannot loosen the limit it is held to without a restart.
static void runOpenLimitPage(uint32_t& lp){
  static const uint8_t V[6] = { 0, 8, 16, 32, 64, 128 };
  static const char* NM[6] = { "No limit", "8", "16", "32", "64", "128" };
  if(!g0_limit_present()){ pkPageMsg("OPEN LIMIT", "32 per sitting.", "This needs the newer signer firmware."); pwWaitBack(lp); return; }
  int sel = -1;
  for(;;){
    if(pkLeaveNow()) return;
    favilla::RkLimit lim;
    if(favilla::rk_limit_read(&lim)){ pkPageMsg("OPEN LIMIT", "Could not read the limit.", favilla::rk_hint()); pwWaitBack(lp); return; }
    int cur = 0; for(int i = 0; i < 6; i++) if(V[i] == lim.next) cur = i;
    if(sel < 0) sel = cur;
    const char* vl[6]; static char dv[6][24];
    for(int i = 0; i < 6; i++){
      dv[i][0] = 0;
      if(V[i] == lim.now && lim.now != lim.next) snprintf(dv[i], sizeof dv[i], "%s", "Until restart");
      else if(V[i] == lim.next && lim.now != lim.next) snprintf(dv[i], sizeof dv[i], "%s", "After restart");
      vl[i] = dv[i];
    }
    static int off = 0;
    uiRows("OPEN LIMIT", NM, vl, 6, sel, off, "LEAVE", cur);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % 6; act = 1; } else if(btn3.isPressed()){ sel = (sel + 5) % 6; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1 || sel == cur) continue;
    const uint8_t L = V[sel];
    const bool now = L && (!lim.now || L < lim.now);
    favilla::RkLimit got;
    const int r = vaultLimitSet(L, &got);
    lp = millis();
    if(r == 1) continue;   // BACK on the pad
    if(r) { pkPageMsg("OPEN LIMIT", "Not changed.", "The PIN check or the signer said no."); pwWaitBack(lp); continue; }
    pkPageMsg("OPEN LIMIT", now ? "Set. It applies now." : "Set. It applies after a restart.",
              now ? nullptr : "Until then the old limit stays.");
    pwWaitBack(lp);
  }
}
static uint32_t pkMenu(){
  int sel = 0; uint32_t lp = millis();
  const int N = 4;   // 9i: Passkeys, Passwords, Codes, Settings
  for(;;){
    if(pkLeaveNow()) return lp;   // 6c: no flash of this menu on the way out
    auto draw = [&](){   // 11cy: plain rows
      static int off = 0;
      char d0[24], d1[24], d2[24];
      { int nk = favilla::rk_count(); snprintf(d0, sizeof d0, nk == 1 ? "1 saved" : "%d saved", nk); }
      { int np = favilla::rk_pw_count(); snprintf(d1, sizeof d1, np == 1 ? "1 saved" : "%d saved", np); }
      { int nc = favilla::rk_totp_count(); snprintf(d2, sizeof d2, nc == 1 ? "1 code" : "%d codes", nc); }
      const char* nm[N] = { "Passkeys", "Passwords", "Codes", "Settings" };
      const char* vl[N] = { d0, d1, d2, nullptr };   // statuses, so they sit on the right
      uiRows("VAULT", nm, vl, N, sel, off);
      dispPush();
    };
    draw(); clearButtonPending();
    int choice = -1;
    while(choice < 0){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture()) return lp;
      if(pkMenuLeave(lp)) return lp;      // a site is asking, the door wedged, or idle: back to the home loop
      if(btn4.isPressed()) return lp;
      if(btn1.isPressed()){ sel = (sel + 1) % N; draw(); }
      else if(btn3.isPressed()){ sel = (sel + N - 1) % N; draw(); }
      if(btn2.isPressed()) choice = sel;
      delay(10);
    }
    if(choice == 0){ runPasskeysPage(); lp = millis(); continue; }
    if(choice == 1){ runPasswordsPage(lp); lp = millis(); continue; }
    if(choice == 2){ runCodesPage(lp); lp = millis(); continue; }
    pkSettings(lp); lp = millis();
  }
}
// PASSKEY > Settings > Usernames (4 Nov 2026): the usernames book. ADD ONE types a
// username on the passphrase reel; ENTER on one offers to remove it from the list
// (entries that use it keep it). The New password picker shows this list.
static void runUsernamesPage(uint32_t& lp){
  char (*ub)[favilla::RK_PW_FIELD_MAX + 1] = (char (*)[favilla::RK_PW_FIELD_MAX + 1])heap_caps_calloc(favilla::RK_UB_MAX, favilla::RK_PW_FIELD_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!ub){ pkPageMsg("USERNAMES", "Out of memory.", nullptr); pwWaitBack(lp); return; }
  struct Free { char (*p)[favilla::RK_PW_FIELD_MAX + 1]; ~Free(){ mbedtls_platform_zeroize(p, favilla::RK_UB_MAX * (favilla::RK_PW_FIELD_MAX + 1)); free(p); } } fr{ub};
  int sel = 0;
  const int VIS = 5, CH = 28, PITCH = 31, Y0 = 36;
  for(;;){
    if(pkLeaveNow()) return;   // 6c: no flash of this menu on the way out
    int n = favilla::rk_ub_list(ub, favilla::RK_UB_MAX);
    if(n < 0){ pkPageMsg("USERNAMES", "Unlock the KEY first.", "The list is sealed with the site index key."); pwWaitBack(lp); return; }
    const int rows = n + 1;
    if(sel >= rows) sel = rows - 1;
    int off = 0; if(rows > VIS){ off = sel - 2; if(off < 0) off = 0; if(off > rows - VIS) off = rows - VIS; }
    fEnd(); spr.fillSprite(C_BG);
    { char t[32]; snprintf(t, sizeof t, n == 1 ? "1 USERNAME" : "%d USERNAMES", n); uiTrackLabel(t, 120, 14, C_EB_BRASS); }
    for(int r = 0; r < VIS && off + r < rows; r++){
      int row = off + r; char nm[72]; uint16_t col = 0;
      if(row == 0){ snprintf(nm, sizeof nm, "%s", n < favilla::RK_UB_MAX ? "ADD ONE" : "LIST FULL"); col = row == sel ? 0 : C_EB_BRASS; }
      else snprintf(nm, sizeof nm, "%s", ub[row - 1]);
      fSet(F_BRAND_B14); pkFitText(nm, sizeof nm, 216 - 24 - 14, true); fEnd();
      uiListCard(12, Y0 + r * PITCH, 216, CH, row == sel, C_EB_BRASS, nm, nullptr, 24, col);
    }
    if(rows > VIS){ const int TX = 237, TY = Y0 + 2, TH = VIS * PITCH - 6; int thumb = TH * VIS / rows; if(thumb < 8) thumb = 8; int ty = TY + (TH - thumb) * off / (rows - VIS);
      spr.drawFastVLine(TX, TY, TH, C_EB_LINE); spr.fillRect(TX - 1, ty, 3, thumb, C_EB_BRASS); }
    uiTrackLabel(sel == 0 ? (n < favilla::RK_UB_MAX ? "ENTER TO ADD ONE" : "REMOVE ONE TO ADD") : "ENTER TO REMOVE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush();
    int act = 0;
    clearButtonPending();
    while(!act){
      pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % rows; act = 1; }
      else if(btn3.isPressed()){ sel = (sel + rows - 1) % rows; act = 1; }
      else if(btn2.isPressed()) act = 2;
      delay(10);
    }
    lp = millis();
    if(act == 1) continue;
    if(sel == 0){
      if(n >= favilla::RK_UB_MAX){ pkPageMsg("USERNAMES", "The list is full.", "Remove one to add another (16 at most)."); pwWaitBack(lp); continue; }
      char nu[PP_MAX + 1] = {0}; int nl = 0;
      if(pwTypeOrScan("NEW USERNAME", "username", nu, sizeof nu, lp)){
        nl = (int)strlen(nu);
        int r = favilla::rk_ub_add(nu);
        LOG_BOOT("[PW] usernames book: add (%d characters): %s\n", nl, favilla::rk_err_name(r));
        if(r){ pkPageMsg("USERNAMES", "Not added.", favilla::rk_err_name(r)); pwWaitBack(lp); }
      }
      mbedtls_platform_zeroize(nu, sizeof nu);
      continue;
    }
    // 5t (4 Nov 2026): its own page. pkPage drew the username in Bold 28 after
    // fitting it for the body font, so long ones ran off both edges.
    { fEnd(); spr.fillSprite(C_BG);
      uiTrackLabel("USERNAMES", 120, 14, C_EB_BRASS);
      ebMarkSmall(101, 38, 6, 2);
      fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
      { const char* h = "Remove it?"; spr.drawString(h, 120 - spr.textWidth(h) / 2, 84); }
      fEndHard();
      fSet(F_BRAND_B14); spr.setTextColor(C_EB_BRASS);
      int y = uiWrapCentre(ub[sel - 1], 124, 210, 18, 2);
      fEnd();
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { const char* l = "Passwords that use it keep it."; spr.drawString(l, 120 - spr.textWidth(l) / 2, y + 8); }
      fEndHard();
      uiCornerAnswers("KEEP", "REMOVE");   // 11cw
      dispPush(); }
    clearButtonPending();
    bool go = false;
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(tickSleepGesture() || pkMenuLeave(lp)) return; if(btn4.isPressed()) break; if(btn2.isPressed()){ go = true; break; } delay(10); }
    if(go){ int r = favilla::rk_ub_del(sel - 1); LOG_BOOT("[PW] usernames book: remove: %s\n", favilla::rk_err_name(r)); if(sel > 1) sel--; }
    lp = millis();
  }
}

// ── The browser channel (Vault phase 5 stage 2, 4 Nov 2026) ───────────────────
// The extension talks to the KEY over the Favilla channel (vchan_hid.h). The
// protocol and its rules live in chan_key.h (host-tested against chan.js);
// this is the KEY's side of the hooks: NVS for paired browsers, mbedTLS for the
// pairing, and the screens. Rulings (Josh, 4 Nov 2026): numeric-comparison
// pairing from Settings > Browsers only; signed requests with a counter; HELLO,
// SIGN IN and NEW LOGIN; PASSKEY life only (any life with no radios later);
// the site comes from the browser's address bar; the KEY types, never sends.
#if defined(FAVILLA_VCHAN)
#include "chan_key.h"
bool chanc_hmac(const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]);
bool chanc_open(const uint8_t seed[32]);
void chanc_close();
void chanc_rng(uint8_t* p, size_t n);
bool chanc_ecdh(const uint8_t peer[65], uint8_t z[32]);
bool chanc_mypub(uint8_t mine[65]);
bool chanc_ready();
namespace cg {
static chan::Key g_key;
static SemaphoreHandle_t g_mx = nullptr;
static bool g_loaded = false;
// The screen request: 1 pairing code to show, 2 sign-in / new login waiting,
// 4 being handled by the screens. Written by the channel task, read by the life.
// Every field but kind is written and read under lock(); kind is also read
// without it (chanPending, the pairing screen's poll) as a hint.
struct Ui { volatile uint8_t kind; uint8_t cmd; uint32_t at; uint32_t code; uint8_t id[chan::ID]; char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1]; uint64_t t; uint8_t flags; };   // 11z: t and flags for a code ask
static Ui g_ui = {};
static volatile bool g_running = false;   // 7g: a sign-in is on the screens (chanUiRun)
static uint32_t g_gen = 0;                // 7g: bumped by every request, so a replaced run does not finish the new one
static volatile uint32_t g_winUntil = 0;
static StaticSemaphore_t g_mxBuf;   // review (4 Nov 2026): created once, statically, before any task can race to make it
static void lock(){ xSemaphoreTake(g_mx, portMAX_DELAY); }
static void unlock(){ xSemaphoreGive(g_mx); }
static bool save(const chan::Client* c, int n){
  Preferences p; if(!p.begin("vchan", false, NVSPART_SEC)) return false;
  size_t w = p.putBytes("cl", c, sizeof(chan::Client) * n); p.end();
  return w == sizeof(chan::Client) * n;
}
static void load(){
  if(g_loaded) return;
  g_loaded = true;
  Preferences p; if(p.begin("vchan", true, NVSPART_SEC)){ if(p.getBytesLength("cl") == sizeof(g_key.cl)) p.getBytes("cl", g_key.cl, sizeof(g_key.cl)); p.end(); }
  g_key.afterLoad();   // the stored ceiling is the floor after a restart
}
static uint8_t life(){ return g_passkeyLife ? (g_pkPinHeld ? chan::L_PASSKEY_READY : chan::L_PASSKEY_LOCKED) : (g_ceremonyBoot ? chan::L_OTHER : chan::L_NOSTR); }
static bool window(){ return g_winUntil && (int32_t)(g_winUntil - millis()) > 0 && chanc_ready(); }
static bool pairShow(uint32_t code, const uint8_t id[chan::ID]){   // under lock (process)
  if(g_ui.kind) return false;   // a request is waiting or on screen
  g_ui.code = code; memcpy(g_ui.id, id, chan::ID);
  __atomic_store_n(&g_ui.kind, (uint8_t)1, __ATOMIC_RELEASE);
  return true;
}
static uint8_t g_askFields = 0;   // 11aw: set by the fields hook just before request()
static void fieldsHook(uint8_t f){ g_askFields = f; }
static chan::Status request(uint8_t cmd, const char* site, const char* user){
  // 7g: a newer ask may replace a sign-in waiting (2) or on screen (4; g_ui.cmd
  // still names it), as chan_key allows. Pairing (1) and a new login never.
  if(g_ui.kind == 1) return chan::S_BUSY;
  if(g_ui.kind && !(g_ui.cmd == chan::C_SIGN_IN || g_ui.cmd == chan::C_AUTO_SIGN_IN)) return chan::S_BUSY;
  g_gen++;
  g_ui.at = millis();
  g_ui.cmd = cmd; snprintf(g_ui.site, sizeof g_ui.site, "%s", site); snprintf(g_ui.user, sizeof g_ui.user, "%s", user);
  g_ui.flags = (cmd == chan::C_SIGN_IN || cmd == chan::C_AUTO_SIGN_IN || cmd == chan::C_NEW_LOGIN) ? g_askFields : 0; g_askFields = 0;   // 11aw, 11az: a new login's form byte
  __atomic_store_n(&g_ui.kind, (uint8_t)2, __ATOMIC_RELEASE);
  LOG_BOOT("[CHAN] %s request from a paired browser (%d + %d characters%s)\n", cmd == chan::C_SIGN_IN ? "sign-in" : cmd == chan::C_AUTO_SIGN_IN ? "automatic sign-in" : "new-login", (int)strlen(site), (int)strlen(user),
           g_ui.flags == 1 ? ", username page" : g_ui.flags == 2 ? ", password page" : (g_ui.flags & chan::FORM_CURRENT) ? ", change-password page" : g_ui.flags ? ", sign-up page" : "");
  return chan::S_OK;
}
// 11z: a one-time code to type, for the site's second step. Replaceable like a
// sign-in. flags bit0: automatic (the page found a code box by itself).
static chan::Status codeRequest(const char* site, uint64_t t, uint8_t flags){
  if(g_ui.kind == 1) return chan::S_BUSY;
  if(g_ui.kind && !(g_ui.cmd == chan::C_SIGN_IN || g_ui.cmd == chan::C_AUTO_SIGN_IN || g_ui.cmd == chan::C_CODE_TYPE)) return chan::S_BUSY;
  g_gen++;
  g_ui.at = millis();
  g_ui.cmd = chan::C_CODE_TYPE; snprintf(g_ui.site, sizeof g_ui.site, "%s", site); g_ui.user[0] = 0; g_ui.t = t; g_ui.flags = flags;
  __atomic_store_n(&g_ui.kind, (uint8_t)2, __ATOMIC_RELEASE);
  LOG_BOOT("[CHAN] %scode request from a paired browser (%d characters%s)\n", (flags & 1) ? "automatic " : "", (int)strlen(site), (flags & 2) ? ", Enter after" : "");
  return chan::S_OK;
}
static void send(const uint8_t* m, size_t n){ vchan::sendMsg(m, n); }
static bool ecdh(const uint8_t peer[65], uint8_t z[32]){ return chanc_ecdh(peer, z); }
static void hooks(){   // under lock
  if(!g_key.h.hmac){ g_key.h = { chanc_hmac, chanc_mypub, ecdh, chanc_rng, save, life, window, pairShow, request, send, FAVILLA_BENCH_DROP, codeRequest }; g_key.h.fields = fieldsHook; }   // 11aw
}
static void onMsg(const uint8_t* m, size_t n){
  lock();
  hooks();
  load();
  g_key.process(m, n);
  unlock();
}
struct Reg { Reg(){ g_mx = xSemaphoreCreateMutexStatic(&g_mxBuf); vchan::g_onMsg = onMsg; } };
static Reg s_reg;
}  // namespace cg
// An explicit request (the popup or the page button) takes over the screen
// like a passkey prompt; an automatic one waits for the home screen.
// 7g: any newer browser ask also takes over while a sign-in is on the screens.
static bool chanSilent(){ return cg::g_ui.cmd == chan::C_AUTO_SIGN_IN || (cg::g_ui.cmd == chan::C_CODE_TYPE && (cg::g_ui.flags & 1)); }   // 11z: an automatic ask waits for the home screen
static bool chanPending(){ return cg::g_ui.kind == 2 && (!chanSilent() || cg::g_running); }
static bool chanQueued(){ return cg::g_ui.kind == 2; }

// An automatic ask that the home screen has not reached in 10 s (the owner is
// in a menu or busy) is dropped as busy, so the browser is never left waiting.
static void chanExpire(){
  cg::lock();
  if(cg::g_ui.kind == 2 && chanSilent() && millis() - cg::g_ui.at > 10000UL){
    cg::g_key.finish(chan::S_BUSY); cg::g_ui.kind = 0;
    mbedtls_platform_zeroize(cg::g_ui.site, sizeof cg::g_ui.site); mbedtls_platform_zeroize(cg::g_ui.user, sizeof cg::g_ui.user);
  }
  cg::unlock();
}
static chan::Status chanCodeRun(const char* site, uint64_t t, uint8_t flags, uint32_t& lp, bool* shown);   // 11z, after ble_app.inc (shares its code chooser)
// A browser asked: run it on the screens, then tell the browser how it went.
// Returns true if anything went on screen (a silent automatic ask does not).
static bool chanUiRun(uint32_t& lp){
  char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1];
  cg::lock();   // review (4 Nov 2026): the snapshot under the lock the channel task wrote it under
  if(cg::g_ui.kind != 2){ cg::unlock(); return false; }
  snprintf(site, sizeof site, "%s", cg::g_ui.site); snprintf(user, sizeof user, "%s", cg::g_ui.user);
  const uint8_t cmd = cg::g_ui.cmd;
  const uint64_t codeT = cg::g_ui.t; const uint8_t codeFlags = cg::g_ui.flags;
  const uint32_t myGen = cg::g_gen;
  cg::g_ui.kind = 4; cg::g_running = true;
  mbedtls_platform_zeroize(cg::g_ui.site, sizeof cg::g_ui.site); mbedtls_platform_zeroize(cg::g_ui.user, sizeof cg::g_ui.user);
  cg::unlock();
  chan::Status st = chan::S_CANCELLED;
  bool shown = cmd != chan::C_AUTO_SIGN_IN && !(cmd == chan::C_CODE_TYPE && (codeFlags & 1));
  if(!g_pkPinHeld || !favilla::rk_ready() || !g0_v15_present()) st = chan::S_LOCKED;
  else if(cmd == chan::C_CODE_TYPE){ bool sh = false; st = chanCodeRun(site, codeT, codeFlags, lp, &sh); if(sh) shown = true; }   // 11z
  else if(cmd == chan::C_SIGN_IN || cmd == chan::C_AUTO_SIGN_IN){
    PwRow* R = (PwRow*)heap_caps_malloc(sizeof(PwRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(R){
      int n = pwBuildRows(R);
      g_pwFields = codeFlags <= chan::FIELDS_PASS ? codeFlags : 0;   // 11aw: for a sign-in the flags byte carries chan::FIELDS_*
      int r = pwSignInFor(R, n, site, user, lp, cmd == chan::C_AUTO_SIGN_IN, cmd == chan::C_SIGN_IN);
      g_pwFields = 0;
      st = r == 1 ? chan::S_TYPED : r == 3 ? chan::S_NO_MATCH : chan::S_CANCELLED;
      if(r != 3) shown = true;
      mbedtls_platform_zeroize(R, sizeof(PwRow) * favilla::RK_MAX); free(R);
    }
  } else {
    const uint32_t t0 = g_pwTypedCount; g_pwNewSaved = false;
    g_pwForm = chan::formByte(codeFlags) ? codeFlags : 0;   // 11az: what the extension saw on the sign-up or change page
    int rr = 0;
    if(g_pwForm & chan::FORM_CURRENT){   // a change-password page: the saved login for this site
      const int r = pwChangeFor(site, user, lp);
      st = r == 1 ? chan::S_TYPED : r == 3 ? chan::S_NO_MATCH : chan::S_CANCELLED;
    } else if(g_pwForm && !(g_pwForm & chan::FORM_USER) && (rr = pwChangeFor(site, user, lp, true)) != 3){
      // 11eq (25 Nov 2026): a reset page (new and confirm boxes, no username, no
      // current password) on a site the KEY has a login for: change that login.
      // It types only the new one. No saved login: a new one, as before.
      st = rr == 1 ? chan::S_TYPED : chan::S_CANCELLED;
    } else {
      pwNew(lp, site, user[0] ? user : nullptr);
      st = g_pwTypedCount != t0 ? chan::S_TYPED : g_pwNewSaved ? chan::S_SAVED : chan::S_CANCELLED;
    }
    g_pwForm = 0;
  }
  mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user);
  LOG_BOOT("[CHAN] %s from the browser: %s\n", cmd == chan::C_SIGN_IN ? "sign-in" : cmd == chan::C_AUTO_SIGN_IN ? "automatic sign-in" : cmd == chan::C_CODE_TYPE ? "code" : "new login", chan::S_TYPED == st ? "typed" : st == chan::S_SAVED ? "saved" : st == chan::S_NO_MATCH ? "no saved login" : st == chan::S_LOCKED ? "locked" : "cancelled");
  cg::lock();
  if(cg::g_gen == myGen){ cg::g_key.finish(st); cg::g_ui.kind = 0; }   // 7g: else a newer ask replaced this one (already told "nothing typed") and is waiting
  else LOG_BOOT("[CHAN] replaced by a newer ask from the browser\n");
  cg::g_running = false;
  cg::unlock();
  if(shown) lp = millis();
  return shown;
}

// Settings > Browsers: the paired browsers, PAIR A BROWSER (a 90 s window and
// the code to compare), and remove.
static void chanPairScreen(uint32_t& lp){
  uint8_t seed[32];
  if(!pwGenSeed(seed) || !chanc_open(seed)){ mbedtls_platform_zeroize(seed, 32); pkPageMsg("BROWSERS", "Could not start pairing.", "The secure element's random number generator did not answer."); pwWaitBack(lp); return; }
  mbedtls_platform_zeroize(seed, 32);
  cg::lock(); cg::hooks(); cg::load(); cg::g_key.windowOpened(); cg::g_winUntil = millis() + 90000UL; cg::unlock();
  LOG_BOOT("[CHAN] pairing window open (90 s)\n");
  int shownSec = -1; bool decided = false, accepted = false; bool showed = false; uint8_t shownId[chan::ID] = {0};
  clearButtonPending();
  while(!decided){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture()) break;
    if(__atomic_load_n(&cg::g_ui.kind, __ATOMIC_ACQUIRE) == 1){   // a browser sent its key: compare the numbers
      uint32_t code; cg::lock(); code = cg::g_ui.code; memcpy(shownId, cg::g_ui.id, chan::ID); cg::unlock(); showed = true;
      char c[8]; snprintf(c, sizeof c, "%03u %03u", (unsigned)(code / 1000), (unsigned)(code % 1000));
      fEnd(); spr.fillSprite(C_BG);
      uiTrackLabel("PAIR A BROWSER", 120, 14, C_EB_BRASS);
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { const char* l = "Does the browser show"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 44); }
      { const char* l = "this number?"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 62); }
      fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
      spr.drawString(c, 120 - spr.textWidth(c) / 2, 100); fEndHard();
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { const char* l = "Only pair from the Favilla extension."; spr.drawString(l, 120 - spr.textWidth(l) / 2, 150); }
      fEndHard();
      uiCornerAnswers("NO MATCH", "MATCHES");   // 11cw
      dispPush(); clearButtonPending();
      uint32_t t0 = millis();
      for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(tickSleepGesture() || btn4.isPressed() || millis() - t0 > 60000UL){ break; }
        if(btn2.isPressed()){ accepted = true; break; }
        delay(10); }
      decided = true; break;
    }
    int left = (int)((int32_t)(cg::g_winUntil - millis()) / 1000);
    if(left < 0) break;
    if(left != shownSec){
      shownSec = left;
      fEnd(); spr.fillSprite(C_BG);
      uiTrackLabel("PAIR A BROWSER", 120, 14, C_EB_BRASS);
      ebMarkSmall(101, 38, 6, 2);
      fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
      { const char* h = "Waiting"; spr.drawString(h, 120 - spr.textWidth(h) / 2, 92); }
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      { const char* l = "In the Favilla extension: right-click,"; spr.drawString(l, 120 - spr.textWidth(l) / 2, 134); }
      { const char* l = "Options, then PAIR."; spr.drawString(l, 120 - spr.textWidth(l) / 2, 152); }
      fEndHard();
      { char t[24]; snprintf(t, sizeof t, "%d S LEFT", left); uiTrackLabel(t, 120, 196, C_EB_BRASS); }
      uiTrackLabel("BACK TO STOP", 120, 216, C_EB_GREY);
      dispPush();
    }
    if(btn4.isPressed()) break;
    delay(10);
  }
  cg::lock();
  cg::g_winUntil = 0; cg::g_key.windowClosed();
  const bool asked = showed;
  if(asked) cg::g_key.pairDecision(accepted, shownId);   // only the attempt that was on screen
  int paired = cg::g_key.count();
  if(cg::g_ui.kind == 1) cg::g_ui.kind = 0;
  cg::unlock();
  chanc_close();
  LOG_BOOT("[CHAN] pairing window closed: %s (%d browser%s paired)\n", !asked ? "no browser asked" : accepted ? "paired" : "refused", paired, paired == 1 ? "" : "s");
  if(asked){ pkPage("BROWSERS", accepted ? "Paired" : "Not paired", accepted ? "The browser can now ask this KEY" : "Nothing was saved.", accepted ? "to sign in. Every typing needs a press." : nullptr, "ENTER TO GO BACK"); pwWaitBack(lp); }
  lp = millis();
}
static void runBrowsersPage(uint32_t& lp){
  int sel = 0;
  const int VIS = 5, CH = 28, PITCH = 31, Y0 = 36;
  for(;;){
    if(pkLeaveNow()) return;
    cg::lock(); cg::load(); chan::Client cl[chan::MAX_CLIENTS]; memcpy(cl, cg::g_key.cl, sizeof cl); cg::unlock();
    int idx[chan::MAX_CLIENTS], n = 0; for(int i = 0; i < chan::MAX_CLIENTS; i++) if(cl[i].used) idx[n++] = i;
    mbedtls_platform_zeroize(cl, sizeof cl);   // keys not needed on screen
    const int rows = n + 1; if(sel >= rows) sel = rows - 1;
    fEnd(); spr.fillSprite(C_BG);
    { char t[32]; snprintf(t, sizeof t, n == 1 ? "1 BROWSER" : "%d BROWSERS", n); uiTrackLabel(t, 120, 14, C_EB_BRASS); }
    for(int r = 0; r < rows && r < VIS; r++){
      char nm[40]; uint16_t col = 0;
      if(r == 0){ snprintf(nm, sizeof nm, "%s", n < chan::MAX_CLIENTS ? "PAIR A BROWSER" : "LIST FULL"); col = r == sel ? 0 : C_EB_BRASS; }
      else { cg::lock(); const uint8_t* id = cg::g_key.cl[idx[r - 1]].id; snprintf(nm, sizeof nm, "Browser %02X%02X%02X", id[0], id[1], id[2]); cg::unlock(); }
      uiListCard(12, Y0 + r * PITCH, 216, CH, r == sel, C_EB_BRASS, nm, nullptr, 24, col);
    }
    uiTrackLabel(sel == 0 ? (n < chan::MAX_CLIENTS ? "ENTER TO PAIR" : "REMOVE ONE TO PAIR") : "ENTER TO REMOVE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % rows; act = 1; } else if(btn3.isPressed()){ sel = (sel + rows - 1) % rows; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
    if(sel == 0){ if(n < chan::MAX_CLIENTS) chanPairScreen(lp); continue; }
    char nm[32]; { cg::lock(); const uint8_t* id = cg::g_key.cl[idx[sel - 1]].id; snprintf(nm, sizeof nm, "Browser %02X%02X%02X", id[0], id[1], id[2]); cg::unlock(); }
    pkAsk("BROWSERS", "Remove it?", nm, "It can ask again only after pairing.", "KEEP", "REMOVE");
    clearButtonPending();
    bool go = false;
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(tickSleepGesture() || pkMenuLeave(lp)) return; if(btn4.isPressed()) break; if(btn2.isPressed()){ go = true; break; } delay(10); }
    if(go){ cg::lock(); cg::g_key.forget(idx[sel - 1]); cg::unlock(); LOG_BOOT("[CHAN] a paired browser removed\n"); if(sel > 1) sel--; }
    lp = millis();
  }
}
static int chanPairedCount(){ cg::lock(); cg::load(); int n = cg::g_key.count(); cg::unlock(); return n; }
#endif  // FAVILLA_VCHAN
#ifdef FAVILLA_BLE_KBD
// ── 8z7 (6 Nov 2026): the iPhone app's sign-in ask ───────────────────────────
// The Favilla sheet in Safari wrote the site (ble_kbd.h phoneRequest) and closed,
// so the page's login field has the focus again. Here it runs like a browser's
// explicit ask: the matches for that site, the owner picks one and presses, and
// the KEY types it as the phone's Bluetooth keyboard (reconnecting it if the
// link dropped meanwhile). Ruled (Josh, 6 Nov 2026): the KEY types, nothing is
// sent to the app. The phone asked, so the typing goes to the phone even with
// the USB cable in.
static uint8_t phoneAskGate(){   // on the NimBLE task: cheap flags only
  if(!g_passkeyLife || !g_btLife) return chan::S_NOT_HERE;
  if(!g_pkPinHeld) return chan::S_LOCKED;
  return chan::S_OK;
}
struct PhoneAskReg { PhoneAskReg(){ blek::s_reqGate = phoneAskGate; } };
static PhoneAskReg s_phoneAskReg;
static void phoneAskRun(uint32_t& lp){
  char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1] = {0};
  bool fill = false; uint8_t peer[7] = {0};
  if(!blek::reqTake(site, sizeof site, &fill, user, sizeof user, peer)) return;   // 9d: FILL may name the account
  lp = millis();   // 11r (10 Nov 2026, Josh: the sign-in screen sometimes flicked straight back to READY): the phone's ask is
                   // activity, as the browser's is (chanUiRun). Every screen below leaves after 60 s on this clock, so a
                   // stale one (the phone was still connected and no KEY button was pressed) left at once as "cancelled".
  LOG_BOOT("[BT] phone sign-in ask on the KEY's screen (%s)\n", fill ? "the login goes back to the app" : "the KEY types it");
  int res = -1;   // 9c: what the app is told when nothing was sent (1 sent, 3 no saved login, else cancelled)
  if(!g_pkPinHeld){ res = -5; pkPageMsg("SIGN IN", "The KEY is locked.", "Enter the passkey PIN, then try again on the phone."); pwWaitBack(lp); }
  else if(!favilla::rk_ready() || !g0_v15_present()){ pkPageMsg("SIGN IN", "Passwords are not open yet.", "Try again on the phone in a moment."); pwWaitBack(lp); }
  else {
    PwRow* R = (PwRow*)heap_caps_malloc(sizeof(PwRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(!R){ pkPageMsg("SIGN IN", "Out of memory.", nullptr); pwWaitBack(lp); }
    else {
      const bool was = g_btPreferPhone; g_btPreferPhone = true;   // the phone asked: type on the phone, cable or not
      g_pwToApp = fill;   // 9c
      g_pwAskIdx = -1;
      snprintf(g_fillSite, sizeof g_fillSite, "%s", fill ? site : ""); snprintf(g_fillUser, sizeof g_fillUser, "%s", fill ? user : "");   // 11bi: for NEW LOGIN
      int r = -1;
      if(g_lastFill.on && millis() - g_lastFill.at > 60000UL) lastFillForget();
      if(fill && g_lastFill.on && !memcmp(peer, g_lastFill.peer, 7) && loginqr::siteMatch(g_lastFill.site, site) >= 2){   // 9d: page two of the same sign-in
        fEnd(); spr.fillSprite(C_BG);
        pwSignInHero(g_lastFill.site, g_lastFill.user, "SEND AGAIN");   // 11er: the same screen, tagged
        fEndHard();
        uiCornerAnswers("BACK", "SEND");   // 11er: BACK goes to the list
        dispPush(); clearButtonPending();
        int act = 0;
        for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
          if(tickSleepGesture() || pkMenuLeave(lp)){ act = -1; break; }
          if(btn4.isPressed()) break; if(btn2.isPressed()){ act = 1; break; } delay(10); }
        lp = millis();
        const int idx = g_lastFill.idx; char ls[101]; snprintf(ls, sizeof ls, "%s", g_lastFill.site);
        lastFillForget();   // used, either way
        if(act == 1){
          favilla::RkLabel L; int e; { g0_window_batch_begin(); e = favilla::rk_pw_label(idx, &L); g0_window_batch_end(); }
          const uint32_t tc = g_pwTypedCount;
          if(!e && !strcmp(L.site, ls)) pwType(idx, L, false, lp);   // pwSendToApp under g_pwToApp
          mbedtls_platform_zeroize(&L, sizeof L);
          if(g_pwTypedCount != tc) r = 1;
        }
        mbedtls_platform_zeroize(ls, sizeof ls);
        if(act == -1) r = 2;
      }
      const int n = pwBuildRows(R);
      if(r < 0) r = pwSignInFor(R, n, site, user, lp, false, true);   // offerSave: the site came from iOS, not from the page
      g_pwToApp = false;
      mbedtls_platform_zeroize(g_fillSite, sizeof g_fillSite); mbedtls_platform_zeroize(g_fillUser, sizeof g_fillUser);
      if(fill && r == 1 && g_pwAskIdx >= 0){   // 9d: remember which entry went to which phone, for 60 s
        favilla::RkLabel L; int e; { g0_window_batch_begin(); e = favilla::rk_pw_label(g_pwAskIdx, &L); g0_window_batch_end(); }
        if(!e){ g_lastFill.on = true; g_lastFill.idx = g_pwAskIdx; memcpy(g_lastFill.peer, peer, 7); g_lastFill.at = millis();
                snprintf(g_lastFill.site, sizeof g_lastFill.site, "%s", L.site); snprintf(g_lastFill.user, sizeof g_lastFill.user, "%s", L.user); }
        mbedtls_platform_zeroize(&L, sizeof L);
      }
      g_btPreferPhone = was; res = r;
      LOG_BOOT("[BT] phone sign-in ask: %s\n", r == 1 ? (fill ? "sent to the app" : "typed") : r == 3 ? "no saved login" : "cancelled");
      mbedtls_platform_zeroize(R, sizeof(PwRow) * favilla::RK_MAX); free(R);
    }
  }
  mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user);
  if(fill && res != 1) blek::fillSend(res == 3 ? chan::S_NO_MATCH : res == -5 ? chan::S_LOCKED : chan::S_CANCELLED, nullptr, nullptr);   // 9c: the app is never left waiting
  blek::reqDone();
  lp = millis();
}
#endif  // FAVILLA_BLE_KBD
#endif  // FAVILLA_PK_RESTORABLE
#if !(defined(FAVILLA_VCHAN) && defined(FAVILLA_PK_RESTORABLE))
static bool chanPending(){ return false; }
static void chanExpire(){}
#endif

#if defined(FAVILLA_BLE_KBD) && defined(FAVILLA_PK_RESTORABLE)
#include "ble_app.inc"   // 9g: the Favilla app's channel over Bluetooth
static bool vaAppRun(uint32_t& lp);   // 11ax (issue #30): vault_api.inc, included after this file
static bool vaAppImport(uint32_t& lp);   // 11bf: the app's import, VAULT mode (vault_api.inc)
#if defined(FAVILLA_VCHAN)
// 11z (11 Nov 2026, Josh: "how can the extension automatically know its a 2fa
// request and push that to the KEY ... and just press enter"): the browser found
// the site's code box and asked. The code linked to the login the KEY just typed
// comes first and alone (11v), then codes whose entry or label is the site. An
// automatic ask with nothing matching ends silently (S_NO_MATCH, nothing on
// screen); only a press on the page button offers "pick one". On ENTER the G0
// computes the code and the KEY types it to the computer, Enter after it when
// the browser asked for that.
static chan::Status chanCodeRun(const char* site, uint64_t t, uint8_t flags, uint32_t& lp, bool* shown){
  *shown = false;
  const bool autoAsk = flags & 1, submit = flags & 2;
  if(!g0_v17_present()) return chan::S_NOT_HERE;
  if(t > 1700000000ull && time(nullptr) < 1700000000){ struct timeval tv = { (time_t)t, 0 }; settimeofday(&tv, nullptr); LOG_BOOT("[OTP] the KEY's clock set from the browser's time\n"); }
  favilla::RkTotp* T = (favilla::RkTotp*)heap_caps_malloc(sizeof(favilla::RkTotp) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  int* idx = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if(!T || !idx){ free(T); free(idx); return chan::S_BUSY; }
  const int n = favilla::rk_totp_rows(T, favilla::RK_MAX);
  int m = 0; bool all = false;
  if(g_pwTypedIdx >= 0 && millis() - g_pwTypedAt < 120000UL){   // the code for the login just typed
    favilla::RkRow row; int ts = -1;
    if(favilla::rk_pw_row(g_pwTypedIdx, &row)) ts = favilla::rk_pw_totp_slot(row.slot);
    for(int i = 0; ts >= 0 && i < n; i++) if(T[i].slot == ts){ idx[m++] = i; break; }
  }
  if(m == 0){
    favilla::RkRow* rows = (favilla::RkRow*)heap_caps_malloc(sizeof(favilla::RkRow) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    const int nr = rows ? favilla::rk_pw_rows(rows, favilla::RK_MAX) : 0;
    for(int i = 0; i < n; i++){
      if(!T[i].known) continue;
      bool hit = otpauth::siteMatch(T[i].site, site);
      if(!hit && rows){ const int lp2 = favilla::rk_totp_linked_pw(T[i].slot); for(int k = 0; lp2 >= 0 && k < nr; k++) if(rows[k].slot == lp2){ hit = rows[k].nameKnown && otpauth::siteMatch(rows[k].site, site); break; } }
      if(hit) idx[m++] = i;
    }
    if(rows){ mbedtls_platform_zeroize(rows, sizeof(favilla::RkRow) * favilla::RK_MAX); free(rows); }
  }
  if(m == 0 && !autoAsk){ for(int i = 0; i < n; i++) if(T[i].known) idx[m++] = i; all = true; }
  auto freeAll = [&](){ mbedtls_platform_zeroize(T, sizeof(favilla::RkTotp) * favilla::RK_MAX); free(T); free(idx); };
  if(m == 0){ freeAll(); LOG_BOOT("[OTP] no code for the browser's site\n"); return chan::S_NO_MATCH; }
  *shown = true;
  if(dimActive) idleDimWake();
  int sel = 0; ag::otpDraw(T, idx, m, sel, site, all, submit ? "SUBMIT" : "TYPE"); clearButtonPending();
  bool yes = false; const uint32_t t0 = millis();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || btn4.isPressed() || millis() - t0 > 30000UL || !g_pkPinHeld) break;
    if(m > 1 && btn1.isPressed()){ sel = (sel + 1) % m; ag::otpDraw(T, idx, m, sel, site, all, submit ? "SUBMIT" : "TYPE"); }
    else if(m > 1 && btn3.isPressed()){ sel = (sel + m - 1) % m; ag::otpDraw(T, idx, m, sel, site, all, submit ? "SUBMIT" : "TYPE"); }
    if(btn2.isPressed()){ yes = true; break; }
    delay(10); }
  chan::Status st = chan::S_CANCELLED;
  if(yes){
    if(!kbd::ready()){ pkPageMsg("CODE", "The computer is not using the KEY as a keyboard.", "Plug the KEY into the computer you want to type on."); pwWaitBack(lp); }
    else {
      pkWorking("CODE", "Typing", "Keep the code box selected", "on the computer.");   // 11cg
      const uint64_t now = t > 1700000000ull ? t : (uint64_t)time(nullptr);
      uint32_t code = 0; uint8_t dg = 0;
      const int r = rkWithPin([&]()->int{ return favilla::rk_totp_code(T[idx[sel]].slot, now, &code, &dg); }, nullptr);   // 25 Nov 2026: the PIN if the limit stopped it
      LOG_BOOT("[OTP] code for the browser: %s | record opens left this sitting: %d\n", r == 0 ? "computed by the G0" : favilla::rk_err_name(r), favilla::rk_open_left());
      if(r == 0){
        char d[12]; int dn = snprintf(d, sizeof d, "%0*lu", (int)dg, (unsigned long)code); code = 0;
        if(submit && dn < (int)sizeof d - 1) d[dn++] = '\n';
        char bad[24] = {0};
        const int res = typer::typeTo(typer::USB, d, (size_t)dn, bad, sizeof bad);
        mbedtls_platform_zeroize(d, sizeof d);
        if(res == 0){ st = chan::S_TYPED; pkPage("CODE", "Typed", submit ? "Code typed, Enter pressed." : "Code typed.", nullptr, nullptr);
          uint32_t t1 = millis(); clearButtonPending(); while(millis() - t1 < 1500){ pumpInputs(); btn3.poll(); btn4.poll(); if(btn2.isPressed() || btn4.isPressed()) break; delay(10); } }
        else { pkPageMsg("CODE", "Typing stopped.", "The computer stopped listening."); pwWaitBack(lp); }
      } else { pkPageMsg("CODE", "No code.", r == favilla::RK_E_BUDGET ? "The vault limit needs your PIN: lock and unlock the KEY." : favilla::rk_err_name(r)); pwWaitBack(lp); }
    }
  } else LOG_BOOT("[OTP] code for the browser refused or timed out on the KEY\n");
  freeAll(); lp = millis();
  return st;
}
#endif
#endif
#ifdef FAVILLA_BLE_KBD
// ── Settings > Bluetooth (4 Nov 2026, Vault phase 6) ─────────────────────────
// The setting is read at power-on: changing it here never starts or stops the
// radio in this life. Phones pair only from PAIR A PHONE, in a Bluetooth life.
static bool btYesNo(uint32_t& lp){
  clearButtonPending();
  for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return false;
    if(btn2.isPressed()) return true;
    delay(10); }
}
// 9g: PAIR A PHONE pairs the phone (its Bluetooth bond, numeric comparison)
// and then the Favilla app on it (the app channel, its own 6-digit code). A
// phone that is already paired only does the app part. Both codes are checked
// on the KEY's screen; nothing is stored without ENTER.
static void btCodeScreen(const char* label, const char* l1, const char* l2, uint32_t code, const char* foot){
  char c[8]; snprintf(c, sizeof c, "%03u %03u", (unsigned)(code / 1000), (unsigned)(code % 1000));
  fEnd(); spr.fillSprite(C_BG);
  uiTrackLabel(label, 120, 14, C_EB_BRASS);
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  spr.drawString(l1, 120 - spr.textWidth(l1) / 2, 44);
  spr.drawString(l2, 120 - spr.textWidth(l2) / 2, 62);
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
  spr.drawString(c, 120 - spr.textWidth(c) / 2, 100); fEndHard();
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  spr.drawString(foot, 120 - spr.textWidth(foot) / 2, 150);
  fEndHard();
  uiCornerAnswers("NO MATCH", "MATCHES");   // 11cw
  dispPush(); clearButtonPending();
}
static void btPairScreen(uint32_t& lp){
  if(!g_btLife){ pkPageMsg("BLUETOOTH", "Bluetooth is off in this start.", "Turn it on, then restart the KEY in VAULT mode."); pwWaitBack(lp); return; }
  const int before = blek::peersCount();
  const bool full = before >= blek::MAX_PEERS;   // 9g: still open: the app can pair on a phone that is already paired
  uint32_t winMs = 90000UL;
#ifdef FAVILLA_PK_RESTORABLE
  bool appOk = false;
  { uint8_t seed[32]; appOk = pwGenSeed(seed) && chanc_open(seed); mbedtls_platform_zeroize(seed, 32); }
  if(appOk) ag::windowOpened(winMs); else LOG_BOOT("[APP] pairing key not made (the SE's random did not answer): the app cannot pair in this window\n");
#endif
  blek::windowOpenFor(winMs);
  uint32_t until = millis() + winMs;
  int shownSec = -1; bool asked = false, accepted = false, paired = false, appAsked = false, appPaired = false;
  clearButtonPending();
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    if(tickSleepGesture()) break;
    uint32_t code;
    if(blek::askPending(&code)){   // the phone asked to pair: compare the numbers
      asked = true; shownSec = -1;
      wp::stop();   // 11cg
      btCodeScreen("PAIR A PHONE", "Does the phone show", "this number?", code, "Accept on the phone as well.");
      const uint32_t t0 = millis();
      for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(!blek::askPending(nullptr)) break;   // the phone gave up (or 25 s passed)
        if(tickSleepGesture() || btn4.isPressed() || millis() - t0 > 24000UL){ blek::answer(false); break; }
        if(btn2.isPressed()){ accepted = true; blek::answer(true); break; }
        delay(10); }
      if(!accepted) break;
      // The bond is written when the phone finishes; give it a few seconds.
      // 11cg: step 1 turns while the phone finishes.
      wp::steps("PAIR A PHONE", "Nearly there");
      wp::step(0, wp::NOW,  "Phone pairs", "accept on the phone if it asks");
      wp::step(1, wp::TODO, "Pair the app", "its own number, once");
      snprintf(wp::P.foot, sizeof wp::P.foot, "BACK TO STOP");
      wp::show();
      const uint32_t t1 = millis();
      while(millis() - t1 < 30000UL){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
        if(blek::peersCount() > before){ paired = true; break; }
        if(blek::s_lastPair == 2 || btn4.isPressed()) break;
#ifdef FAVILLA_PK_RESTORABLE
        if(ag::g_ask){ paired = true; break; }   // the app is already on its own pairing: the bond went through
#endif
        delay(20); }
      if(!paired) break;
#ifdef FAVILLA_PK_RESTORABLE
      if(!appOk) break;
      until = millis() + 60000UL; blek::windowOpenFor(60000UL); ag::g_winUntil = until;   // now the app's own pairing, on this phone
      clearButtonPending();
      continue;
#else
      break;
#endif
    }
#ifdef FAVILLA_PK_RESTORABLE
    { uint8_t id[chan::ID];
      if(ag::askPending(&code, id)){   // the app sent its key: compare the app's code
        appAsked = true;
        wp::stop();   // 11cg
        btCodeScreen("PAIR THE APP", "Does the Favilla app", "show this number?", code, "Only pair from the Favilla app.");
        const uint32_t t0 = millis(); bool yes = false;
        for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
          if(tickSleepGesture() || btn4.isPressed() || millis() - t0 > 60000UL) break;
          if(btn2.isPressed()){ yes = true; break; }
          delay(10); }
        appPaired = ag::decide(yes, id);
        mbedtls_platform_zeroize(id, sizeof id);
        break;
      } }
#endif
    const int left = (int)((int32_t)(until - millis()) / 1000);
    if(left < 0) break;
    if(left != shownSec){
      // 11cg (22 Nov 2026, UX drop 1): what to do, in order; the step the KEY
      // is waiting on turns; the grey bar runs down the window instead of a
      // seconds count. Repainted once a second (the ring turns on its own).
      const bool fresh = shownSec < 0;
      shownSec = left;
      const uint32_t winNow = paired ? 60000UL : winMs;
      if(fresh){
        if(paired){
          wp::steps("PAIR A PHONE", "Now the app");
          wp::step(0, wp::DONE, "Phone paired", "Bluetooth bond saved");
          wp::step(1, wp::NOW,  "Pair the app", "Pair KEY in the Favilla app");
        } else {
          wp::steps("PAIR A PHONE", "Open Favilla");
          wp::step(0, wp::NOW,  "Choose Pair KEY", full ? "on a phone already paired" : "in the app on the phone");
          wp::step(1, wp::TODO, "Check the number", "the same on both screens");
          wp::step(2, wp::TODO, "Pair the app", "its own number, once");
        }
        snprintf(wp::P.foot, sizeof wp::P.foot, "BACK TO STOP");
        wp::P.barCol = C_EB_GREY;
      }
      wp::P.bar = (float)left * 1000.0f / (float)winNow;
      wp::show();
    }
    if(btn4.isPressed()) break;
    delay(10);
  }
  wp::stop();   // 11cg
  blek::windowClose();
#ifdef FAVILLA_PK_RESTORABLE
  ag::windowClosed(); chanc_close();
#endif
  LOG_BOOT("[BT] pairing window closed: phone %s, app %s (%d phone%s paired)\n", !asked ? "not asked" : paired ? "paired" : "not paired",
           !appAsked ? "not asked" : appPaired ? "paired" : "not paired", blek::peersCount(), blek::peersCount() == 1 ? "" : "s");
  // 11cg: good news closes by itself; "not paired" waits for a press.
  if(appAsked){
    if(appPaired) wp::done("PAIR A PHONE", "App paired", "Sign-ins go only to the app.");
    else { pkPage("PAIR A PHONE", "App not paired", "Nothing was saved.", nullptr, "ENTER TO GO BACK"); pwWaitBack(lp); }
  }
  else if(asked){
    if(paired) wp::done("PAIR A PHONE", "Paired", "Pair the app next, from here.");
    else { pkPage("PAIR A PHONE", "Not paired", "Nothing was saved.", nullptr, "ENTER TO GO BACK"); pwWaitBack(lp); }
  }
  lp = millis();
}
// 9c: Bluetooth off / on for the app only / on with the keyboard as well.
// Both settings are read at power-on, so a change applies from the next start.
static int btModeNow(){ return !blek::settingOn() ? 0 : blek::kbSettingOn() ? 2 : 1; }
static void btModePicker(uint32_t& lp){
  const int cur = btModeNow(); int sel = cur;
  static const char* NAME[3] = { "Off", "App only", "App and keyboard" };   // tracked caps, 204 px: kept short
  static const char* SUB[3] = { "Bluetooth stays off", "Fills in, no keyboard", "Also types on any phone" };
  for(;;){
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("BLUETOOTH", 120, 14, C_EB_BRASS);
    for(int k = 0; k < 3; k++){ char d[40]; snprintf(d, sizeof d, "%s%s", k == cur ? "Now: " : "", SUB[k]); uiListCard(12, 52 + 46 * k, 216, 42, sel == k, C_EB_BRASS, NAME[k], d, 24); }
    uiTrackLabel("ENTER TO CHOOSE", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % 3; act = 1; } else if(btn3.isPressed()){ sel = (sel + 2) % 3; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
    if(sel == cur) return;
    bool ok = blek::settingSet(sel != 0);
    if(ok && sel != 0) ok = blek::kbSettingSet(sel == 2);
    LOG_BOOT("[BT] setting %s (from the next start): %s\n", NAME[sel], ok ? "saved" : "NOT saved");
    pkPageMsg("BLUETOOTH", ok ? (sel == 0 ? "Off from the next start." : sel == 1 ? "App only from the next start." : "App and keyboard from the next start.") : "Not saved.",
              ok ? (sel == 0 ? "Never in NOSTR or Bitcoin mode either way." : "Restart the KEY in VAULT mode to use it.") : "The setting could not be written.");
    pwWaitBack(lp); return;
  }
}
static void runBluetoothPage(uint32_t& lp){
  int sel = 0;
  for(;;){
    if(pkLeaveNow()) return;
    const bool set = blek::settingOn(); const int np = blek::peersCount();
    fEnd(); spr.fillSprite(C_BG);
    uiTrackLabel("BLUETOOTH", 120, 14, C_EB_BRASS);
    char d[40];
    { const int m = btModeNow(); const bool now = g_btLife && blek::s_up;   // 9c: what this life runs vs what the next start will
      const int live = !now ? 0 : blek::kbOn() ? 2 : 1;
      static const char* M[3] = { "Off", "App only", "App and keyboard" };
      if(m == live || (!g_btLife && m == 0)) snprintf(d, sizeof d, "%s", M[m]); else snprintf(d, sizeof d, "%s, next start", M[m]); }
    uiListCard(12, 52, 216, 42, sel == 0, C_EB_BRASS, "Bluetooth", d, 24);
    snprintf(d, sizeof d, "%s", !g_btLife ? "Needs it on at start" : np >= blek::MAX_PEERS ? "List full" : blek::ready() ? "A phone is connected" : "Ready");
    uiListCard(12, 98, 216, 42, sel == 1, C_EB_BRASS, "Pair a phone", d, 24);
    snprintf(d, sizeof d, np == 0 ? "None paired" : np == 1 ? "1 paired" : "%d paired", np);
    uiListCard(12, 144, 216, 42, sel == 2, C_EB_BRASS, "Forget phones", d, 24);
    uiTrackLabel("ENTER TO OPEN", 120, 196, C_EB_BRASS);
    uiTrackLabel("BACK TO LEAVE", 120, 216, C_EB_GREY);
    dispPush(); clearButtonPending();
    int act = 0;
    while(!act){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
      if(tickSleepGesture() || pkMenuLeave(lp) || btn4.isPressed()) return;
      if(btn1.isPressed()){ sel = (sel + 1) % 3; act = 1; } else if(btn3.isPressed()){ sel = (sel + 2) % 3; act = 1; } else if(btn2.isPressed()) act = 2;
      delay(10); }
    lp = millis();
    if(act == 1) continue;
    if(sel == 0){
      (void)set; btModePicker(lp);   // 9c
    } else if(sel == 1){
      btPairScreen(lp);
    } else {
      btForgetScreen(lp);
    }
    lp = millis();
  }
}
// 11aj (12 Nov 2026, Josh): FORGET PHONES as its own screen, so the NOSTR
// Bluetooth life's Network menu can offer it too (it only had Pair a phone).
static void btForgetScreen(uint32_t& lp){
  const int np = blek::peersCount();
  if(np == 0){ pkPageMsg("BLUETOOTH", "No phones are paired.", nullptr); pwWaitBack(lp); return; }
  pkAsk("BLUETOOTH", "Forget phones?", np == 1 ? "The paired phone is removed." : "All paired phones are removed.", "They can pair again later.", "KEEP", "FORGET");
  if(btYesNo(lp)){ bool ok = blek::forgetAll();
#ifdef FAVILLA_PK_RESTORABLE
    ok = ag::forgetAll() && ok;   // 9g: the paired app installs go with the phones
#endif
    pkPageMsg("BLUETOOTH", ok ? "Forgotten." : "Not forgotten.", ok ? "Remove Favilla KEY on the phone too." : "The list could not be written."); pwWaitBack(lp); }
}
#endif  // FAVILLA_BLE_KBD

// Blocking PIN pad, the same chrome as the BTC PIN screen (pinDrawChrome).
// Returns true with 6 digits in out[]; there is no cancel (this life has
// nothing else to go to; sleep is the way out).
// 10m: the passkey PIN pad's first frame (digit 0 of '000000'), for the door
// hand-off in setup(); pkPinPad's own first draw is the same picture.
static void pkPinPadPreview(){
  g_pinMark = { 1.0f, 0.0f, 255, false, 0 };
  pinDrawChrome("VAULT PIN", C_EB_BRASS, 0, 0, PIN_NEW_LEN);
  const int DIGIT_IN_BOX = 15; fSet(F_TITLE); spr.setTextColor(C_EB_INK); fDrawCentre("0", 120, PIN_INK_CY - DIGIT_IN_BOX); fEnd();
  dispPush();
}
// 11w: the pad in the door hand-off gap, drawn exactly as pkPinPad draws it.
static void prePinDrawVault(const char* pin, int digit, bool armed){
  g_pinMark = { 1.0f, 0.0f, (uint8_t)(armed ? 150 : 255), false, 0 };
  pinDrawChrome("VAULT PIN", C_EB_BRASS, armed ? PIN_NEW_LEN : digit, armed ? -1 : digit, PIN_NEW_LEN);
  if(armed){ fSet(F_HEAD); spr.setTextColor(C_EB_BRASS); fDrawCentre("PRESS TO CONFIRM", 120, 170); fEnd(); }
  else { const int DIGIT_IN_BOX = 15; fSet(F_TITLE); spr.setTextColor(C_EB_INK); char ch[2] = { pin[digit], 0 }; fDrawCentre(ch, 120, PIN_INK_CY - DIGIT_IN_BOX); fEnd(); }
  dispPush();
}
static bool pkPinPad(char out[9], bool canCancel){
  char pin[9]; for(int i = 0; i < PIN_NEW_LEN; i++) pin[i] = '0'; pin[PIN_NEW_LEN] = 0;
  int digit = 0; bool armed = false;
  {   // 11w: what was pressed on the pad while the boot finished
    bool submitted = false;
    if(prePinStop(pin, &digit, &armed, &submitted) && submitted){ memcpy(out, pin, PIN_NEW_LEN); out[PIN_NEW_LEN] = 0; mbedtls_platform_zeroize(pin, sizeof pin); return true; }
  }
  auto draw = [&](){
    g_pinMark = { 1.0f, 0.0f, (uint8_t)(armed ? 150 : 255), false, 0 };
    pinDrawChrome("VAULT PIN", C_EB_BRASS, armed ? PIN_NEW_LEN : digit, armed ? -1 : digit, PIN_NEW_LEN);
    if(armed){ fSet(F_HEAD); spr.setTextColor(C_EB_BRASS); fDrawCentre("PRESS TO CONFIRM", 120, 170); fEnd(); }
    else { const int DIGIT_IN_BOX = 15; fSet(F_TITLE); spr.setTextColor(C_EB_INK); char ch[2] = { pin[digit], 0 }; fDrawCentre(ch, 120, PIN_INK_CY - DIGIT_IN_BOX); fEnd(); }
    dispPush();
  };
  clearButtonPending();
  draw();
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll();
    if(tickSleepGesture()) return false;
    pkSerialTick(); pkTripwire();
    if(btn3.isPressed()){ if(!armed){ pin[digit] = ((pin[digit]-'0'+1)%10)+'0'; draw(); } }
    else if(btn1.isPressed()){ if(!armed){ pin[digit] = ((pin[digit]-'0'+9)%10)+'0'; draw(); } }
    else if(btn4.isPressed()){ if(armed){ armed = false; digit = PIN_NEW_LEN-1; draw(); } else if(digit > 0){ digit--; draw(); }
      else if(canCancel){ mbedtls_platform_zeroize(pin, sizeof pin); return false; } }   // 4 Nov 2026: BACK on the first digit cancels (Delete all)
    else if(btn2.isPressed()){
      if(!armed){ if(++digit == PIN_NEW_LEN){ digit = PIN_NEW_LEN-1; armed = true; } draw(); }
      else { memcpy(out, pin, PIN_NEW_LEN); out[PIN_NEW_LEN] = 0; mbedtls_platform_zeroize(pin, sizeof pin); return true; }
    }
    delay(10);
  }
}

// Ask until the SE accepts the passkey PIN. Never returns without it.
static void passkeyUnlock(){
  for(;;){
    if(g_pkFails >= PK_SEND_MAX){
      LOG_BOOT("[PASSKEY] PIN budget spent (%d wrong in a row) - not sending another\n", g_pkFails);
      pkPage("VAULT", "PIN locked", "Too many wrong passkey PINs.", "Passkeys stay locked on this key.", "HOLD BOTH LEFT TO SLEEP", C_EB_GREY);
      pkHoldForever();
    }
    char pin[9] = {0};
    if(!pkPinPad(pin)) continue;   // (sleep gesture: goSleep never returns)
    pkPage("VAULT", "Checking", "Checking the PIN on the", "secure element.", nullptr);
    // Count the attempt BEFORE it reaches the SE (review, 30 Oct 2026): a power
    // cut between the SE's decrement and our save can then never let a tenth
    // attempt through. A right PIN clears it again.
    g_pkFails++; pkFailsSave();
    I2C_LOCK();
    int ok = favilla::se_passkey_pin_check(pin);
    I2C_UNLOCK();
    if(ok == 1){
      I2C_LOCK(); memcpy(g_pkPin, pin, sizeof g_pkPin); g_pkPinHeld = true; I2C_UNLOCK();
      uvNotePin(pin);   // 31 Oct 2026: the passkey PIN, entered on the KEY: user verification for 10 minutes
      mbedtls_platform_zeroize(pin, sizeof pin);
      g_pkFails = 0; pkFailsSave();
      LOG_BOOT("[PASSKEY] passkey PIN accepted by the SE - door open for this life\n");
      return;
    }
    mbedtls_platform_zeroize(pin, sizeof pin);
    LOG_BOOT("[PASSKEY] passkey PIN refused (%d of %d)\n", g_pkFails, PK_SEND_MAX);
    char l2[40]; snprintf(l2, sizeof l2, "%d tries left before it locks.", PK_SEND_MAX - g_pkFails);
    pkPage("VAULT", "Wrong PIN", "That passkey PIN was not right.", l2, "ENTER TO TRY AGAIN");
    clearButtonPending();
    for(;;){ pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire(); if(tickSleepGesture()) break; if(btn2.isPressed()) break; delay(20); }
  }
}

// ── the life ─────────────────────────────────────────────────────────────────
static void passkeyLifeRun(){
#ifdef FAVILLA_FIDO_PROBE
  fido::start();   // 10d: the FIDO service runs in this life only
#endif
  pmInit();   // 9n: automatic light sleep (light-sleep build only; a logged no-op on the stock core). setup()'s own call comes after this life takes over.
#if defined(FAVILLA_FIDO_PROBE) && defined(FAVILLA_VCHAN)
  vchan::begin();   // 8x: the channel's task and queue exist only in the PASSKEY life (internal RAM)
#endif
#ifdef FAVILLA_BLE_KBD
  if(g_btLife){
    LOG_BOOT("[PASSKEY] passkey life running (Bluetooth keyboard on: setting on at power-on; no Wi-Fi)\n");
    // 8d (bench, 5 Nov 2026: 8c ran out of internal RAM in NimBLE's attribute
    // table). The camera's resident driver and its 36 KB reserve are the
    // largest internal blocks this life holds; Bluetooth gets them first. The
    // reserve is taken back after Bluetooth is up if a 34 KB block is still
    // there (the camera's own gate); if not, a scan in this life may say the
    // camera cannot start.
    cameraRelease(); camReserveRelease("Bluetooth needs the RAM");
    LOG_BOOT("[BT] before start: internal free %u, largest %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
#ifdef FAVILLA_PK_RESTORABLE
    ag::init();   // 9g: the paired apps are known before the first write (the raw paths shut if any)
#endif
    blek::startAsync();
  }
  else
#endif
  LOG_BOOT("[PASSKEY] passkey life running (no radio, FIDO only)\n");
  pkFailsLoad();
  if(!g0_present()){   // review, 30 Oct 2026: without the G0 nothing can mint V_3; say so instead of taking PINs
    LOG_BOOT("[PASSKEY] no G0 - passkey mode cannot sign\n");
    pkPage("VAULT", "Signer missing", "The signer chip did not answer.", "Passkeys cannot work.", "HOLD BOTH LEFT TO SLEEP", C_EB_GREY);
    pkHoldForever();
  }
  bool ready;
  { I2C_LOCK(); ready = favilla::se_passkey_ready(); I2C_UNLOCK(); }
  if(!ready){
    LOG_BOOT("[PASSKEY] this unit has no passkey PIN / V_3 (set up before passkeys) - re-onboard on a FAVILLA_PASSKEY_DOOR build\n");
    pkPage("VAULT", "Not set up", "This key was set up before", "passkeys. Wipe and set it up again.", "HOLD BOTH LEFT TO SLEEP", C_EB_GREY);
    pkHoldForever();
  }
#ifdef FAVILLA_PK_RESTORABLE
  // Silicon 2 Nov 2026: setup() mounts nvs_vault only after this life has
  // taken over (it never returns), so the PASSKEY life must mount it itself.
  if(favilla::rk_mount()) LOG_BOOT("[RK] nvs_vault mounted (passkey life): %d passwordless passkey record(s), %d password(s)\n", favilla::rk_count(), favilla::rk_pw_count());
#endif
  passkeyUnlock();
#ifdef FAVILLA_PK_RESTORABLE
  // v19 (13 Nov 2026): a vault set up before "one door, one PIN" cannot be opened
  // by a v19 G0 (its copy is under a key the G0 decrypted itself). Say so, plainly.
  { bool old = false; if(g0_doorpin_present()){ I2C_LOCK(); old = favilla::se_pk_old_generation(); I2C_UNLOCK(); }
    if(old){
      LOG_BOOT("[PK2B] this KEY was set up before G0 v19: set it up again (restore from the words)\n");
      pkPage("VAULT", "Set up again", "The signer was updated.", "Restore from your words.", "HOLD BOTH LEFT TO SLEEP", C_RED);
      pkHoldForever();
    } }
  if(g0_pk2b_present()){ g0_set_window_hooks(pkWinOpenHook, pkWinCloseHook); pk2bFirstLogin(); vpubEnsure(); pkIdxUnlock(); }
  { bool p; I2C_LOCK(); p = favilla::se_pkr_ready_passkey(); I2C_UNLOCK();
    LOG_BOOT("[PK2B] passkey life: PASSKEY copy %s, record store %s, G0 2b %s\n", p ? "present" : "ABSENT", favilla::rk_ready() ? "ready" : "OFF", g0_pk2b_present() ? "present" : "absent"); }
#endif
  pkHome();
  uint32_t lastUse = millis();
  bool shown = false; uint32_t shownSeq = 0; unsigned long shownAt = 0;
  for(;;){
    esp_task_wdt_reset();
    pumpInputs(); btn3.poll(); btn4.poll();
    battRead(); tickLowBattery();
    pkSerialTick(); pkTripwire();
    if(favilla::se_passkey_wedged()){
      passkeyLock("latch not closed");
      dispRestartForever("RESTART NEEDED", "The passkey latch did not close.", "Restart the key.");   // never returns
    }
    // A website asking for a press.
    uint8_t st = fido::g_up.state; uint32_t seq = fido::g_up.seq;
    // 31 Oct 2026 (review, HIGH): a request for user verification gets the PIN
    // screen here too. Before this, the passkey life drew kind 2 as a normal
    // prompt and a press set UV.
    if(st == 1 && fido::g_up.kind == 2 && (!shown || seq != shownSeq)){
      if(dimActive) idleDimWake();
      shown = true; shownSeq = seq; shownAt = millis(); lastUse = millis();
      LOG_BOOT("[FIDO] PIN asked (passkey life) for %s\n", fido::g_up.rp);
      uint8_t r = uvPinPrompt(seq);
      if(r && fido::g_up.state == 1 && fido::g_up.seq == seq) fido::g_up.state = r;
      st = fido::g_up.state; lastUse = millis();
    }
    else if(st == 1 && (!shown || seq != shownSeq)){
      if(dimActive) idleDimWake();
      clearButtonPending();
      shown = true; shownSeq = seq; shownAt = millis(); lastUse = millis();
      g_pickSel = 0;
      fidoDrawPrompt();   // kind 3 draws the account picker
      LOG_BOOT("[FIDO] prompt shown (passkey life): %s %s\n", fido::g_up.what, fido::g_up.rp);
    } else if(shown){
      if(st == 1 && seq == shownSeq){   // never answer a request that is not the one on screen
        lastUse = millis();
        if(fido::g_up.kind == 3){         // 2b: the no-username picker in this life
          if(!g_pkPinHeld){ fido::g_up.state = 3; st = 3; }
          else { const int pn = fido::g_pick.n;
            if(pn > 1 && btn1.isPressed()){ g_pickSel = (g_pickSel + 1) % pn; fidoDrawPicker(); }
            else if(pn > 1 && btn3.isPressed()){ g_pickSel = (g_pickSel + pn - 1) % pn; fidoDrawPicker(); } }
        }
        if(st == 3){ /* refused above */ }
        else if(btn2.isPressedFresh(shownAt)) { if(fido::g_up.kind == 3) fido::g_pick.sel = (uint8_t)g_pickSel; fido::g_up.state = 2; st = 2; }
        else if(btn4.isPressedFresh(shownAt)) { fido::g_up.state = 3; st = 3; }
      }
      if(st != 1){
        shown = false;
        LOG_BOOT("[FIDO] prompt closed: %s\n", st == 2 ? "approved" : st == 3 ? "refused" : "withdrawn by the host / timeout");
        clearButtonPending();
        pkHome();
      }
    } else {
#if defined(FAVILLA_VCHAN) && defined(FAVILLA_PK_RESTORABLE)
      if(chanQueued()){   // a paired browser asked to sign in or save a login
        const bool explicitAsk = chanPending();
        if(explicitAsk && dimActive) idleDimWake();   // an automatic ask wakes the screen only if it has a login to offer
        if(chanUiRun(lastUse) || explicitAsk){ clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); }
      }
#endif
#if defined(FAVILLA_BLE_KBD) && defined(FAVILLA_PK_RESTORABLE)
      { bool f = false; if(blek::reqExpire(&f) && f) blek::fillSend(chan::S_CANCELLED, nullptr, nullptr); }   // 9c: a FILL ask not taken is answered
#ifdef FAVILLA_PK_RESTORABLE
      if(ag::otpTick(lastUse)){ clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); }   // 9i: the app asked for a one-time code
      if(ag::listTick(lastUse)){ clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); }   // 9h: the app asked for the list (item 4)
#endif
      if(vaAppRun(lastUse)){ clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); }   // 11ax (issue #30): the app's Accounts page saves or deletes
      if(vaAppImport(lastUse)){ clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); }   // 11bf: the app imports another manager's export
      { const int si = ag::showTake();   // 11s: the app's accounts page asked to see one entry
        if(si >= 0){ if(dimActive) idleDimWake(); lastUse = millis(); pwEntry(si, 0, 0, lastUse); clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome(); } }
      { // 11s: health backfill - a few OPENs per sitting on a quiet screen, for entries never assessed
        static uint32_t hbAt = 0, hbEpoch = 0; static int hbN = 0;
        if(hbEpoch != favilla::rk_lock_epoch()){ hbEpoch = favilla::rk_lock_epoch(); hbN = 0; }
        if(g_pkPinHeld && favilla::rk_ready() && !pkLeaveNow() && !blek::reqQueued()) hbAssessOneTick();   // 11ax: ASSESS_ONE first
        const bool asked = g_hbWant > 0;
        if(g_pkPinHeld && (asked || hbN < 6) && favilla::rk_ready() && (asked || millis() - lastUse > 20000UL) && millis() - hbAt > (asked ? 200UL : 5000UL) && !pkLeaveNow() && !blek::reqQueued()){
          hbAt = millis(); bool did; { g0_window_batch_begin(); did = favilla::rk_health_backfill_one(); g0_window_batch_end(); }
          if(did){ hbN++; if(asked){ g_hbWant--; g_hbDoneNow++; } LOG_BOOT("[PW] health backfill: one entry assessed (%d this sitting)\n", hbN); }
          else { hbN = 6; g_hbWant = 0; } } }
      if(blek::reqQueued()){   // 8z7: the iPhone app's Favilla sheet asked to sign in
        if(dimActive) idleDimWake();
        phoneAskRun(lastUse); clearButtonPending(); lastUse = millis(); if(!pkLeaveNow()) pkHome();
      }
#endif
#ifdef FAVILLA_BLE_KBD
      { // 8d: give the camera its block back once Bluetooth is up. 8u: again after
        // every restart that follows a scan (8t took it only once per life, so the
        // second scan found the block split: bench 5 Nov, scan, type, scan failed).
        // 11e: the reserve is no longer taken while Bluetooth is up (see main.cpp's
        // loop): stopping Bluetooth for a scan returns 45 KB, the camera needs 17.6.
        if(g_btLife && blek::s_up && !g_pkCamBack){ g_pkCamBack = true;
          LOG_BOOT("[BT] up: internal free %u, largest %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)); } }
      { static int lastBt = -1; const int b = blek::ready() ? 3 : blek::s_up ? 2 : blek::s_paused ? 4 : blek::starting() ? 1 : 0;   // the home screen's Bluetooth line follows the phone
        if(b != lastBt){ lastBt = b; if(!dimActive && !pkLeaveNow()) pkHome(); } }
#endif
      // 11bg (bench 17 Nov 2026: "hard to wake in VAULT mode"): dark, this loop
      // runs every 100 ms, and a debounced press needs two readings 100 ms apart
      // both down, so a quick tap fell between them and the screen stayed dark.
      // Wake on one raw reading of any button instead, as loop() does in the
      // NOSTR life. idleDimWake() gates the press itself, so it does not also
      // act on the home screen.
      if(dimActive && (digitalRead(BTN1_GPIO) == LOW || digitalRead(BTN2_GPIO) == LOW || digitalRead(BTN3_GPIO) == LOW || digitalRead(BTN4_GPIO) == LOW)){
        lastUse = millis();
#ifdef FAVILLA_BLE_KBD
        if(g_btLife && blek::s_up && !blek::s_conn) blek::wake(15000);   // as a press does (8y)
#endif
        idleDimWake(); pkHome();
      }
      // Idle: any press wakes a dark screen; dim after the usual timeout; lock
      // after PK_AUTOLOCK_MS with nothing happening.
      bool enter = btn2.isPressed();
      bool pressed = enter || btn1.isPressed() || btn3.isPressed() || btn4.isPressed();
      if(pressed){ lastUse = millis();
#ifdef FAVILLA_BLE_KBD
        // 8y (5 Nov 2026, the iPhone app): a press on the home screen makes the KEY
        // findable for 15 s, so the Favilla app (its AutoFill sheet) can reach it.
        // There is no advertising at rest (8m); the link is dropped 3 s after it
        // goes idle, as for typing. Ruled A: the phone may attach the keyboard
        // for those seconds.
        if(g_btLife && blek::s_up && !blek::s_conn) blek::wake(15000);
#endif
        if(dimActive){ idleDimWake(); pkHome(); }
#ifdef FAVILLA_PK_RESTORABLE
        else if(enter && g0_pk2b_present()){ lastUse = pkMenu(); if(!pkLeaveNow()) pkHome(); }   // 6c: a site asking goes straight to its prompt   // the last press in the menu, so auto-lock still counts
#endif
      }
      if(!dimActive && millis() - lastUse >= DIM_TIMEOUT_MS) idleDimFadeOut();
      if(millis() - lastUse >= PK_AUTOLOCK_MS){
        passkeyLock("auto-lock");
#ifdef FAVILLA_PK_RESTORABLE
        pwBgReset();
#endif
        if(dimActive) idleDimWake();
        passkeyUnlock();
#ifdef FAVILLA_PK_RESTORABLE
        pk2bFirstLogin();   // review (L4): a copy write that failed earlier is retried at each unlock
        vpubEnsure();       // phase 3: likewise
        pkIdxUnlock();      // P4-10: the site names, at once
#endif
        lastUse = millis();
        pkHome();
      }
    }
    if(tickSleepGesture()) { /* goSleep never returns */ }
    // 11cf (power, 21 Nov 2026): this loop never called it, so in VAULT mode the
    // first battery read in the dark (30 s in, 11k wakes the G0 for it), a health
    // backfill, or an app request left the G0 awake (WFI, about 2.5 to 4 mA) until
    // the screen next lit. The NOSTR life and the menus have always called it.
    g0DimSleepTick();
    // 9y (power): 10 ms a pass kept the chip waking 100 times a second with the
    // screen dark, cutting every light-sleep nap short. Dark, 100 ms (the NOSTR
    // life's loop does the same): a press still shows within a tenth of a
    // second, and a website's prompt or a phone's request arrives by its own
    // task and wakes the screen on the next pass.
    delay(dimActive ? 100 : 10);
  }
}
