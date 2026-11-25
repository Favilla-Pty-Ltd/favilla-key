// =============================================================================
// vault_api.inc - the PWA's password page, KEY side (3 Nov 2026, Vault spec 7f,
// phase 4: the PWA in NOSTR mode over Wi-Fi). Included by main.cpp after the
// FIDO glue and passkey_life.inc (env:favilla_key_fido only).
//
// What the phone can do, all over the sealed session, KEY unlocked, NOSTR life,
// NOSTR gate open (the passkey master's NOSTR copy is on the SE):
//   GET  /api/vault/pw            site and username of every entry (LABEL, never
//                                 an OPEN); the KEY labels uncached entries in
//                                 the background while the phone keeps asking.
//   POST /api/vault/pw/save       add or edit one entry. The KEY shows the site
//                                 and username; a 1 s hold of ENTER seals it.
//   POST /api/vault/pw/delete     delete one entry, same press.
//   GET  /api/vault/pw/result     the last job: waiting / working / done.
//   POST /api/vault/import/begin  the PIN on the KEY opens the G0's import window
//                                 (UVCHECK, then VAULT op 5 straight after).
//   POST /api/vault/import/end    the phone is done: the window closes here.
// While the window is open, saves marked "import" are sealed with no press:
// the PIN was the consent. The window closes on BACK, a lock, /end, or 10
// minutes without an entry (the G0's own window ends at the next lock).
//
// No endpoint ever returns a password. Passwords sent by the phone are wiped
// from the request body and the JSON parser's memory once sealed.
//
// The approval, the PIN pad and the import screen are overlays like the
// reconnect approval: non-blocking ticks from loop(), menus yield to them, the
// footer does not paint over them (g_vaultOverlay, checked with g_rcApprove).
// =============================================================================

// ---- the JSON parser's memory, wiped on free (passwords pass through it) ------
#include "otpauth.h"   // 11ac: base32 and the SHA1 check for the one-time code import
struct VaWipeAlloc : ArduinoJson::Allocator {
  void* allocate(size_t n) override {
    size_t* p = (size_t*)malloc(n + sizeof(size_t)); if (!p) return nullptr; *p = n; return p + 1;
  }
  void deallocate(void* ptr) override {
    if (!ptr) return;
    size_t* p = (size_t*)ptr - 1; mbedtls_platform_zeroize(p, *p + sizeof(size_t)); free(p);
  }
  void* reallocate(void* ptr, size_t n) override {
    if (!ptr) return allocate(n);
    void* q = allocate(n); if (!q) return nullptr;
    size_t old = ((size_t*)ptr)[-1]; memcpy(q, ptr, old < n ? old : n);
    deallocate(ptr); return q;
  }
};
static VaWipeAlloc g_vaAlloc;
static void vaWipeString(String& s){ if(s.length()) mbedtls_platform_zeroize((void*)s.c_str(), s.length()); s = String(); }

// ---- state ---------------------------------------------------------------------
enum { VJ_NONE = 0, VJ_SAVE, VJ_DELETE, VJ_PIN, VJ_DELMANY, VJ_RECOVERY };   // VJ_DELMANY: 4 Nov 2026, the phone's "Delete selected"; VJ_RECOVERY: 11aa, the site's recovery codes
enum { VJP_IDLE = 0, VJP_ASK, VJP_WORK, VJP_DONE };
static struct {
  uint8_t  kind, phase;
  uint32_t seq;
  int      res, slot;
  char     err[20];          // short code for the PWA: declined, timeout, gone, locked, pin, uv, refused, full, budget, g0, nvs, size
  bool     edit, keepPass, keepNote, imp;
  bool     keepOld;          // 11bi (issue #38): the app's PW_SAVE flags bit0, a changed password keeps the old one as "<site> (old)"
  uint8_t  id8[8];
  favilla::RkPass* e;        // PSRAM, wiped when the job ends
  unsigned long at;
  bool     sawRel, inited; float lastPct;
  char     pin[PIN_NEW_LEN + 1]; int digit; bool armed, wrong;
  char     site[favilla::RK_SITE_MAX + 1], user[favilla::RK_PW_FIELD_MAX + 1];   // what the screen shows (no password)
  int*     manySlots; uint8_t (*manyIds)[8]; int manyN, manyDone;   // VJ_DELMANY (PSRAM, freed when the job ends)
  char   (*rc)[favilla::RK_RC_LEN + 1]; int rcN;   // VJ_RECOVERY (PSRAM, wiped and freed when the job ends)
} g_vj;
static struct { bool open; int saved, failed, kept, sealsLeft; unsigned long at, last, drawn; int drawnSaved; } g_vImp;   // kept (11bh): already on the KEY, not counted in failed
static bool g_vImpUsed = false;              // this life's window was opened (the G0 allows one)
static bool vaImportUsed(){ return g_vImpUsed; }   // 11bf: for the app channel (ble_app.inc)
static unsigned long g_vListWantUntil = 0;   // the phone is reading the list: label in the background until then
static const unsigned long VA_ASK_MS = 60000UL, VA_PIN_MS = 90000UL, VA_IMPORT_IDLE_MS = 600000UL;

static void vaOverlaySync(){ g_vaultOverlay = (g_vj.phase == VJP_ASK) || g_vImp.open; }

static void vaJobEnd(int res, const char* err){
  g_vj.res = res; strlcpy(g_vj.err, err ? err : "", sizeof g_vj.err);
  g_vj.phase = VJP_DONE;
  if(g_vj.e){ favilla::rk_pw_wipe(g_vj.e); free(g_vj.e); g_vj.e = nullptr; }
  if(g_vj.manySlots){ free(g_vj.manySlots); g_vj.manySlots = nullptr; }
  if(g_vj.manyIds){ free(g_vj.manyIds); g_vj.manyIds = nullptr; }
  if(g_vj.rc){ mbedtls_platform_zeroize(g_vj.rc, (favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX); free(g_vj.rc); g_vj.rc = nullptr; }   // 11aa
  mbedtls_platform_zeroize(g_vj.pin, sizeof g_vj.pin);
  vaOverlaySync();
}
static const char* vaErrOf(int r){
  switch(r){
    case favilla::RK_E_FULL: return "full"; case favilla::RK_E_BUDGET: return "budget"; case favilla::RK_E_SIZE: return "size";
    case favilla::RK_E_NVS: return "nvs"; case favilla::RK_E_NOVAULT: return "novault";
    default: return favilla::rk_last_res() == 0xEA ? "refused" : "g0";
  }
}

// Where the overlay covered a screen, put it back (as the FIDO prompt does).
static void vaRestoreScreen(){
  clearButtonPending();
  if(nextState != currentState) { }
  else if(currentState == ST_MENU) dispMenu();
  else if(currentState != (DeviceState)99) { nextState = currentState; currentState = (DeviceState)99; }
}

// ---- gate ------------------------------------------------------------------------
// 0 open; else the HTTP answer was sent.
// v19 (13 Nov 2026, one door one PIN): the NOSTR life opens no vault record and
// holds no site index key. These routes answer "gate" (the PWA shows "VAULT mode
// only"); the relay backup, which carries the records sealed, still runs here.
static int vaCheck(){
  if(!fsec::apiCheckAuth2()){ fsec::apiSend(401, "{\"error\":\"Unauthorized\"}"); return 1; }
  if(!wallet.unlocked){ fsec::apiSend(403, "{\"error\":\"Device locked\",\"locked\":true}"); return 1; }
  if(g_passkeyLife || !favilla::rk_ready() || !g0_v15_present() || !g0_pk2b_present()){ fsec::apiSend(409, "{\"error\":\"unsupported\"}"); return 1; }
  if(!fidoBePkrOpen()){ fsec::apiSend(409, "{\"error\":\"gate\"}"); return 1; }   // v19: always in a NOSTR life with a v19 G0: the PWA shows "VAULT mode only"
  return 0;
}
static constexpr int VA_PAGE = 40;   // list rows per reply (bench 3 Nov: ~3.5 KB of JSON)
static void vaJsonStr(String& o, const char* s){
  o += '"';
  for(const uint8_t* p = (const uint8_t*)s; *p; p++){
    if(*p == '"' || *p == '\\'){ o += '\\'; o += (char)*p; }
    else if(*p < 0x20){ char b[8]; snprintf(b, sizeof b, "\\u%04x", *p); o += b; }
    else o += (char)*p;
  }
  o += '"';
}
static void vaHex8(char* out, const uint8_t id[8]){ for(int i = 0; i < 8; i++) sprintf(out + 2*i, "%02x", id[i]); out[16] = 0; }
static bool vaUnhex8(const char* s, uint8_t id[8]){
  if(!s || strlen(s) != 16) return false;
  for(int i = 0; i < 8; i++){ unsigned v; if(sscanf(s + 2*i, "%2x", &v) != 1) return false; id[i] = (uint8_t)v; }
  return true;
}
static bool vaPendingSite(const char* s){   // "New entry N": saved on the KEY by the generator, site and username still to come
  if(strncmp(s, "New entry ", 10)) return false;
  const char* p = s + 10; if(!*p) return false;
  for(; *p; p++) if(*p < '0' || *p > '9') return false;
  return true;
}

// ---- screens --------------------------------------------------------------------
static void vaFitLine(const char* s, char* out, size_t cap, int maxW){
  strlcpy(out, s, cap);
  if(spr.textWidth(out) <= maxW) return;
  size_t n = strlen(out);
  while(n > 0){ n--; while(n > 0 && ((uint8_t)out[n] & 0xC0) == 0x80) n--;   // cut on a character boundary
    out[n] = 0; char t[160]; snprintf(t, sizeof t, "%s...", out); if(spr.textWidth(t) <= maxW){ strlcpy(out, t, cap); return; } }
}
static void vaDrawAsk(float pct){
  if(pct < 0.0f) pct = 0.0f;
  if(pct > 1.0f) pct = 1.0f;
  const bool many = g_vj.kind == VJ_DELMANY, rc = g_vj.kind == VJ_RECOVERY;
  const bool del = g_vj.kind == VJ_DELETE || many;
  const char* hdr = many ? "DELETE ENTRIES" : del ? "DELETE ENTRY" : rc ? "RECOVERY CODES" : g_vj.edit ? "CHANGE ENTRY" : "NEW ENTRY";
  const char* ask = del ? "DELETE?" : "SAVE?";
  const char* doing = del ? "DELETING" : "SAVING";
  spr.fillSprite(C_BG);
  uiHeader(hdr, C_EB_BRASS);
  g_ebMarkOX = 96; g_ebMarkOY = 44;
  g_pinMark = { pct, 0.0f, 255, false, 0 };
  ebMarkDraw(g_pinMark);
  pinDrawLabel(pct > 0.02f ? doing : ask, 104, pct > 0.02f ? C_EB_INK : C_EB_GREY);
  char line[160], u[150];
  fSet(F_BODY); spr.setTextColor(C_EB_INK);
  vaFitLine(g_vj.site, line, sizeof line, 200); fDrawCentre(line, 120, 132); fEnd();
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  if(many) strlcpy(u, "and their passwords, from this KEY", sizeof u);
  else if(rc) snprintf(u, sizeof u, g_vj.rcN == 1 ? "1 recovery code, sealed here" : "%d recovery codes, sealed here", g_vj.rcN);
  else if(g_vj.user[0]) snprintf(u, sizeof u, "as %s", g_vj.user); else strlcpy(u, "no username", sizeof u);
  vaFitLine(u, line, sizeof line, 200); fDrawCentre(line, 120, 149); fEnd();
  if(g_vj.kind == VJ_SAVE && g_vj.keepOld){ fSet(F_BODY); spr.setTextColor(C_EB_BRASS); fDrawCentre("Keeps the old one as OLD", 120, 165); fEnd(); }   // 11bi
  spr.drawFastHLine(24, 178, 192, C_EB_LINE);
  fSet(F_BODY); spr.setTextColor(del ? C_RED : C_EB_BRASS);
  fDrawCentre(del ? "Hold ENTER to delete" : "Hold ENTER to save", 120, 188); fEnd();
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  fDrawCentre("BACK to cancel", 120, 210); fEnd();
  g_ebMarkOX = 96; g_ebMarkOY = 32;
  dispPush();
}
static void vaDrawPin(){
  char label[40];
  if(g_vj.wrong) snprintf(label, sizeof label, "WRONG PIN, %d LEFT", (int)(UV_MAX_WRONG - g_uvWrong));
  else snprintf(label, sizeof label, "IMPORT PIN");
  g_pinMark = { 1.0f, 0.0f, (uint8_t)(g_vj.armed ? 150 : 255), false, 0 };
  pinDrawChrome(label, g_vj.wrong ? C_RED : C_EB_BRASS, g_vj.armed ? PIN_NEW_LEN : g_vj.digit, g_vj.armed ? -1 : g_vj.digit, PIN_NEW_LEN);
  if(g_vj.armed){ fSet(F_HEAD); spr.setTextColor(C_EB_BRASS); fDrawCentre("PRESS TO CONFIRM", 120, 170); fEnd(); }
  else { const int DIGIT_IN_BOX = 15; fSet(F_TITLE); spr.setTextColor(C_EB_INK); char ch[2] = { g_vj.pin[g_vj.digit], 0 }; fDrawCentre(ch, 120, PIN_INK_CY - DIGIT_IN_BOX); fEnd(); }
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  uiWrapCentre("Opens the import window for your phone", 200, 210, 18, 1);
  fEndHard();
  dispPush();
}
static void vaDrawImport(){
  char head[24], l1[48];
  snprintf(head, sizeof head, g_vImp.saved == 1 ? "1 saved" : "%d saved", g_vImp.saved);
  if(g_vImp.failed) snprintf(l1, sizeof l1, "%d could not be saved.", g_vImp.failed);
  else if(g_vImp.kept) snprintf(l1, sizeof l1, "%d already here, kept.", g_vImp.kept);   // 11bh
  else strlcpy(l1, "Your phone is sending entries.", sizeof l1);
  pkPage("IMPORT", head, l1, "A lock also closes the window.", "BACK TO CLOSE");
  g_vImp.drawn = millis(); g_vImp.drawnSaved = g_vImp.saved + 1000 * g_vImp.failed;
}

static void vaImportClose(const char* why){
  if(!g_vImp.open) return;
  g_vImp.open = false;
  favilla::rk_idx_batch(false);
  LOG_BOOT("[VAULT] import window closed (%s): %d saved, %d failed\n", why, g_vImp.saved, g_vImp.failed);
  vaOverlaySync();
  if(!fidoPromptActive()) vaRestoreScreen();
}

// ---- the work ---------------------------------------------------------------------
static void vaDoSave(){
  favilla::RkPass* e = g_vj.e;
  favilla::RkPass* o = nullptr;
  int r = favilla::RK_OK, slot = -1, oldSlot = -1;   // oldSlot: 11bi, the (old) copy this save made
  if(g_vj.edit){
    int i = favilla::rk_pw_index_of(g_vj.slot, g_vj.id8);
    if(i < 0){ vaJobEnd(-100, "gone"); return; }
    o = (favilla::RkPass*)vbAlloc(sizeof(favilla::RkPass));
    if(!o){ vaJobEnd(favilla::RK_E_NVS, "nvs"); return; }
    r = RK_PIN(favilla::rk_pw_open(i, o));   // one OPEN: the password, note and dates the phone never sees
    if(r){ favilla::rk_pw_wipe(o); free(o); vaJobEnd(r, vaErrOf(r)); return; }
    if(g_vj.keepPass) strlcpy(e->pass, o->pass, sizeof e->pass);
    if(g_vj.keepNote) strlcpy(e->note, o->note, sizeof e->note);
    e->created = o->created;
    e->policy = g_vj.keepPass ? (o->policy & ~pwgen::POLICY_PENDING) : 0;   // a typed-in password has no generator policy
    e->slot = g_vj.slot;
    // 11bi (issue #38): the app asked to keep the old password, as CHANGE PASSWORD
    // does (11az): copied to "<site> (old)" first, with its note, so a site that
    // refuses the new one leaves nobody locked out. Only when the password changes.
    if(g_vj.keepOld && !g_vj.keepPass && strcmp(e->pass, o->pass)){
      char os[favilla::RK_SITE_MAX + 1]; snprintf(os, sizeof os, "%.*s%s", (int)(favilla::RK_SITE_MAX - (sizeof PW_OLD_TAG - 1)), o->site, PW_OLD_TAG);
      if(pwIsOld(o->site) || pwFindExact(os, o->user) >= 0){ favilla::rk_pw_wipe(o); free(o); vaJobEnd(-106, "waiting"); return; }   // an old copy, or a change already waiting
      favilla::RkPass* c = (favilla::RkPass*)vbAlloc(sizeof(favilla::RkPass));
      if(!c){ favilla::rk_pw_wipe(o); free(o); vaJobEnd(favilla::RK_E_NVS, "nvs"); return; }
      memcpy(c, o, sizeof *c); c->slot = -1;
      snprintf(c->site, sizeof c->site, "%s", os);
      snprintf(c->note, sizeof c->note, "%s", "Kept by CHANGE PASSWORD until the site takes the new one.");
      r = RK_PIN(favilla::rk_pw_save(c, &oldSlot));
      favilla::rk_pw_wipe(c); free(c);
      LOG_BOOT("[VAULT] app change: old password of slot %d kept as (old) in slot %d: %s\n", g_vj.slot, oldSlot, favilla::rk_err_name(r));
      if(r){ favilla::rk_pw_wipe(o); free(o); vaJobEnd(r, vaErrOf(r)); return; }
    }
    favilla::rk_pw_wipe(o); free(o);
    if(favilla::rk_pw_check(strlen(e->site), strlen(e->user), strlen(e->pass), strlen(e->note))){
      if(oldSlot >= 0){ g0_window_batch_begin(); favilla::rk_delete(oldSlot); g0_window_batch_end(); }
      vaJobEnd(favilla::RK_E_SIZE, "size"); return; }
  }
  e->origin = g_vj.imp ? favilla::RK_ORIGIN_IMPORT : (g_vj.edit && g_vj.keepPass) ? favilla::RK_ORIGIN_UNKNOWN : favilla::RK_ORIGIN_OWN;   // 11s: an edit that keeps the password keeps its origin
  r = RK_PIN(favilla::rk_pw_save(e, &slot));
  if(r && oldSlot >= 0){ int de; { g0_window_batch_begin(); de = favilla::rk_delete(oldSlot); g0_window_batch_end(); } LOG_BOOT("[VAULT] app change not saved: the (old) copy removed again: %s\n", favilla::rk_err_name(de)); }   // 11bi
  g_vj.slot = slot;
  if(r != favilla::RK_OK || !favilla::rk_pw_id_of(slot, g_vj.id8)) memset(g_vj.id8, 0, 8);   // the id of what was written, for the phone (from the clear header: no LABEL)
  LOG_BOOT("[VAULT] PWA %s: %s (slot %d)%s\n", g_vj.imp ? "import entry" : g_vj.edit ? "edit" : "new entry", favilla::rk_err_name(r), slot, r ? favilla::rk_hint() : "");
  vaJobEnd(r, r ? vaErrOf(r) : "");
}
static void vaDoDelete(){
  int i = favilla::rk_pw_index_of(g_vj.slot, g_vj.id8);
  if(i < 0){ vaJobEnd(-100, "gone"); return; }
  int r; { g0_window_batch_begin(); r = favilla::rk_delete(g_vj.slot); g0_window_batch_end(); }
  LOG_BOOT("[VAULT] PWA delete: %s (slot %d)\n", favilla::rk_err_name(r), g_vj.slot);
  vaJobEnd(r, r ? vaErrOf(r) : "");
}
static void vaDoRecovery(){   // 11aa
  int i = favilla::rk_pw_index_of(g_vj.slot, g_vj.id8);
  if(i < 0 || !g_vj.rc){ vaJobEnd(-100, "gone"); return; }
  int slot = -1, r; r = RK_PIN(favilla::rk_rc_save(g_vj.site, g_vj.user, g_vj.rc, g_vj.rcN, &slot));
  LOG_BOOT("[VAULT] PWA recovery codes: %s (%d codes, record slot %d)\n", favilla::rk_err_name(r), g_vj.rcN, slot);
  vaJobEnd(r, r ? vaErrOf(r) : "");
}
static void vaDoDeleteMany(){
  int done = 0, skipped = 0;
  int r = favilla::rk_delete_many(g_vj.manySlots, g_vj.manyIds, g_vj.manyN, &done, &skipped);   // no G0 call: tombstones, NVS, the index
  g_vj.manyDone = done;
  LOG_BOOT("[VAULT] PWA delete selected: %d of %d deleted, %d had changed meanwhile: %s\n", done, g_vj.manyN, skipped, favilla::rk_err_name(r));
  vaJobEnd(r, r ? vaErrOf(r) : "");
}
static void vaDoPin(){
  int r = uvCheckPin(g_vj.pin);
  mbedtls_platform_zeroize(g_vj.pin, sizeof g_vj.pin);
  if(r == 1){
    int seals = 0, tags = 0;
    int w = favilla::rk_pw_import_window(&seals, &tags);   // straight after the right UVCHECK: nothing in between
    g_uvWrong = 0;
    if(w){ LOG_BOOT("[VAULT] import window: %s, G0 0x%02X %s\n", favilla::rk_err_name(w), favilla::rk_last_res(), favilla::rk_hint()); vaJobEnd(w, vaErrOf(w)); vaRestoreScreen(); return; }
    g_vImpUsed = true;
    favilla::rk_idx_batch(true);   // P4-10: one index write at the end, not one per entry
    g_vImp = {}; g_vImp.open = true; g_vImp.sealsLeft = seals; g_vImp.at = g_vImp.last = millis();
    LOG_BOOT("[VAULT] import window open: %d seals, %d tags\n", seals, tags);
    vaJobEnd(0, "");
    vaOverlaySync();
    vaDrawImport();
    return;
  }
  if(r < 0){ uvForget(); LOG_BOOT("[VAULT] import PIN could not be checked (no G0 reference)\n"); vaJobEnd(-101, "uv"); vaRestoreScreen(); return; }
  if(++g_uvWrong >= UV_MAX_WRONG){ uvForget(); LOG_BOOT("[VAULT] import: %d wrong PINs, user verification off until a lock and unlock on the KEY\n", (int)UV_MAX_WRONG); vaJobEnd(-102, "pin"); vaRestoreScreen(); return; }
  LOG_BOOT("[VAULT] import: wrong PIN (%d left)\n", (int)(UV_MAX_WRONG - g_uvWrong));
  for(int i = 0; i < PIN_NEW_LEN; i++) g_vj.pin[i] = '0';
  g_vj.digit = 0; g_vj.armed = false; g_vj.wrong = true;
  vaDrawPin();
}

// Every loop(). Returns quickly; the G0 work of one job runs in one tick.
static void vaultApiTick(){
  // A lock ends everything: the window, a question on screen, a job not yet run.
  if(!wallet.unlocked){
    if(g_vImp.open) vaImportClose("lock");
    if(g_vj.phase == VJP_ASK || g_vj.phase == VJP_WORK){ bool ask = g_vj.phase == VJP_ASK; if(ask) securityUxEnd(); vaJobEnd(-103, "locked"); if(ask) vaRestoreScreen(); }
    return;
  }
  vpubPendingTick();   // v19: once per unlock, the publishing key copy under the daily layer
  if(fidoPromptActive()) return;   // a website's prompt has the screen; we draw again after it
  if(g_vj.phase == VJP_WORK){
    if(g_vj.imp && !g_vImp.open){ vaJobEnd(-106, "window"); return; }   // closed on the KEY after the phone sent it
    if(g_vj.kind == VJ_SAVE) vaDoSave(); else if(g_vj.kind == VJ_DELETE) vaDoDelete(); else if(g_vj.kind == VJ_DELMANY) vaDoDeleteMany(); else if(g_vj.kind == VJ_RECOVERY) vaDoRecovery();
    if(g_vj.imp && g_vImp.open){ if(g_vj.res == 0) g_vImp.saved++; else g_vImp.failed++; g_vImp.last = millis(); }
    return;
  }
  if(g_vj.phase == VJP_ASK){
    lastActivity = millis();
    if(g_vj.kind == VJ_PIN){
      pumpInputs(); btn3.poll(); btn4.poll();
      if(millis() - g_vj.at > VA_PIN_MS){ securityUxEnd(); vaJobEnd(-104, "timeout"); vaRestoreScreen(); return; }
      if(btn3.isPressed()){ if(!g_vj.armed){ g_vj.pin[g_vj.digit] = ((g_vj.pin[g_vj.digit]-'0'+1)%10)+'0'; } vaDrawPin(); }
      else if(btn1.isPressed()){ if(!g_vj.armed){ g_vj.pin[g_vj.digit] = ((g_vj.pin[g_vj.digit]-'0'+9)%10)+'0'; } vaDrawPin(); }
      else if(btn4.isPressed()){
        if(g_vj.armed){ g_vj.armed = false; g_vj.digit = PIN_NEW_LEN-1; vaDrawPin(); }
        else if(g_vj.digit > 0){ g_vj.digit--; vaDrawPin(); }
        else { securityUxEnd(); vaJobEnd(-105, "declined"); LOG_BOOT("[VAULT] import PIN cancelled on the KEY\n"); vaRestoreScreen(); }
      }
      else if(btn2.isPressed()){
        if(!g_vj.armed){ if(++g_vj.digit == PIN_NEW_LEN){ g_vj.digit = PIN_NEW_LEN-1; g_vj.armed = true; } vaDrawPin(); }
        else { securityUxEnd(); vaDoPin(); }
      }
      else if(g_vj.inited == false){ vaDrawPin(); g_vj.inited = true; }
      return;
    }
    btn2.poll(); btn4.poll();
    bool decline = btn4.isPressed();
    bool timeout = millis() - g_vj.at > VA_ASK_MS;
    if(btn2.stable == HIGH) g_vj.sawRel = true;
    float pct = g_vj.sawRel ? btn2.holdProgress(g_vj.kind == VJ_DELMANY ? 2000 : 1000) : 0.0f;   // many at once: a 2 s hold
    if(pct >= 1.0f){
      clearButtonPending(); securityUxEnd();
      g_vj.phase = VJP_WORK; vaOverlaySync();
      if(g_vj.kind == VJ_SAVE) vaDoSave(); else if(g_vj.kind == VJ_DELMANY) vaDoDeleteMany(); else if(g_vj.kind == VJ_RECOVERY) vaDoRecovery(); else vaDoDelete();
      if(g_vj.res == 0){
        if(g_vj.kind == VJ_DELMANY){ char t[40]; snprintf(t, sizeof t, g_vj.manyDone == 1 ? "1 entry" : "%d entries", g_vj.manyDone); dispEmberBurst("Deleted", "DELETED", t); }
        else dispEmberBurst(g_vj.kind == VJ_DELETE ? "Deleted" : "Saved", g_vj.kind == VJ_DELETE ? "DELETED" : g_vj.kind == VJ_RECOVERY ? "CODES SEALED" : "SAVED", g_vj.site);
      }
      else dispEmberFail("Not saved", "NOT SAVED", g_vj.res == -100 ? "The entry changed meanwhile" : favilla::rk_err_name(g_vj.res), 1600);
      vaRestoreScreen();
      return;
    }
    if(decline || timeout){
      clearButtonPending(); securityUxEnd();
      vaJobEnd(timeout ? -104 : -105, timeout ? "timeout" : "declined");
      buzzerFail(); dispEmberFail("Cancelled", "CANCELLED", "Nothing was changed", 1200);
      LOG_BOOT("[VAULT] PWA %s %s on the KEY\n", g_vj.kind == VJ_DELMANY ? "delete selected" : g_vj.kind == VJ_DELETE ? "delete" : g_vj.kind == VJ_RECOVERY ? "recovery codes" : "save", timeout ? "timed out" : "declined");
      vaRestoreScreen();
      return;
    }
    vaDrawAsk(pct);   // every tick, like the reconnect approval: nothing else paints over it
    return;
  }
  if(g_vImp.open){
    lastActivity = millis();
    btn4.poll();
    if(btn4.isPressed()){ clearButtonPending(); vaImportClose("BACK on the KEY"); return; }
    if(millis() - g_vImp.last > VA_IMPORT_IDLE_MS){ vaImportClose("10 minutes without an entry"); return; }
    if(g_vImp.drawnSaved != g_vImp.saved + 1000 * g_vImp.failed || millis() - g_vImp.drawn > 1000) vaDrawImport();
    return;
  }
  // The phone is reading the list: label one entry not yet in the cache (about
  // half a second each on the G0; the list fills in as the phone polls).
  // 3 Nov 2026 (bench): one label is ~0.47 s of a frozen loop, so none while the owner is using the buttons.
  if(g_vListWantUntil && (long)(g_vListWantUntil - millis()) > 0 && !g_rcApprove.active && millis() - lastButtonPress > 1200){
    // Bench 3 Nov 2026: names only (the index has most of them; a label heals the
    // rest), newest first. Usernames are read one at a time when the phone asks
    // for Edit (/api/vault/pw/user), not for the whole list.
    static int* ord = nullptr; if(!ord) ord = (int*)heap_caps_malloc(sizeof(int) * favilla::RK_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);   // 11dr: PSRAM, once (was 1.6 KB of internal RAM at 400)
    if(!ord) return;
    int n = favilla::rk_pw_order(ord, favilla::RK_MAX); bool labelled = false;
    for(int k = 0; k < n; k++){
      int i = ord[k];
      if(favilla::rk_pw_site_known(i)) continue;
      favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(i, &L); g0_window_batch_end(); }
      mbedtls_platform_zeroize(&L, sizeof L);
      labelled = true;
      if(r){ LOG_BOOT("[VAULT] list: LABEL %s, G0 0x%02X %s\n", favilla::rk_err_name(r), favilla::rk_last_res(), favilla::rk_hint()); g_vListWantUntil = 0; }
      break;
    }
    if(!labelled) favilla::rk_idx_flush();   // every name known: write the heals (a no-op when nothing changed)
  }
}

// ---- endpoints ------------------------------------------------------------------
static bool vaJobBusy(){ return g_vj.phase == VJP_ASK || g_vj.phase == VJP_WORK; }
static void vaSendJob(){
  char id[17]; vaHex8(id, g_vj.id8);
  const char* st = g_vj.phase == VJP_ASK ? "waiting" : g_vj.phase == VJP_WORK ? "working" : g_vj.phase == VJP_DONE ? "done" : "none";
  String o = "{\"seq\":" + String(g_vj.seq) + ",\"state\":\"" + st + "\",\"ok\":" + (g_vj.phase == VJP_DONE && g_vj.res == 0 ? "true" : "false")
           + ",\"error\":\"" + g_vj.err + "\",\"slot\":" + String(g_vj.slot) + ",\"id\":\"" + id + "\""
           + ",\"importOpen\":" + (g_vImp.open ? "true" : "false") + ",\"importSaved\":" + String(g_vImp.saved) + ",\"deleted\":" + String(g_vj.manyDone) + "}";
  fsec::apiSend(200, o);
}
static void vaJobStart(uint8_t kind){
  g_vj.kind = kind; g_vj.seq++; g_vj.res = 0; g_vj.err[0] = 0; g_vj.at = millis(); g_vj.manyDone = 0;
  g_vj.sawRel = false; g_vj.lastPct = -1.0f; g_vj.inited = false; g_vj.keepOld = false;
  g_vj.digit = 0; g_vj.armed = false; g_vj.wrong = false;
  for(int i = 0; i < PIN_NEW_LEN; i++) g_vj.pin[i] = '0';
  g_vj.pin[PIN_NEW_LEN] = 0;
}
static void vaAskBegin(){
  g_vj.phase = VJP_ASK; vaOverlaySync();
  if(dimActive) idleDimWake();
  lastActivity = millis();
  securityUxBegin();
  buzzerSignRequest();
  clearButtonPending();
  btn2.resetHold(); btn4.resetHold();
}

void vaultApiRegister(){
  // 3 Nov 2026 (bench, 194 entries): the whole list in one reply (about 14 KB of
  // JSON, 19 KB sealed) took 6.7 to 10.4 s with ~5-9 KB of internal heap left
  // after a DM burst, and the phone gave up. The list now comes in pages of
  // VA_PAGE rows (about the size that always loaded fast), asked for with a
  // sealed POST so the page number is authenticated too (a GET's query string
  // is not covered by its MAC). GET still answers with the first page.
  auto vaList = [](int from){
    g_vListWantUntil = millis() + 15000UL;
    favilla::RkRow* rows = (favilla::RkRow*)vbAlloc(sizeof(favilla::RkRow) * favilla::RK_MAX);   // PSRAM
    if(!rows){ fsec::apiSend(500, "{\"error\":\"memory\"}"); return; }
    const int n = favilla::rk_pw_rows(rows, favilla::RK_MAX);   // one lock for the whole list (bench: 10 s row by row)
    int listed = 0, named = 0;
    for(int k = 0; k < n; k++){ listed += rows[k].nameKnown; named += rows[k].userKnown; }
    if(from < 0 || from > n) from = n;
    const int to = (n - from) > VA_PAGE ? from + VA_PAGE : n;
    String o; o.reserve(640 + (to - from) * 110);
    o = "{\"entries\":[";
    for(int k = from; k < to; k++){
      favilla::RkRow& row = rows[k];
      char id[17]; vaHex8(id, row.id8);
      if(k > from) o += ',';
      o += "{\"slot\":" + String(row.slot) + ",\"id\":\"" + id + "\",\"site\":";
      if(row.nameKnown) vaJsonStr(o, row.site); else o += "null";   // listed while its name is read, never left out
      if(row.cut) o += ",\"cut\":true";
      if(row.userKnown){ o += ",\"user\":"; vaJsonStr(o, row.user); } else o += ",\"user\":null";
      o += ",\"pending\":"; o += row.pending ? "true" : "false";
      o += ",\"health\":" + String((int)row.health) + '}';   // 11s: the health byte (pk_records.h); 0 = nothing known yet
    }
    mbedtls_platform_zeroize(rows, sizeof(favilla::RkRow) * favilla::RK_MAX); free(rows);
    o += "],\"from\":" + String(from) + ",\"next\":" + (to < n ? String(to) : String("null"))
       + ",\"total\":" + String(n) + ",\"listed\":" + String(listed) + ",\"usersKnown\":" + String(named) + ",\"max\":" + String(favilla::RK_MAX) + ",\"records\":" + String(favilla::rk_count_all())
       + ",\"labelsLeft\":" + String(favilla::rk_label_left()) + ",\"opensLeft\":" + String(favilla::rk_open_left())
       + ",\"importOpen\":" + (g_vImp.open ? "true" : "false") + ",\"importUsed\":" + (g_vImpUsed ? "true" : "false")
       + ",\"importSaved\":" + String(g_vImp.saved) + ",\"importSealsLeft\":" + String(g_vImp.sealsLeft) + "}";
    fsec::apiSend(200, o);
  };
  apiOn("/api/vault/pw", HTTP_GET, [vaList](){
    apiAddCORS();
    if(vaCheck()) return;
    vaList(0);
  });
  apiOn("/api/vault/pw/page", HTTP_POST, [vaList](){
    apiAddCORS();
    if(vaCheck()) return;
    String body = fsec::apiReadBody();
    JsonDocument doc;
    if(deserializeJson(doc, body)){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    vaList(doc["from"] | 0);
  });
  apiOn("/api/vault/pw/page", HTTP_OPTIONS, handleApiOptions);
  // Bench 3 Nov 2026: one entry's username (and its full name), read when the phone
  // opens it for Edit: one LABEL, about half a second, instead of the whole list.
  apiOn("/api/vault/pw/user", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    String body = fsec::apiReadBody();
    JsonDocument doc;
    if(deserializeJson(doc, body)){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    int slot = doc["slot"] | -1; uint8_t id8[8];
    int i = vaUnhex8(doc["id"] | "", id8) ? favilla::rk_pw_index_of(slot, id8) : -1;
    if(i < 0){ fsec::apiSend(409, "{\"error\":\"gone\"}"); return; }
    favilla::RkLabel L; int r; { g0_window_batch_begin(); r = favilla::rk_pw_label(i, &L); g0_window_batch_end(); }
    if(r || L.slot != slot || memcmp(L.id8, id8, 8)){ mbedtls_platform_zeroize(&L, sizeof L); fsec::apiSend(409, r ? "{\"error\":\"g0\"}" : "{\"error\":\"gone\"}"); return; }
    String o = "{\"slot\":" + String(slot) + ",\"site\":"; vaJsonStr(o, L.site); o += ",\"user\":"; vaJsonStr(o, L.user); o += "}";
    mbedtls_platform_zeroize(&L, sizeof L);
    fsec::apiSend(200, o);
  });
  apiOn("/api/vault/pw/user", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/pw/result", HTTP_GET, [](){
    apiAddCORS();
    if(!fsec::apiCheckAuth2()){ fsec::apiSend(401, "{\"error\":\"Unauthorized\"}"); return; }
    vaSendJob();
  });
  apiOn("/api/vault/pw/save", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(vaJobBusy()){ fsec::apiSend(409, "{\"error\":\"busy\"}"); return; }
    String body = fsec::apiReadBody();
    JsonDocument doc(&g_vaAlloc);
    DeserializationError de = deserializeJson(doc, body);
    vaWipeString(body); vaWipeString(fsec::g_openedBody);
    if(de){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    favilla::RkPass* e = (favilla::RkPass*)vbAlloc(sizeof(favilla::RkPass));
    if(!e){ fsec::apiSend(500, "{\"error\":\"memory\"}"); return; }
    memset(e, 0, sizeof *e); e->slot = -1;
    const char* site = doc["site"] | ""; const char* user = doc["user"] | ""; const char* pass = doc["pass"] | ""; const char* note = doc["note"] | "";
    int slot = doc["slot"] | -1; const char* idh = doc["id"] | ""; bool imp = doc["import"] | false;
    bool hasNote = !doc["note"].isNull();
    size_t sn = strlen(site), un = strlen(user), pn = strlen(pass), nn = strlen(note);
    const char* bad = nullptr;
    uint8_t id8[8] = {0};
    if(sn < 1 || sn > favilla::RK_SITE_MAX || un > favilla::RK_PW_FIELD_MAX || pn > favilla::RK_PW_FIELD_MAX || nn > favilla::RK_PW_FIELD_MAX) bad = "size";
    else if(slot >= 0 && (!vaUnhex8(idh, id8) || favilla::rk_pw_index_of(slot, id8) < 0)) bad = "gone";
    else if(slot < 0 && pn == 0) bad = "nopass";
    else if(imp && (!g_vImp.open || slot >= 0)) bad = "window";
    else if(favilla::rk_pw_check(sn, un, pn ? pn : 1, nn)) bad = "size";
    if(bad){
      favilla::rk_pw_wipe(e); free(e); doc.clear();
      String o = String("{\"error\":\"") + bad + "\"}"; fsec::apiSend(bad[0] == 'g' ? 409 : 400, o); return;
    }
    memcpy(e->site, site, sn); memcpy(e->user, user, un); if(pn) memcpy(e->pass, pass, pn); if(nn) memcpy(e->note, note, nn);
    doc.clear();   // the parser's copy of the password is wiped on free (VaWipeAlloc)
    if(g_vj.e){ favilla::rk_pw_wipe(g_vj.e); free(g_vj.e); }
    vaJobStart(VJ_SAVE);
    g_vj.e = e; g_vj.slot = slot; g_vj.edit = slot >= 0; g_vj.keepPass = (pn == 0); g_vj.keepNote = g_vj.edit && !hasNote; g_vj.imp = imp;
    memcpy(g_vj.id8, id8, 8);
    strlcpy(g_vj.site, e->site, sizeof g_vj.site); strlcpy(g_vj.user, e->user, sizeof g_vj.user);
    if(imp){ g_vj.phase = VJP_WORK; g_vImp.last = millis(); }   // the PIN opened the window: no press per entry
    else vaAskBegin();
    vaSendJob();
  });
  apiOn("/api/vault/pw/delete", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(vaJobBusy()){ fsec::apiSend(409, "{\"error\":\"busy\"}"); return; }
    String body = fsec::apiReadBody();
    JsonDocument doc;
    if(deserializeJson(doc, body)){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    int slot = doc["slot"] | -1; uint8_t id8[8];
    int i = vaUnhex8(doc["id"] | "", id8) ? favilla::rk_pw_index_of(slot, id8) : -1;
    if(i < 0){ fsec::apiSend(409, "{\"error\":\"gone\"}"); return; }
    favilla::RkLabel L;
    if(favilla::rk_pw_label(i, &L)){ fsec::apiSend(409, "{\"error\":\"g0\"}"); return; }   // the screen shows what is deleted
    vaJobStart(VJ_DELETE);
    g_vj.slot = slot; g_vj.edit = false; g_vj.imp = false; memcpy(g_vj.id8, id8, 8);
    strlcpy(g_vj.site, L.site, sizeof g_vj.site); strlcpy(g_vj.user, L.user, sizeof g_vj.user);
    mbedtls_platform_zeroize(&L, sizeof L);
    vaAskBegin();
    vaSendJob();
  });
  // 4 Nov 2026: "Delete selected" on the phone. One question on the KEY for all of
  // them (a 2 s hold), then one tombstone write and one index write. Items are
  // "slot:id" so a body of 200 stays about 5 KB; an item whose record changed
  // since the phone's list is skipped, never a different record deleted.
  apiOn("/api/vault/pw/delete-many", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(vaJobBusy()){ fsec::apiSend(409, "{\"error\":\"busy\"}"); return; }
    String body = fsec::apiReadBody();
    JsonDocument doc;
    if(deserializeJson(doc, body)){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    JsonArray items = doc["items"].as<JsonArray>();
    const int n = items.isNull() ? 0 : (int)items.size();
    if(n < 1 || n > favilla::RK_MAX){ fsec::apiSend(400, "{\"error\":\"size\"}"); return; }
    int* sl = (int*)vbAlloc(sizeof(int) * n); uint8_t (*ids)[8] = (uint8_t (*)[8])vbAlloc(8 * n);
    if(!sl || !ids){ free(sl); free(ids); fsec::apiSend(500, "{\"error\":\"nvs\"}"); return; }
    int k = 0;
    for(JsonVariant v : items){
      const char* it = v | ""; const char* c = strchr(it, ':');
      if(!c || c == it || c - it > 3){ continue; }
      int slot = atoi(it);
      if(slot < 0 || slot >= favilla::RK_MAX || !vaUnhex8(c + 1, ids[k])) continue;
      sl[k++] = slot;
    }
    if(!k){ free(sl); free(ids); fsec::apiSend(409, "{\"error\":\"gone\"}"); return; }
    vaJobStart(VJ_DELMANY);
    g_vj.manySlots = sl; g_vj.manyIds = ids; g_vj.manyN = k; g_vj.edit = false; g_vj.imp = false; g_vj.slot = -1; memset(g_vj.id8, 0, 8);
    snprintf(g_vj.site, sizeof g_vj.site, k == 1 ? "1 entry" : "%d entries", k); g_vj.user[0] = 0;
    vaAskBegin();
    vaSendJob();
  });
  apiOn("/api/vault/pw/delete-many", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/import/begin", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(g_vImp.open){ vaSendJob(); return; }   // already open: nothing to ask
    if(vaJobBusy()){ fsec::apiSend(409, "{\"error\":\"busy\"}"); return; }
    if(g_vImpUsed){ fsec::apiSend(409, "{\"error\":\"used\"}"); return; }   // one window per power-on life (the G0 enforces it too)
    if(!g_uvSet){ fsec::apiSend(409, "{\"error\":\"uv\"}"); return; }      // unlocked from the phone, or 3 wrong PINs: lock and unlock on the KEY
    vaJobStart(VJ_PIN);
    g_vj.slot = -1; g_vj.edit = false; g_vj.imp = false; memset(g_vj.id8, 0, 8);
    g_vj.site[0] = 0; g_vj.user[0] = 0;
    vaAskBegin();
    LOG_BOOT("[VAULT] import: PIN asked on the KEY\n");
    vaSendJob();
  });
  apiOn("/api/vault/import/end", HTTP_POST, [](){
    apiAddCORS();
    if(!fsec::apiCheckAuth2()){ fsec::apiSend(401, "{\"error\":\"Unauthorized\"}"); return; }
    vaImportClose("the phone is done");
    vaSendJob();
  });
  apiOn("/api/vault/pw", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/pw/result", HTTP_OPTIONS, handleApiOptions);
  // 11s: the breach check (Have I Been Pwned range API, k-anonymity). GET: the
  // 5-hex-digit SHA-1 prefixes of passwords held in RAM and not yet checked, no
  // entry attached. POST {"p":"ABCDE","s":["<35 hex>",...]}: one bucket's
  // suffixes (padding lines with count 0 may be left in); the KEY matches and
  // records the verdict. Passwords and their hashes never leave the KEY.
  apiOn("/api/vault/health", HTTP_GET, [](){
    apiAddCORS();
    if(vaCheck()) return;
    uint8_t (*pf)[3] = (uint8_t (*)[3])vbAlloc(3 * favilla::RK_MAX);
    if(!pf){ fsec::apiSend(500, "{\"error\":\"memory\"}"); return; }
    const int np = favilla::rk_health_prefixes(pf, favilla::RK_MAX);
    String o; o.reserve(64 + np * 10);
    o = "{\"pending\":" + String(favilla::rk_health_pending()) + ",\"unseen\":" + String(favilla::rk_health_unseen()) + ",\"assessing\":" + String((int)g_hbWant) + ",\"opened\":" + String((int)g_hbDoneNow) + ",\"prefixes\":[";
    for(int k = 0; k < np; k++){ char h[8]; snprintf(h, sizeof h, "%02X%02X%X", pf[k][0], pf[k][1], pf[k][2] >> 4); if(k) o += ','; o += '"'; o += h; o += '"'; }
    o += "]}";
    free(pf);
    fsec::apiSend(200, o);
  });
  apiOn("/api/vault/health", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    String body = fsec::apiReadBody();
    JsonDocument doc(&g_vaAlloc);
    DeserializationError de = deserializeJson(doc, body);
    vaWipeString(body); vaWipeString(fsec::g_openedBody);
    if(de){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    const char* p = doc["p"] | ""; JsonArray sa = doc["s"].as<JsonArray>();
    auto nib = [](char c)->int{ if(c >= '0' && c <= '9') return c - '0'; c |= 0x20; if(c >= 'a' && c <= 'f') return c - 'a' + 10; return -1; };
    if(strlen(p) != 5 || sa.isNull()){ fsec::apiSend(400, "{\"error\":\"p (5 hex) and s (array) wanted\"}"); return; }
    uint8_t pre[3] = {0, 0, 0}; for(int i = 0; i < 5; i++){ int v = nib(p[i]); if(v < 0){ fsec::apiSend(400, "{\"error\":\"p\"}"); return; } if(i & 1) pre[i / 2] |= v; else pre[i / 2] |= v << 4; }
    const int n = sa.size(); if(n > 2400){ fsec::apiSend(400, "{\"error\":\"too many\"}"); return; }
    const bool more = doc["more"] | false;   // 11bc: a part of a bucket, more to follow (the verdict waits for the last)
    uint8_t* suf = (uint8_t*)vbAlloc((size_t)n * 18 + 18); if(!suf){ fsec::apiSend(500, "{\"error\":\"memory\"}"); return; }
    int k = 0;
    for(JsonVariant v : sa){
      const char* h = v.as<const char*>(); if(!h) continue;
      size_t L = strlen(h); const char* colon = strchr(h, ':'); if(colon) L = (size_t)(colon - h);   // "SUFFIX:COUNT" lines pass through as they come
      if(L != 35) continue;
      uint8_t* d = suf + k * 18; memset(d, 0, 18); bool ok = true;
      for(int i = 0; i < 35 && ok; i++){ int x = nib(h[i]); if(x < 0) ok = false; else if(i & 1) d[i / 2] |= x; else d[i / 2] |= x << 4; }
      if(ok) k++;
    }
    const int d = favilla::rk_health_bucket(pre, suf, k, !more);
    mbedtls_platform_zeroize(suf, (size_t)n * 18 + 18); free(suf);
    if(d < 0){   // 24 Nov 2026: far too few suffixes for a real bucket (a failed fetch): no verdict
      LOG_BOOT("[VAULT] PWA breach bucket %s: %d suffixes in all is too few for a real bucket, REFUSED\n", p, k);
      fsec::apiSend(422, "{\"error\":\"bucket too small\",\"pending\":" + String(favilla::rk_health_pending()) + "}"); return;
    }
    LOG_BOOT("[VAULT] PWA breach bucket %s: %d suffixes%s, %d entr%s decided\n", p, k, more ? " (a part)" : "", d, d == 1 ? "y" : "ies");
    fsec::apiSend(200, "{\"decided\":" + String(d) + ",\"pending\":" + String(favilla::rk_health_pending()) + "}");
  });
  apiOn("/api/vault/health", HTTP_OPTIONS, handleApiOptions);
  // "Check all": assess up to 24 never-seen entries now (the KEY's loop does the opens,
  // one every 200 ms; the G0 allows 32 per sitting and 8 are kept back for sign-ins).
  // GET /api/vault/health then reports "assessing" until it is done; the PWA fetches
  // the buckets after. Returns how many entries still have no hash this sitting.
  apiOn("/api/vault/health/assess", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    const int unseen = favilla::rk_health_unseen();
    int n = unseen < 24 ? unseen : 24;
    g_hbDoneNow = 0; g_hbWant = n;
    LOG_BOOT("[VAULT] PWA check all: %d entr%s never assessed, %d to open now\n", unseen, unseen == 1 ? "y" : "ies", n);
    fsec::apiSend(200, "{\"unseen\":" + String(unseen) + ",\"opening\":" + String(n) + "}");
  });
  apiOn("/api/vault/health/assess", HTTP_OPTIONS, handleApiOptions);
  // 11aa: the site's recovery codes for one entry: {slot, id, codes: [...]} (1 to 16 codes,
  // each 1 to 24 printable characters). The KEY asks for a hold, then seals them as a
  // record found by the entry's site tag (rk_rc_save). Same gate as a save.
  apiOn("/api/vault/recovery", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(vaJobBusy()){ fsec::apiSend(409, "{\"error\":\"busy\"}"); return; }
    String body = fsec::apiReadBody();
    JsonDocument doc(&g_vaAlloc);
    DeserializationError de = deserializeJson(doc, body);
    vaWipeString(body); vaWipeString(fsec::g_openedBody);
    if(de){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    int slot = doc["slot"] | -1; uint8_t id8[8];
    int i = vaUnhex8(doc["id"] | "", id8) ? favilla::rk_pw_index_of(slot, id8) : -1;
    JsonArray codes = doc["codes"].as<JsonArray>();
    const int n = codes.isNull() ? 0 : (int)codes.size();
    if(i < 0){ doc.clear(); fsec::apiSend(409, "{\"error\":\"gone\"}"); return; }
    if(n < 1 || n > favilla::RK_RC_MAX){ doc.clear(); fsec::apiSend(400, "{\"error\":\"size\"}"); return; }
    char (*rc)[favilla::RK_RC_LEN + 1] = (char (*)[favilla::RK_RC_LEN + 1])vbAlloc((favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX);
    if(!rc){ doc.clear(); fsec::apiSend(500, "{\"error\":\"memory\"}"); return; }
    memset(rc, 0, (favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX);
    bool bad = false; int k = 0;
    for(JsonVariant v : codes){
      const char* c = v.as<const char*>(); const size_t l = c ? strlen(c) : 0;
      if(l < 1 || l > favilla::RK_RC_LEN){ bad = true; break; }
      for(size_t q = 0; q < l; q++) if((uint8_t)c[q] < 0x21 || (uint8_t)c[q] > 0x7E){ bad = true; break; }
      if(bad) break;
      memcpy(rc[k++], c, l);
    }
    doc.clear();
    if(bad){ mbedtls_platform_zeroize(rc, (favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX); free(rc); fsec::apiSend(400, "{\"error\":\"size\"}"); return; }
    favilla::RkLabel L;
    if(favilla::rk_pw_label(i, &L)){ mbedtls_platform_zeroize(rc, (favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX); free(rc); fsec::apiSend(409, "{\"error\":\"g0\"}"); return; }   // the exact site and username: the tag must match the entry's
    if(g_vj.rc){ mbedtls_platform_zeroize(g_vj.rc, (favilla::RK_RC_LEN + 1) * favilla::RK_RC_MAX); free(g_vj.rc); }
    vaJobStart(VJ_RECOVERY);
    g_vj.rc = rc; g_vj.rcN = k; g_vj.slot = slot; g_vj.edit = true; g_vj.imp = false; memcpy(g_vj.id8, id8, 8);
    strlcpy(g_vj.site, L.site, sizeof g_vj.site); strlcpy(g_vj.user, L.user, sizeof g_vj.user);
    mbedtls_platform_zeroize(&L, sizeof L);
    vaAskBegin();
    vaSendJob();
  });
  apiOn("/api/vault/recovery", HTTP_OPTIONS, handleApiOptions);
  // 11ac (issue #16): one-time code secrets from another manager's export (Apple
  // Passwords CXF, 1Password, Bitwarden carry them as otpauth fields). Only inside
  // the import window the PIN opened (no press per code, as for passwords):
  // {site, acct, secret (base32), digits, period, algo}. The secret passes through
  // the ESP32 once, into the G0's seal, and is wiped. Saved under the given site, so
  // a password entry with that exact site links to it (11v/11aa tag rule).
  apiOn("/api/vault/otp/save", HTTP_POST, [](){
    apiAddCORS();
    if(vaCheck()) return;
    if(!g_vImp.open){ fsec::apiSend(409, "{\"error\":\"window\"}"); return; }
    if(!g0_v17_present()){ fsec::apiSend(409, "{\"error\":\"g0\"}"); return; }
    String body = fsec::apiReadBody();
    JsonDocument doc(&g_vaAlloc);
    DeserializationError de = deserializeJson(doc, body);
    vaWipeString(body); vaWipeString(fsec::g_openedBody);
    if(de){ fsec::apiSend(400, "{\"error\":\"Bad JSON\"}"); return; }
    const char* site = doc["site"] | ""; const char* acct = doc["acct"] | ""; const char* sec = doc["secret"] | ""; const char* algo = doc["algo"] | "SHA1";
    const int digits = doc["digits"] | 6, period = doc["period"] | 30;
    const size_t sn = strlen(site), an = strlen(acct);
    const char* bad = nullptr;
    uint8_t secret[otpauth::SECRET_MAX]; size_t secN = 0;
    if(sn < 1 || sn > favilla::RK_SITE_MAX || an > favilla::RK_PW_FIELD_MAX) bad = "size";
    else if(!otpauth::ieq(algo, strlen(algo), "SHA1")) bad = "algo";
    else if(digits < 6 || digits > 8) bad = "digits";
    else if(period < 1 || period > 255) bad = "period";
    else if(otpauth::b32(sec, strlen(sec), secret, sizeof secret, &secN) != otpauth::OK) bad = "secret";
    int r = -1, slot = -1;
    if(!bad){ g0_window_batch_begin(); r = favilla::rk_totp_save(site, acct, secret, secN, (uint8_t)digits, (uint8_t)period, &slot); g0_window_batch_end(); }
    mbedtls_platform_zeroize(secret, sizeof secret);
    doc.clear();   // the parser's copy of the secret goes with it (VaWipeAlloc)
    if(bad){ fsec::apiSend(400, String("{\"error\":\"") + bad + "\"}"); return; }
    g_vImp.last = millis(); if(r == 0) g_vImp.saved++; else g_vImp.failed++;
    LOG_BOOT("[VAULT] PWA one-time code import: %s (slot %d, %d digits, %d s)\n", r == 0 ? "sealed" : favilla::rk_err_name(r), slot, digits, period);
    if(r){ fsec::apiSend(500, String("{\"error\":\"") + vaErrOf(r) + "\"}"); return; }
    fsec::apiSend(200, "{\"ok\":true,\"slot\":" + String(slot) + "}");
  });
  apiOn("/api/vault/otp/save", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/pw/save", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/pw/delete", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/import/begin", HTTP_OPTIONS, handleApiOptions);
  apiOn("/api/vault/import/end", HTTP_OPTIONS, handleApiOptions);
}

// ---- 11ax (12 Nov 2026, issue #30): the app's Accounts page edits in VAULT mode --
// The app channel (ble_app.inc, ag::) checks and queues a save or delete; the
// PASSKEY life's loop calls this. It runs the PWA's own job (g_vj, vaDoSave,
// vaDoDelete, vaDoDeleteMany) behind the PWA's own question (vaDrawAsk), as a
// blocking screen like the other app asks in this life, then tells the channel
// how it went for PW_RESULT. True if anything went on screen.
#ifdef FAVILLA_BLE_KBD
static bool vaAppRun(uint32_t& lp){
  if(g_vlAskPin){ g_vlAskPin = false; if(dimActive) idleDimWake(); vaultLimitPin("Room to save a new password"); return true; }   // 25 Nov 2026: GEN_PW found no room
  ag::PwJob j;
  if(!ag::pwJobTake(&j)) return false;
  struct Drop { ag::PwJob& j; ~Drop(){ ag::pwJobDrop(j); } } dropJ{j};   // the password copy is wiped whatever happens
  if(vaJobBusy() || !g_pkPinHeld){ ag::pwJobDone(chan::PW_FAILED, nullptr, g_pkPinHeld ? chan::S_BUSY : chan::S_LOCKED); return false; }
  if(dimActive) idleDimWake();
  if(j.kind == 1){
    vaJobStart(VJ_SAVE);
    g_vj.e = j.e; j.e = nullptr;   // the job owns it now; vaJobEnd wipes it
    g_vj.slot = j.edit ? j.slot : -1; g_vj.edit = j.edit; g_vj.keepPass = j.keepPass; g_vj.keepNote = j.keepNote; g_vj.imp = false; g_vj.keepOld = j.keepOld;
    memcpy(g_vj.id8, j.id8, 8);
    strlcpy(g_vj.site, j.site, sizeof g_vj.site); strlcpy(g_vj.user, j.user, sizeof g_vj.user);
  } else if(j.n == 1){
    vaJobStart(VJ_DELETE);
    g_vj.slot = j.slots[0]; g_vj.edit = false; g_vj.imp = false; memcpy(g_vj.id8, j.ids[0], 8);
    const int i = favilla::rk_pw_index_of(j.slots[0], j.ids[0]);
    favilla::RkLabel L; int r = i < 0 ? -1 : 0;
    if(!r){ g0_window_batch_begin(); r = favilla::rk_pw_label(i, &L); g0_window_batch_end(); }   // the screen shows what is deleted
    if(r){ mbedtls_platform_zeroize(&L, sizeof L); vaJobEnd(-100, "gone"); ag::pwJobDone(chan::PW_CHANGED, nullptr, 0); return false; }
    strlcpy(g_vj.site, L.site, sizeof g_vj.site); strlcpy(g_vj.user, L.user, sizeof g_vj.user);
    mbedtls_platform_zeroize(&L, sizeof L);
  } else {
    int* sl = (int*)vbAlloc(sizeof(int) * j.n); uint8_t (*ids)[8] = (uint8_t (*)[8])vbAlloc(8 * j.n);
    if(!sl || !ids){ free(sl); free(ids); ag::pwJobDone(chan::PW_FAILED, nullptr, chan::S_BUSY); return false; }
    for(int k = 0; k < j.n; k++){ sl[k] = j.slots[k]; memcpy(ids[k], j.ids[k], 8); }
    vaJobStart(VJ_DELMANY);
    g_vj.manySlots = sl; g_vj.manyIds = ids; g_vj.manyN = j.n; g_vj.edit = false; g_vj.imp = false; g_vj.slot = -1; memset(g_vj.id8, 0, 8);
    strlcpy(g_vj.site, j.site, sizeof g_vj.site); g_vj.user[0] = 0;
  }
  LOG_BOOT("[VAULT] app %s on the KEY: %s\n", g_vj.kind == VJ_SAVE ? (g_vj.edit ? "edit" : "new entry") : g_vj.kind == VJ_DELETE ? "delete" : "delete selected", "asking");
  vaAskBegin();
  const uint32_t holdMs = g_vj.kind == VJ_DELMANY ? 2000 : 1000;   // many at once: a 2 s hold, as for the PWA
  uint8_t state = chan::PW_ASKING, reason = 0;
  for(;;){
    pumpInputs(); btn2.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    lastActivity = millis();
    if(!g_pkPinHeld){ state = chan::PW_FAILED; reason = chan::S_LOCKED; break; }
    if(pkLeaveNow()){ state = chan::PW_FAILED; reason = chan::S_BUSY; break; }   // a website's prompt or a browser ask has the screen
    if(millis() - g_vj.at > VA_ASK_MS){ state = chan::PW_TIMEOUT; break; }
    if(btn4.isPressed()){ state = chan::PW_DECLINED; break; }
    if(btn2.stable == HIGH) g_vj.sawRel = true;
    const float pct = g_vj.sawRel ? btn2.holdProgress(holdMs) : 0.0f;
    if(pct >= 1.0f) break;
    vaDrawAsk(pct);
    delay(10);
  }
  clearButtonPending(); securityUxEnd();
  if(state != chan::PW_ASKING){
    vaJobEnd(state == chan::PW_TIMEOUT ? -104 : -105, state == chan::PW_TIMEOUT ? "timeout" : "declined");
    if(state != chan::PW_FAILED || reason != chan::S_BUSY){ buzzerFail(); dispEmberFail("Cancelled", "CANCELLED", "Nothing was changed", 1200); }
    LOG_BOOT("[VAULT] app job %s on the KEY\n", state == chan::PW_TIMEOUT ? "timed out" : state == chan::PW_DECLINED ? "declined" : "withdrawn");
    ag::pwJobDone(state, nullptr, reason);
    lp = millis();
    return true;
  }
  g_vj.phase = VJP_WORK; vaOverlaySync();
  if(g_vj.kind == VJ_SAVE) vaDoSave(); else if(g_vj.kind == VJ_DELMANY) vaDoDeleteMany(); else vaDoDelete();
  const int res = g_vj.res;
  if(res == 0){
    if(g_vj.kind == VJ_DELMANY){ char t[40]; snprintf(t, sizeof t, g_vj.manyDone == 1 ? "1 entry" : "%d entries", g_vj.manyDone); dispEmberBurst("Deleted", "DELETED", t); }
    else dispEmberBurst(g_vj.kind == VJ_DELETE ? "Deleted" : "Saved", g_vj.kind == VJ_DELETE ? "DELETED" : "SAVED", g_vj.site);
    ag::pwJobDone(chan::PW_DONE, g_vj.kind == VJ_SAVE ? g_vj.id8 : nullptr, 0);
  } else {
    dispEmberFail("Not saved", "NOT SAVED", res == -100 ? "The entry changed meanwhile" : res == -106 ? "An old copy is waiting" : favilla::rk_err_name(res), 1600);
    if(res == -100) ag::pwJobDone(chan::PW_CHANGED, nullptr, 0);
    else ag::pwJobDone(chan::PW_FAILED, nullptr, res == -106 ? chan::S_EXISTS : res == favilla::RK_E_FULL ? chan::S_VAULT_FULL : res == favilla::RK_E_BUDGET ? chan::S_BUDGET :
                                                res == favilla::RK_E_SIZE ? chan::S_TOO_LONG : chan::S_STORAGE);
  }
  lp = millis();
  return true;
}

// ---- 11bf (16 Nov 2026): import from the app, VAULT mode ------------------------
// The PWA's import window, driven by the app channel (ble_app.inc: IMPORT_BEGIN,
// IMPORT_ITEM, IMPORT_STATUS, IMPORT_END) in the PASSKEY life, where G0 v19
// alone seals an import. The passkey PIN typed again on the KEY is the presence
// and the G0's UVCHECK that arms its one import window per power-on; then each
// item is sealed as the PWA's import save is (vaDoSave with imp, origin
// "imported"; a one-time code through rk_totp_save), with no press per item.
// A blocking screen like the other app asks in this life. True if it showed.
static uint8_t vaImportStatusOf(int r){
  if(r == favilla::RK_OK) return chan::S_OK;
  if(r == favilla::RK_E_FULL) return chan::S_VAULT_FULL;
  if(r == favilla::RK_E_SIZE) return chan::S_TOO_LONG;
  if(r == favilla::RK_E_EXISTS) return chan::S_EXISTS;   // 11bh: the KEY's entry was kept
  return chan::S_STORAGE;
}
static uint8_t vaImportOne(chan::ImportItem* it){
  if(it->kind == chan::IMPORT_PW){
    favilla::RkPass* e = (favilla::RkPass*)vbAlloc(sizeof(favilla::RkPass));
    if(!e) return chan::S_STORAGE;
    memset(e, 0, sizeof *e); e->slot = -1;
    strlcpy(e->site, it->site, sizeof e->site); strlcpy(e->user, it->user, sizeof e->user);
    strlcpy(e->pass, it->pass, sizeof e->pass); strlcpy(e->note, it->note, sizeof e->note);
    vaJobStart(VJ_SAVE);
    g_vj.e = e; g_vj.slot = -1; g_vj.edit = false; g_vj.keepPass = false; g_vj.keepNote = false; g_vj.imp = true; memset(g_vj.id8, 0, 8);
    strlcpy(g_vj.site, e->site, sizeof g_vj.site); strlcpy(g_vj.user, e->user, sizeof g_vj.user);
    g_vj.phase = VJP_WORK;
    vaDoSave();   // seals it (origin: imported) and ends the job, wiping the copy
    return vaImportStatusOf(g_vj.res);
  }
  int slot = -1, r;
  r = RK_PIN(favilla::rk_totp_save(it->site, it->user, it->secret, it->secretN, it->digits, it->period, &slot));
  LOG_BOOT("[VAULT] app one-time code import: %s (slot %d, %u digits, %u s)\n", r == 0 ? "sealed" : favilla::rk_err_name(r), slot, (unsigned)it->digits, (unsigned)it->period);
  return vaImportStatusOf(r);
}
// The PIN typed on the import screen: 0 window open, 1 wrong (try again),
// 2 three wrong, 3 the G0 would not open the window.
static int vaImportPinPasskey(){
  if(!g_pkPinHeld) return 3;
  uint8_t d = 0;
  I2C_LOCK(); for(int i = 0; i < PIN_NEW_LEN; i++) d |= (uint8_t)(g_pkPin[i] ^ g_vj.pin[i]); I2C_UNLOCK();
  if(d){
    mbedtls_platform_zeroize(g_vj.pin, sizeof g_vj.pin);
    if(++g_uvWrong >= UV_MAX_WRONG){ LOG_BOOT("[VAULT] app import: %d wrong PINs\n", (int)UV_MAX_WRONG); return 2; }
    LOG_BOOT("[VAULT] app import: wrong PIN (%d left)\n", (int)(UV_MAX_WRONG - g_uvWrong));
    return 1;
  }
  g_uvWrong = 0;
  uint8_t left = 0;
  int c = g0_uv_check(g_vj.pin, &left);   // the G0's own PIN check arms its one import window
  if(c != 1 && g0_uv_set(g_vj.pin)) c = g0_uv_check(g_vj.pin, &left);   // no reference on the G0 (3 wrong elsewhere): set it again from the PIN just typed
  mbedtls_platform_zeroize(g_vj.pin, sizeof g_vj.pin);
  if(c != 1){ LOG_BOOT("[VAULT] app import: the G0 PIN check did not pass (%d)\n", c); return 3; }
  int seals = 0, tags = 0;
  const int w = favilla::rk_pw_import_window(&seals, &tags);   // straight after the right UVCHECK: nothing in between
  if(w){ LOG_BOOT("[VAULT] app import window: %s, G0 0x%02X %s\n", favilla::rk_err_name(w), favilla::rk_last_res(), favilla::rk_hint()); return 3; }
  g_vImpUsed = true;
  favilla::rk_idx_batch(true);   // one index write at the end, not one per entry
  g_vImp = {}; g_vImp.open = true; g_vImp.sealsLeft = seals; g_vImp.at = g_vImp.last = millis();
  LOG_BOOT("[VAULT] app import window open: %d seals, %d tags\n", seals, tags);
  return 0;
}
static bool vaAppImport(uint32_t& lp){
  if(!ag::impBeginTake()) return false;
  if(vaJobBusy() || !g_pkPinHeld){ ag::impSet(chan::IMP_REFUSED, g_pkPinHeld ? chan::S_BUSY : chan::S_LOCKED); return false; }
  if(g_vImpUsed){ ag::impSet(chan::IMP_REFUSED, chan::S_USED); return false; }
  if(dimActive) idleDimWake();
  // 1. The passkey PIN again, on the KEY (the PWA's IMPORT PIN screen).
  vaJobStart(VJ_PIN);
  g_vj.slot = -1; g_vj.edit = false; g_vj.imp = false; memset(g_vj.id8, 0, 8); g_vj.site[0] = 0; g_vj.user[0] = 0;
  vaAskBegin();
  LOG_BOOT("[VAULT] app import: PIN asked on the KEY\n");
  uint8_t why = 0xFF;
  for(;;){
    pumpInputs(); btn3.poll(); btn4.poll(); pkSerialTick(); pkTripwire();
    lastActivity = millis();
    if(!g_pkPinHeld){ why = chan::S_LOCKED; break; }
    if(pkLeaveNow()){ why = chan::S_BUSY; break; }
    if(ag::impEndAsked() || millis() - g_vj.at > VA_PIN_MS){ why = chan::S_CANCELLED; break; }
    if(btn3.isPressed()){ if(!g_vj.armed){ g_vj.pin[g_vj.digit] = ((g_vj.pin[g_vj.digit]-'0'+1)%10)+'0'; } vaDrawPin(); }
    else if(btn1.isPressed()){ if(!g_vj.armed){ g_vj.pin[g_vj.digit] = ((g_vj.pin[g_vj.digit]-'0'+9)%10)+'0'; } vaDrawPin(); }
    else if(btn4.isPressed()){
      if(g_vj.armed){ g_vj.armed = false; g_vj.digit = PIN_NEW_LEN-1; vaDrawPin(); }
      else if(g_vj.digit > 0){ g_vj.digit--; vaDrawPin(); }
      else { why = chan::S_CANCELLED; break; }
    }
    else if(btn2.isPressed()){
      if(!g_vj.armed){ if(++g_vj.digit == PIN_NEW_LEN){ g_vj.digit = PIN_NEW_LEN-1; g_vj.armed = true; } vaDrawPin(); }
      else {
        const int p = vaImportPinPasskey();
        if(p == 0){ why = chan::S_OK; break; }
        if(p == 2){ why = chan::S_PIN_WRONG; break; }
        if(p == 3){ why = chan::S_STORAGE; break; }
        for(int i = 0; i < PIN_NEW_LEN; i++) g_vj.pin[i] = '0';
        g_vj.digit = 0; g_vj.armed = false; g_vj.wrong = true;
        vaDrawPin();
      }
    }
    else if(!g_vj.inited){ vaDrawPin(); g_vj.inited = true; }
    delay(10);
  }
  clearButtonPending(); securityUxEnd();
  vaJobEnd(why == chan::S_OK ? 0 : -105, why == chan::S_OK ? "" : "declined");   // wipes the PIN digits
  if(why != chan::S_OK){
    ag::impSet(chan::IMP_REFUSED, why);
    LOG_BOOT("[VAULT] app import: window not opened (status %u)\n", (unsigned)why);
    if(why != chan::S_BUSY){ buzzerFail(); dispEmberFail("Not opened", "IMPORT", why == chan::S_PIN_WRONG ? "Three wrong PINs" : why == chan::S_STORAGE ? "The signer refused it" : "Nothing was imported", 1400); }
    lp = millis();
    return true;
  }
  // 2. The window: the app sends items, the KEY seals each one, no press.
  ag::impSet(chan::IMP_OPEN, 0);
  vaOverlaySync();
  vaDrawImport();
  why = chan::S_OK;
  for(;;){
    pumpInputs(); btn4.poll(); pkSerialTick(); pkTripwire();
    lastActivity = millis();
    if(!g_pkPinHeld){ why = chan::S_LOCKED; break; }
    if(pkLeaveNow()){ why = chan::S_BUSY; break; }
    if(btn4.isPressed()){ why = chan::S_CANCELLED; break; }
    // 11bh: every item waiting (up to 8) under ONE passkey window (passkey
    // session, latch, master read). One window per item took 2 to 3 s an item
    // on the bench (17 Nov 2026).
    chan::ImportItem* its[8] = {};
    const int nIt = ag::impItemsTake(its, 8);
    if(nIt){
      g0_window_batch_begin();
      for(int i = 0; i < nIt; i++){
        const uint8_t st = vaImportOne(its[i]);
        mbedtls_platform_zeroize(its[i], sizeof *its[i]); free(its[i]);
        if(st == chan::S_OK) g_vImp.saved++; else if(st == chan::S_EXISTS) g_vImp.kept++; else g_vImp.failed++;
        ag::impItemDone(st);
        vaDrawImport();
      }
      g0_window_batch_end();
      g_vImp.last = millis();
      continue;
    }
    if(ag::impEndAsked()){ why = chan::S_OK; break; }
    if(millis() - g_vImp.last > VA_IMPORT_IDLE_MS){ why = chan::S_TIMEOUT_IDLE; break; }
    if(g_vImp.drawnSaved != g_vImp.saved + 1000 * g_vImp.failed || millis() - g_vImp.drawn > 1000) vaDrawImport();
    delay(10);
  }
  clearButtonPending();
  g_vImp.open = false;
  favilla::rk_idx_batch(false);
  vaOverlaySync();
  ag::impSet(chan::IMP_CLOSED, why);
  LOG_BOOT("[VAULT] app import window closed (%s): %d saved, %d already on the KEY, %d failed\n",
           why == chan::S_OK ? "the app is done" : why == chan::S_CANCELLED ? "BACK on the KEY" : why == chan::S_LOCKED ? "locked" : why == chan::S_BUSY ? "a website asked" : "10 minutes without an entry",
           g_vImp.saved, g_vImp.kept, g_vImp.failed);
  if(why != chan::S_BUSY){
    char t[40]; snprintf(t, sizeof t, g_vImp.saved == 1 ? "1 entry" : "%d entries", g_vImp.saved);
    if(g_vImp.failed){ char f[40]; snprintf(f, sizeof f, "%d saved, %d not", g_vImp.saved, g_vImp.failed); dispEmberFail("Imported", "IMPORTED", f, 1600); }
    else dispEmberBurst("Imported", "IMPORTED", t);
  }
  lp = millis();
  return true;
}
#endif
