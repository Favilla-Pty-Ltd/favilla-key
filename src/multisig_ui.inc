// ============================================================================
// multisig_ui.inc — the MULTISIG screens behind the BITCOIN door.
//
// Included from bitcoin_menu.inc just before the door menu (needs everything
// above it: spr, fonts, uiHeader, psbtDrawAddrWrapped, showQR, qrDisp, camera,
// g_ms, g_ms_our_*). Nothing here opens an SE session: the door is already
// open, our BIP-48 xpub was derived at entry, and signing lives in
// psbtGatedSign() like every other signature.
//
// Screens
//   MULTISIG        list of registered wallets + "Import wallet" + "Export key"
//   Import wallet   camera: animated ur:bytes (Sparrow -> Export -> Keystone
//                   Multisig -> Show QR) or a single-QR Coldcard text file.
//                   Confirms name / policy / every cosigner fingerprint (ours
//                   marked) before saving. Refuses configs we are not part of.
//   <wallet>        Receive, Verify address, Cosigners, Delete
//   Receive         address browser at the wallet's bookmark: up/down = index,
//                   ENTER = scan-to-verify, BACK = leave (bookmark saved)
//   Verify address  camera: scan an address QR from Sparrow/BlueWallet, search
//                   both chains outward from the bookmark, verdict screen.
//   Export key      page 0: animated UR crypto-account (wpkh m/84 + wsh m/48/2)
//                   page 1: text [fp/48h/0h/0h/2h]xpub...  (up/down toggles)
//
// Conventions: ASCII only (the .vlw fonts have no middle dot), no footer hints
// (Josh's rule), every loop feeds the watchdog and refreshes the ceremony
// idle timer on any press.
// ============================================================================

// ── Camera helpers ─────────────────────────────────────────────────────────
// Scan until ONE decoded QR string lands in qrResultBuf, or timeout/BACK.
// Returns true with qrResultBuf valid. Same qrScanOnce() pattern as
// ab_scan_to_add(): synchronous, live preview, camera torn down on exit.
static bool msScanOneQr(const char* header, const char* prompt, unsigned long timeoutMs) {
  spr.fillSprite(C_BG);
  uiHeader(header, C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  fDrawCentre(prompt, 120, 108); fEnd();
  dispPush(); delay(600);
  pwrBoost(); autoNetCancel();
  g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
  cameraStart(); qrFound = false;
  unsigned long ns = millis(), lastQR = 0; bool got = false;
  while (millis() - ns < timeoutMs) {
    esp_task_wdt_reset();
    btn4.poll();
    if (btn4.isPressed()) break;
    if (!qrFound && millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS) { lastQR = millis(); qrScanOnce(); }
    if (qrFound) { qrFound = false; got = true; break; }
  }
  g_airgapLivePreview = false; cameraStop(); pwrIdle();
  clearButtonPending(); drainButtonsAfterTransition();
  g_ceremonyStart = millis();
  return got;
}

// Scan an animated UR (any type) OR a plain-text QR into `out`. Returns the
// byte length, 0 on cancel/timeout, -1 on a bad sequence. `type_out` receives
// the UR type ("bytes", "crypto-psbt", ...) or "text" for a non-UR QR.
static int msScanUrOrText(const char* header, const char* prompt, uint8_t* out, size_t out_cap,
                          char type_out[24], unsigned long timeoutMs) {
  type_out[0] = 0;
  if (!urAirgapEnsure()) { dispError("UR: no memory"); errorPause(); return -1; }
  ur_decoder_reset(urAirgapDec);
  spr.fillSprite(C_BG);
  uiHeader(header, C_BTC_ACCENT);
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  fDrawCentre(prompt, 120, 108); fEnd();
  dispPush(); delay(600);
  pwrBoost(); autoNetCancel();
  g_airgapLivePreview = true; g_airgapUrGot = 0; g_airgapUrTotal = 0;
  cameraStart(); qrFound = false;
  static char* line = nullptr;
  if (!line) { line = (char*)ps_malloc(1024); if (!line) line = (char*)malloc(1024); }
  if (!line) { g_airgapLivePreview = false; cameraStop(); pwrIdle(); dispError("No memory"); errorPause(); return -1; }
  unsigned long ns = millis(), lastQR = 0; int result = 0;
  while (millis() - ns < timeoutMs) {
    esp_task_wdt_reset();
    btn4.poll();
    if (btn4.isPressed()) break;
    if (!qrFound && millis() - lastQR > QR_AIRGAP_SCAN_INTERVAL_MS) { lastQR = millis(); qrScanOnce(); }
    if (!qrFound) continue;
    qrFound = false;
    if (strncmp(qrResultBuf, "ur:", 3) == 0 || strncmp(qrResultBuf, "UR:", 3) == 0) {
      strncpy(line, qrResultBuf, 1023); line[1023] = 0;
      int fr = ur_feed(urAirgapDec, line);
      { int ng = (int)urAirgapDec->n_got; if (ng > g_airgapUrGot) g_airgapUrGot = ng;
        if (urAirgapDec->have_meta && (int)urAirgapDec->seqLen > g_airgapUrTotal) g_airgapUrTotal = (int)urAirgapDec->seqLen;
        if (g_airgapUrTotal > 0 && g_airgapUrGot > g_airgapUrTotal) g_airgapUrGot = g_airgapUrTotal; }
      if (fr < 0 && urAirgapDec->err) { result = -1; break; }
      if (fr == 1) {
        int mlen = ur_decoder_result(urAirgapDec, out, out_cap);
        if (mlen <= 0) { result = -1; break; }
        strncpy(type_out, urAirgapDec->ur_type, 23); type_out[23] = 0;
        result = mlen; break;
      }
      ns = millis();   // a good part resets the patience timer
    } else {
      size_t n = strlen(qrResultBuf);
      if (n == 0 || n >= out_cap) { result = -1; break; }
      memcpy(out, qrResultBuf, n); strcpy(type_out, "text");
      result = (int)n; break;
    }
  }
  g_airgapLivePreview = false; cameraStop(); pwrIdle();
  clearButtonPending(); drainButtonsAfterTransition();
  g_ceremonyStart = millis();
  return result;
}

// ── Small drawing helpers ──────────────────────────────────────────────────
static void msFpStr(const uint8_t fp[4], char out[9]) {
  snprintf(out, 9, "%02x%02x%02x%02x", fp[0], fp[1], fp[2], fp[3]);
}
static void msPolicyStr(const ms_wallet_t* w, char* out, size_t cap) {
  snprintf(out, cap, "%u of %u", (unsigned)w->m, (unsigned)w->n);
}

// Wait for ENTER (true) / BACK (false) with a timeout. Feeds the watchdog.
static bool msWaitEnterBack(unsigned long timeoutMs) {
  drainButtonsAfterTransition();
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    esp_task_wdt_reset(); delay(10);
    if (btn2.isPressed()) { g_ceremonyStart = millis(); return true; }
    if (btn4.isPressed()) { g_ceremonyStart = millis(); return false; }
  }
  return false;
}

// Cosigner list screen shared by Import-confirm and "Cosigners".
// 29 Oct 2026: paged, 6 fingerprints a page. The old single page stopped
// drawing at y 190, so a wallet with more than 7 cosigners could be registered
// without every key on screen. `foot` draws the hold footer (Register) or a
// plain BACK line.
#define MS_CS_PER_PAGE 6
static int msCosignerPages(const ms_wallet_t* w){ return (w->n + MS_CS_PER_PAGE - 1) / MS_CS_PER_PAGE; }
static void msDrawCosignersPage(const ms_wallet_t* w, const char* header, uint16_t accent, int page,
                                const char* holdAction, const char* sub, float hp) {
  spr.fillSprite(C_BG);
  uiHeader(header, accent);
  char pol[16]; msPolicyStr(w, pol, sizeof(pol));
  fSet(F_HEAD); spr.setTextColor(C_EB_INK); fDrawCentre(w->name, 120, 34); fEnd();
  int pages = msCosignerPages(w);
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  { char l[48];
    if (pages > 1) snprintf(l, sizeof(l), "%s multisig   keys %d-%d of %u", pol, page * MS_CS_PER_PAGE + 1,
                            (page + 1) * MS_CS_PER_PAGE < w->n ? (page + 1) * MS_CS_PER_PAGE : w->n, (unsigned)w->n);
    else snprintf(l, sizeof(l), "%s multisig, P2WSH", pol);
    fDrawCentre(l, 120, 54); } fEnd();
  int y = 78;
  for (int i = page * MS_CS_PER_PAGE; i < w->n && i < (page + 1) * MS_CS_PER_PAGE; i++) {
    char fp[9]; msFpStr(w->cs[i].fp, fp);
    bool ours = (i == w->our_index);
    fSet(F_MONO); spr.setTextColor(ours ? C_EB_INK : C_EB_GREY);
    char row[16]; snprintf(row, sizeof(row), "%2d  %s", i + 1, fp);
    spr.drawString(row, 40, y); fEnd();
    if (ours) uiTrackLabel("THIS KEY", 178, y + 1, accent, 2);
    y += 18;
  }
  if (w->our_index == 0xFF) {
    fSet(F_BODY); spr.setTextColor(C_RED); fDrawCentre("This KEY is not a cosigner", 120, 186); fEnd();
  }
  if (holdAction) uiHoldFooter(holdAction, sub, hp, accent);
  else { spr.fillRect(0, 196, 240, 44, C_BG); fSet(F_SMALL); spr.setTextColor(C_EB_GREY); fDrawCentre(sub ? sub : "BACK to leave", 120, 214); }
  dispPush();
}
// Read-only cosigner pages (COSIGNERS, NOT A COSIGNER). UP/DOWN page, ENTER or BACK leaves.
static void msShowCosigners(const ms_wallet_t* w, const char* header, uint16_t accent) {
  int page = 0, pages = msCosignerPages(w);
  msDrawCosignersPage(w, header, accent, page, nullptr, pages > 1 ? "DOWN for more   BACK to leave" : "BACK to leave", 0);
  drainButtonsAfterTransition();
  unsigned long t0 = millis();
  while (millis() - t0 < 60000UL) {
    esp_task_wdt_reset(); delay(10);
    if (btn4.isPressed() || btn2.isPressed()) { g_ceremonyStart = millis(); return; }
    int np = page;
    if (btn1.isPressed() && page < pages - 1) np = page + 1;
    else if (btn3.isPressed() && page > 0) np = page - 1;
    if (np != page) { page = np; t0 = millis(); g_ceremonyStart = millis();
      msDrawCosignersPage(w, header, accent, page, nullptr, page < pages - 1 ? "DOWN for more   BACK to leave" : "BACK to leave", 0); }
  }
}
// Register confirm: every page must be seen before the hold can register.
// Hold ENTER (1.5 s) registers, BACK cancels. Returns true to register.
static bool msConfirmRegister(const ms_wallet_t* w) {
  int page = 0, pages = msCosignerPages(w), seen = 0;
  auto draw = [&](float hp){
    bool all = (seen >= pages - 1);
    msDrawCosignersPage(w, "REGISTER WALLET", C_BTC_ACCENT, page,
                        all ? "HOLD ENTER TO REGISTER" : "DOWN FOR MORE KEYS",
                        all ? "BACK cancels" : "See every key before registering", hp);
  };
  draw(0);
  drainButtonsAfterTransition();
  unsigned long shown = millis(), t0 = millis(); float last = 0;
  while (millis() - t0 < 60000UL) {
    esp_task_wdt_reset(); delay(10);
    if (btn4.isPressed()) { g_ceremonyStart = millis(); return false; }
    btn2.isPressed();
    int np = page;
    if (btn1.isPressed() && page < pages - 1) np = page + 1;
    else if (btn3.isPressed() && page > 0) np = page - 1;
    if (np != page) { page = np; if (page > seen) seen = page; t0 = millis(); g_ceremonyStart = millis(); draw(0); continue; }
    if (seen < pages - 1) continue;
    float hp = holdSince(btn2, shown, 1500);
    if (hp >= 1.0f) { btn2.resetHold(); g_ceremonyStart = millis(); return true; }
    if (hp > 0 || last > 0) { uiHoldFooter("HOLD ENTER TO REGISTER", hp > 0 ? "Let go to stop" : "BACK cancels", hp, C_BTC_ACCENT);
                              dispPushRegion(0, 196, 240, 44); last = hp; t0 = millis(); }
  }
  return false;
}

// ── Import ────────────────────────────────────────────────────────────────
// Shared by the Multisig menu ("Import wallet") and by ST_AIRGAP_SIGN when a
// ur:bytes sequence is scanned in Send. Parses, checks membership, confirms
// on the trusted display, saves. Returns true if a wallet was added.
bool msImportConfig(const char* text, size_t len) {
  // Distinguish the two failure causes: no memory vs no BIP-48 key this life.
  // "Wallet key not ready" used to cover both and told you nothing.
  if (!msEnsureMem()) { dispError("No memory for wallets"); errorPause(); return false; }
  if (!g_ms_our_valid) { dispError("BIP-48 key unavailable"); errorPause(); return false; }
  static ms_wallet_t w;   // ~0.9KB, keep off the stack
  char err[32] = {0};
  if (!ms_config_parse(text, len, &w, err)) { dispError(err[0] ? err : "Bad wallet file"); errorPause(); return false; }
  bool member = ms_wallet_find_ours(&w, g_btc_master_fp, &g_ms_our_xpub);
  if (!member) {
    msShowCosigners(&w, "NOT A COSIGNER", C_RED);
    return false;
  }
  if (ms_store_find_same(g_ms, &w) >= 0) { dispError("Already registered"); errorPause(); return false; }
  if (ms_store_free_slot(g_ms) < 0) { dispError("Wallet slots full (4)"); errorPause(); return false; }
  if (!msConfirmRegister(&w)) return false;   // 29 Oct 2026: hold ENTER, every key seen
  if (!ms_store_add(g_ms, &w)) { dispError("Could not add"); errorPause(); return false; }
  if (!ms_store_save()) { dispError("Save failed"); errorPause(); return false; }
  dispSuccess("Registered", w.name, C_BTC_ACCENT); errorPause();
  return true;
}

// Called from main.cpp ST_AIRGAP_SIGN when the scanned UR is "bytes".
bool msImportFromUrBytes(const uint8_t* msg, size_t msg_len) {
  if (!g_ms_scratch) { dispError("No memory"); errorPause(); return false; }
  int n = ur_extract_bytes(msg, msg_len, g_ms_scratch, UR_MAX_MESSAGE - 1);
  if (n <= 0) { dispError("Not a wallet file"); errorPause(); return false; }
  g_ms_scratch[n] = 0;
  return msImportConfig((const char*)g_ms_scratch, (size_t)n);
}

static void msImportScan() {
  if (!g_ms_scratch) { dispError("No memory"); errorPause(); return; }
  char type[24];
  int n = msScanUrOrText("IMPORT WALLET", "Scan your wallet app's QR", g_ms_scratch, UR_MAX_MESSAGE - 1, type, 120000UL);
  if (n < 0) { dispError("Bad QR sequence"); errorPause(); return; }
  if (n == 0) return;
  if (strcmp(type, "bytes") == 0) { msImportFromUrBytes(g_ms_scratch, (size_t)n); return; }
  if (strcmp(type, "text") == 0) { g_ms_scratch[n] = 0; msImportConfig((const char*)g_ms_scratch, (size_t)n); return; }
  dispError("Not a wallet file"); errorPause();
}

// ── Receive (browse + scan-to-verify) ────────────────────────────────────
static void msDrawReceive(const ms_wallet_t* w, uint32_t change, uint32_t index, const char* addr) {
  spr.fillSprite(C_BG);
  spr.fillRect(0, 0, 240, 20, 0x0000);
  spr.fillRect(0, 0, 3, 20, C_BTC_ACCENT);
  char t[40]; snprintf(t, sizeof(t), "%s #%u", change ? "Change" : "Receive", (unsigned)index);
  fSet(F_BODY); spr.setTextColor(C_BTC_ACCENT); spr.drawString(t, 8, 4); fEnd();
  fSet(F_BODY); spr.setTextColor(C_DIM);
  { int tw = spr.textWidth(w->name); spr.drawString(w->name, 240 - tw - 8, 4); } fEnd();

  // 62-char bech32 -> uppercase so the QR uses alphanumeric mode: version 3
  // holds 77 alnum chars at ECC_LOW (29 modules = 6 px each).
  char up[100]; size_t n = strlen(addr); if (n >= sizeof(up)) n = sizeof(up) - 1;
  for (size_t i = 0; i < n; i++) up[i] = (addr[i] >= 'a' && addr[i] <= 'z') ? (char)(addr[i] - 32) : addr[i];
  up[n] = 0;
  QRCode qr; uint8_t qrBuf[qrcode_getBufferSize(4)];
  int ver = (n <= 77) ? 3 : 4;
  if (qrcode_initText(&qr, qrBuf, ver, ECC_LOW, up) == 0) {
    int dim = qr.size, sc = 180 / dim; if (sc < 1) sc = 1;
    int px = dim * sc, ox = (240 - px) / 2, oy = 28 + (180 - px) / 2;
    spr.fillRoundRect(ox - 6, oy - 6, px + 12, px + 12, 6, C_QR_WHITE);
    for (int y = 0; y < dim; y++) for (int x = 0; x < dim; x++)
      if (qrcode_getModule(&qr, x, y)) spr.fillRect(ox + x * sc, oy + y * sc, sc, sc, C_BG);
  } else {
    fSet(F_BODY); spr.setTextColor(C_RED); fDrawCentre("QR error", 120, 110); fEnd();
  }
  fSet(F_MONO); spr.setTextColor(C_EB_GREY);
  char sa[32]; snprintf(sa, sizeof(sa), "%.8s...%s", addr, addr + n - 8);
  { int saw = spr.textWidth(sa); spr.drawString(sa, (240 - saw) / 2, 214); } fEnd();
  DISP_LOCK(); spr.pushSprite(0, 0); DISP_UNLOCK();
}

// Progress callback for the search: bar + watchdog.
static bool msSearchProgress(uint32_t done, uint32_t total) {
  esp_task_wdt_reset();
  int wdt = (int)((uint64_t)done * 200 / (total ? total : 1));
  spr.fillRect(20, 150, 200, 6, C_BORDER);
  spr.fillRect(20, 150, wdt, 6, C_BTC_ACCENT);
  dispPush();
  return true;
}

// Scan an address QR and prove (or disprove) it belongs to wallet w.
static void msVerifyAddress(ms_wallet_t* w) {
  if (!msScanOneQr("VERIFY ADDRESS", "Scan the address to check", 60000UL)) return;
  uint8_t spk[40];
  size_t sl = ms_addr_to_spk(qrResultBuf, spk, sizeof(spk));
  if (sl == 0) { dispError("Not a Bitcoin address"); errorPause(); return; }
  if (sl != 34 || spk[0] != 0x00 || spk[1] != 0x20) { dispError("Not a P2WSH address"); errorPause(); return; }
  spr.fillSprite(C_BG); uiHeader("VERIFYING", C_BTC_ACCENT);
  fSet(F_HEAD); spr.setTextColor(C_EB_INK); fDrawCentre("Searching addresses...", 120, 100); fEnd();
  fSet(F_BODY); spr.setTextColor(C_DIM); fDrawCentre("both chains, 0-1000", 120, 124); fEnd();
  dispPush();
  pwrBoost();
  uint32_t c = 0, i = 0;
  bool found = ms_search_spk(w, spk, 34, w->recv_bookmark, PSBT_CHANGE_GAP_LIMIT, &c, &i, msSearchProgress);
  pwrIdle();
  char addr[100]; addr[0] = 0;
  spr.fillSprite(C_BG);
  if (found) {
    uiHeader("ADDRESS IS YOURS", C_BTC_ACCENT);
    drawTick(104, 44, C_BTC_ACCENT);
    char l[40]; snprintf(l, sizeof(l), "%s #%u", c ? "Change" : "Receive", (unsigned)i);
    fSet(F_HEAD); spr.setTextColor(C_BTC_ACCENT); fDrawCentre(l, 120, 66); fEnd();
    fSet(F_BODY); spr.setTextColor(C_EB_GREY); fDrawCentre(w->name, 120, 90); fEnd();
    ms_address(w, c, i, addr, sizeof(addr));
    psbtDrawAddrWrapped(addr, 10, 116, C_EB_GREY);
    // 29 Oct 2026: persist the advance here. Receive used to write its own
    // (lower) index back on exit, undoing it, and Verify from the menu never saved.
    if (!c && i > w->recv_bookmark) { w->recv_bookmark = i; ms_store_save(); }
  } else {
    uiHeader("NOT THIS WALLET", C_RED);
    spr.drawWideLine(108, 40, 132, 56, 3, C_RED); spr.drawWideLine(132, 40, 108, 56, 3, C_RED);
    fSet(F_HEAD); spr.setTextColor(C_RED); fDrawCentre("Address not found", 120, 70); fEnd();
    fSet(F_BODY); spr.setTextColor(C_EB_GREY);
    fDrawCentre("Not in the first 1000", 120, 96);
    fDrawCentre("addresses of this wallet.", 120, 114);
    fDrawCentre("Do not send to it.", 120, 140); fEnd();
  }
  dispPush();
  msWaitEnterBack(60000);
}

static void msReceive(ms_wallet_t* w) {
  uint32_t idx = w->recv_bookmark; char addr[100];
  if (!ms_address(w, 0, idx, addr, sizeof(addr))) { dispError("Derive failed"); errorPause(); return; }
  msDrawReceive(w, 0, idx, addr);
  drainButtonsAfterTransition();
  unsigned long t0 = millis();
  while (millis() - t0 < 300000UL) {
    esp_task_wdt_reset(); delay(5);
    bool moved = false;
    if (btn1.isPressed()) { if (idx < PSBT_CHANGE_GAP_LIMIT) { idx++; moved = true; } }
    else if (btn3.isPressed()) { if (idx > 0) { idx--; moved = true; } }
    else if (btn2.isPressed()) { g_ceremonyStart = millis(); msVerifyAddress(w); if (!ms_address(w, 0, idx, addr, sizeof(addr))) return; msDrawReceive(w, 0, idx, addr); drainButtonsAfterTransition(); t0 = millis(); continue; }
    else if (btn4.isPressed()) break;
    if (moved) {
      g_ceremonyStart = millis(); t0 = millis();
      if (!ms_address(w, 0, idx, addr, sizeof(addr))) { dispError("Derive failed"); errorPause(); return; }
      msDrawReceive(w, 0, idx, addr);
    }
  }
  if (idx > w->recv_bookmark) { w->recv_bookmark = idx; ms_store_save(); }   // forward only (29 Oct 2026)
}

// ── Key export pager (shared by the cosigner and single-sig exports) ─────
// Three pages, BTN1/BTN3 to move, ENTER or BACK to exit:
//   page 1  animated UR crypto-account (ONE descriptor)
//   page 2  a single static QR of `json` (Coldcard-format)
//   page 3  a single static QR of `text` (descriptor / key expression)
// The first cosigner export shipped a crypto-account holding BOTH the wpkh
// and wsh descriptors; Sparrow tolerates that, BlueWallet takes the first one,
// finds single-sig where a cosigner belongs and answers "invalid cosigner". So:
// one descriptor per QR, always.
// 29 Oct 2026: QRTFT::show draws no labels (the QR owns the screen), so a
// paged export never said which page was showing. Each page change now shows
// a short title card first: what this QR is, and page N of M.
static void msPageCard(const char* what, int page, int pages) {
  spr.fillSprite(C_BG);
  char pg[24]; snprintf(pg, sizeof(pg), "PAGE %d OF %d", page + 1, pages);
  uiTrackLabel(pg, 120, 84, C_EB_GREY);
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
  if (spr.textWidth(what) <= 220) spr.drawString(what, 120 - spr.textWidth(what) / 2, 104);
  else { fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_INK); uiWrapCentre(what, 108, 210, 18, 3); }
  fEndHard();
  { int w = pages * 5 + (pages - 1) * 7, x = 120 - w / 2;
    for (int i = 0; i < pages; i++) spr.fillRect(x + i * 12, 150, 5, 5, i == page ? C_EB_BRASS : C_EB_LINE); }
  // Every pager page is public data (xpubs, descriptors): say so, plainly.
  spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
  { const char* a = "Public key only. It can't spend.";
    const char* b = "Safe to scan into your wallet app.";
    spr.drawString(a, 120 - spr.textWidth(a) / 2, 174); spr.drawString(b, 120 - spr.textWidth(b) / 2, 192); }
  fEndHard();
  dispPush();
  delay(700);
}
static void btcExportPager(const uint8_t* acct, size_t al, const char* json, const char* text,
                           const char* jsonLabel, const char* textLabel) {
  static char (*frags)[640] = nullptr;
  if (!frags) { frags = (char(*)[640])ps_malloc(8 * 640); if (!frags) frags = (char(*)[640])malloc(8 * 640); }
  if (!frags) { dispError("No memory"); errorPause(); return; }
  int nf = ur_encode_message("crypto-account", acct, al, frags, 640, 8);
  if (nf < 1) { dispError("UR encode failed"); errorPause(); return; }
  char fpl[24]; snprintf(fpl, sizeof(fpl), "fp %02x%02x%02x%02x",
                         g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3]);
  int page = 0, fi = 0; unsigned long lastFrame = 0, shownAt = millis(); bool redraw = true;
  clearButtonPending(); btn1.resetHold(); btn2.resetHold(); btn3.resetHold(); btn4.resetHold();
  while (millis() - shownAt < 300000UL) {
    esp_task_wdt_reset(); delay(15);
    if (btn1.isPressedFresh(shownAt)) { page = (page + 1) % 3; redraw = true; fi = 0; g_ceremonyStart = millis(); }
    else if (btn3.isPressedFresh(shownAt)) { page = (page + 2) % 3; redraw = true; fi = 0; g_ceremonyStart = millis(); }
    if (btn2.isPressedFresh(shownAt) || btn4.isPressedFresh(shownAt)) break;
    if (redraw) msPageCard(page == 0 ? "Sparrow" : page == 1 ? jsonLabel : textLabel, page, 3);
    if (page == 0) {
      if (redraw || (nf > 1 && millis() - lastFrame > 500)) {
        lastFrame = millis(); qrDisp.showUrFrame(frags[fi], fi, nf); fi = (fi + 1) % nf; redraw = false;
      }
    } else if (redraw) {
      showQR(page == 1 ? json : text, page == 1 ? jsonLabel : textLabel, fpl);
      redraw = false;
    }
  }
}

// ── Export cosigner key (multisig, m/48'/0'/0'/2') ────────────────────────
//   page 1  UR crypto-account, wsh descriptor ONLY   (Sparrow scan, Keystone-style)
//   page 2  Coldcard JSON {"xfp","p2wsh_deriv","p2wsh":"Zpub..."}   (BlueWallet
//           cosigner import, Sparrow "Coldcard Multisig"). Zpub, not xpub: the
//           SLIP-132 version bytes are how that format signals P2WSH.
//   page 3  [fp/48h/0h/0h/2h]xpub...   (manual entry, no camera)
static void msExportKey() {
  if (!g_ms_our_valid) { dispError("BIP-48 key unavailable"); errorPause(); return; }
  static uint8_t acct[512];
  size_t al = ms_export_crypto_account(g_btc_master_fp, nullptr, &g_ms_our_xpub, acct, sizeof(acct));
  if (!al) { dispError("Export failed"); errorPause(); return; }
  char zp[128];
  if (!ms_xpub_to_string(&g_ms_our_xpub, MS_VER_ZPUB, zp, sizeof(zp))) { dispError("Zpub encode failed"); errorPause(); return; }
  char json[260];
  snprintf(json, sizeof(json),
           "{\"xfp\":\"%02X%02X%02X%02X\",\"p2wsh_deriv\":\"m/48'/0'/0'/2'\",\"p2wsh\":\"%s\"}",
           g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3], zp);
  char expr[200]; ms_key_expr(g_btc_master_fp, &g_ms_our_xpub, expr, sizeof(expr));
  btcExportPager(acct, al, json, expr, "BlueWallet", "Paste as text");
}

// ── Export single-sig account key (m/84'/0'/0') ───────────────────────────
// Replaces the old btc_show_export(), which showed one static QR of
// wpkh([fp/84h/0h/0h]zpub...). That did carry the fingerprint, but a zpub
// inside a descriptor is non-standard (BIP-380 descriptors carry xpubs), it
// had no /<0;1>/* chain suffix, and there was no form BlueWallet could read.
//   page 1  UR crypto-account, wpkh descriptor ONLY
//   page 2  Coldcard JSON {"xfp","bip84":{"deriv","xpub","_pub":"zpub..."}}
//           (BlueWallet watch-only import, Sparrow "Coldcard" file/scan)
//   page 3  wpkh([fp/84h/0h/0h]xpub.../<0;1>/*)   standard descriptor, text
void btcExportSingleSig() {
  if (!g_btc_xpub_valid) { dispError("Wallet not derived"); errorPause(); return; }
  static uint8_t acct[512];
  size_t al = ms_export_crypto_account(g_btc_master_fp, &g_btc_account_xpub, nullptr, acct, sizeof(acct));
  if (!al) { dispError("Export failed"); errorPause(); return; }
  char xp[128], zp[128];
  if (!ms_xpub_to_string(&g_btc_account_xpub, MS_VER_XPUB, xp, sizeof(xp)) ||
      !bip84_serialise_xpub_struct(&g_btc_account_xpub, BIP84_NETWORK_MAINNET, zp, sizeof(zp))) {
    dispError("Key encode failed"); errorPause(); return;
  }
  char fpU[9]; snprintf(fpU, sizeof(fpU), "%02X%02X%02X%02X",
                        g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3]);
  static char json[420];
  snprintf(json, sizeof(json),
           "{\"xfp\":\"%s\",\"bip84\":{\"name\":\"p2wpkh\",\"xfp\":\"%s\",\"deriv\":\"m/84'/0'/0'\",\"xpub\":\"%s\",\"_pub\":\"%s\"}}",
           fpU, fpU, xp, zp);
  char desc[220];
  snprintf(desc, sizeof(desc), "wpkh([%02x%02x%02x%02x/84h/0h/0h]%s/<0;1>/*)",
           g_btc_master_fp[0], g_btc_master_fp[1], g_btc_master_fp[2], g_btc_master_fp[3], xp);
  btcExportPager(acct, al, json, desc, "BlueWallet", "Paste as text");
}

// ── Per-wallet admin menu (23 Sep 2026: Receive + Verify moved up to the
// door's RECEIVE menu, so this is cosigners + delete only) ──────────────────
// WALLET INFO (25 Sep 2026): what this wallet is, in one screen. The
// checksum is the eight characters to read against Sparrow / Nunchuk.
static void msWalletInfo(const ms_wallet_t* w) {
  static PS_ARRAY(char, desc, 1200); char cs[9] = "--------";
  bool ok = ms_wallet_descriptor(w, desc, sizeof(desc), cs);
  spr.fillSprite(C_BG); uiHeader("WALLET INFO", C_BTC_ACCENT);
  fSet(F_HEAD); spr.setTextColor(C_EB_INK); fDrawCentre(w->name, 120, 44); fEnd();
  char line[48];
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  snprintf(line, sizeof(line), "%u of %u   P2WSH sortedmulti", (unsigned)w->m, (unsigned)w->n);
  fDrawCentre(line, 120, 72);
  fDrawCentre("m/48'/0'/0'/2'", 120, 90);
  fEnd();
  fSet(F_BODY); spr.setTextColor(C_EB_INK);
  if (w->our_index < w->n) {
    const uint8_t* f = w->cs[w->our_index].fp;
    snprintf(line, sizeof(line), "This KEY: cosigner %u of %u", (unsigned)w->our_index + 1, (unsigned)w->n);
    fDrawCentre(line, 120, 118);
    snprintf(line, sizeof(line), "fp %02x%02x%02x%02x", f[0], f[1], f[2], f[3]);
    fDrawCentre(line, 120, 136);
  } else {
    fDrawCentre("This KEY: not a cosigner", 120, 118);
  }
  fEnd();
  fSet(F_SMALL); spr.setTextColor(C_EB_GREY); fDrawCentre("descriptor checksum", 120, 162); fEnd();
  fSet(F_HEAD); spr.setTextColor(ok ? C_BTC_ACCENT : C_RED); fDrawCentre(ok ? cs : "unavailable", 120, 178); fEnd();
  pinDrawLabel("PRESS BACK", 212, C_EB_GREY);
  dispPush();
  msWaitEnterBack(60000);
}
// EXPORT DESCRIPTOR: the full descriptor as one text QR (Sparrow, Nunchuk,
// Core all import this). Up to ~5 cosigners fits QR v20; larger wallets
// fall back to one QR per cosigner key expression, paged with UP/DOWN.
static void msExportDescriptor(const ms_wallet_t* w) {
  static PS_ARRAY(char, desc, 1200); char cs[9];
  if (!ms_wallet_descriptor(w, desc, sizeof(desc), cs)) { dispError("Descriptor failed"); errorPause(); return; }
  char foot[24]; snprintf(foot, sizeof(foot), "#%s", cs);
  if (strlen(desc) <= 858) {
    showQR(desc, "Wallet descriptor", foot);
    msWaitEnterBack(300000);
    return;
  }
  int page = 0; unsigned long shownAt = millis(); bool redraw = true;
  clearButtonPending();
  while (millis() - shownAt < 300000UL) {
    esp_task_wdt_reset(); delay(15);
    if (btn1.isPressed()) { page = (page + 1) % w->n; redraw = true; g_ceremonyStart = millis(); }
    else if (btn3.isPressed()) { page = (page + w->n - 1) % w->n; redraw = true; g_ceremonyStart = millis(); }
    if (btn2.isPressed() || btn4.isPressed()) break;
    if (redraw) {
      char expr[200], lab[32];
      ms_key_expr(w->cs[page].fp, &w->cs[page].xpub, expr, sizeof(expr));
      snprintf(lab, sizeof(lab), "Cosigner %d of %u", page + 1, (unsigned)w->n);
      msPageCard(lab, page, w->n);
      showQR(expr, lab, foot);
      redraw = false;
    }
  }
}

static const char* msWalletItems[] = { "Wallet info", "Export descriptor", "Cosigners", "Delete wallet" };
static const char* msWalletDescs[]  = { "Policy and checksum", "QR for any wallet app", "Keys and fingerprints", "Forget this wallet" };
#define MS_WALLET_ITEMS 4
static void msWalletMenu(int slot) {
  ms_wallet_t* w = &g_ms->w[slot];
  int idx = 0;
  drainButtonsAfterTransition();
  dispCardList(w->name, msWalletItems, msWalletDescs, MS_WALLET_ITEMS, idx, C_BTC_ACCENT, true, -1, 3);
  while (true) {
    esp_task_wdt_reset(); delay(5);
    if (tickSleepGesture()) continue;
    if (btn1.isPressed()) { idx = (idx + 1) % MS_WALLET_ITEMS; g_ceremonyStart = millis(); dispCardList(w->name, msWalletItems, msWalletDescs, MS_WALLET_ITEMS, idx, C_BTC_ACCENT, true, -1, 3); }
    else if (btn3.isPressed()) { idx = (idx + MS_WALLET_ITEMS - 1) % MS_WALLET_ITEMS; g_ceremonyStart = millis(); dispCardList(w->name, msWalletItems, msWalletDescs, MS_WALLET_ITEMS, idx, C_BTC_ACCENT, true, -1, 3); }
    else if (btn4.isPressed()) { g_ceremonyStart = millis(); return; }
    else if (btn2.isPressed()) {
      g_ceremonyStart = millis();
      switch (idx) {
        case 0: msWalletInfo(w); break;
        case 1: msExportDescriptor(w); break;
        case 2: msShowCosigners(w, "COSIGNERS", C_BTC_ACCENT); break;
        case 3: {
          spr.fillSprite(C_BG); uiHeader("DELETE WALLET?", C_RED);
          fSet(F_HEAD); spr.setTextColor(C_EB_INK); fDrawCentre(w->name, 120, 50); fEnd();
          fSet(F_BODY); spr.setTextColor(C_EB_GREY);
          fDrawCentre("The KEY forgets this wallet.", 120, 80);
          fDrawCentre("Funds are unaffected.", 120, 98); fEnd();
          uiHoldFooter("HOLD ENTER TO DELETE", "BACK keeps it", 0, C_RED);
          dispPush();
          // 29 Oct 2026: a hold of ENTER, not a tap. BACK keeps the wallet.
          bool del = false;
          { unsigned long shown = millis(), t0 = millis(); float last = 0;
            drainButtonsAfterTransition();
            while (millis() - t0 < 30000UL) {
              esp_task_wdt_reset(); delay(10);
              if (btn4.isPressed()) break;
              btn2.isPressed();
              float hp = holdSince(btn2, shown, 1500);
              if (hp >= 1.0f) { del = true; btn2.resetHold(); break; }
              if (hp > 0 || last > 0) { uiHoldFooter("HOLD ENTER TO DELETE", hp > 0 ? "Let go to stop" : "BACK keeps it", hp, C_RED);
                                        dispPushRegion(0, 196, 240, 44); last = hp; t0 = millis(); }
            } }
          if (del) { ms_store_remove(g_ms, slot); ms_store_save(); dispSuccess("Deleted", "Wallet removed", C_BTC_ACCENT); errorPause(); return; }
          break;
        }
      }
      drainButtonsAfterTransition();
      dispCardList(w->name, msWalletItems, msWalletDescs, MS_WALLET_ITEMS, idx, C_BTC_ACCENT, true, -1, 3);
    }
  }
}

// ── Generic scrolling list with the ceremony idle refresh. Returns the
// chosen index or -1 on BACK. Keeps the four door sub-menus to one shape. ──
static int msPickFrom(const char* title, const char** items, int n, const char** descs = nullptr) {
  int idx = 0;
  drainButtonsAfterTransition();
  dispCardList(title, items, descs, n, idx, C_BTC_ACCENT, true);
  while (true) {
    esp_task_wdt_reset(); delay(5);
    if (tickSleepGesture()) continue;
    if (btn1.isPressed())      { idx = (idx + 1) % n;     g_ceremonyStart = millis(); dispCardList(title, items, descs, n, idx, C_BTC_ACCENT, true); }
    else if (btn3.isPressed()) { idx = (idx + n - 1) % n; g_ceremonyStart = millis(); dispCardList(title, items, descs, n, idx, C_BTC_ACCENT, true); }
    else if (btn4.isPressed()) { g_ceremonyStart = millis(); return -1; }
    else if (btn2.isPressed()) { g_ceremonyStart = millis(); return idx; }
  }
}
// Wallet descriptions: "2 of 3 multisig" for registered wallets.
static void msWalletDesc(const ms_wallet_t* w, char* out, size_t cap) {
  snprintf(out, cap, "%u of %u multisig", (unsigned)w->m, (unsigned)w->n);
}

// A multisig wallet that this seed is not a cosigner of can show its cosigners
// and be deleted, but must not hand out addresses.
static bool msOursOrRefuse(ms_wallet_t* w) {
  if (w->our_index != 0xFF) return true;
  dispError("Not this seed's wallet"); errorPause(); return false;
}

// ── RECEIVE (door card 2) ──────────────────────────────────────────────────
// No multisig registered -> straight to the single-sig receive screen.
// Otherwise: Single-sig, each multisig wallet by name, Verify address.
void btcReceiveMenu() {
  if (!g_ms || btcMsCount() == 0) { btc_show_receive(); return; }
  const char* items[MS_MAX_WALLETS + 2]; int slots[MS_MAX_WALLETS + 2];
  const char* descs[MS_MAX_WALLETS + 2]; static char wd[MS_MAX_WALLETS][20];
  while (true) {
    int n = 0;
    items[n] = "Single-sig"; descs[n] = "Your everyday wallet"; slots[n] = -1; n++;
    for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) { msWalletDesc(&g_ms->w[i], wd[i], sizeof wd[i]); items[n] = g_ms->w[i].name; descs[n] = wd[i]; slots[n] = i; n++; }
    items[n] = "Verify address"; descs[n] = "Check a multisig address"; slots[n] = -2; n++;
    int pick = msPickFrom("Receive", items, n, descs);
    if (pick < 0) return;
    if (slots[pick] == -1) { btc_show_receive(); continue; }
    if (slots[pick] == -2) {
      // Verify is per multisig wallet: one wallet -> go; several -> pick which.
      int cnt = btcMsCount(), only = -1;
      for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) only = i;
      if (cnt == 1) { if (msOursOrRefuse(&g_ms->w[only])) msVerifyAddress(&g_ms->w[only]); continue; }
      const char* vi[MS_MAX_WALLETS]; const char* vd[MS_MAX_WALLETS]; int vs[MS_MAX_WALLETS]; int vn = 0;
      for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) { msWalletDesc(&g_ms->w[i], wd[i], sizeof wd[i]); vi[vn] = g_ms->w[i].name; vd[vn] = wd[i]; vs[vn] = i; vn++; }
      int vp = msPickFrom("Verify address", vi, vn, vd);
      if (vp >= 0 && msOursOrRefuse(&g_ms->w[vs[vp]])) msVerifyAddress(&g_ms->w[vs[vp]]);
      continue;
    }
    if (msOursOrRefuse(&g_ms->w[slots[pick]])) msReceive(&g_ms->w[slots[pick]]);
  }
}

// ── WALLETS (door card 3) ──────────────────────────────────────────────────
// Single-sig (info / address book / export), each multisig wallet (cosigners /
// delete), Import multisig, Export cosigner key.
static const char* btcSingleSigItems[] = { "Wallet info", "Address book", "Export watch-only" };
static const char* btcSingleSigDescs[] = { "Account key and path", "Saved destinations", "Watch only, can't spend" };
static void btcSingleSigMenu() {
  while (true) {
    int pick = msPickFrom("Single-sig", btcSingleSigItems, 3, btcSingleSigDescs);
    if (pick < 0) return;
    switch (pick) {
      case 0: btc_show_wallet_info(); break;
      case 1: btc_show_addrbook(); break;
      case 2: btcExportSingleSig(); break;
    }
  }
}
// 23 Nov 2026 (#57): clear the coin memory. Only needed when a coin was first
// signed with a wrong amount (the attack's first round), so its true amount is
// now refused. A hold of ENTER, as Delete wallet.
static void btcForgetCoinHistory() {
  spr.fillSprite(C_BG); uiHeader("FORGET HISTORY?", C_RED);
  fSet(F_BODY); spr.setTextColor(C_EB_GREY);
  fDrawCentre("The KEY forgets the amounts", 120, 62);
  fDrawCentre("it signed coins with.", 120, 80);
  fDrawCentre("Only do this if a coin's", 120, 110);
  fDrawCentre("real amount is refused.", 120, 128); fEnd();
  uiHoldFooter("HOLD ENTER TO FORGET", "BACK keeps it", 0, C_RED);
  dispPush();
  bool go = false;
  { unsigned long shown = millis(), t0 = millis(); float last = 0;
    drainButtonsAfterTransition();
    while (millis() - t0 < 30000UL) {
      esp_task_wdt_reset(); delay(10);
      if (btn4.isPressed()) break;
      btn2.isPressed();
      float hp = holdSince(btn2, shown, 1500);
      if (hp >= 1.0f) { go = true; btn2.resetHold(); break; }
      if (hp > 0 || last > 0) { uiHoldFooter("HOLD ENTER TO FORGET", hp > 0 ? "Let go to stop" : "BACK keeps it", hp, C_RED);
                                dispPushRegion(0, 196, 240, 44); last = hp; t0 = millis(); }
    } }
  if (go) { cmForgetAll(); dispSuccess("Forgotten", "Coin history cleared", C_BTC_ACCENT); errorPause(); }
  drainButtonsAfterTransition();
}
void btcWalletsMenu() {
  const char* items[MS_MAX_WALLETS + 4]; int slots[MS_MAX_WALLETS + 4];
  const char* descs[MS_MAX_WALLETS + 4]; static char wd[MS_MAX_WALLETS][20];
  while (true) {
    int n = 0;
    items[n] = "Single-sig"; descs[n] = "Info, address book, export"; slots[n] = -1; n++;
    if (g_ms) for (int i = 0; i < MS_MAX_WALLETS; i++) if (g_ms->w[i].valid) { msWalletDesc(&g_ms->w[i], wd[i], sizeof wd[i]); items[n] = g_ms->w[i].name; descs[n] = wd[i]; slots[n] = i; n++; }
    items[n] = "Import multisig";     descs[n] = "Scan a wallet config"; slots[n] = -2; n++;
    items[n] = "Join a multisig";     descs[n] = "Public key only, can't spend"; slots[n] = -3; n++;   // 29 Oct 2026: was "Share this KEY's key"
    items[n] = "Forget coin history"; descs[n] = "Clear remembered amounts"; slots[n] = -4; n++;   // 23 Nov 2026 (#57)
    int pick = msPickFrom("Wallets", items, n, descs);
    if (pick < 0) return;
    if (slots[pick] == -1)      btcSingleSigMenu();
    else if (slots[pick] == -2) { if (g_ms) msImportScan(); else { dispError("No memory"); errorPause(); } }
    else if (slots[pick] == -3) msExportKey();
    else if (slots[pick] == -4) btcForgetCoinHistory();
    else                        msWalletMenu(slots[pick]);
  }
}
