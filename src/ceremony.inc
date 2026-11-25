// ceremony.inc — Bitcoin signing ceremony (airgap-only TX doctrine, V23)
//
// See the doctrine block next to the globals in main.cpp. This file holds the
// three user-facing pieces:
//   ceremonyOffer()   — full-screen interstitial explaining the reboot
//                       sandwich; two-press confirm (arm + commit) so a stray
//                       press can never trigger a reboot cycle. Refuses to arm
//                       under a battery floor.
//   ceremonyRequest() — persists the one-shot flag and reboots. Never returns.
//   ceremonyFinish()  — end-of-session card + deep sleep; wake lands on the
//                       BITCOIN SESSION screen. Never returns.
//
// Naming: "ceremony" == the Bitcoin session (radios never initialised).
// Since 7 Oct 2026 the door enters it IN PLACE (ceremonyEnterInPlace in
// main.cpp); ceremonyRequest's restart is only used by the PSBT-rescan offer.
//
// Buttons follow the main-side grammar: background btnPollTask latches
// presses; blocking loops consume via btnX.isPressed(). BTN2 = ENTER,
// BTN4 = BACK.

static const int CEREMONY_BATT_FLOOR = 15;   // % — refuse to start below this

static void ceremonyDrawOffer(const char* why, bool armed, bool lowBatt) {
  spr.fillSprite(C_BG);
  if (lowBatt) {
    // Dedicated warning screen — the ceremony steps are noise when the only
    // valid action is charging. Amber header, the warning as the hero.
    uiHeader("Bitcoin", C_AMBER);
    fSet(F_HEAD); spr.setTextColor(C_AMBER);
    fDrawCentre("WARNING", 120, 66); fEnd();
    fSet(F_TITLE); spr.setTextColor(C_AMBER);
    fDrawCentre("BATTERY LOW", 120, 96); fEnd();
    fSet(F_HEAD); spr.setTextColor(C_FG);
    fDrawCentre("CHARGE BEFORE TX", 120, 140); fEnd();
    if (battPercent >= 0) {
      char pb[12]; snprintf(pb, sizeof(pb), "%d%%", battPercent);
      fSet(F_BODY); spr.setTextColor(C_MUTED);
      fDrawCentre(pb, 120, 168); fEnd();
    }
    fSet(F_BODY); spr.setTextColor(C_DIM);
    fDrawCentre("BACK TO EXIT", 120, 202); fEnd();
    dispPush();
    return;
  }
  // 7 Oct 2026: "SIGNING CEREMONY" meant nothing to a new user. Plain words:
  // what is about to happen and why, in the brand header grammar.
  uiHeader("Bitcoin", C_EB_BRASS);
  fSet(F_HEAD);
  spr.setTextColor(C_TEXT2);
  fDrawCentre(why, 120, 50);
  spr.setTextColor(C_FG);
  fDrawCentre("1  RESTART, RADIOS OFF", 120, 86);
  fDrawCentre("2  SCAN  CHECK  SIGN", 120, 112);
  fDrawCentre("3  RESTART BACK", 120, 138);
  fEnd();
  if (armed) {
    fSet(F_HEAD); spr.setTextColor(C_AMBER);
    fDrawCentre("PRESS AGAIN TO RESTART", 120, 178); fEnd();
  } else {
    uiCornerAnswers("CANCEL", "BEGIN");   // 11cw: the answers in the corners
  }
  dispPush();
}

void ceremonyRequest() {
  // 7 Oct 2026 (Josh, from video): no interstitial at all. Screen to black,
  // flag, restart; the ceremony boot skips the brand reveal and lands on the
  // BTC PIN page, which says AIR-GAPPED in green at the bottom. Door choice
  // -> PIN, nothing in between.
  spr.fillSprite(C_BG); dispPush();
  { Preferences p; p.begin("sys", false); p.putUChar("ceremony", 1); p.end(); }
  delay(150);
  esp_restart();
}

void ceremonyFinish(const char* msg) {
  // Two-door (11 Sep 2026): a ceremony boot is the BTC door for this whole
  // power-on life; a soft reboot would land on a Nostr screen that cannot
  // open. 23 Sep 2026: instead of holding the screen hot until a battery pull
  // (hours of backlight + 80 MHz), say what happened and DEEP SLEEP. Wake is
  // an ESP32 reset with the door still saved as BTC, so the next boot holds
  // the BITCOIN SESSION screen: ENTER re-enters the ceremony (the G0 re-mints
  // the latch from SPENT), the two left buttons restart for Nostr. Never
  // returns; never soft-reboots.
  pwrIdle();
  spr.fillSprite(C_BG);
  uiHeader("Bitcoin", C_EB_BRASS);
  fSet(F_HEAD); spr.setTextColor(C_TEXT2);
  fDrawCentre(msg, 120, 52); fEnd();
  fSet(F_TITLE); spr.setTextColor(C_FG);
  fDrawCentre("SLEEPING", 120, 92); fEnd();
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  fDrawCentre("Wake to continue Bitcoin", 120, 140); fEnd();
  fSet(F_BODY); spr.setTextColor(C_DIM);
  fDrawCentre("Two LEFT buttons together:", 120, 176);
  fDrawCentre("restart to use Nostr", 120, 194); fEnd();
  dispPush();
  unsigned long t0 = millis();
  while (millis() - t0 < 3000UL) { esp_task_wdt_reset(); delay(50); }
  goSleep();   // never returns
  for (;;) { esp_task_wdt_reset(); delay(200); }
}

// Shown when a Bitcoin PSBT is scanned in a NOSTR life. The latch is NOSTR for
// this power-on life and no PIN or reboot can move it, so offering the
// ceremony would only produce "BTC refused: latch not neutral" after a reboot.
// Explain the real path instead. Returns on BACK/ENTER or after 60 s.
void ceremonyExplainNostrMode(const char* header) {
  drainButtonsAfterTransition();
  spr.fillSprite(C_BG);
  uiHeader(header, C_AMBER);
  fSet(F_HEAD); spr.setTextColor(C_TEXT2);
  fDrawCentre("This device is in", 120, 50);
  fDrawCentre("NOSTR mode", 120, 72); fEnd();
  fSet(F_HEAD); spr.setTextColor(C_FG);
  fDrawCentre("1  POWER OFF AND ON", 120, 110);
  fDrawCentre("2  CHOOSE BITCOIN", 120, 136);
  fDrawCentre("3  SCAN AGAIN", 120, 162); fEnd();
  fSet(F_BODY); spr.setTextColor(C_DIM);
  fDrawCentre("BACK TO EXIT", 120, 202); fEnd();
  dispPush();
  unsigned long shownAt = millis();
  while (true) {
    esp_task_wdt_reset();
    delay(15);
    if (btn4.isPressed() || btn2.isPressed()) return;
    if (millis() - shownAt > 60000UL) return;
  }
}

void ceremonyOffer(const char* why) {
  battRead();                          // refresh (30s-throttled internally)
  bool lowBatt = (battPercent >= 0 && battPercent < CEREMONY_BATT_FLOOR);
  drainButtonsAfterTransition();       // don't let the press that got us here arm
  bool armed = false;
  unsigned long armedAt = 0, shownAt = millis();
  ceremonyDrawOffer(why, armed, lowBatt);
  while (true) {
    esp_task_wdt_reset();
    delay(15);
    if (btn4.isPressed()) return;                       // BACK — declined
    if (millis() - shownAt > 60000UL) return;           // idle — treat as declined
    if (armed && millis() - armedAt > 5000UL) {         // arm window lapsed
      armed = false; ceremonyDrawOffer(why, armed, lowBatt);
    }
    if (btn2.isPressed()) {
      if (lowBatt) continue;                            // can't arm on low battery
      if (!armed) { armed = true; armedAt = millis();
                    ceremonyDrawOffer(why, armed, lowBatt); }
      else ceremonyRequest();                           // never returns
    }
  }
}
