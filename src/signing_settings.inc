// ══════════════════════════════════════════════════════════════════════════
// ── SIGNING MODE SETTINGS ─────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════
//
// Integration — in nostr_signer_v20.ino:
//
// 1. Add to global state section (near AUTO_SLEEP_MS):
//      #include "signing_settings.ino"   // or merge manually
//
// 2. In runSettingsMenu(), add "SIGNING" as the first settings item:
//      const char* settingsItemsWifi[]  = {"SIGNING","RELAYS","CHANGE MODE",...};
//      const char* settingsItemsOther[] = {"SIGNING","RELAYS","CHANGE MODE",...};
//    Then shift all existing case numbers up by 1 and add:
//      case 0: runSigningSettings(); return;
//
// 3. In handleApiSign(), replace the fixed pendingApproval=true block with:
//      if(signingModeAutoApprove(evKind)){
//        // Auto-sign immediately
//        bool ok=signNostrEvent(iosSignEvent,iosSignResult,sizeof(iosSignResult));
//        if(ok) iosSignApproved=true;
//        iosSignPending=false;
//        dispLoading("AUTO SIGNED","Event published",nullptr,C_GREEN); delay(800);
//        nextState=ST_MENU;
//      } else {
//        pendingApproval=true; lastActivity=millis();
//      }
//
// ══════════════════════════════════════════════════════════════════════════

// ── Signing mode enum ─────────────────────────────────────────────────────
#define SIGN_MANUAL     0   // Always prompt — BTN1 approve, BTN2 reject
#define SIGN_AUTO       1   // Auto-sign everything (pocket mode)
#define SIGN_SELECTIVE  2   // Auto low-risk, prompt high-risk

int signingMode = SIGN_MANUAL;

void loadSigningMode() {
  Preferences p; p.begin("signing", true);
  signingMode = p.getInt("mode", SIGN_MANUAL);
  p.end();
  if (signingMode < 0 || signingMode > 2) signingMode = SIGN_MANUAL;
}

void readGateClose();
void saveSigningMode(int m) {
  signingMode = m;
  readGateClose();   // 11au: a mode change never inherits an open reading window
  Preferences p; p.begin("signing", false);
  p.putInt("mode", m);
  p.end();
}

// ── Returns true if this event kind should be auto-signed ─────────────────
bool signingModeAutoApprove(int evKind) {
  switch (signingMode) {
    case SIGN_AUTO:
      return true;  // sign everything
    case SIGN_SELECTIVE:
      // Low-risk: notes, likes, reposts, zap requests, relay list, NIP-17 seal
      // Kind 13 (NIP-17 seal) is auto-signed because seals are never published
      // standalone — they're encrypted inside kind:1059 gift wraps and only
      // visible to the recipient. Prompting on each DM kills send speed.
      return (evKind == 1 || evKind == 6 || evKind == 7 ||
              evKind == 9734 || evKind == 10002 || evKind == 13);
      // High-risk (always prompt): profile(0), contacts(3), legacy DM(4), delete(5)
    case SIGN_MANUAL:
    default:
      return false;
  }
}

bool signingIsManual() { return signingMode == SIGN_MANUAL; }   // 11au: the read gate asks this

const char* signingModeName(int m) {
  switch (m) {
    case SIGN_AUTO:      return "Auto";
    case SIGN_SELECTIVE: return "Selective";
    default:             return "Manual";
  }
}

const char* signingModeDesc(int m) {
  switch (m) {
    case SIGN_AUTO:      return "Sign all events instantly";
    case SIGN_SELECTIVE: return "Auto notes/likes, prompt DMs";
    default:             return "Always prompt to approve";
  }
}

// Small checkmark glyph — square-capped, matches the device's tick style.
// Local copy (drawTick in bitcoin_menu.inc isn't visible here — that file is
// included after this one).
static void sgnDrawCheck(int cx, int cy, uint16_t col){
  spr.drawWideLine(cx - 5, cy - 1, cx - 1, cy + 4, 3, col);  // short down-stroke
  spr.drawWideLine(cx - 1, cy + 4, cx + 7, cy - 7, 3, col);  // long up-stroke
}

// ── Signing settings screen ───────────────────────────────────────────────
void dispSigningSettings(int sel) {
  spr.fillSprite(C_BG);
  uiHeader("Signing Mode", C_AMBER);

  // Three mode cards. The active (saved) mode is marked with a checkmark on
  // the right; the selected (highlighted) card gets the coloured border.
  const int modes[3] = { SIGN_MANUAL, SIGN_SELECTIVE, SIGN_AUTO };
  const uint16_t colors[3] = { C_AMBER, C_BLUE, C_GREEN };

  for (int i = 0; i < 3; i++) {
    int y = 52 + i * 62;
    bool active = (i == sel);
    bool current = (modes[i] == signingMode);
    uint16_t col = colors[i];

    // 7 Oct 2026 (Entropy Ember): the shared list card, each in its mode colour.
    char nm[16];
    uiListCard(12, y, 216, 54, active, col, uiUpper(signingModeName(modes[i]), nm, sizeof nm), signingModeDesc(modes[i]), 24);

    // Active mode → checkmark on the right (in the card's colour).
    if (current) {
      sgnDrawCheck(212, y + 27, active ? col : C_EB_GREY);
    }
  }

  dispPush();
}

// ── Auto-signing acknowledgement ─────────────────────────────────────────
// Shown after an auto-sign completes (the actual signing already happened
// by the time this displays — see runStateMachine where pendingAutoSign is
// processed). Uses the same animated success tick as manual signing for
// consistent visual feedback across all sign paths.
//
// Note: dispSuccessFor self-times via SUCC_TOTAL_MS (~1150ms). Callers
// that previously added their own delay after this should reconsider —
// the animation already provides the dwell time.
void dispAutoSigning(const char* kindLabel) {
  char msg[64];
  snprintf(msg, sizeof(msg), "Auto-signed: %s", kindLabel);
  // Contextual icon for zap/like/note/repost (falls back to tick otherwise).
  // g_signKind was set by the approval/sign path before auto-sign fired.
  dispSignSuccessFor("Approved", msg);
}

// ── Run signing settings menu ─────────────────────────────────────────────
void runSigningSettings() {
  int sel = 0;
  // Start selection on current mode
  const int modes[3] = { SIGN_MANUAL, SIGN_SELECTIVE, SIGN_AUTO };
  for (int i = 0; i < 3; i++) {
    if (modes[i] == signingMode) { sel = i; break; }
  }

  dispSigningSettings(sel);

  while (true) {
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    tickStatusBarInMenu(false);   // no footer on this screen

    if (btn1.isPressed()) {            // SCROLL DOWN
      sel = (sel + 1) % 3;
      dispSigningSettings(sel);
    }
    if (btn3.isPressed()) {            // SCROLL UP
      sel = (sel - 1 + 3) % 3;
      dispSigningSettings(sel);
    }
    if (btn4.isPressed()) {            // BACK (no change)
      return;
    }
    if (btn2.isPressed()) {            // SELECT — set active mode, stay in menu
      saveSigningMode(modes[sel]);     // updates signingMode → checkmark follows
      dispSigningSettings(sel);        // repaint so the ✓ moves to this card
    }

    delay(10);
  }
}
