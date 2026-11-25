// ─────────────────────────────────────────────────────────────────────────────
// attest_flow.inc — on-device attestation UX (Favilla KEY)
//
// #include'd inside main.cpp (needs qrScanOnce/showQR/cameraStart/qrResultBuf/
// the button objects/pwrBoost etc. — all main.cpp internals). Mirrors the
// self-contained scan loop used by runRestoreFlow(): one context owns the
// camera via qrScanOnce(), BACK cancels, and on a decoded FAVC1: challenge we
// sign with the SE and display the FAVR1: answer QR.
//
// Flow:
//   1. consent screen (attestation is NOT signing a transaction — make that clear)
//   2. camera up, scan for a "FAVC1:" challenge QR
//   3. parse it (favilla_attest.h), sign the domain-separated preimage in the SE
//   4. show the "FAVR1:" answer QR for the verifier to scan; BACK exits
//
// The SE attestation key must already be provisioned (manufacture step). If it
// is not, we say so and bail rather than silently doing nothing.
// ─────────────────────────────────────────────────────────────────────────────

// favilla_attest.h provides attest_parse_challenge / attest_build_answer, which
// call se_attest_pubkey / se_attest_sign (favilla:: — SE-native).
#include "favilla_attest.h"

// The SE implementations live in favilla:: (se_signer.cpp via se_attest.inc).
// Declare them here so the global thunks below can name them — main.cpp only
// declared exists/provision/selftest earlier (for the serial command), not
// pubkey/sign.
namespace favilla {
  bool se_attest_pubkey(uint8_t pk33[33]);
  bool se_attest_sign(const uint8_t hash32[32], uint8_t sig64[64]);
}

// Bridge the header's extern se_attest_* (global) to the favilla:: definitions.
// favilla_attest.h declares them extern in the global namespace; provide global
// thunks so attest_build_answer()'s calls resolve to the one SE implementation.
bool se_attest_exists()                                   { return favilla::se_attest_exists(); }
bool se_attest_pubkey(uint8_t pk33[33])                   { return favilla::se_attest_pubkey(pk33); }
bool se_attest_sign(const uint8_t h[32], uint8_t s[64])   { return favilla::se_attest_sign(h, s); }

// Show a short-lived status line centered on screen (matches the app's simple
// full-screen message style, e.g. dispError at main.cpp:4539).
static void attestMsg(const char* line1, const char* line2, uint16_t col){
  spr.fillSprite(C_BG);
  uiHeader("Verify device", col);
  fSet(F_BODY); spr.setTextColor(C_FG);
  fDrawCentre(line1, 120, 96);
  if(line2) fDrawCentre(line2, 120, 124);
  fEnd();
  uiFooter(); dispPush();
}

// Process an ALREADY-SCANNED FAVC1: challenge string (the smart scanner already
// has it in qrResultBuf). Signs and shows the FAVR1: answer QR. Returns true if
// it was a valid challenge and was handled; false if the string isn't a FAVC1
// challenge (so the caller can fall through to other QR types).
bool attestHandleScanned(const char* scanned){
  AttestChallenge ch;
  String raw=String(scanned); raw.trim();
  if(!attest_parse_challenge(raw, ch)) return false;   // not ours
  if(!favilla::se_attest_exists()){
    attestMsg("Not provisioned", "No attestation key", C_RED);
    delay(1600); return true;
  }
  attestMsg("Signing...", nullptr, C_GREEN);
  String answer = attest_build_answer(ch);
  if(answer.length()==0){
    attestMsg("Sign failed", "SE error", C_RED);
    delay(1600); return true;
  }
  showQR(answer.c_str(), "Scan with verify page", "BACK  done");
  // DEBUG (bench): also print the answer to serial so it can be pasted into the
  // verify page's manual box — isolates "device signs correctly" from "webcam
  // reads the QR". Strip before ship.
  Serial.print("[attest] FAVR1 answer: ");
  Serial.println(answer);
  clearButtonPending();
  while(true){ btn4.poll(); if(btn4.isPressed()) break; delay(20); }
  clearButtonPending();
  return true;
}

// The attestation flow. Returns to caller (which sets nextState=ST_MENU).
void runAttestFlow(){
  // ── 0. precondition: key must exist ─────────────────────────────────────
  if(!favilla::se_attest_exists()){
    attestMsg("Not provisioned", "No attestation key", C_RED);
    delay(1600);
    return;
  }

  // ── 1. consent — attestation is NOT a spend/sign-of-your-keys ────────────
  // 11cb (Josh's pick B of three mockups): the VAULT page language, no header
  // or footer: tracked label, a two-line Archivo Bold 28 question, two
  // numbered steps (Archivo Bold 14, Archivo 13 grey), tracked BACK line.
  // Up for 4 s; ENTER skips ahead to the QR, BACK cancels.
  {
    fEndHard();
    spr.fillSprite(C_BG);
    uiTrackLabel("VERIFY DEVICE", 120, 14, C_EB_BRASS);
    spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
    const char* h1 = "Is this KEY"; const char* h2 = "genuine?";
    spr.drawString(h1, 120 - spr.textWidth(h1)/2, 40);
    spr.drawString(h2, 120 - spr.textWidth(h2)/2, 72);
    fEndHard();
    const char* stepT[2] = { "Scan the next QR", "Press ENTER" };
    const char* stepS[2] = { "with your phone", "when the page is open" };
    for(int i = 0; i < 2; i++){
      const int y = 122 + i * 34;
      spr.drawCircle(39, y + 11, 11, C_EB_BRASS); spr.drawCircle(39, y + 11, 10, C_EB_BRASS);
      // 11cc: centre the digit on its INK, from the font's own glyph metrics
      // (TFT_eSPI draws a glyph's top at y + ascent - dY and its left at
      // x + dX). textWidth()/2 and a guessed y put it 2 px high (11cb bench).
      char n[2] = { (char)('1' + i), 0 };
      fSet(F_BRAND_B12); spr.setTextColor(C_EB_BRASS);
      { uint16_t gi = 0; const int cx = 39, cy = y + 11;
        if(spr.getUnicodeIndex((uint16_t)n[0], &gi))
          spr.drawString(n, cx - spr.gdX[gi] - spr.gWidth[gi] / 2, cy - (spr.gFont.maxAscent - spr.gdY[gi]) - spr.gHeight[gi] / 2);
        else spr.drawString(n, cx - spr.textWidth(n) / 2, cy - 5); }
      fEnd();
      fSet(F_BRAND_B14); spr.setTextColor(C_EB_INK); spr.drawString(stepT[i], 62, y + 1); fEnd();
      fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
      spr.drawString(stepS[i], 62, y + 19); fEndHard();
    }
    uiTrackLabel("BACK TO CANCEL", 120, 212, C_EB_GREY);
    fEnd();
    dispPush();
    clearButtonPending();
    const unsigned long t0 = millis();
    while(millis() - t0 < 4000){
      btn2.poll(); btn4.poll(); esp_task_wdt_reset();
      if(btn4.isPressed()){ clearButtonPending(); return; }
      if(btn2.isPressed()) break;
      delay(10);
    }
  }

  // ── 1b. 11bz: the verify page's address as a QR, so a phone camera opens it
  // straight away. A fixed string in the firmware: nothing can point it at
  // another site. ENTER goes on to the KEY's own scan of the page's
  // challenge; BACK returns to the PIN screen. No timeout here (phones take
  // a moment); the scan step keeps its 45 s window.
  clearButtonPending();
  showQR("https://favillakey.io/verify");   // full screen, no labels (QRTFT::show draws none)
  while(true){
    btn2.poll(); btn4.poll(); esp_task_wdt_reset();
    if(btn4.isPressed()){ clearButtonPending(); return; }
    if(btn2.isPressed()) break;
    delay(10);
  }
  clearButtonPending();

  // ── 2. camera up + scan for FAVC1: (mirror restore-flow entry exactly) ───
  attestMsg("Point at the", "verify QR", C_GREEN);
  delay(400);
  pwrBoost();          // grab+decode+preview MUST run at 240MHz
  camHoldWake();       // 11bj: the scan's own hold (10q/11b); cameraStop() releases it
  g_airgapLivePreview=true;
  cameraStart(); qrFound=false;
  if(!cameraRunning){ g_airgapLivePreview=false; return; }  // error screen already shown
  // stale-frame flush (matches restore/scan)
  for(int _f=0; _f<4; _f++){ camera_fb_t* _sf=esp_camera_fb_get(); if(_sf) esp_camera_fb_return(_sf); vTaskDelay(pdMS_TO_TICKS(25)); }
  qrResultBuf[0]=0; qrDiagReset(); qrDumpReset();

  AttestChallenge ch;
  bool haveChallenge=false;
  unsigned long start=millis(), lastQR=0;
  while(millis()-start < 45000){          // 45s scan window
    btn4.poll();
    if(btn4.isPressed()){                  // BACK = cancel
      g_airgapLivePreview=false; cameraStop(); clearButtonPending(); return;
    }
    if(!qrFound && (millis()-lastQR > QR_AIRGAP_SCAN_INTERVAL_MS)){
      qrScanOnce();                        // draws live preview, decodes, sets qrFound
      lastQR=millis(); delay(5);
    }
    if(qrFound){
      qrFound=false;
      String raw=String(qrResultBuf); raw.trim();
      // DEBUG (bench): show what was actually scanned so we can see why a
      // challenge is/isn't recognised. Length + first chars only.
      Serial.printf("[attest] scanned %d chars: %.24s%s\n",
                    raw.length(), raw.c_str(), raw.length()>24?"...":"");
      // Only a FAVC1: challenge is valid here; ignore anything else and keep scanning.
      if(attest_parse_challenge(raw, ch)){ haveChallenge=true; break; }
      Serial.println("[attest] not a valid FAVC1 challenge — keep scanning");
      // not ours — clear and continue scanning
      qrResultBuf[0]=0;
    }
  }
  g_airgapLivePreview=false; cameraStop(); clearButtonPending();

  if(!haveChallenge){
    attestMsg("No code found", "Try again", C_AMBER);
    delay(1500); return;
  }

  // ── 3. sign the challenge in the SE ──────────────────────────────────────
  attestMsg("Signing...", nullptr, C_GREEN);
  String answer = attest_build_answer(ch);   // SE-native sign; "" on failure
  if(answer.length()==0){
    attestMsg("Sign failed", "SE error", C_RED);
    delay(1600); return;
  }

  // ── 4. show the FAVR1: answer QR until BACK ──────────────────────────────
  showQR(answer.c_str(), "Scan with verify page", "BACK  done");
  // hold the QR up; poll for BACK
  clearButtonPending();
  while(true){
    btn4.poll();
    if(btn4.isPressed()) break;
    delay(20);
  }
  clearButtonPending();
}
