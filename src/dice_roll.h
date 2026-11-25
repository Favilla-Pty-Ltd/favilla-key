// ─────────────────────────────────────────────────────────────────────────────
// dice_roll.h — verifiable dice-only entropy page  (Favilla KEY)
//
// The STANDARD, externally-verifiable dice method used by Coldcard and SeedSigner:
// the seed entropy is SHA-256 over the roll digits as an ASCII string, and NOTHING
// else. No device secret is mixed in, so the user can reproduce the whole thing
// off-device and prove the KEY didn't cheat:
//
//     entropy = SHA-256( "3141592..."  )        // roll digits, ASCII, no separator
//     seed    = BIP-39( entropy[:len] )          // len = 16 (12w) or 32 (24w)
//
// External check (any airgapped machine):
//     printf '3141592...' | sha256sum            // -> the same entropy hex
// then feed that entropy to any BIP-39 tool -> the same words. The 0-rolls hash is
// always e3b0c4..b855 (SHA-256 of the empty string) — the same "tell" Coldcard
// shows, which proves the device is really hashing the rolls.
//
// TRADE-OFF (by design): this path trusts the DICE, not the SE051. The secure
// element is not an entropy source here — that is the price of verifiability, and
// it is the accepted standard. ~99 d6 rolls = 255.9 bits. The SE-only path remains
// the default for users who prefer the hardware TRNG and don't need to verify.
//
// Because secrecy of the rolls is not what protects a *combined* seed here (there
// is no combine — the rolls ARE the seed), the running hash and a recent-roll tail
// are shown on-device to aid entry and verification; the seed-generation ceremony
// is assumed private, exactly as Coldcard/SeedSigner assume.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_DICE_ROLL_H
#define FAVILLA_DICE_ROLL_H

#ifndef C_GREEN
#error "dice_roll.h must be #included AFTER the C_* colours and the display/button/font setup."
#endif

#include "dice_entropy.h"                          // the pure, KAT-tested construction

#define DICE_ROLL_MIN_24     99            // 99 * log2(6) = 255.9 bits  (matches Coldcard)
#define DICE_ROLL_MIN_12     50            // 50 * log2(6) = 129.2 bits

static uint8_t g_diceRollBuf[DICE_ROLL_MAX];  // one digit per roll (value 1..6)
static int     g_diceRollCount = 0;
static bool    g_diceRollValid = false;       // true once a full session was hashed
static uint8_t g_diceEntropy[32];             // SHA-256(ascii rolls) — the seed entropy for the dice path

// ── SHA-256 over the current rolls (ASCII digits). Zero rolls -> e3b0c4..b855. ─
// Thin wrapper over the pure, KAT-tested diceEntropyFromRolls().
static void diceRollHash(uint8_t digest[32]){
  diceEntropyFromRolls(g_diceRollBuf, g_diceRollCount, digest);
}

// ── Draw one die face as pips (3x3 grid; bitmask = row*3 + col) ──────────────
// ── Layout (25 Sep 2026 redesign) ───────────────────────────────────────────
// Borrowed the best of everyone: our own die picker, SeedSigner's grid of
// slots that fills as you roll (progress + review + mis-press catch in one
// glance), Coldcard's running SHA-256 for verifiers, Krux's quality check at
// the end. Hints sit at the corners that match the physical buttons:
// top-left/right scroll the face, bottom-left BACK undoes, bottom-right ENTER
// commits. The grid is 10 wide; for 99 rolls it scrolls to the five most
// recent rows while rolling and pages 1-50 / 51-99 on the review screen.
#define DICE_GRID_COLS 10
#define DICE_GRID_ROWS 5
#define DICE_CELL      18
#define DICE_GAP       3
#define DICE_GRID_X    15
#define DICE_GRID_Y    104

static void diceDrawFace(int fx, int fy, int S, int value){
  static const uint16_t PIPS[7] = { 0x000, 0x010, 0x101, 0x111, 0x145, 0x155, 0x16D };
  // Soft shadow + light grey face: readable, not glaring. It is a picker.
  spr.fillRoundRect(fx + 2, fy + 3, S, S, 10, 0x0000);
  spr.fillRoundRect(fx, fy, S, S, 10, 0xC658);              // ~#C4CAD4
  int gx[3] = { fx + (S*25)/100, fx + S/2, fx + (S*75)/100 };
  int gy[3] = { fy + (S*25)/100, fy + S/2, fy + (S*75)/100 };
  int pipR = S/12;
  uint16_t m = PIPS[(value>=1 && value<=6) ? value : 1];
  for(int cell=0; cell<9; cell++)
    if(m & (1u<<cell)){ int c=cell%3, r=cell/3; spr.fillCircle(gx[c], gy[r], pipR, 0x18E4); }
}

// Grid of roll slots. firstRow = the top row shown; highlightLast lights the
// newest roll green so a mis-press is caught as it happens.
static void diceDrawGrid(int firstRow, int target, bool highlightLast){
  for(int r = 0; r < DICE_GRID_ROWS; r++){
    int row = firstRow + r;
    for(int col = 0; col < DICE_GRID_COLS; col++){
      int i = row * DICE_GRID_COLS + col;
      if(i >= target) continue;
      int cx = DICE_GRID_X + col * (DICE_CELL + DICE_GAP), cy = DICE_GRID_Y + r * (DICE_CELL + DICE_GAP);
      if(i < g_diceRollCount){
        bool last = highlightLast && (i == g_diceRollCount - 1);
        spr.fillRoundRect(cx, cy, DICE_CELL, DICE_CELL, 3, last ? C_GREEN : C_PANEL2);
        char t[2] = { (char)('0' + g_diceRollBuf[i]), 0 };
        fSet(F_SMALL); spr.setTextColor(last ? C_BG : C_FG);
        int tw = spr.textWidth(t);
        spr.drawString(t, cx + (DICE_CELL - tw) / 2, cy + 4); fEnd();
      } else {
        spr.drawRoundRect(cx, cy, DICE_CELL, DICE_CELL, 3, C_BORDER2);
      }
    }
  }
}

static void diceDrawHash(int y, uint16_t col){
  uint8_t h[32]; diceRollHash(h);
  char hx[24];
  snprintf(hx, sizeof hx, "%02x%02x%02x..%02x%02x%02x", h[0],h[1],h[2], h[29],h[30],h[31]);
  fSet(F_SMALL); spr.setTextColor(C_DIM); spr.drawString("sha256", 16, y + 3); fEnd();
  fSet(F_MONO); spr.setTextColor(col); fDrawCentre(hx, 120, y); fEnd();
  mbedtls_platform_zeroize(h, sizeof(h));
}

static void diceRollDraw(int value, int target){
  spr.fillSprite(C_BG);
  uiHeader("DICE ENTROPY", C_GREEN);
  // Hero count, left.
  fSet(F_SMALL); spr.setTextColor(C_MUTED); spr.drawString("ROLL", 16, 46); fEnd();
  char n[8]; snprintf(n, sizeof n, "%d", g_diceRollCount);
  fSet(F_TITLE); spr.setTextColor(C_FG); spr.drawString(n, 16, 54); int nw = spr.textWidth(n); fEnd();
  char of[12]; snprintf(of, sizeof of, "/ %d", target);
  fSet(F_HEAD); spr.setTextColor(C_MUTED); spr.drawString(of, 16 + nw + 4, 70); fEnd();
  // Die picker, right.
  diceDrawFace(150, 36, 58, value);
  // Grid: five most recent rows.
  int curRow = (g_diceRollCount > 0) ? (g_diceRollCount - 1) / DICE_GRID_COLS : 0;
  int firstRow = (curRow >= DICE_GRID_ROWS) ? curRow - (DICE_GRID_ROWS - 1) : 0;
  if(firstRow > 0){
    char rs[24]; snprintf(rs, sizeof rs, "rows %d-%d", firstRow*DICE_GRID_COLS + 1, (firstRow + DICE_GRID_ROWS)*DICE_GRID_COLS);
    fSet(F_SMALL); spr.setTextColor(C_DIM); spr.drawString(rs, 16, 95); fEnd();
  }
  diceDrawGrid(firstRow, target, true);
  diceDrawHash(216, C_GREEN);
  dispPush();
}

// ── Quality check (Krux-style) ───────────────────────────────────────────────
// Real dice produce every face, no face dominates, runs stay short and the
// sequence does not march 1-2-3-4-5-6. Someone typing "random" numbers or
// mashing one button fails these. Thresholds are loose enough that genuine
// rolls essentially never trip them (each < 0.1% at 50 rolls).
struct DiceQuality { int counts[7]; int minCount, maxCount, longestRun; int seqPct; bool ok; };
static DiceQuality diceQuality(){
  DiceQuality q = {}; q.minCount = 1000; q.longestRun = 0;
  int run = 1, seq = 0;
  for(int i = 0; i < g_diceRollCount; i++){
    q.counts[g_diceRollBuf[i]]++;
    if(i > 0){
      if(g_diceRollBuf[i] == g_diceRollBuf[i-1]){ if(++run > q.longestRun) q.longestRun = run; } else run = 1;
      int d = (int)g_diceRollBuf[i] - (int)g_diceRollBuf[i-1];
      if(d == 1 || d == -1 || d == 5 || d == -5) seq++;        // adjacent faces, wrapping
    }
  }
  if(q.longestRun == 0) q.longestRun = 1;
  for(int f = 1; f <= 6; f++){ if(q.counts[f] < q.minCount) q.minCount = q.counts[f]; if(q.counts[f] > q.maxCount) q.maxCount = q.counts[f]; }
  q.seqPct = (g_diceRollCount > 1) ? (seq * 100) / (g_diceRollCount - 1) : 0;
  int n = g_diceRollCount;
  q.ok = (q.minCount > 0) && (q.maxCount * 100 <= n * 40) && (q.longestRun < 8) && (q.seqPct <= 60);
  return q;
}

static void diceReviewDraw(int page, int pages, int target, const DiceQuality& q){
  spr.fillSprite(C_BG);
  uiHeader("DICE ENTROPY", C_GREEN);
  if(pages > 1){ fSet(F_HEAD); spr.setTextColor(C_MUTED); spr.drawString("<", 14, 33); spr.drawString(">", 219, 33); fEnd(); }
  fSet(F_SMALL); spr.setTextColor(q.ok ? C_GREEN : C_AMBER); spr.drawString(q.ok ? "DONE" : "CHECK", 16, 46); fEnd();
  char n[8]; snprintf(n, sizeof n, "%d", g_diceRollCount);
  fSet(F_TITLE); spr.setTextColor(C_FG); spr.drawString(n, 16, 54); int nw = spr.textWidth(n); fEnd();
  fSet(F_HEAD); spr.setTextColor(C_MUTED); spr.drawString("rolls", 16 + nw + 4, 70); fEnd();
  char l1[32], l2[32], l3[32];
  if(q.ok) snprintf(l1, sizeof l1, "Looks rolled, not typed");
  else     snprintf(l1, sizeof l1, "These look typed");
  snprintf(l2, sizeof l2, "each face %d-%d times", q.minCount, q.maxCount);
  snprintf(l3, sizeof l3, "longest run %d", q.longestRun);
  fSet(F_SMALL);
  spr.setTextColor(q.ok ? C_GREEN : C_AMBER); spr.drawString(l1, 118, 50);
  spr.setTextColor(C_MUTED); spr.drawString(l2, 118, 62); spr.drawString(l3, 118, 74);
  fEnd();
  if(pages > 1){
    char ps[24]; snprintf(ps, sizeof ps, "rolls %d-%d", page*50 + 1, (page*50 + 50 < target) ? page*50 + 50 : target);
    fSet(F_SMALL); spr.setTextColor(C_DIM); spr.drawString(ps, 16, 95); fEnd();
  }
  diceDrawGrid(page * DICE_GRID_ROWS, target, false);
  // On a failed check the hash is meaningless anyway: its line carries the
  // instruction instead (the row below it was off the bottom of the panel).
  if(q.ok) diceDrawHash(216, C_GREEN);
  else { fSet(F_BODY); spr.setTextColor(C_AMBER); fDrawCentre("BACK to start over with real dice", 120, 216); fEnd(); }
  dispPush();
}

// Review + quality gate. Returns true to accept, false to start over / undo.
static bool diceRollReview(int target){
  DiceQuality q = diceQuality();
  int pages = (target + 49) / 50, page = 0;
  diceReviewDraw(page, pages, target, q);
  delay(250);
  clearButtonPending();
  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    if(pages > 1 && btn1.isPressed()){ page = (page + 1) % pages; diceReviewDraw(page, pages, target, q); }
    else if(pages > 1 && btn3.isPressed()){ page = (page + pages - 1) % pages; diceReviewDraw(page, pages, target, q); }
    else if(btn2.isPressed()){ if(q.ok) return true; buzzerFail(); }
    else if(btn4.isPressed()){
      if(!q.ok){ g_diceRollCount = 0; }         // start over: nothing kept
      else       { g_diceRollCount--; }         // undo the last roll and keep going
      return false;
    }
    esp_task_wdt_reset(); delay(5);
  }
}

static void diceRollFinish(){
  diceRollHash(g_diceEntropy);
  g_diceRollValid = true;
  mbedtls_platform_zeroize(g_diceRollBuf, sizeof(g_diceRollBuf));   // raw rolls no longer needed
}

static void runDiceRoll(int target){
  int value = 1;
  g_diceRollCount = 0;
  g_diceRollValid = false;
  if(target < 1) target = DICE_ROLL_MIN_24;
  if(target > DICE_ROLL_MAX) target = DICE_ROLL_MAX;
  diceRollDraw(value, target);
  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    if(btn1.isPressed()){ value = (value % 6) + 1; diceRollDraw(value, target); }
    else if(btn3.isPressed()){ value = ((value + 4) % 6) + 1; diceRollDraw(value, target); }
    else if(btn2.isPressed()){
      if(g_diceRollCount < DICE_ROLL_MAX){
        g_diceRollBuf[g_diceRollCount++] = (uint8_t)value;
        buzzerOK();
        if(g_diceRollCount >= target){
          if(diceRollReview(target)){ diceRollFinish(); return; }
          diceRollDraw(value, target);           // undo or start over: back to rolling
          continue;
        }
        diceRollDraw(value, target);
      }
    }
    else if(btn4.isPressed()){
      if(g_diceRollCount > 0){ g_diceRollCount--; diceRollDraw(value, target); }
      else { g_diceRollValid = false; break; }
    }
    esp_task_wdt_reset();
    delay(5);
  }
}

#endif // FAVILLA_DICE_ROLL_H
