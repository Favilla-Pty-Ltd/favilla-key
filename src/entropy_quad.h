// ─────────────────────────────────────────────────────────────────────────────
// entropy_quad.h — the quadrant seed ceremony  (Favilla KEY)
//
// Settings > Device > Quadrant seed.
//
// Four 8x8 quadrants, one per source, colour-coded. The DEVICE deals each block;
// the user chooses only WHERE it lands. When the board is full it is hashed —
//
//     entropy = SHA-256(board)
//
// — with no domain tag and no device secret, so the owner can reproduce it off
// -device from the 32 bytes shown on screen. The picture IS the pre-image. This
// is the dice path's verifiability applied to the hardware sources.
//
//   ┌─ WHY THE DEVICE DEALS ────────────────────────────────────────────────┐
//   │ If the user could see a block before deciding whether to keep it, the  │
//   │ choice itself becomes a channel: rejecting candidates until one looks  │
//   │ "right" is selection, and selection removes entropy. One rejection per │
//   │ deal costs ~5.6 bits; sixteen deals with free rejection would cost     │
//   │ ~90 bits of a 256-cell board. So: freeze on press, place blind, reveal │
//   │ after. Placement is free choice over 24 orderings and leaks nothing.   │
//   │                                                                        │
//   │ Backing out after a reveal wipes the WHOLE board, not one block, for   │
//   │ the same reason. A user who restarts N times still loses log2(N) bits; │
//   │ that is unavoidable and is true of dice too.                           │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ 256 CELLS ARE NOT 256 BITS ──────────────────────────────────────────┐
//   │ Measured on this hardware (n=1 unit, one temperature — see the entropy │
//   │ study): SE051 64, camera ~59 lit but ~5 dark, motion ~58, esp_fill_    │
//   │ random 0 by our own design because we do not budget it. A full board   │
//   │ is worth ~181 bits in good light and ~127 in the dark. The device      │
//   │ MEASURES the two noisy sources at deal time and shows the real number. │
//   │ Displaying "256 bits" here would be exactly the error the study is     │
//   │ about.                                                                 │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ NOT WIRED TO THE WALLET ─────────────────────────────────────────────┐
//   │ This page sets g_quadEntropy / g_quadValid and nothing consumes them.  │
//   │ Onboarding is untouched. Wiring it in is a separate, separately-       │
//   │ flashed change.                                                        │
//   └────────────────────────────────────────────────────────────────────────┘
//
// CONTROLS: btn1 next quadrant · btn3 previous quadrant · btn2 ENTER · btn4 BACK
// NOTE: Button::isPressed() CLEARS the pending flag. Read each button ONCE per
// loop into a local — calling it twice in one iteration swallows the press.
//
// Include ONCE alongside dice_roll.h, AFTER the colours, display, buttons,
// camera, showQR and the global BMA400 `accel`.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_ENTROPY_QUAD_H
#define FAVILLA_ENTROPY_QUAD_H

#ifndef C_GREEN
#error "entropy_quad.h must be #included AFTER the C_* colours, display, buttons, camera, showQR and the global BMA400 'accel'."
#endif

#include <math.h>
#include "quad_entropy.h"                  // the pure, KAT-tested construction

// ── geometry ────────────────────────────────────────────────────────────────
#define QG_PX   10                          // cell pitch, px
#define QG_X0   40                          // (240 - 16*10) / 2
#define QG_Y0   44
#define QG_W    (QUAD_N * QG_PX)            // 160

// ── sources ─────────────────────────────────────────────────────────────────
enum { QS_SE = 0, QS_CAM = 1, QS_ESP = 2, QS_ACC = 3, QS_N = 4 };
static const char* const QS_NAME[QS_N] = { "SE051", "Camera", "ESP32", "Motion" };

// Deal order is fixed and shown ahead of each deal, so the user always knows
// which source is coming — they choose the quadrant, never the bits.
static const uint8_t QS_ORDER[QUAD_COUNT] = { QS_SE, QS_CAM, QS_ESP, QS_ACC };

static inline uint16_t qsCol(int s){
  switch(s){
    case QS_SE:  return C_CYAN;
    case QS_CAM: return C_AMBER;
    case QS_ESP: return C_BLUE;
    default:     return C_GREEN;
  }
}
// RGB565 half / quarter brightness — mask each channel's LSB before shifting.
static inline uint16_t qHalf(uint16_t c){ return (uint16_t)((c & 0xF7DEu) >> 1); }
static inline uint16_t qQuarter(uint16_t c){ return qHalf(qHalf(c)); }

// ── liveness thresholds ─────────────────────────────────────────────────────
// Camera: measured LSB frame-to-frame agreement is 0.529 lit (47% of sampled
// pixels change) and 0.943 dark (5.7%). 25% is comfortably between the two and
// is the number shown on screen next to the live figure.
#define QCAM_MIN_CHANGE   0.25f
#define QCAM_EST          1024              // pixels sampled for the estimate
#define QCAM_MAX_FRAMES   48                // settle cap (the transient is not a constant)
#define QCAM_MIN_FRAMES   8
// Motion: at rest the per-axis LSB min-entropy measured 0.85-1.00 bits. 0.5 is
// a floor for "this sensor is producing noise at all", not a quality bar.
#define QACC_MIN_H        0.5f
#define QACC_NEED         256               // distinct samples for the estimate
#define QACC_TIMEOUT_MS   5000

// ── state ───────────────────────────────────────────────────────────────────
static uint8_t qBoard[QUAD_BYTES];
static uint8_t qCov[QUAD_BYTES];
static uint8_t qBlk[QUAD_BLKB];             // the dealt-but-unplaced block
static uint8_t qQuadSrc[QUAD_COUNT];        // 0xFF = empty
static int     qBits10[QS_N];               // honest bits x10, per source
static int     qCamChange10 = 0;            // measured % of pixels changing x10
static int     qCamFrames   = 0;            // frames discarded before settling

// Set on completion so onboarding could consume it later. Nothing reads these.
static uint8_t g_quadEntropy[32];
static bool    g_quadValid = false;

static uint8_t qCamA[QCAM_EST];             // file-scope: keeps the page off the stack
static uint8_t qAccLsb[3][QACC_NEED];

// ── min-entropy of a biased bit, from a probability ─────────────────────────
// H = -log2(max(p, 1-p)). This is the same most-common-value estimate used
// throughout the study, so the on-screen number and the paper agree.
static float qMinEnt(float p){
  float pm = (p > 0.5f) ? p : (1.0f - p);
  if(pm >= 0.9999f) return 0.0f;
  if(pm <= 0.5f)    return 1.0f;
  return -log2f(pm);
}
static inline int qBits10From(float hPerBit){
  float b = hPerBit * (float)QUAD_BITS * 10.0f;
  if(b < 0.0f) b = 0.0f;
  return (int)(b + 0.5f);
}

// ── source deals ────────────────────────────────────────────────────────────
// Each returns true and fills blk[8] + bits10, or false with *why naming the
// source and the failure. A refused deal reveals no bits, so retrying it is
// free — unlike backing out after a reveal.

static bool qDealSE(uint8_t blk[QUAD_BLKB], int* bits10, const char** why){
  if(!favilla::se_random(blk, QUAD_BLKB)){ *why = "SE051 TRNG did not respond"; return false; }
  int allZero = 1, allOne = 1;
  for(int i = 0; i < QUAD_BLKB; i++){
    if(blk[i] != 0x00) allZero = 0;
    if(blk[i] != 0xFF) allOne  = 0;
  }
  if(allZero || allOne){ *why = "SE051 returned a constant block"; return false; }
  // 64 bits asserted, not measured: a certified TRNG's output cannot be
  // validated from 8 bytes, and on this path it is also not verifiable. See
  // the study, §5 — this is the honest cost of using a secure element here.
  *bits10 = QUAD_BITS * 10;
  return true;
}

static bool qDealESP(uint8_t blk[QUAD_BLKB], int* bits10, const char** why){
  (void)why;
  esp_fill_random(blk, QUAD_BLKB);
  // Zero by design. esp_fill_random is unbudgeted in every Favilla entropy
  // path: the radios are off during seed generation, so it is in its degraded
  // state, and no test we can run on-device would detect a reduced seeding
  // space. It is margin, not budget. Shown as 0 so the screen does not lie.
  *bits10 = 0;
  return true;
}

// Camera: settle, then two frames. Bits come from strided LSBs across the whole
// sensor — never a contiguous 8x8 patch, because adjacent LSBs agree 0.545
// horizontally and 0.563 vertically, so a patch would be visibly correlated.
static bool qDealCam(uint8_t blk[QUAD_BLKB], int* bits10, const char** why){
  pwrBoost();
  cameraStart();

  // Discard the warm-up transient. It does NOT reproduce across boots (three
  // captures gave three shapes, two of them anti-correlated at -0.71), so a
  // fixed "discard 34 frames" is fitted to one case. Settle on the actual
  // frame mean instead, with a hard cap.
  float prevMean = -1.0f; int stable = 0; qCamFrames = 0;
  while(qCamFrames < QCAM_MAX_FRAMES){
    camera_fb_t* fb = esp_camera_fb_get();
    if(!fb){ cameraStop(); pwrIdle(); *why = "Camera not responding"; return false; }
    if(fb->len < 4096){ esp_camera_fb_return(fb); cameraStop(); pwrIdle();
                        *why = "Camera frame too small"; return false; }
    size_t st = fb->len / QCAM_EST;
    uint32_t sum = 0;
    for(int i = 0; i < QCAM_EST; i++) sum += fb->buf[i * st];
    float m = (float)sum / (float)QCAM_EST;
    esp_camera_fb_return(fb);
    qCamFrames++;
    if(prevMean >= 0.0f && fabsf(m - prevMean) < 0.5f) stable++; else stable = 0;
    prevMean = m;
    if(qCamFrames >= QCAM_MIN_FRAMES && stable >= 3) break;
    esp_task_wdt_reset(); delay(5);
  }

  // Frame A: keep the sampled LSBs.
  camera_fb_t* fa = esp_camera_fb_get();
  if(!fa){ cameraStop(); pwrIdle(); *why = "Camera stopped producing"; return false; }
  size_t stE = fa->len / QCAM_EST;
  for(int i = 0; i < QCAM_EST; i++) qCamA[i] = (uint8_t)(fa->buf[i * stE] & 1);
  esp_camera_fb_return(fa);
  esp_task_wdt_reset(); delay(5);

  // Frame B: agreement against A, and the block bits.
  camera_fb_t* fbb = esp_camera_fb_get();
  if(!fbb){ cameraStop(); pwrIdle(); *why = "Camera stopped producing"; return false; }
  uint32_t agree = 0;
  size_t stE2 = fbb->len / QCAM_EST;
  for(int i = 0; i < QCAM_EST; i++)
    if(((fbb->buf[i * stE2]) & 1) == qCamA[i]) agree++;
  size_t stB = fbb->len / QUAD_BITS;                  // ~1200 px apart at QVGA
  memset(blk, 0, QUAD_BLKB);
  for(int i = 0; i < QUAD_BITS; i++)
    if(fbb->buf[i * stB] & 1) blk[i >> 3] |= (uint8_t)(1u << (7 - (i & 7)));
  esp_camera_fb_return(fbb);

  cameraStop(); pwrIdle();

  float p = (float)agree / (float)QCAM_EST;           // agreement
  float change = 1.0f - p;
  qCamChange10 = (int)(change * 1000.0f + 0.5f);
  if(change < QCAM_MIN_CHANGE){
    memset(blk, 0, QUAD_BLKB);
    *why = "Camera too dark - uncover the lens";
    return false;
  }
  *bits10 = qBits10From(qMinEnt(p));
  return true;
}

// Motion: dedup first. Free-polling reads the BMA400 ~4.4x faster than its
// 200 Hz ODR, so 77% of raw reads are exact repeats of the previous one. Taking
// them at face value overstates the bit count 5.7x. Only samples that differ
// from the immediately preceding triple are used.
static bool qDealAcc(uint8_t blk[QUAD_BLKB], int* bits10, const char** why){
  accel.wakeMode();
  int n = 0, fails = 0;
  int16_t px = 0, py = 0, pz = 0; bool first = true;
  uint32_t t0 = millis();
  while(n < QACC_NEED && (millis() - t0) < QACC_TIMEOUT_MS){
    int16_t x, y, z;
    if(!accel.read(x, y, z)){
      if(++fails > 32){ *why = "Motion sensor did not respond"; return false; }
      esp_task_wdt_reset(); delay(2); continue;
    }
    fails = 0;
    if(!first && x == px && y == py && z == pz){ esp_task_wdt_reset(); delay(1); continue; }
    first = false; px = x; py = y; pz = z;
    qAccLsb[0][n] = (uint8_t)(x & 1);
    qAccLsb[1][n] = (uint8_t)(y & 1);
    qAccLsb[2][n] = (uint8_t)(z & 1);
    n++;
    esp_task_wdt_reset();
  }
  if(n < 32){ *why = "Motion sensor not producing"; return false; }

  float hSum = 0.0f;
  for(int a = 0; a < 3; a++){
    uint32_t ones = 0;
    for(int i = 0; i < n; i++) ones += qAccLsb[a][i];
    hSum += qMinEnt((float)ones / (float)n);
  }
  float hMean = hSum / 3.0f;
  if(hMean < QACC_MIN_H){
    memset(blk, 0, QUAD_BLKB);
    *why = "Motion output too regular";
    return false;
  }

  memset(blk, 0, QUAD_BLKB);
  int bi = 0;
  for(int s = 0; s < n && bi < QUAD_BITS; s++)
    for(int a = 0; a < 3 && bi < QUAD_BITS; a++){
      if(qAccLsb[a][s]) blk[bi >> 3] |= (uint8_t)(1u << (7 - (bi & 7)));
      bi++;
    }
  mbedtls_platform_zeroize(qAccLsb, sizeof(qAccLsb));
  *bits10 = qBits10From(hMean);
  return true;
}

static bool qDeal(int src, uint8_t blk[QUAD_BLKB], int* bits10, const char** why){
  switch(src){
    case QS_SE:  return qDealSE(blk, bits10, why);
    case QS_CAM: return qDealCam(blk, bits10, why);
    case QS_ESP: return qDealESP(blk, bits10, why);
    default:     return qDealAcc(blk, bits10, why);
  }
}

// ── drawing ─────────────────────────────────────────────────────────────────
static void qDrawCell(int r, int c, uint16_t col){
  spr.fillRect(QG_X0 + c * QG_PX + 1, QG_Y0 + r * QG_PX + 1, QG_PX - 2, QG_PX - 2, col);
}

// carrySrc >= 0 means a block is dealt and face-down on quadrant `cursor`.
static void qDrawBoard(int cursor, int carrySrc){
  for(int q = 0; q < QUAD_COUNT; q++){
    int r0, c0; quadOrigin(q, &r0, &c0);
    if(qQuadSrc[q] != 0xFF){                                  // placed and revealed
      uint16_t on = qsCol(qQuadSrc[q]), off = qQuarter(on);
      for(int r = 0; r < QUAD_SIDE; r++)
        for(int c = 0; c < QUAD_SIDE; c++)
          qDrawCell(r0 + r, c0 + c,
                    quadGet(qBoard, (r0 + r) * QUAD_N + (c0 + c)) ? on : off);
    } else if(carrySrc >= 0 && q == cursor){                   // face-down
      uint16_t col = qsCol(carrySrc);
      for(int r = 0; r < QUAD_SIDE; r++)
        for(int c = 0; c < QUAD_SIDE; c++)
          qDrawCell(r0 + r, c0 + c, ((r + c) & 1) ? qQuarter(col) : qHalf(col));
      fSet(F_HEAD); spr.setTextColor(col);
      fDrawCentre("?", QG_X0 + (c0 + 4) * QG_PX, QG_Y0 + (r0 + 3) * QG_PX + 2); fEnd();
    } else {                                                   // empty
      for(int r = 0; r < QUAD_SIDE; r++)
        for(int c = 0; c < QUAD_SIDE; c++)
          spr.fillRect(QG_X0 + (c0 + c) * QG_PX + QG_PX/2 - 1,
                       QG_Y0 + (r0 + r) * QG_PX + QG_PX/2 - 1, 2, 2, C_VDIM);
      if(q == cursor)
        spr.drawRect(QG_X0 + c0 * QG_PX, QG_Y0 + r0 * QG_PX,
                     QUAD_SIDE * QG_PX, QUAD_SIDE * QG_PX, C_DIM);
    }
  }
  // quadrant divider — makes the four-way split legible even when full
  spr.drawFastVLine(QG_X0 + QUAD_SIDE * QG_PX - 1, QG_Y0, QG_W, C_BORDER2);
  spr.drawFastHLine(QG_X0, QG_Y0 + QUAD_SIDE * QG_PX - 1, QG_W, C_BORDER2);
}

static void qFoot(const char* s, uint16_t col, int y){
  fSet(F_SMALL); spr.setTextColor(col); fDrawCentre(s, 120, y); fEnd();
}

static void qDrawPage(int cursor, int carrySrc, const char* prompt, uint16_t promptCol){
  spr.fillSprite(C_BG);
  uiHeader("Quadrant seed", C_GREEN);
  qDrawBoard(cursor, carrySrc);
  char s[48];
  snprintf(s, sizeof s, "%d / 256 cells", quadCoverageCount(qCov));
  qFoot(s, C_DIM, 214);
  qFoot(prompt, promptCol, 232);
  dispPush();
}

static void qDrawBusy(const char* what){
  spr.fillSprite(C_BG);
  uiHeader("Quadrant seed", C_GREEN);
  fSet(F_HEAD); spr.setTextColor(C_AMBER); fDrawCentre(what, 120, 104); fEnd();
  qFoot("sampling - do not move", C_DIM, 140);
  dispPush();
}

static void qDrawFail(const char* src, const char* why){
  spr.fillSprite(C_BG);
  uiHeader("Source refused", C_RED);
  fSet(F_HEAD); spr.setTextColor(C_RED);  fDrawCentre(src, 120, 92);  fEnd();
  fSet(F_SMALL); spr.setTextColor(C_TEXT2); fDrawCentre(why, 120, 122); fEnd();
  qFoot("nothing was dealt - no bits lost", C_VDIM, 196);
  qFoot("ENTER retry  ·  BACK abort", C_DIM, 232);
  dispPush();
}

// ── verify: the board bytes and the hash they produce ───────────────────────
static void qDrawVerify(const char* hex){
  spr.fillSprite(C_BG);
  uiHeader("Verify", C_GREEN);
  fSet(F_SMALL); spr.setTextColor(C_MUTED); fDrawCentre("BOARD - 32 bytes", 120, 46); fEnd();
  char line[17];
  for(int i = 0; i < 4; i++){
    memcpy(line, hex + i * 16, 16); line[16] = 0;
    fSet(F_MONO); spr.setTextColor(C_FG); fDrawCentre(line, 120, 64 + i * 18); fEnd();
  }
  fSet(F_SMALL); spr.setTextColor(C_MUTED); fDrawCentre("SHA-256 ->", 120, 146); fEnd();
  char h[17];
  static const char* H = "0123456789abcdef";
  for(int i = 0; i < 4; i++){
    for(int j = 0; j < 8; j++){            // 8 bytes = 16 chars per line
      uint8_t b = g_quadEntropy[i * 8 + j];
      h[j * 2]     = H[(b >> 4) & 0xF];
      h[j * 2 + 1] = H[b & 0xF];
    }
    h[16] = 0;
    fSet(F_MONO); spr.setTextColor(C_GREEN); fDrawCentre(h, 120, 164 + i * 16); fEnd();
  }
  qFoot("btn1 QR  ·  ENTER continue", C_DIM, 232);
  dispPush();
}

// ── the honest bit count, per source ────────────────────────────────────────
static void qDrawBits(){
  spr.fillSprite(C_BG);
  uiHeader("Honest bits", C_AMBER);
  int total = 0;
  for(int i = 0; i < QS_N; i++) total += qBits10[i];
  static const char* NOTE[QS_N] = { "asserted", "measured", "unbudgeted", "measured" };
  for(int i = 0; i < QS_N; i++){
    int y = 52 + i * 26;
    fSet(F_BODY); spr.setTextColor(qsCol(i)); spr.drawString(QS_NAME[i], 22, y); fEnd();
    char v[16]; snprintf(v, sizeof v, "%d.%d", qBits10[i] / 10, qBits10[i] % 10);
    fSet(F_MONO); spr.setTextColor(C_FG); fDrawRight(v, 168, y + 2); fEnd();
    fSet(F_SMALL); spr.setTextColor(C_VDIM); spr.drawString(NOTE[i], 176, y + 3); fEnd();
  }
  spr.drawFastHLine(22, 158, 196, C_BORDER2);
  fSet(F_BODY); spr.setTextColor(C_AMBER); spr.drawString("Total", 22, 168); fEnd();
  char t[24]; snprintf(t, sizeof t, "%d.%d", total / 10, total % 10);
  fSet(F_MONO); spr.setTextColor(C_AMBER); fDrawRight(t, 168, 170); fEnd();
  fSet(F_SMALL); spr.setTextColor(C_VDIM); spr.drawString("of 256 cells", 176, 171); fEnd();
  char c[56];
  snprintf(c, sizeof c, "camera %d.%d%% changed  ·  min %d%%",
           qCamChange10 / 10, qCamChange10 % 10, (int)(QCAM_MIN_CHANGE * 100.0f));
  qFoot(c, C_MUTED, 200);
  qFoot("cells are not bits  ·  ENTER done", C_DIM, 232);
  dispPush();
}

// Next empty quadrant, searching in direction d. BOUNDED: returns the current
// cursor if none is free, rather than spinning forever on a full board.
static int qNextEmpty(const uint8_t src[QUAD_COUNT], int cursor, int d){
  for(int k = 0; k < QUAD_COUNT; k++){
    cursor = (cursor + d + QUAD_COUNT) % QUAD_COUNT;
    if(src[cursor] == 0xFF) return cursor;
  }
  return cursor;
}

// Backing out after any block has been revealed discards the whole board.
// Returns true if the user confirmed.
static bool qConfirmDiscard(){
  spr.fillSprite(C_BG);
  uiHeader("Discard board?", C_RED);
  fSet(F_SMALL); spr.setTextColor(C_TEXT2);
  fDrawCentre("Starting over throws away every", 120, 92);
  fDrawCentre("block placed, not just this one.", 120, 112);
  fDrawCentre("Each restart also costs a little", 120, 140);
  fDrawCentre("of the board's unpredictability.", 120, 160);
  fEnd();
  qFoot("BACK confirm  ·  ENTER keep going", C_DIM, 232);
  dispPush();
  while(true){
    btn2.poll(); btn4.poll();
    bool keep = btn2.isPressed(), go = btn4.isPressed();
    if(go)   return true;
    if(keep) return false;
    esp_task_wdt_reset(); delay(5);
  }
}

// ── the page (blocking, like the other Settings pages) ──────────────────────
enum { QP_INTRO = 0, QP_READY, QP_CARRY, QP_FAIL, QP_DONE, QP_VERIFY, QP_BITS };

static void runEntropyQuad(){
  int page = QP_INTRO, step = 0, cursor = 0;
  const char* failWhy = "";
  char hex[QUAD_BYTES * 2 + 1];

  memset(qBoard, 0, sizeof qBoard);
  memset(qCov,   0, sizeof qCov);
  memset(qBlk,   0, sizeof qBlk);
  memset(qQuadSrc, 0xFF, sizeof qQuadSrc);
  for(int i = 0; i < QS_N; i++) qBits10[i] = 0;
  qCamChange10 = 0; qCamFrames = 0;
  g_quadValid = false;
  mbedtls_platform_zeroize(g_quadEntropy, sizeof g_quadEntropy);

  // intro
  spr.fillSprite(C_BG);
  uiHeader("Quadrant seed", C_GREEN);
  fSet(F_SMALL); spr.setTextColor(C_TEXT2);
  fDrawCentre("Four blocks, one per source.", 120, 70);
  fDrawCentre("The KEY deals each one face down;", 120, 90);
  fDrawCentre("you choose only where it lands.", 120, 110);
  fDrawCentre("The finished board is hashed -", 120, 138);
  fDrawCentre("check it yourself off-device.", 120, 158);
  fEnd();
  qFoot("preview only - not written to wallet", C_VDIM, 196);
  qFoot("ENTER begin  ·  BACK exit", C_DIM, 232);
  dispPush();

  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    // Read each button EXACTLY ONCE — isPressed() consumes the press.
    bool kNext = btn1.isPressed();
    bool kEnt  = btn2.isPressed();
    bool kPrev = btn3.isPressed();
    bool kBack = btn4.isPressed();

    if(page == QP_INTRO){
      if(kEnt){
        page = QP_READY; step = 0; cursor = 0;
        char p[40]; snprintf(p, sizeof p, "Next: %s  ·  ENTER deals", QS_NAME[QS_ORDER[0]]);
        qDrawPage(cursor, -1, p, qsCol(QS_ORDER[0]));
      } else if(kBack) break;
    }

    else if(page == QP_READY){
      if(kEnt){
        int src = QS_ORDER[step];
        qDrawBusy(QS_NAME[src]);
        int bits10 = 0;
        if(!qDeal(src, qBlk, &bits10, &failWhy)){
          page = QP_FAIL;
          qDrawFail(QS_NAME[src], failWhy);
        } else {
          qBits10[src] = bits10;
          cursor = (qQuadSrc[0] == 0xFF) ? 0 : qNextEmpty(qQuadSrc, 0, 1);
          page = QP_CARRY;
          qDrawPage(cursor, src, "scroll to place  ·  ENTER drops", qsCol(src));
        }
      } else if(kBack){
        if(step == 0) break;                       // nothing placed yet
        if(qConfirmDiscard()) break;
        char p[40]; snprintf(p, sizeof p, "Next: %s  ·  ENTER deals", QS_NAME[QS_ORDER[step]]);
        qDrawPage(-1, -1, p, qsCol(QS_ORDER[step]));
      }
    }

    else if(page == QP_CARRY){
      int src = QS_ORDER[step];
      if(kNext || kPrev){
        cursor = qNextEmpty(qQuadSrc, cursor, kNext ? 1 : -1);
        qDrawPage(cursor, src, "scroll to place  ·  ENTER drops", qsCol(src));
      } else if(kEnt){
        if(!quadPlaceBlock(qBoard, qCov, cursor, qBlk)){
          // structurally impossible with disjoint quadrants — but the gate is
          // the point, so fail closed rather than write a silent overlap.
          page = QP_FAIL; failWhy = "Cell collision - board rejected";
          qDrawFail(QS_NAME[src], failWhy);
        } else {
          qQuadSrc[cursor] = (uint8_t)src;
          mbedtls_platform_zeroize(qBlk, sizeof qBlk);
          buzzerOK();
          qDrawPage(cursor, -1, "placed", qsCol(src));
          delay(400);
          step++;
          if(step >= QUAD_COUNT){
            if(!quadCoverageFull(qCov)){
              page = QP_FAIL; failWhy = "Board not fully covered";
              qDrawFail("Coverage", failWhy);
            } else {
              quadEntropyFromBoard(qBoard, g_quadEntropy);
              g_quadValid = true;
              page = QP_DONE;
              qDrawPage(-1, -1, "256 / 256  ·  ENTER to verify", C_GREEN);
            }
          } else {
            page = QP_READY;
            char p[40]; snprintf(p, sizeof p, "Next: %s  ·  ENTER deals", QS_NAME[QS_ORDER[step]]);
            qDrawPage(-1, -1, p, qsCol(QS_ORDER[step]));
          }
        }
      } else if(kBack){
        // Backing out after a reveal discards EVERYTHING — see the header note.
        // The dealt block is discarded with it; it is never re-offered, so this
        // cannot be used to fish for a block the user likes the look of.
        if(qConfirmDiscard()) break;
        qDrawPage(cursor, src, "scroll to place  ·  ENTER drops", qsCol(src));
      }
    }

    else if(page == QP_FAIL){
      if(kEnt){
        page = QP_READY;
        char p[40]; snprintf(p, sizeof p, "Next: %s  ·  ENTER deals", QS_NAME[QS_ORDER[step]]);
        qDrawPage(-1, -1, p, qsCol(QS_ORDER[step]));
      } else if(kBack) break;
    }

    else if(page == QP_DONE){
      if(kEnt){ quadBoardHex(qBoard, hex); page = QP_VERIFY; qDrawVerify(hex); }
      else if(kBack) break;
    }

    else if(page == QP_VERIFY){
      if(kNext){
        quadBoardHex(qBoard, hex);
        showQR(hex, "Board bytes", "sha256 -> entropy");
        while(true){
          btn1.poll(); btn2.poll(); btn4.poll();
          if(btn1.isPressed() || btn2.isPressed() || btn4.isPressed()) break;
          esp_task_wdt_reset(); delay(5);
        }
        qDrawVerify(hex);
      } else if(kEnt){ page = QP_BITS; qDrawBits(); }
      else if(kBack){ page = QP_DONE; qDrawPage(-1, -1, "256 / 256  ·  ENTER to verify", C_GREEN); }
    }

    else if(page == QP_BITS){
      if(kEnt || kBack) break;
    }

    esp_task_wdt_reset();
    delay(5);
  }

  mbedtls_platform_zeroize(qBoard, sizeof qBoard);
  mbedtls_platform_zeroize(qBlk,   sizeof qBlk);
  mbedtls_platform_zeroize(qCamA,  sizeof qCamA);
  mbedtls_platform_zeroize(qAccLsb, sizeof qAccLsb);
  memset(qCov, 0, sizeof qCov);
  memset(qQuadSrc, 0xFF, sizeof qQuadSrc);
  // g_quadEntropy is left for a future onboarding caller; it is wiped on the
  // next entry. Nothing reads it today.
}

#endif // FAVILLA_ENTROPY_QUAD_H
