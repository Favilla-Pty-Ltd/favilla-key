// ─────────────────────────────────────────────────────────────────────────────
// entropy_overlay.h — the XOR overlay seed ceremony  (Favilla KEY)
//
// Settings > Device > Overlay seed.
//
// Two live 16x16 grids. The user watches the SE051 and freezes it; watches the
// camera (covering the lens to prove it is really being read) and freezes it;
// the board is the two XORed together, and
//
//     entropy = SHA-256(A XOR B)
//
// Every value is shown as hex. A person with no tools can check the XOR cell by
// cell on screen, and a person with a shell can reproduce the whole thing.
//
//   ┌─ WHY THIS IS NOT A "VERIFY MODE" ─────────────────────────────────────┐
//   │ This is the SAME function real onboarding must call. There is no demo  │
//   │ flag, no test path, no branch that behaves differently when nobody is  │
//   │ checking. If auditing lived in its own menu item, backdoored firmware  │
//   │ would simply behave honestly there and dishonestly in the real path —  │
//   │ a defeat device. So the hex is ALWAYS shown and the user is free to    │
//   │ ignore it. Do not add a "skip verification" fast path.                 │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ WHAT THE XOR ACTUALLY BUYS ──────────────────────────────────────────┐
//   │ The SE051 is on I2C and never sees a camera frame; the camera never    │
//   │ sees the SE051's output. Neither vendor can cancel the other, so a     │
//   │ backdoor in EITHER part alone still leaves the board unpredictable to  │
//   │ that vendor. That is the claim, and it is defensible.                  │
//   │                                                                        │
//   │ It says nothing about the integrator. This ESP32 reads both layers and │
//   │ does the XOR, so compromised firmware picks B = A XOR target and every │
//   │ check on this screen still passes. Reproducible builds and secure boot │
//   │ are what address that. Dice is what addresses it for someone who       │
//   │ trusts neither.                                                        │
//   └────────────────────────────────────────────────────────────────────────┘
//
// CONTROLS: btn1 right / next · btn3 up / previous · btn2 ENTER · btn4 BACK
// NOTE: Button::isPressed() CLEARS the pending flag. Read each button ONCE per
// loop into a local — calling it twice in one iteration swallows the press.
//
// Include ONCE after the colours, display, buttons, camera, showQR.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_ENTROPY_OVERLAY_H
#define FAVILLA_ENTROPY_OVERLAY_H

#ifndef C_GREEN
#error "entropy_overlay.h must be #included AFTER the C_* colours, display, buttons, camera and showQR."
#endif

#include <math.h>
#include "overlay_entropy.h"          // the pure, KAT-tested construction

// Bigger grid, no header bar, ONE line of text. The old page carried a 28px
// header strip, a 160px grid and TWO stacked lines — four bands of information
// on a 240px screen, none of them dominant. The grid IS the page; everything
// else is a caption.
#define OV_PX   11                    // cell pitch, px (was 10)
#define OV_X0   32                    // (240 - 16*11) / 2
#define OV_Y0   32
#define OV_W    (OVL_N * OV_PX)

// PARITY WHITENING — see entropy_restart.h for the full reasoning. One pixel's
// LSB carries that pixel's permanent DC bias (a per-die fingerprint, the same
// physics as PRNU), which is static and therefore contributes structure rather
// than randomness. Each cell is the XOR of OV_WHITEN_K pixels taken OVL_CELLS
// apart, so the contributors are ~19,000 pixels from each other.
#define OV_WHITEN_K       4
// Rolling window for the live bit estimate. The old code accumulated agreement
// from the moment the page opened and never reset, so it was a CUMULATIVE
// average — cover the lens after 30 s and the number barely moved. It also
// estimated on a different pixel set (1024 at one stride) from the one the
// cells came from (256 at another), so it described a population the frozen
// layer was not drawn from. Both fixed: the estimate is now over the SAME
// whitened cells, across the last OV_CAM_WIN frames only.
//   24 frames x 256 cells = 6,144 comparisons -> SE on p ~= 0.0064, about
//   +/- 2 bits over 256, and it flushes in ~2.6 s so covering the lens shows.
#define OV_CAM_WIN        24
#define OV_CAM_EST        1024        // pixels sampled per frame for the SETTLE test
#define OV_CAM_MIN_CHANGE 0.25f       // advisory only — see the note at ovComposeOk
#define OV_CAM_MAX_FRAMES 48
#define OV_CAM_MIN_FRAMES 8
#define OV_MIN_BITS       128         // hard floor: refuse to compose below this

// The camera layer is what protects the board if the SE051 is backdoored, so
// its gain is a SECURITY parameter, not an image-quality one. Measured on this
// hardware 5 Aug 2026, lens covered: at the shipping baseline (agc_gain 0,
// aec_value 40) the dark frame mean is 0.07 counts — below one LSB — and the
// layer carries ~21 bits over 256 cells. At gain 16 / aec 300 the mean is 3.2
// counts and the layer carries ~243. Same sensor, same darkness, 12x the
// entropy, entirely from two register writes.
// AUTO-TUNE. There is no fixed (gain, aec) that works in both light and dark:
// pixels pinned at either rail cannot change, so the LSBs freeze. Measured on
// hardware 5 Aug 2026 — gain 0/aec 40 gives 22 bits in the dark (floored at 0)
// and 235 lit; gain 16/aec 300 gives 254 in the dark and 6 lit (saturated at
// 255). The layer only works when pixels sit off both rails.
//
// So the exposure is chosen at capture time by measuring the thing that
// actually matters — the fraction of cells that CHANGE between frames — and
// walking up a sensitivity ladder until it is high enough. Bright rooms stop at
// the first rung; a covered lens walks to the top. Roughly 1-3 s.
//
// The measurement tool (entropy_restart.h) deliberately does NOT do this: a
// dataset needs a fixed, stated operating point or the numbers are not
// comparable. Auto-tune belongs in the ceremony, not in the lab instrument.
static const struct { int gain; int aec; } OV_TUNE[] = {
  {  0,   40 },   // bright room
  {  0,  150 },
  {  4,  300 },
  {  8,  300 },
  { 16,  300 },   // covered lens / very dark
  { 30,  600 },
};
#define OV_TUNE_N     ((int)(sizeof(OV_TUNE)/sizeof(OV_TUNE[0])))
#define OV_TUNE_GOOD  0.40f   // change fraction that is "good enough" — stop here
#define OV_TUNE_FRAMES 6      // frames per rung: 5 pairs x 256 cells = 1280 samples
// The tune runs ONCE, at the start of the camera step, and is then held. That is
// deliberate. A tracking exposure would silently keep the bit count high however
// the light changed, and the user would learn nothing; a fixed one means moving
// the device between light and dark visibly moves the bar. Seeing the sensor
// respond IS the point of the ceremony.
//
// The safety net is therefore not "keep it high automatically" but "refuse to
// capture it low" — see OV_CAM_PASS_BITS below.

#define OV_CAM_GAIN       16
#define OV_CAM_AEC        300
// Pass line for the camera layer ALONE. Below this, the board is carried by the
// SE051 and a compromised secure element would not be caught by anything on
// screen. Above it, the camera alone clears secp256k1's own 128-bit ceiling.
#define OV_CAM_PASS_BITS  128

// Layer colours match the grids on favillakey.io/verify/seed exactly, so the
// device and the web verifier are read as the same three things. Converted
// from the site's hex to RGB565: green #80CC00 is already C_GREEN, the other
// two have no equivalent in the device palette so they are pinned here.
static const uint16_t OV_COL_SE  = C_GREEN;   // #80CC00  A - SE051
static const uint16_t OV_COL_CAM = 0xE3E5;    // #e07d2a  B - camera
static const uint16_t OV_COL_BRD = 0xCD49;    // #c9a84c  board
// Frozen is shown in white rather than amber: amber sits too close to the
// camera's orange to read as a state change on that screen.
#define OV_COL_HELD  C_FG

static inline uint16_t ovHalf(uint16_t c){ return (uint16_t)((c & 0xF7DEu) >> 1); }
static inline uint16_t ovQuarter(uint16_t c){ return ovHalf(ovHalf(c)); }

// ── state ───────────────────────────────────────────────────────────────────
static uint8_t ovA[OVL_BYTES];        // SE051 layer
static uint8_t ovB[OVL_BYTES];        // camera layer
static uint8_t ovBoard[OVL_BYTES];
static uint8_t ovLive[OVL_BYTES];     // whichever layer is currently animating
static bool    ovCamPrevOk = false;
static bool    ovCamUp     = false;
static bool    ovSeDead    = false;
static uint16_t ovAgrRing[OV_CAM_WIN];            // per-frame cell agreement counts
static uint8_t  ovRingN = 0, ovRingI = 0;
static uint8_t  ovPrevCells[OVL_BYTES];
static bool     ovPrevOk = false;
static int      ovCamHeldBits10 = -1;             // snapshot taken AT freeze
static int      ovGain = OV_CAM_GAIN, ovAec = OV_CAM_AEC;  // chosen by ovAutoTune()
static float    ovLastMean = -1.0f;              // liveness: is light arriving
static int     ovSeBits10 = 0, ovCamBits10 = 0;
static int     ovFrames   = 0;                    // successful refreshes on this layer

// A layer cannot be frozen until it has actually been sampled. Without this a
// fast ENTER captures the initialised buffer — all zeros — which looks like a
// legitimate grid, XORs in as a constant, and silently costs the user that
// whole layer. The camera minimum is higher because its honest bit count comes
// from frame-to-frame agreement, which needs several frames to mean anything.
#define OV_MIN_SE_FRAMES   2
#define OV_MIN_CAM_FRAMES  8

// Set on completion. Onboarding consumes THIS, by calling runEntropyOverlay()
// directly — never a copy or a variant of it.
static uint8_t g_ovlEntropy[32];
static bool    g_ovlValid = false;

// Agreement over the last OV_CAM_WIN frames, on the cells themselves.
// Returns -1 until there is enough history to say anything.
static float ovCamAgreement(){
  if(ovRingN == 0) return -1.0f;
  uint32_t ag = 0;
  for(int i = 0; i < ovRingN; i++) ag += ovAgrRing[i];
  return (float)ag / ((float)ovRingN * (float)OVL_CELLS);
}

static float ovMinEnt(float p){
  float pm = (p > 0.5f) ? p : (1.0f - p);
  if(pm >= 0.9999f) return 0.0f;
  if(pm <= 0.5f)    return 1.0f;
  return -log2f(pm);
}
static inline int ovBits10(float perBit){
  float b = perBit * (float)OVL_CELLS * 10.0f;
  if(b < 0.0f) b = 0.0f;
  return (int)(b + 0.5f);
}

// ── SE051 layer: a fresh 32-byte draw per refresh ──────────────────────────
static void ovRefreshSE(){
  uint8_t buf[OVL_BYTES];
  if(favilla::se_random(buf, sizeof buf)){
    memcpy(ovLive, buf, sizeof buf);
    ovSeDead = false;
  } else {
    ovSeDead = true;
  }
  mbedtls_platform_zeroize(buf, sizeof buf);
}

// ── camera layer ────────────────────────────────────────────────────────────
// Grid cells are strided across the whole sensor — never a contiguous patch,
// because adjacent LSBs agree 0.545 horizontally and 0.563 vertically, so a
// patch would be visibly correlated. A separate, larger sample drives the
// frame-to-frame agreement estimate that becomes the honest bit count.
static bool ovRefreshCam(){
  camera_fb_t* fb = esp_camera_fb_get();
  if(!fb) return false;
  if(fb->len != (size_t)fb->width * (size_t)fb->height){
    // A TORN frame is still thousands of bytes, so a size floor lets it through
    // and the stride then samples shifted pixels. Demand the exact size.
    esp_camera_fb_return(fb); return false;
  }

  // Frame mean — the LIGHT signal, kept separate from the BIT signal. Two
  // different questions; one number was accidentally answering both.
  {
    size_t se = fb->len / 1024; uint32_t sum = 0;
    for(int i = 0; i < 1024; i++) sum += fb->buf[i * se];
    ovLastMean = (float)sum / 1024.0f;
  }

  // Whitened cells: each is the XOR of OV_WHITEN_K pixels OVL_CELLS apart.
  size_t st = fb->len / ((size_t)OVL_CELLS * OV_WHITEN_K);
  for(int i = 0; i < OVL_CELLS; i++){
    int bit = 0;
    for(int j = 0; j < OV_WHITEN_K; j++)
      bit ^= fb->buf[((size_t)i + (size_t)j * OVL_CELLS) * st] & 1;
    ovlSet(ovLive, i, bit);
  }
  esp_camera_fb_return(fb);

  // Rate estimate on the SAME cells, over a rolling window.
  if(ovPrevOk){
    uint16_t ag = 0;
    for(int i = 0; i < OVL_CELLS; i++)
      if(ovlGet(ovLive, i) == ovlGet(ovPrevCells, i)) ag++;
    ovAgrRing[ovRingI] = ag;
    ovRingI = (uint8_t)((ovRingI + 1) % OV_CAM_WIN);
    if(ovRingN < OV_CAM_WIN) ovRingN++;
  }
  memcpy(ovPrevCells, ovLive, OVL_BYTES);
  ovPrevOk = true;
  return true;
}

// Discard the warm-up transient. It does NOT reproduce across boots — three
// captures gave three shapes, two of them anti-correlated at -0.71 — so a fixed
// "discard 34 frames" is fitted to one case. Settle on the frame mean instead.
// MUST run after every cameraStart()/resume: camApplySensorTuning() re-applies
// the shipping baseline (aec 40, gain 0) each time, which would silently put
// the camera layer back to ~21 bits in the dark.
static void ovApplyCamSettings(){
  sensor_t* s = esp_camera_sensor_get();
  if(!s) return;
  if(s->set_exposure_ctrl) s->set_exposure_ctrl(s, 0);
  if(s->set_gain_ctrl)     s->set_gain_ctrl(s, 0);
  if(s->set_aec2)          s->set_aec2(s, 0);
  if(s->set_aec_value)     s->set_aec_value(s, ovAec);
  if(s->set_agc_gain)      s->set_agc_gain(s, ovGain);
  if(s->set_gainceiling)   s->set_gainceiling(s, (gainceiling_t)6);
  delay(30);
}

// Walk the sensitivity ladder until the measured change fraction is good
// enough, then stop. Returns the best change fraction found.
static float ovAutoTune(){
  float best = -1.0f; int bestI = 0;
  for(int t = 0; t < OV_TUNE_N; t++){
    ovGain = OV_TUNE[t].gain; ovAec = OV_TUNE[t].aec;
    ovApplyCamSettings();
    ovRingN = 0; ovRingI = 0; ovPrevOk = false;
    for(int f = 0; f < OV_TUNE_FRAMES * 3 && ovRingN < OV_TUNE_FRAMES - 1; f++){
      ovRefreshCam();                      // dud frames simply do not fill the ring
      esp_task_wdt_reset(); delay(20);
    }
    float p = ovCamAgreement();
    float ch = (p < 0.0f) ? 0.0f : (1.0f - p);

    spr.fillSprite(C_BG);
    uiHeader("TUNING CAMERA", OV_COL_CAM);
    fSet(F_SMALL); spr.setTextColor(C_TEXT2);
    fDrawCentre("finding the exposure where", 120, 92);
    fDrawCentre("the sensor noise is visible", 120, 112);
    char l2[48];
    snprintf(l2, sizeof l2, "gain %d  aec %d  ->  %d%%",
             ovGain, ovAec, (int)(ch * 100.0f + 0.5f));
    fDrawCentre(l2, 120, 150);
    fEnd();
    dispPush();

    if(ch > best){ best = ch; bestI = t; }
    if(ch >= OV_TUNE_GOOD) break;          // good enough — bright rooms stop early
  }
  ovGain = OV_TUNE[bestI].gain; ovAec = OV_TUNE[bestI].aec;
  ovApplyCamSettings();
  ovRingN = 0; ovRingI = 0; ovPrevOk = false;   // live estimate starts clean
  return best;
}

static bool ovCamStart(){
  if(ovCamUp) return true;
  pwrBoost();
  cameraStart();
  ovApplyCamSettings();
  ovAutoTune();
  float prev = -1.0f; int stable = 0, frames = 0;
  while(frames < OV_CAM_MAX_FRAMES){
    camera_fb_t* fb = esp_camera_fb_get();
    if(!fb){ cameraStop(); pwrIdle(); return false; }
    if(fb->len < 4096){ esp_camera_fb_return(fb); cameraStop(); pwrIdle(); return false; }
    size_t st = fb->len / OV_CAM_EST;
    uint32_t sum = 0;
    for(int i = 0; i < OV_CAM_EST; i++) sum += fb->buf[i * st];
    float m = (float)sum / (float)OV_CAM_EST;
    esp_camera_fb_return(fb);
    frames++;
    if(prev >= 0.0f && fabsf(m - prev) < 0.5f) stable++; else stable = 0;
    prev = m;
    if(frames >= OV_CAM_MIN_FRAMES && stable >= 3) break;
    esp_task_wdt_reset(); delay(5);
  }
  ovCamUp = true; ovPrevOk = false; ovRingN = 0; ovRingI = 0;
  ovCamHeldBits10 = -1;
  return true;
}
static void ovCamStop(){
  if(!ovCamUp) return;
  // Leave the sensor as the rest of the product expects it. The next
  // cameraResumeHW() re-applies the shipping tuning anyway, but do not rely on
  // a later call to undo something this page did.
  sensor_t* s = esp_camera_sensor_get();
  if(s){
    if(s->set_aec_value)   s->set_aec_value(s, 40);
    if(s->set_agc_gain)    s->set_agc_gain(s, 0);
    if(s->set_gainceiling) s->set_gainceiling(s, (gainceiling_t)0);
  }
  cameraStop(); pwrIdle(); ovCamUp = false;
}

// ── honest bits ─────────────────────────────────────────────────────────────
// XOR of independent layers is at least as unpredictable as the BEST layer, so
// the board is floored by the max — not the sum, and not the average. A dead
// layer XORs in as a constant, which is a bijection: it cannot subtract.
static int ovBoardBits10(){
  int a = ovSeBits10, b = ovCamBits10;
  return (a > b) ? a : b;
}
static void ovScoreLayers(){
  ovSeBits10 = ovSeDead ? 0 : (OVL_CELLS * 10);
  // Use the snapshot taken AT FREEZE, not whatever the live figure has drifted
  // to since — the number must describe the conditions the layer was captured
  // under, or uncovering the lens afterwards would improve the score for bits
  // that were already taken.
  if(ovCamHeldBits10 >= 0){ ovCamBits10 = ovCamHeldBits10; return; }
  float p = ovCamAgreement();
  ovCamBits10 = (p < 0.0f) ? 0 : ovBits10(ovMinEnt(p));
}

// ─────────────────────────────────────────────────────────────────────────────
// THE FLOW — one rule, applied everywhere
//
//   btn2 ENTER   always moves you FORWARD one step. It is the only key that
//                changes anything: it freezes a layer, reveals a QR, composes
//                the board, and finishes.
//   btn1 / btn3  scroll FORWARD and BACK through every step you have already
//                seen, without changing anything. Look at the SE grid again,
//                its QR, the camera grid, the board — then scroll back to
//                where you were, or press ENTER to jump there.
//   btn4 BACK    leaves the page.
//
// Ten steps, and ENTER walks them in a straight line:
//
//   1 SE051 live      ENTER freezes it
//   2 SE051 frozen    ENTER shows its QR          (same step, now still)
//   3 A as a QR       ENTER starts the camera
//   4 camera live     ENTER freezes it
//   5 camera frozen   ENTER shows its QR
//   6 B as a QR       ENTER composes the board
//   7 the board       A xor B
//   8-9-10 hex        A, B, board, entropy — one screen each
//   11 honest bits    ENTER finishes
//
// Nothing here needs two presses to get past, and no screen uses the scroll
// keys for two different things. That was the whole complaint about the first
// version: the QR was a modal that swallowed a press, so ENTER sometimes moved
// you on and sometimes just dismissed something.
// ─────────────────────────────────────────────────────────────────────────────

// A layer QR is SEED-EQUIVALENT: anyone who reads it can rebuild the wallet. It
// used to appear mid-flow under the single word "secret", to a first-time owner
// with no idea what it was for. Each QR now sits behind a WARNING step that says
// what it is, what it costs, and where it is used — and scroll-forward skips
// straight past it, so most owners never display the QR at all.
// FOUR hex screens in a row (A, B, board, entropy) was three too many for a
// first-time owner who will read none of them, and the layer values are
// already on the two QRs. One screen, showing the ENTROPY — the value that
// actually becomes the key — and pointing at the website for the rest.
enum { ST_SE = 0, ST_SE_WARN, ST_SE_QR, ST_CAM, ST_CAM_WARN, ST_CAM_QR, ST_BOARD,
       ST_HEX_ENT, ST_BITS, ST_N };
#define OV_QR_URL "favillakey.io/verify/seed"
#define OV_STEPS ST_N

static bool ovSeFrozen = false, ovCamFrozen = false;

// ── drawing ─────────────────────────────────────────────────────────────────
// ── layout ──────────────────────────────────────────────────────────────────
// The grid ends at OV_GRID_BOT. NOTHING is drawn over it — the two text lines
// below sit centred in the strip between the grid and the bottom edge, and
// every screen uses the same two slots: what the source is doing, and what
// ENTER will do next. The step counter lives in the header, not in that strip.
#define OV_GRID_BOT  (OV_Y0 + OVL_N * OV_PX)      // 208
#define OV_L1        213                          // the ONE line, F_HEAD
#define OV_L2        213                          // kept as an alias: the old
                                                  // second line is gone, and
                                                  // callers that used it now
                                                  // write the same slot

static void ovDrawGrid(const uint8_t* g, uint16_t on, uint16_t off){
  for(int i = 0; i < OVL_CELLS; i++)
    spr.fillRect(OV_X0 + (i % OVL_N) * OV_PX + 1, OV_Y0 + (i / OVL_N) * OV_PX + 1,
                 OV_PX - 2, OV_PX - 2, ovlGet(g, i) ? on : off);
}
// Scale is deliberately 128..256, not 0..256. Below 128 there is nothing worth
// showing a proportion of — the layer has failed — so the bar reads empty and
// red. Full means the layer alone would carry a 256-bit seed.
static uint16_t ovBarCol(int bits10){
  if(bits10 < OV_CAM_PASS_BITS * 10) return C_RED;
  if(bits10 < 192 * 10)              return C_AMBER;
  return C_GREEN;
}
static void ovBar(int bits10, int x, int y, int w, int h){
  spr.drawRect(x, y, w, h, C_BORDER2);
  int lo = OV_CAM_PASS_BITS * 10, hi = OVL_CELLS * 10;
  int fill = 0;
  if(bits10 > lo) fill = (int)(((long)(bits10 - lo) * (w - 2)) / (hi - lo));
  if(fill > w - 2) fill = w - 2;
  if(fill > 0) spr.fillRect(x + 1, y + 1, fill, h - 2, ovBarCol(bits10));
  // the pass line itself, drawn at the left edge so "any fill at all" == pass
  spr.drawFastVLine(x, y - 2, h + 4, ovBarCol(bits10));
}

static void ovLine(const char* s, uint16_t col, int y){
  if(!s || !*s) return;
  fSet(F_SMALL); spr.setTextColor(col); fDrawCentre(s, 120, y); fEnd();
}
// "SE051  4/10" — one header, one place to look for where you are.
// Title row, drawn without uiHeader — no 28px reserved strip, no divider rule.
// Name on the left in the accent colour, step counter small on the right.
static void ovHead(const char* name, int view, uint16_t accent){
  // 29 Oct 2026: amber headers -> brass (the grid colours stay: they match the
  // web verifier's grids on purpose).
  if(accent == C_AMBER) accent = C_EB_BRASS;
  fSet(F_HEAD); spr.setTextColor(accent);
  spr.drawString(name, 10, 6); fEnd();
  char t[12]; snprintf(t, sizeof t, "%d/%d", view + 1, OV_STEPS);
  fSet(F_HEAD_SM); spr.setTextColor(C_VDIM);
  { int w = spr.textWidth(t); spr.drawString(t, 230 - w, 10); }
  fEnd();
}

// The one line under the grid. F_HEAD, not F_BODY — it is the only caption on
// the page and it should read at a glance, not require looking.
static void ovSay(const char* s, uint16_t col){
  fSet(F_HEAD); spr.setTextColor(col); fDrawCentre(s, 120, OV_L1); fEnd();
}
static inline const char* ovAction(int view, int top, const char* atFront){
  return (view < top) ? "ENTER returns" : atFront;
}

// Current live estimate for the camera layer, in tenths of a bit.
static int ovCamLiveBits10(){
  float p = ovCamAgreement();
  return (p < 0.0f) ? 0 : ovBits10(ovMinEnt(p));
}

static inline bool ovCanFreeze(int which){
  if(ovFrames < (which ? OV_MIN_CAM_FRAMES : OV_MIN_SE_FRAMES)) return false;
  // 14 Oct 2026: the SE051 layer cannot be frozen unless the LAST draw came
  // from the chip. A dead SE would otherwise freeze a stale buffer (or the
  // zeros it was cleared to) and leave the seed resting on the camera alone.
  if(!which && ovSeDead) return false;
  if(which){
    // The bit count comes from the rolling ring, so the ring must hold enough
    // history for the snapshot to mean anything.
    if(ovRingN < OV_MIN_CAM_FRAMES) return false;
    // HARD GATE. The camera layer is what protects the board if the SE051 is
    // compromised, so capturing it below the pass line would leave the whole
    // no-single-vendor claim resting on nothing. The board figure would still
    // read 256 (floored by the SE051's asserted bits), which is exactly why
    // this has to be refused rather than merely displayed.
    if(ovCamLiveBits10() < OV_CAM_PASS_BITS * 10) return false;
  }
  return true;
}

static void ovPaintLayer(int which, int view, int top){
  bool frozen = which ? ovCamFrozen : ovSeFrozen;
  const uint8_t* g = frozen ? (which ? ovB : ovA) : ovLive;
  uint16_t col = which ? OV_COL_CAM : OV_COL_SE;

  // ONE caption, chosen by priority: a refusal beats a state, a state beats a
  // prompt. The old page said all three at once in two stacked lines and the
  // important one was never the biggest.
  char say[40]; uint16_t sayCol = C_TEXT2;

  if(which == 0){
    if(ovSeDead)      { snprintf(say, sizeof say, "NO RESPONSE"); sayCol = C_RED; }
    else if(frozen)   { snprintf(say, sizeof say, "FROZEN");      sayCol = OV_COL_HELD; }
    else if(!ovCanFreeze(0))
                      { snprintf(say, sizeof say, "READING");     sayCol = C_DIM; }
    else              { snprintf(say, sizeof say, "LIVE");        sayCol = col; }
  } else {
    float p  = ovCamAgreement();
    int   bt = (ovCamHeldBits10 >= 0) ? ovCamHeldBits10
             : ((p < 0.0f) ? 0 : ovBits10(ovMinEnt(p)));
    if(frozen){
      snprintf(say, sizeof say, "FROZEN AT %d BITS", bt / 10);
      sayCol = OV_COL_HELD;
    } else if(ovFrames < OV_MIN_CAM_FRAMES || ovRingN < OV_MIN_CAM_FRAMES){
      snprintf(say, sizeof say, "READING"); sayCol = C_DIM;
    } else if(bt < OV_CAM_PASS_BITS * 10){
      // Name the DIRECTION. The device knows whether the sensor is saturated
      // (mean at the top rail) or starved; "under 128 bits" made the user guess.
      if(ovLastMean > 200.0f)    snprintf(say, sizeof say, "TOO BRIGHT");
      else if(ovLastMean < 2.0f) snprintf(say, sizeof say, "TOO DARK");
      else                       snprintf(say, sizeof say, "NOT ENOUGH NOISE");
      sayCol = C_RED;
    } else {
      snprintf(say, sizeof say, "%d BITS", bt / 10);
      sayCol = C_GREEN;
    }
  }

  spr.fillSprite(C_BG);
  ovHead(which ? "CAMERA" : "SECURE ELEMENT", view, frozen ? OV_COL_HELD : col);
  ovDrawGrid(g, col, ovQuarter(col));
  ovSay(say, sayCol);
  dispPush();
}

// The QR is a normal step, not a modal. It paints and returns; the main loop
// keeps handling buttons, so ENTER moves on exactly once like everywhere else.
static void ovPaintQrWarn(int which, int view, int top){
  spr.fillSprite(C_BG);
  ovHead(which ? "CAMERA" : "SECURE ELEMENT", view, C_RED);
  fSet(F_HEAD); spr.setTextColor(C_FG);
  fDrawCentre("Seed material", 120, 34); fEnd();
  fSet(F_BODY); spr.setTextColor(C_TEXT2);
  fDrawCentre("The next screen shows this",  120, 64);
  fDrawCentre("sensor as a QR code. Anyone", 120, 82);
  fDrawCentre("who reads it can rebuild",    120, 100);
  fDrawCentre("your wallet.",                120, 118);
  fEnd();
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  fDrawCentre("Only for testing, or on a", 120, 146);
  fDrawCentre("machine kept offline.",     120, 164);
  fEnd();
  fSet(F_HEAD_SM); spr.setTextColor(C_EB_BRASS);
  fDrawCentre(OV_QR_URL, 120, 190); fEnd();
  ovLine(ovAction(view, top, "ENTER shows it"), C_DIM, OV_L2);
  dispPush();
}

static void ovPaintQr(const uint8_t* layer, const char* name, int view, int top){
  char hx[65]; ovlHex(layer, 32, hx);
  char top_[32]; snprintf(top_, sizeof top_, "%s  %d/%d", name, view + 1, OV_STEPS);
  char bot[40];  snprintf(bot, sizeof bot, "seed material - %s", ovAction(view, top, "ENTER continues"));
  showQR(hx, top_, bot);
}

static void ovPaintBoard(int view, int top){
  (void)top;
  spr.fillSprite(C_BG);
  ovHead("YOUR KEY", view, OV_COL_BRD);
  ovDrawGrid(ovBoard, OV_COL_BRD, ovQuarter(OV_COL_BRD));
  // No truncated hash here. An abbreviation nobody can check against anything
  // is decoration; the full value is one step away.
  ovSay("BOTH SENSORS COMBINED", OV_COL_BRD);
  dispPush();
}

static void ovPaintHex(int which, int view, int top){
  (void)which; (void)top;                 // one screen now: the entropy
  spr.fillSprite(C_BG);
  ovHead("YOUR SEED", view, C_AMBER);
  char hx[65]; ovlHex(g_ovlEntropy, 32, hx);
  char line[17];
  // Bigger pitch and the mono face at full brightness: this is meant to be
  // transcribed or compared, not glanced at.
  for(int i = 0; i < 4; i++){
    memcpy(line, hx + i * 16, 16); line[16] = 0;
    fSet(F_MONO); spr.setTextColor(C_FG); fDrawCentre(line, 120, 62 + i * 28); fEnd();
  }
  fSet(F_BODY); spr.setTextColor(C_MUTED);
  fDrawCentre("Check it at", 120, 188);
  fDrawCentre(OV_QR_URL, 120, 208);
  fEnd();
  dispPush();
}

static void ovPaintBits(int view, int top){
  (void)top;
  // REWRITTEN. The previous version led with "If the chip maker lied" — a
  // threat the owner has never considered, raised at the end of the flow, in a
  // frame that reads as an accusation. And it could only ever show a PASS: the
  // freeze gate refuses a camera under OV_CAM_PASS_BITS, so the ceremony never
  // arrives here with a bad number. A screen that always says the same thing
  // teaches nothing.
  //
  // Same fact, stated as provenance: two independent sources, what each is
  // worth, and the property that actually follows from XOR — either one alone
  // is enough. The asserted/measured distinction stays, because it is the
  // honest difference between a certificate and a measurement, but it is a
  // qualifier now rather than the headline.
  // 29 Oct 2026 (page language, board N4): one label, two rows of name /
  // number / what the number is, one rule, one sentence, the action. The
  // lime bar, the green and orange names and the amber header are gone: the
  // number already says what the bar said, and three accents on one page read
  // as noise. The grid pages keep their layer colours (they match the web
  // verifier); this summary page does not need them.
  (void)top;
  spr.fillSprite(C_BG);
  uiTrackLabel("TWO SOURCES", 120, 14, C_EB_GREY);
  struct { const char* name; int bits; const char* what; uint16_t numCol; } row[2] = {
    { "SECURE CHIP", ovSeBits10 / 10, ovSeDead ? "no response" : "claimed by the chip maker", ovSeDead ? C_RED : C_EB_INK },
    { "CAMERA",      ovCamBits10 / 10, "measured on this KEY",                                  C_EB_INK },
  };
  for(int i = 0; i < 2; i++){
    int y = 44 + i * 54;
    uiTrackLabel(row[i].name, 24 + uiTrackWidth(row[i].name, 2) / 2, y + 4, C_EB_BRASS, 2);
    fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_GREY);
    spr.drawString(row[i].what, 24, y + 22);
    fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(row[i].numCol);
    char v[8]; snprintf(v, sizeof v, "%d", row[i].bits);
    spr.drawString(v, 216 - spr.textWidth(v), y);
    fEndHard();
  }
  spr.drawFastHLine(24, 156, 192, C_EB_LINE);
  spr.loadFont(FONT_Archivo_Regular_13);
  spr.setTextColor(C_EB_INK);  { const char* t = "Bits each. Trust neither, use both."; spr.drawString(t, 120 - spr.textWidth(t)/2, 166); }
  spr.setTextColor(C_EB_GREY); { const char* t = "Neither can weaken the other.";       spr.drawString(t, 120 - spr.textWidth(t)/2, 184); }
  fEndHard();
  uiTrackLabel(view < top ? "ENTER RETURNS" : "ENTER TO FINISH", 120, 212, C_EB_BRASS);
  dispPush();
}

static void ovDrawFail(const char* why){
  spr.fillSprite(C_BG);
  uiHeader("REFUSED", C_RED);
  fSet(F_SMALL); spr.setTextColor(C_TEXT2); fDrawCentre(why, 120, 108); fEnd();
  ovLine("nothing was written", C_VDIM, OV_L1);
  ovLine("ENTER starts over - BACK exits", C_DIM, OV_L2);
  dispPush();
}

static void ovPaint(int view, int top){
  switch(view){
    case ST_SE:      ovPaintLayer(0, view, top); break;
    case ST_SE_WARN: ovPaintQrWarn(0, view, top); break;
    case ST_SE_QR:   ovPaintQr(ovA, "A", view, top); break;
    case ST_CAM:     ovPaintLayer(1, view, top); break;
    case ST_CAM_WARN:ovPaintQrWarn(1, view, top); break;
    case ST_CAM_QR:  ovPaintQr(ovB, "B", view, top); break;
    case ST_BOARD:   ovPaintBoard(view, top); break;
    case ST_HEX_ENT: ovPaintHex(3, view, top); break;
    default:         ovPaintBits(view, top); break;
  }
}

// ── the ceremony. Onboarding calls THIS. No demo flag, no second path. ─────
static bool runEntropyOverlay(){
  int view = ST_SE, top = ST_SE;
  bool failed = false, intro = true;
  const char* why = "";
  uint32_t lastTick = 0;

  memset(ovA, 0, sizeof ovA); memset(ovB, 0, sizeof ovB);
  memset(ovBoard, 0, sizeof ovBoard); memset(ovLive, 0, sizeof ovLive);
  ovSeDead = false; ovPrevOk = false; ovRingN = 0; ovRingI = 0; ovCamHeldBits10 = -1;
  ovSeBits10 = 0; ovCamBits10 = 0; ovFrames = 0;
  ovSeFrozen = false; ovCamFrozen = false;
  g_ovlValid = false;
  mbedtls_platform_zeroize(g_ovlEntropy, sizeof g_ovlEntropy);

  // Five lines of 10px grey explaining a mechanism, on the screen where the
  // owner has just committed to a path and wants to know what happens next.
  // Replaced with the claim, then the two sources as cards, then the action.
  // "XOR" is gone from here — it belongs on the verify screens, not the
  // welcome.
  // 29 Oct 2026 (page language): headline in Archivo Bold 28, one grey line,
  // two explainer rows (hairline cards, not "selected", so they don't read as
  // a choice), and the action as a tracked brass footer. The green "Press
  // Enter" is gone.
  spr.fillSprite(C_BG);
  uiTrackLabel("TWO CHIPS, ONE KEY", 120, 14, C_EB_GREY);
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(C_EB_INK);
  spr.drawString("Neither maker can know your key.", 120 - spr.textWidth("Neither maker can know your key.")/2, 38);
  fEndHard();
  ppCard32(64,  62, "SECURE ELEMENT", "Random number chip", false, C_EB_BRASS, ppIconCpu32,      C_EB_INK);
  ppCard32(134, 62, "CAMERA",         "Sensor noise",       false, C_EB_BRASS, ppIconAperture32, C_EB_INK);
  uiTrackLabel("ENTER TO CONTINUE", 120, 210, C_EB_BRASS);
  dispPush();

  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    // Read each button EXACTLY ONCE — isPressed() consumes the press.
    bool kFwd  = btn1.isPressed();
    bool kEnt  = btn2.isPressed();
    bool kBack = btn3.isPressed();
    bool kExit = btn4.isPressed();

    // live sampling only on the step you are actually watching
    if(!intro && !failed && view == top && (millis() - lastTick) > 110 &&
       ((view == ST_SE && !ovSeFrozen) || (view == ST_CAM && !ovCamFrozen))){
      lastTick = millis();
      if(view == ST_SE){ ovRefreshSE(); ovFrames++; }
      else if(ovRefreshCam()) ovFrames++;
      ovPaint(view, top);
    }

    if(kExit) break;

    if(failed){
      if(kEnt){                                  // start over, nothing kept
        memset(ovA, 0, sizeof ovA); memset(ovB, 0, sizeof ovB);
        ovRingN = 0; ovRingI = 0; ovPrevOk = false; ovCamHeldBits10 = -1;
        ovSeFrozen = false; ovCamFrozen = false; ovFrames = 0;
        failed = false; view = top = ST_SE;
        ovRefreshSE(); ovFrames++; ovPaint(view, top);
      }
      esp_task_wdt_reset(); delay(5); continue;
    }

    if(intro){
      if(kEnt){ intro = false; ovRefreshSE(); ovFrames++; ovPaint(view, top); }
      esp_task_wdt_reset(); delay(5); continue;
    }

    if(kFwd || kBack){                           // review — changes nothing
      int nv = view + (kFwd ? 1 : -1);
      if(nv < ST_SE) nv = ST_SE;
      if(nv > top)   nv = top;
      if(nv != view){ view = nv; ovPaint(view, top); }
    }
    else if(kEnt){
      if(view < top){ view = top; ovPaint(view, top); }   // jump back to the front
      else switch(view){
        case ST_SE:
          if(!ovSeFrozen){
            if(ovCanFreeze(0)){ memcpy(ovA, ovLive, OVL_BYTES); ovSeFrozen = true; buzzerOK(); }
            ovPaint(view, top);
          } else { view = top = ST_SE_WARN; ovPaint(view, top); }
          break;
        case ST_SE_QR:
          if(!ovCamStart()){ why = "Camera did not start"; failed = true; ovDrawFail(why); }
          else { ovFrames = 0; view = top = ST_CAM; ovPaint(view, top); }
          break;
        case ST_CAM:
          if(!ovCamFrozen){
            if(ovCanFreeze(1)){
              memcpy(ovB, ovLive, OVL_BYTES);
              // Snapshot the rate AT FREEZE. Otherwise uncovering the lens
              // afterwards would improve the score for bits already taken.
              float pf = ovCamAgreement();
              ovCamHeldBits10 = (pf < 0.0f) ? 0 : ovBits10(ovMinEnt(pf));
              ovCamFrozen = true; buzzerOK();
            }
            ovPaint(view, top);
          } else { view = top = ST_CAM_WARN; ovPaint(view, top); }
          break;
        case ST_CAM_QR:
          ovCamStop();
          // 14 Oct 2026: no SE051, no seed. Ask the chip once more at the
          // moment of generation: the SE layer must have been frozen from a
          // real draw AND the chip must still answer now. Otherwise refuse -
          // a camera-only seed breaks the no-single-vendor property.
          ovRefreshSE();
          ovScoreLayers();
          if(ovSeDead || !ovSeFrozen || ovlLayerConstant(ovA)){
            why = "Secure element not responding"; failed = true; ovDrawFail(why);
          } else
          // Fail closed only when BOTH layers are worthless. A dark camera on
          // its own is fine — XOR with a constant cannot subtract.
          if(ovlLayerConstant(ovA) && ovlLayerConstant(ovB)){
            why = "Both layers are constant"; failed = true; ovDrawFail(why);
          } else if(ovCamBits10 < OV_CAM_PASS_BITS * 10){
            // Backstop for the freeze gate. The board figure is floored by the
            // SE051's asserted 256 and would read full here, so this check has
            // to be on the CAMERA layer specifically or the no-single-vendor
            // claim is unenforced.
            why = "Camera layer under 128 bits"; failed = true; ovDrawFail(why);
          } else if(ovBoardBits10() < OV_MIN_BITS * 10){
            why = "Both layers too weak - change the light"; failed = true; ovDrawFail(why);
          } else {
            ovlXor(ovA, ovB, ovBoard);
            ovlEntropyFromBoard(ovBoard, g_ovlEntropy);
            g_ovlValid = true;
            view = top = ST_BOARD; ovPaint(view, top);
          }
          break;
        case ST_BITS:
          goto done;
        default:
          view = top = view + 1; ovPaint(view, top);
          break;
      }
    }

    esp_task_wdt_reset();
    delay(5);
  }

done:
  ovCamStop();
  mbedtls_platform_zeroize(ovA, sizeof ovA);
  mbedtls_platform_zeroize(ovB, sizeof ovB);
  mbedtls_platform_zeroize(ovBoard, sizeof ovBoard);
  mbedtls_platform_zeroize(ovLive, sizeof ovLive);
  mbedtls_platform_zeroize(ovPrevCells, sizeof ovPrevCells);
  return g_ovlValid;
}

#endif // FAVILLA_ENTROPY_OVERLAY_H
