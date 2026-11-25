// work_page.inc - 11cg (22 Nov 2026, UX drop 1): screens that move while the
// KEY waits. Included from main.cpp after the ember helpers, before the PASSKEY
// life and the vault code that use it.
//
// Josh's rulings (20 Nov): nothing waits on a still screen; a step that is not
// consent goes on by itself; good news closes by itself, bad news waits.
//
// Three page kinds, all in the house style (tracked label, Archivo Bold 28
// headline, Archivo 13 lines, tracked footer), the same component as the
// verify card (attest_flow.inc):
//   STEPS  a headline and up to three numbered steps. The step the KEY is
//          waiting on has a turning ring around its number; done steps are a
//          filled brass circle with a tick. Optional bar under the steps.
//   EMBER  the 48 px ember flickering (the signing screen's working noise), a
//          headline, a line, and an optional bar with a tracked count.
//   SMALL  pkPage's layout (40 px ember, headline at 92, two lines) with the
//          small ember flickering.
// A core-1 task animates the ring or the ember about 25 times a second, so it
// keeps moving while the main loop blocks on the G0, the relay or the app.
// Every draw into the shared sprite, the task's and the caller's, happens
// under one mutex. The task never touches fonts; it repaints only the ring's
// annulus (the number inside stays) or the ember's cells.
//
// Use:
//   wp::Page& p = wp::steps("BACKUP", "Backing up");
//   wp::step(0, wp::DONE, "Sealed on the KEY", "41 passkeys");
//   wp::step(1, wp::NOW,  "Sending to the app", "64% of 33 KB");
//   wp::step(2, wp::TODO, "Relay keeps it", "vault.favillakey.io");
//   p.bar = 0.64f; wp::show();          // repaint after each change
//   ...
//   wp::done("BACKUP", "Backed up", "64 entries on the relay");   // closes by itself
//   wp::stop();                          // or this, before any other screen

namespace wp {

enum : uint8_t { TODO = 0, NOW = 1, DONE = 2, DO = 3 };   // DO: an instruction for the owner (brass number, no ring)
enum : uint8_t { K_STEPS = 0, K_EMBER = 1, K_SMALL = 2 };

struct Step { char title[28]; char sub[34]; uint8_t st; };
struct Page {
  uint8_t kind = K_STEPS;
  char label[24] = "", head[26] = "", line1[40] = "", line2[40] = "", count[24] = "", foot[28] = "";
  uint16_t footCol = C_EB_GREY;
  Step st[3]; uint8_t nStep = 0;
  float bar = -1.0f;                 // <0: no bar
  uint16_t barCol = C_EB_BRASS;
};

static Page P;
static SemaphoreHandle_t s_mx = nullptr;
static StaticSemaphore_t s_mxBuf;
static TaskHandle_t s_task = nullptr;
static volatile bool s_run = false;
static volatile int  s_ringY = -1;  // centre y of the NOW step's ring, -1 none

static inline void lock()   { if(!s_mx) s_mx = xSemaphoreCreateMutexStatic(&s_mxBuf); xSemaphoreTake(s_mx, portMAX_DELAY); }
static inline void unlock() { xSemaphoreGive(s_mx); }

// ── geometry (checked against the VLW fonts on 22 Nov: every headline, line,
// step and footer below fits, and the digits centre on their ink) ──
static const int STEP_Y0 = 84, STEP_PITCH = 34, RING_CX = 39, RING_R = 11;
static const int BAR_STEPS_X = 62, BAR_STEPS_W = 150, BAR_STEPS_Y = 192;
static const int BAR_EMBER_X = 40, BAR_EMBER_W = 160, BAR_EMBER_Y = 172;
static const int EMBER_X = 96, EMBER_Y = 40, SMALL_X = 101, SMALL_Y = 38;

// The digit centred on its ink (11cc's formula).
static void digit(char ch, int cx, int cy, uint16_t col){
  char n[2] = { ch, 0 };
  fSet(F_BRAND_B12); spr.setTextColor(col);
  uint16_t gi = 0;
  if(spr.getUnicodeIndex((uint16_t)n[0], &gi))
    spr.drawString(n, cx - spr.gdX[gi] - spr.gWidth[gi] / 2, cy - (spr.gFont.maxAscent - spr.gdY[gi]) - spr.gHeight[gi] / 2);
  else spr.drawString(n, cx - spr.textWidth(n) / 2, cy - 5);
  fEnd();
}

// The ring's annulus: a grey base and a 110 degree brass arc starting at a0
// (degrees, 0 at 12 o'clock, clockwise), anti-aliased by coverage. Only the
// pixels between r 8.4 and 12.2 are written, so the number inside stays.
static void ringFrame(int cx, int cy, float a0){
  const float rIn = RING_R - 2.6f, rOut = RING_R + 0.5f, baseIn = RING_R - 1.5f;
  for(int dy = -RING_R - 1; dy <= RING_R + 1; dy++) for(int dx = -RING_R - 1; dx <= RING_R + 1; dx++){
    const float d = sqrtf((float)(dx * dx + dy * dy));
    if(d < rIn - 0.5f || d > rOut + 0.5f) continue;
    float ang = atan2f((float)dx, (float)-dy) * 57.29578f; if(ang < 0) ang += 360.0f;
    float rel = ang - a0; while(rel < 0) rel += 360.0f; while(rel >= 360.0f) rel -= 360.0f;
    const bool inArc = rel <= 110.0f;
    float cov; uint16_t col;
    if(inArc){ cov = fminf(fminf(d - (rIn - 0.5f), (rOut + 0.5f) - d), 1.0f); col = C_EB_BRASS; }
    else     { cov = fminf(fminf(d - (baseIn - 0.5f), (rOut + 0.5f) - d), 1.0f); col = C_EB_LINE; }
    if(cov <= 0.0f){ spr.drawPixel(cx + dx, cy + dy, C_BG); continue; }
    spr.drawPixel(cx + dx, cy + dy, cov >= 1.0f ? col : ebMix(C_BG, col, (uint8_t)(cov * 255.0f)));
  }
}
static void smallNoise(){
  for(int r = 0; r < 5; r++) for(int c = 0; c < 5; c++){
    if(abs(r - 2) + abs(c - 2) > 2) continue;
    // 11cg: the 6 px cells need more light than the 48 px mark's noise to read
    // as working rather than dead (22 Nov pixel check): a quarter brass, the
    // rest from the noise's warmer half.
    const uint32_t k = esp_random() % 100;
    const uint16_t col = k < 12 ? C_EB_BRASS : k < 25 ? C_EB_BRASS2 : EB_NOISE[4 + (esp_random() & 3)];
    spr.fillRect(SMALL_X + c * 8, SMALL_Y + r * 8, 6, 6, col);
  }
}
static void bigNoise(){
  const int ox = g_ebMarkOX, oy = g_ebMarkOY;
  g_ebMarkOX = EMBER_X; g_ebMarkOY = EMBER_Y;
  PinMarkState m = { 0.0f, 0.0f, 255, false, 0 };
  ebMarkDraw(m);
  g_ebMarkOX = ox; g_ebMarkOY = oy;
}

static void taskFn(void*){
  while(s_run){
    lock();
    const uint32_t t = millis();
    if(P.kind == K_STEPS && s_ringY >= 0){
      ringFrame(RING_CX, s_ringY, (float)((t % 1100) * 360 / 1100));
      dispPushRegion(RING_CX - RING_R - 1, s_ringY - RING_R - 1, 2 * RING_R + 3, 2 * RING_R + 3);
    } else if(P.kind == K_EMBER){
      bigNoise(); dispPushRegion(EMBER_X, EMBER_Y, 48, 48);
    } else if(P.kind == K_SMALL){
      static uint32_t last = 0;
      if(t - last >= 60){ last = t; smallNoise(); dispPushRegion(SMALL_X, SMALL_Y, 38, 38); }
    }
    unlock();
    vTaskDelay(pdMS_TO_TICKS(40));
  }
  s_task = nullptr;
  vTaskDelete(NULL);
}
static void startTask(){
  if(s_run) return;
  s_run = true;
  xTaskCreatePinnedToCore(taskFn, "wpAnim", 3072, nullptr, 1, &s_task, 1);
}
void stop(){
  if(!s_run) return;
  s_run = false;
  while(s_task) vTaskDelay(pdMS_TO_TICKS(2));
}

static void track(const char* t, int y, uint16_t col){ if(t && *t) uiTrackLabel(t, 120, y, col); }
static void headAt(const char* h, int y){
  if(!*h) return;
  fEndHard(); spr.loadFont(FONT_Archivo_Bold_28_full); spr.setTextColor(C_EB_INK);
  spr.drawString(h, 120 - spr.textWidth(h) / 2, y);
  fEndHard();
}
static void lineAt(const char* l, int y, uint16_t col){
  if(!*l) return;
  fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(col);
  spr.drawString(l, 120 - spr.textWidth(l) / 2, y);
  fEndHard();
}
static void barAt(int x, int y, int w, float p, uint16_t col){
  spr.fillRect(x, y, w, 2, C_EB_LINE);
  if(p > 0.0f){ if(p > 1.0f) p = 1.0f; spr.fillRect(x, y, (int)(w * p), 2, col); }
}

// Paint the whole page from P (call after every change).
void show(){
  if(bgSpinnerRunning) bgSpinnerStop();
  lock();
  spr.fillSprite(C_BG);
  track(P.label, 14, C_EB_BRASS);
  int ringY = -1;
  if(P.kind == K_STEPS){
    headAt(P.head, 36);
    for(int i = 0; i < P.nStep; i++){
      const Step& s = P.st[i]; const int y = STEP_Y0 + i * STEP_PITCH, cy = y + 11;
      if(s.st == DONE){
        spr.fillCircle(RING_CX, cy, RING_R, C_EB_BRASS);
        // tick, 2 px: (cx-5,cy) -> (cx-2,cy+3) -> (cx+5,cy-4)
        spr.drawWideLine(RING_CX - 5, cy, RING_CX - 2, cy + 3, 2.2f, C_BG, C_EB_BRASS);
        spr.drawWideLine(RING_CX - 2, cy + 3, RING_CX + 5, cy - 4, 2.2f, C_BG, C_EB_BRASS);
      } else if(s.st == NOW){
        ringFrame(RING_CX, cy, (float)((millis() % 1100) * 360 / 1100)); digit((char)('1' + i), RING_CX, cy, C_EB_BRASS); ringY = cy;
      } else if(s.st == DO){
        spr.drawCircle(RING_CX, cy, RING_R, C_EB_BRASS); spr.drawCircle(RING_CX, cy, RING_R - 1, C_EB_BRASS);
        digit((char)('1' + i), RING_CX, cy, C_EB_BRASS);
      } else {
        spr.drawCircle(RING_CX, cy, RING_R, C_EB_LINE); spr.drawCircle(RING_CX, cy, RING_R - 1, C_EB_LINE);
        digit((char)('1' + i), RING_CX, cy, C_EB_GREY);
      }
      const uint16_t tc = (s.st == NOW || s.st == DO) ? C_EB_INK : s.st == DONE ? C_MUTED : C_EB_GREY;
      fSet(F_BRAND_B14); spr.setTextColor(tc); spr.drawString(s.title, 62, y + 1); fEnd();
      if(s.sub[0]){ fEndHard(); spr.loadFont(FONT_Archivo_Regular_13); spr.setTextColor(s.st == NOW ? C_EB_BRASS : C_EB_GREY); spr.drawString(s.sub, 62, y + 19); fEndHard(); }
    }
    if(P.bar >= 0.0f) barAt(BAR_STEPS_X, BAR_STEPS_Y, BAR_STEPS_W, P.bar, P.barCol);
    track(P.foot, 212, P.footCol);
  } else if(P.kind == K_EMBER){
    bigNoise();
    headAt(P.head, 100);
    lineAt(P.line1, 140, C_EB_GREY);
    if(P.bar >= 0.0f) barAt(BAR_EMBER_X, BAR_EMBER_Y, BAR_EMBER_W, P.bar, P.barCol);
    track(P.count, 184, C_EB_GREY);
    track(P.foot, 212, P.footCol);
  } else {
    smallNoise();
    headAt(P.head, 92);
    lineAt(P.line1, 134, C_EB_GREY);
    lineAt(P.line2, 152, C_EB_GREY);
    if(P.bar >= 0.0f) barAt(BAR_EMBER_X, 172, BAR_EMBER_W, P.bar, P.barCol);
    track(P.foot, 202, P.footCol);
  }
  s_ringY = ringY;
  dispPush();
  unlock();
  if(ringY >= 0 || P.kind != K_STEPS) startTask(); else stop();
}

static void copy(char* d, size_t n, const char* s){ snprintf(d, n, "%s", s ? s : ""); }
Page& begin(uint8_t kind, const char* label, const char* head){
  stop();
  P = Page(); P.kind = kind; copy(P.label, sizeof P.label, label); copy(P.head, sizeof P.head, head);
  return P;
}
Page& steps(const char* label, const char* head){ return begin(K_STEPS, label, head); }
Page& ember(const char* label, const char* head){ return begin(K_EMBER, label, head); }
Page& small(const char* label, const char* head){ return begin(K_SMALL, label, head); }
void step(int i, uint8_t st, const char* title, const char* sub){
  if(i < 0 || i > 2) return;
  P.st[i].st = st; copy(P.st[i].title, sizeof P.st[i].title, title); copy(P.st[i].sub, sizeof P.st[i].sub, sub);
  if(P.nStep < i + 1) P.nStep = i + 1;
}
void setStep(int i, uint8_t st, const char* sub = nullptr){
  if(i < 0 || i >= P.nStep) return;
  P.st[i].st = st; if(sub) copy(P.st[i].sub, sizeof P.st[i].sub, sub);
}

// Good news: the ember resolves and bursts (the signing screen's grammar), the
// page holds about 1.5 s and returns by itself. ENTER or BACK skip the hold.
// Bad news never comes here: it waits for a press (msgWait / pkPage + a wait).
void done(const char* label, const char* head, const char* line){
  stop();
  const int ox = g_ebMarkOX, oy = g_ebMarkOY;
  g_ebMarkOX = EMBER_X; g_ebMarkOY = EMBER_Y;
  buzzerOK();
  clearButtonPending();
  const uint32_t t0 = millis();
  bool first = true;
  while(true){
    const uint32_t el = millis() - t0;
    if(el >= 1500) break;
    btn2.poll(); btn4.poll(); esp_task_wdt_reset();
    if(!first && (btn2.isPressed() || btn4.isPressed())) break;
    first = false;
    lock();
    spr.fillSprite(C_BG);
    track(label, 14, C_EB_BRASS);
    const float fp = el < 600 ? el / 600.0f : 1.0f;
    PinMarkState m = { 1.0f, fp < 1.0f ? fp : 0.0f, 255, false, 0 };
    ebMarkDraw(m);
    headAt(head, 100);
    lineAt(line, 140, C_EB_GREY);
    dispPush();
    unlock();
    delay(el < 600 ? 16 : 60);
  }
  g_ebMarkOX = ox; g_ebMarkOY = oy;
  clearButtonPending();
}

}  // namespace wp
