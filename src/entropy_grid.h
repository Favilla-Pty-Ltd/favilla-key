// ─────────────────────────────────────────────────────────────────────────────
// entropy_grid.h — live entropy visualiser + compose page  (Favilla KEY)
//
// Settings > Device > Entropy grid.
//
// Three live 16x16 grids, one per source, each drawn from that source's RAW
// low bits. You can scroll between them, pause one, capture its shape, then
// drop pieces of captured shapes onto a working grid and see a mixed preview.
//
//   ┌─ WHAT THIS PROVES, AND WHAT IT DOES NOT ──────────────────────────────┐
//   │ A churning grid proves the source is ALIVE and producing. Cover the    │
//   │ lens and the camera grid all but freezes; unplug the accelerometer and │
//   │ it stops entirely. That is the failure nobody holding a Coldcard could │
//   │ see, made visible.                                                     │
//   │                                                                        │
//   │ It does NOT prove the source is unpredictable. A backdoored PRNG draws │
//   │ an identically beautiful grid. No picture can show you randomness      │
//   │ quality — only gross failure. Say so on screen; do not imply more.     │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ NOT THE SEED PATH ───────────────────────────────────────────────────┐
//   │ Nothing here touches generateSeedEntropy() or the wallet. The MIX      │
//   │ PREVIEW is a demonstration digest, labelled as such, and is discarded  │
//   │ on exit. The grid the user composes is NEVER a key: composing is       │
//   │ AUTHORING a value (a brainwallet), while the preview is a fresh draw   │
//   │ from all sources with the action log folded in as unbudgeted margin.   │
//   └────────────────────────────────────────────────────────────────────────┘
//
// CONTROLS (matching the menu idiom used everywhere else):
//   btn1 = scroll forward   btn3 = scroll back
//   btn2 = ENTER            btn4 = BACK (one level up; from the menu, exit)
//
// In MOVE the two scroll buttons work on DIFFERENT axes, which is what makes a
// 256-cell board reachable with two buttons: btn1 steps RIGHT one cell (+1),
// btn3 steps UP one row (-16). Both wrap. Coarse with one, fine with the other
// — worst case 16 + 16 presses instead of up to 255 on a single linear axis.
// A piece overhanging an edge wraps around (torus) rather than clipping;
// clipping would create dead zones where scrolling stops doing anything.
//
// NOTE: Button::isPressed() CLEARS the pending flag. Read each button ONCE per
// loop into a local — calling it twice in one iteration silently swallows the
// press (that bug made both scroll buttons move the same direction).
//
// Include ONCE alongside dice_roll.h / entropy_capture.h, AFTER the colours,
// display, buttons, camera and the global BMA400 `accel`.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_ENTROPY_GRID_H
#define FAVILLA_ENTROPY_GRID_H

#ifndef C_GREEN
#error "entropy_grid.h must be #included AFTER the C_* colours, display, buttons, camera and the global BMA400 'accel'."
#endif

#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#define EG_N        16                       // 16 x 16
#define EG_CELLS    (EG_N * EG_N)            // 256 cells = 256 bits
#define EG_BYTES    (EG_CELLS / 8)           // 32
#define EG_PX       11                       // cell pitch, px
#define EG_X0       32                       // (240 - 16*11) / 2
#define EG_Y0       46
#define EG_MAXCAP   3                        // captured shapes kept (RAM, not policy)

enum { EG_SRC_SE = 0, EG_SRC_CAM = 1, EG_SRC_ACC = 2, EG_SRC_N = 3 };
static const char* const EG_SRC_NAME[EG_SRC_N] = { "SE051", "Camera", "Motion" };

// Menu rows. Order is load-bearing: rows 0..2 map to EG_SRC_*.
static const char* const EG_MENU[] = { "View SE051", "View camera", "View motion",
                                       "Compose", "Mix preview" };
#define EG_MENU_N  ((int)(sizeof(EG_MENU)/sizeof(EG_MENU[0])))

static const uint8_t EG_SIZES[] = { 8, 6, 4, 2 };
#define EG_SIZES_N ((int)(sizeof(EG_SIZES)/sizeof(EG_SIZES[0])))

// ── state ────────────────────────────────────────────────────────────────────
static uint8_t egLive[EG_BYTES];                    // the grid currently on screen
static uint8_t egCap[EG_MAXCAP][EG_BYTES];          // captured shapes
static uint8_t egCapSrc[EG_MAXCAP];                 // which source each came from
static int     egCapN   = 0;
static int     egPick   = 0;                        // which capture is on the cursor
static uint8_t egWork[EG_BYTES];                    // compose board
static uint8_t egPrev[EG_BYTES];                    // mix preview digest
static int     egActions = 0;                       // count only; the log itself is
static mbedtls_sha256_context egLog;                // folded in incrementally (bounded RAM)
static bool    egSrcDead[EG_SRC_N];                 // last refresh produced nothing
static bool    egCamUp   = false;                   // camera rail brought up by us

static inline int  egGet(const uint8_t* g, int i){ return (g[i>>3] >> (7 - (i & 7))) & 1; }
static inline void egSet(uint8_t* g, int i, int v){
  uint8_t m = (uint8_t)(1u << (7 - (i & 7)));
  if(v) g[i>>3] |= m; else g[i>>3] = (uint8_t)(g[i>>3] & ~m);
}

// Fold one action into the running log hash. Keeps RAM flat no matter how long
// the user plays — the alternative (buffering a list) is unbounded by design.
static void egAct(uint8_t kind, uint32_t a, uint32_t b){
  uint8_t rec[13];
  uint32_t t = (uint32_t)millis();
  rec[0] = kind;
  memcpy(rec + 1, &t, 4); memcpy(rec + 5, &a, 4); memcpy(rec + 9, &b, 4);
  mbedtls_sha256_update(&egLog, rec, sizeof(rec));
  egActions++;
}

// ── source refresh: each fills 256 bits, or marks itself dead ────────────────
static void egRefreshSE(){
  uint8_t buf[EG_BYTES];
  if(favilla::se_random(buf, sizeof(buf))){ memcpy(egLive, buf, sizeof(buf)); egSrcDead[EG_SRC_SE] = false; }
  else egSrcDead[EG_SRC_SE] = true;
  mbedtls_platform_zeroize(buf, sizeof(buf));
}

// One frame -> 256 LSBs, sampled across the whole sensor so a partial failure
// shows up as a partial freeze rather than a clean-looking corner.
static void egRefreshCam(){
  camera_fb_t* fb = esp_camera_fb_get();
  if(!fb){ egSrcDead[EG_SRC_CAM] = true; return; }
  if(fb->len < (size_t)EG_CELLS){ esp_camera_fb_return(fb); egSrcDead[EG_SRC_CAM] = true; return; }
  size_t stride = fb->len / EG_CELLS;
  for(int i = 0; i < EG_CELLS; i++) egSet(egLive, i, fb->buf[i * stride] & 1);
  esp_camera_fb_return(fb);
  egSrcDead[EG_SRC_CAM] = false;
}

// Shift new accelerometer LSBs in from the end, so a working sensor visibly
// scrolls and a stalled one visibly stops. 3 axes per read = 3 bits.
static void egRefreshAcc(){
  int16_t x, y, z; int got = 0;
  for(int n = 0; n < 24; n++){
    if(!accel.read(x, y, z)) break;
    for(int k = 0; k < EG_BYTES - 1; k++) egLive[k] = (uint8_t)((egLive[k] << 3) | (egLive[k+1] >> 5));
    egLive[EG_BYTES-1] = (uint8_t)((egLive[EG_BYTES-1] << 3)
                       | (((x & 1) << 2) | ((y & 1) << 1) | (z & 1)));
    got++;
  }
  egSrcDead[EG_SRC_ACC] = (got == 0);
}

static void egRefresh(int src){
  if(src == EG_SRC_SE)       egRefreshSE();
  else if(src == EG_SRC_CAM) egRefreshCam();
  else                       egRefreshAcc();
}

// ── drawing ──────────────────────────────────────────────────────────────────
static void egDrawGrid(const uint8_t* g, uint16_t onCol, uint16_t offCol){
  for(int i = 0; i < EG_CELLS; i++){
    int cx = EG_X0 + (i % EG_N) * EG_PX;
    int cy = EG_Y0 + (i / EG_N) * EG_PX;
    spr.fillRect(cx + 1, cy + 1, EG_PX - 2, EG_PX - 2, egGet(g, i) ? onCol : offCol);
  }
}

static void egFoot(const char* s, uint16_t col){
  fSet(F_SMALL); spr.setTextColor(col); fDrawCentre(s, 120, 233); fEnd();
}

static void egDrawMenu(int sel){
  spr.fillSprite(C_BG);
  uiHeader("Entropy grid", C_GREEN);
  for(int i = 0; i < EG_MENU_N; i++){
    int y = 52 + i * 30;
    bool on = (i == sel);
    if(on) spr.fillRect(18, y - 13, 204, 26, C_AMBER_SOFT);
    fSet(F_BODY); spr.setTextColor(on ? C_GREEN : C_DIM);
    fDrawCentre(EG_MENU[i], 120, y + 4); fEnd();
  }
  char s[40]; snprintf(s, sizeof s, "%d captured  ·  %d actions", egCapN, egActions);
  egFoot(s, C_VDIM);
  dispPush();
}

// mode: 0 view, 1 compose idle, 2 size, 3 move, 4 preview
static void egDrawPage(int mode, int src, bool paused, int si, int cursor){
  spr.fillSprite(C_BG);
  if(mode == 0){
    uiHeader(EG_SRC_NAME[src], paused ? C_AMBER : C_GREEN);
    egDrawGrid(egLive, C_GREEN, C_BORDER2);
    if(egSrcDead[src])   egFoot("no response - source not producing", C_RED);
    else if(paused)      egFoot("paused  ·  ENTER captures", C_AMBER);
    else                 egFoot("live  ·  ENTER pauses", C_DIM);
  } else if(mode == 4){
    uiHeader("Mix preview", C_AMBER);
    egDrawGrid(egPrev, C_AMBER, C_BORDER2);
    char hx[24];
    snprintf(hx, sizeof hx, "%02x%02x%02x..%02x%02x%02x",
             egPrev[0], egPrev[1], egPrev[2], egPrev[29], egPrev[30], egPrev[31]);
    fSet(F_MONO); spr.setTextColor(C_AMBER); fDrawCentre(hx, 120, 233); fEnd();
  } else {
    uiHeader("Compose", C_GREEN);
    egDrawGrid(egWork, C_GREEN, C_BG);
    // Ghost the selected capture in EVERY compose mode, not just once armed —
    // otherwise the piece appears from nowhere and the user cannot tell which
    // captured shape they are about to stamp down.
    if(egCapN > 0){
      const uint8_t* g = egCap[egPick];
      int s = EG_SIZES[si], cx = cursor % EG_N, cy = cursor / EG_N;
      for(int r = 0; r < s; r++) for(int c = 0; c < s; c++){
        int gx = (cx + c) % EG_N, gy = (cy + r) % EG_N;
        spr.fillRect(EG_X0 + gx*EG_PX + 1, EG_Y0 + gy*EG_PX + 1, EG_PX - 2, EG_PX - 2,
                     egGet(g, r*EG_N + c) ? C_AMBER : C_AMBER_DIM);
      }
    }
    if(mode >= 2){   // cursor corner tick, always visible over the ghost
      int cx = cursor % EG_N, cy = cursor / EG_N;
      spr.fillRect(EG_X0 + cx*EG_PX + 1, EG_Y0 + cy*EG_PX + 1, EG_PX - 2, 2, C_GREEN);
      spr.fillRect(EG_X0 + cx*EG_PX + 1, EG_Y0 + cy*EG_PX + 1, 2, EG_PX - 2, C_GREEN);
    }
    char s[52];
    if(mode == 1){
      if(egCapN){
        snprintf(s, sizeof s, "%s #%d  ·  scroll to change", EG_SRC_NAME[egCapSrc[egPick]], egPick + 1);
        egFoot(s, C_DIM);
      } else egFoot("capture a source first", C_RED);
    } else if(mode == 2){
      snprintf(s, sizeof s, "%s #%d   %dx%d  ·  scroll to resize",
               EG_SRC_NAME[egCapSrc[egPick]], egPick + 1, EG_SIZES[si], EG_SIZES[si]);
      egFoot(s, C_AMBER);
    } else {
      snprintf(s, sizeof s, "cell %d   btn1 right  ·  btn3 up", cursor);
      egFoot(s, C_DIM);
    }
  }
  dispPush();
}

// ── mix preview: a FRESH draw from every source + the action log ─────────────
// Deliberately not the composed grid: composing authors a value, which is a
// brainwallet. This only ever ADDS the user's play to a real draw.
static void egMixPreview(){
  mbedtls_sha256_context sha;
  uint8_t se[EG_BYTES], esp[EG_BYTES], logd[32];
  bool haveSE = favilla::se_random(se, sizeof(se));
  esp_fill_random(esp, sizeof(esp));

  mbedtls_sha256_context logCopy;
  mbedtls_sha256_init(&logCopy);
  mbedtls_sha256_clone(&logCopy, &egLog);
  mbedtls_sha256_finish(&logCopy, logd);
  mbedtls_sha256_free(&logCopy);

  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, (const uint8_t*)"FAVILLA-GRID-PREVIEW-V1", 23);
  if(haveSE) mbedtls_sha256_update(&sha, se, sizeof(se));
  mbedtls_sha256_update(&sha, esp,   sizeof(esp));
  mbedtls_sha256_update(&sha, egWork, sizeof(egWork));
  mbedtls_sha256_update(&sha, logd,  sizeof(logd));
  mbedtls_sha256_finish(&sha, egPrev);
  mbedtls_sha256_free(&sha);

  mbedtls_platform_zeroize(se,   sizeof(se));
  mbedtls_platform_zeroize(esp,  sizeof(esp));
  mbedtls_platform_zeroize(logd, sizeof(logd));
  LOG_BOOT("[EGRID] preview fp=%02x%02x se=%d actions=%d\n",
           egPrev[0], egPrev[1], haveSE ? 1 : 0, egActions);
}

// ── camera rail: only up while the camera page is open ──────────────────────
static void egCamUpNow(){
  if(egCamUp) return;
  pwrBoost();
  cameraStart();
  for(int i = 0; i < 4; i++){                       // flush the warm-up frames
    camera_fb_t* f = esp_camera_fb_get();
    if(f) esp_camera_fb_return(f);
    esp_task_wdt_reset(); delay(10);
  }
  egCamUp = true;
}
static void egCamDown(){
  if(!egCamUp) return;
  cameraStop();
  pwrIdle();
  egCamUp = false;
}

// ── the page (blocking, like the other Settings pages) ──────────────────────
static void runEntropyGrid(){
  int mode = -1;                 // -1 menu, 0 view, 1 compose, 2 size, 3 move, 4 preview
  int mi = 0, src = 0, si = 0, cursor = 0;
  bool paused = false;
  uint32_t lastTick = 0;

  egCapN = 0; egActions = 0; egPick = 0;
  memset(egCapSrc, 0, sizeof(egCapSrc));
  memset(egWork, 0, sizeof(egWork));
  memset(egLive, 0, sizeof(egLive));
  for(int i = 0; i < EG_SRC_N; i++) egSrcDead[i] = false;
  mbedtls_sha256_init(&egLog);
  mbedtls_sha256_starts(&egLog, 0);
  mbedtls_sha256_update(&egLog, (const uint8_t*)"FAVILLA-GRID-LOG-V1", 19);
  accel.wakeMode();

  egDrawMenu(mi);

  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();

    if(mode == 0 && !paused && (millis() - lastTick) > 90){
      lastTick = millis();
      egRefresh(src);
      egDrawPage(0, src, paused, si, cursor);
    }

    // Read each button EXACTLY ONCE — isPressed() consumes the press.
    bool kFwd = btn1.isPressed();
    bool kEnt = btn2.isPressed();
    bool kBack = btn3.isPressed();
    bool kExit = btn4.isPressed();

    if(kFwd || kBack){                                    // ── scroll ──
      int d = kFwd ? 1 : -1;
      if(mode == -1){ mi = (mi + d + EG_MENU_N) % EG_MENU_N; egAct(1, (uint32_t)mi, 0); egDrawMenu(mi); }
      else if(mode == 1 && egCapN > 0){                   // choose WHICH capture
        egPick = (egPick + d + egCapN) % egCapN;
        egAct(13, (uint32_t)egPick, 0); egDrawPage(mode, src, paused, si, cursor);
      }
      else if(mode == 2){ si = (si + d + EG_SIZES_N) % EG_SIZES_N; egAct(2, EG_SIZES[si], 0); egDrawPage(mode, src, paused, si, cursor); }
      else if(mode == 3){
        // btn1 -> right one cell, btn3 -> up one row. Both wrap.
        cursor = (cursor + (kFwd ? 1 : (EG_CELLS - EG_N))) % EG_CELLS;
        egAct(3, (uint32_t)cursor, 0); egDrawPage(mode, src, paused, si, cursor);
      }
    }
    else if(kEnt){                                        // ── ENTER ──
      if(mode == -1){
        if(mi < EG_SRC_N){
          src = mi; paused = false; mode = 0;
          if(src == EG_SRC_CAM) egCamUpNow();
          egAct(4, (uint32_t)src, 0);
          egRefresh(src); egDrawPage(0, src, paused, si, cursor);
        } else if(mi == 3){
          mode = 1; egAct(5, 0, 0); egDrawPage(1, src, paused, si, cursor);
        } else {
          egMixPreview(); mode = 4; egAct(6, 0, 0); egDrawPage(4, src, paused, si, cursor);
        }
      }
      else if(mode == 0){
        if(!paused){ paused = true; egAct(7, (uint32_t)src, 0); egDrawPage(0, src, paused, si, cursor); }
        else {
          if(egCapN < EG_MAXCAP){ memcpy(egCap[egCapN], egLive, EG_BYTES); egCapSrc[egCapN] = (uint8_t)src; egCapN++; }
          else {
            memmove(egCap[0], egCap[1], (EG_MAXCAP-1)*EG_BYTES);
            memmove(egCapSrc, egCapSrc + 1, EG_MAXCAP - 1);
            memcpy(egCap[EG_MAXCAP-1], egLive, EG_BYTES); egCapSrc[EG_MAXCAP-1] = (uint8_t)src;
          }
          egPick = egCapN - 1;                            // newest is what you'll place
          buzzerOK(); egAct(8, (uint32_t)src, (uint32_t)egCapN);
          paused = false; egCamDown(); mode = -1; egDrawMenu(mi);
        }
      }
      else if(mode == 1){ if(egCapN){ mode = 2; egAct(9, 0, 0); egDrawPage(2, src, paused, si, cursor); } }
      else if(mode == 2){ mode = 3; egAct(10, EG_SIZES[si], 0); egDrawPage(3, src, paused, si, cursor); }
      else if(mode == 3){
        const uint8_t* g = egCap[egPick];
        int s = EG_SIZES[si], cx = cursor % EG_N, cy = cursor / EG_N;
        for(int r = 0; r < s; r++) for(int c = 0; c < s; c++)
          egSet(egWork, ((cy + r) % EG_N) * EG_N + ((cx + c) % EG_N), egGet(g, r*EG_N + c));
        buzzerOK(); egAct(11, (uint32_t)cursor, (uint32_t)s);
        mode = 1; egDrawPage(1, src, paused, si, cursor);
      }
      else if(mode == 4){ mode = -1; egDrawMenu(mi); }
    }
    else if(kExit){                                       // ── BACK ──
      if(mode == -1) break;
      if(mode == 0){ paused = false; egCamDown(); }
      mode = (mode == 3) ? 2 : ((mode == 2) ? 1 : -1);
      egAct(12, (uint32_t)mode, 0);
      if(mode == -1) egDrawMenu(mi); else egDrawPage(mode, src, paused, si, cursor);
    }

    esp_task_wdt_reset();
    delay(5);
  }

  egCamDown();
  mbedtls_sha256_free(&egLog);
  mbedtls_platform_zeroize(egLive, sizeof(egLive));
  mbedtls_platform_zeroize(egCap,  sizeof(egCap));
  memset(egCapSrc, 0, sizeof(egCapSrc));
  mbedtls_platform_zeroize(egWork, sizeof(egWork));
  mbedtls_platform_zeroize(egPrev, sizeof(egPrev));
  egCapN = 0; egActions = 0;
}

#endif // FAVILLA_ENTROPY_GRID_H
