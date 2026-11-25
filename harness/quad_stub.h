/* quad_stub.h — minimal host stand-ins for the device APIs entropy_quad.h uses.
 * Enough to compile and drive the page under ASan/UBSan on a PC. Nothing here
 * ships. Drawing is recorded, not rendered. */
#ifndef QUAD_STUB_H
#define QUAD_STUB_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define C_BG 0x0000
#define C_FG 0xFFFF
#define C_AMBER 0xF480
#define C_GREEN 0x8660
#define C_RED 0xF800
#define C_BLUE 0x035F
#define C_CYAN 0x07FF
#define C_DIM 0x738E
#define C_VDIM 0x4A49
#define C_BORDER2 0x2945
#define C_TEXT2 0x9CF3
#define C_MUTED 0x9492

#define F_TITLE 0
#define F_HEAD 1
#define F_BODY 2
#define F_SMALL 3
#define F_HEAD_SM 5
#define F_DISPLAY 6
#define F_TITLE 0
#define F_MONO 4
#define F_MONO 4

/* ── fake clock ───────────────────────────────────────────────────────────── */
static uint32_t g_ms = 0;
static uint32_t g_spins = 0;
static inline uint32_t millis(void){ return g_ms; }
static inline void delay(uint32_t m){
  g_ms += m ? m : 1;
  /* A blocking device page never returns on its own. If a test script runs out
   * of presses the page would spin forever, so bail loudly rather than hang. */
  if(++g_spins > 4000000u){ fprintf(stderr, "STUB: page never exited\n"); exit(2); }
}
static inline void esp_task_wdt_reset(void){}

/* ── display ──────────────────────────────────────────────────────────────── */
/* Text draws are recorded so a test can assert nothing is painted over the
 * grid. Every text helper funnels through txtRec(). */
#define TXTMAX 64
static int g_txtY[TXTMAX]; static int g_txtN = 0;
static inline void txtRec(int y){ if(g_txtN < TXTMAX) g_txtY[g_txtN++] = y; }
static inline void txtReset(void){ g_txtN = 0; }

struct Spr {
  void fillSprite(uint16_t){}
  void fillRect(int,int,int,int,uint16_t){}
  void drawRect(int,int,int,int,uint16_t){}
  void drawRoundRect(int,int,int,int,int,uint16_t){}
  void fillRoundRect(int,int,int,int,int,uint16_t){}
  void drawFastVLine(int,int,int,uint16_t){}
  void drawFastHLine(int,int,int,uint16_t){}
  void setTextColor(uint16_t){}
  void drawString(const char*,int,int y){ txtRec(y); }
  int  textWidth(const char* s){ return (int)strlen(s) * 7; }
};
static Spr spr;
static inline void fSet(int){}
static inline void fEnd(void){}
static inline void fDrawCentre(const char*,int,int y){ txtRec(y); }
static inline void fDrawRight(const char*,int,int y){ txtRec(y); }
static inline void uiCard(int,int,const char*,const char*,bool,unsigned short=0){}
static inline void uiHeader(const char*, uint16_t = 0xF480){}
static inline void dispPush(void){}
static inline void buzzerOK(void){}
static inline void pwrBoost(void){}
static inline void pwrIdle(void){}
static char g_lastQr[128];
static inline void showQR(const char* m, const char* = nullptr, const char* = nullptr){
  snprintf(g_lastQr, sizeof g_lastQr, "%s", m);
}

/* ── buttons: driven from a scripted queue ────────────────────────────────── */
#define KEYQ 256
#define KEY_IDLE 9                       /* consume loop time without a press */
static uint8_t g_keys[KEYQ]; static int g_keyN = 0, g_keyI = 0;   /* 1..4 */
static uint8_t g_pending = 0;                                     /* consumed by isPressed */
static int g_idle = 0;
static void keyPush(uint8_t k){ if(g_keyN < KEYQ) g_keys[g_keyN++] = k; }
static void keyWait(void){ keyPush(KEY_IDLE); }                   /* ~400 loop iterations */
static void keyReset(void){ g_keyN = g_keyI = 0; g_pending = 0; g_idle = 0; g_spins = 0; }
static int  g_keysLeft(void){ return g_keyN - g_keyI; }

struct Btn {
  uint8_t id;
  void poll(){
    if(id != 1 || g_pending) return;
    if(g_idle > 0){ g_idle--; return; }
    if(g_keyI >= g_keyN){ g_pending = 4; return; }  /* exhausted -> hold BACK to unwind */
    uint8_t k = g_keys[g_keyI++];
    if(k == KEY_IDLE){ g_idle = 400; return; }
    g_pending = k;
  }
  bool isPressed(){ if(g_pending == id){ g_pending = 0; return true; } return false; }
};
/* btn1 polls first in every loop, so it advances the queue for all four. */
static Btn btn1{1}, btn2{2}, btn3{3}, btn4{4};

/* ── accelerometer ────────────────────────────────────────────────────────── */
static int  g_accMode = 0;      /* 0 = noisy, 1 = frozen LSBs, 2 = no ACK */
static struct Accel {
  void wakeMode(){}
  bool read(int16_t& x, int16_t& y, int16_t& z){
    if(g_accMode == 2) return false;
    static uint32_t s = 12345;
    s = s * 1664525u + 1013904223u;
    if(g_accMode == 1){ x = 10; y = (int16_t)(-20 + (int)((s >> 20) & 3) * 2); z = -512; return true; }
    x = (int16_t)(10 + (int)((s >> 3) & 7));
    y = (int16_t)(-20 + (int)((s >> 9) & 7));
    z = (int16_t)(-512 + (int)((s >> 15) & 15));
    return true;
  }
} accel;

/* ── camera ───────────────────────────────────────────────────────────────── */
typedef struct { uint8_t* buf; size_t len; int width; int height; } camera_fb_t;
static int g_camMode = 0;       /* 0 = lit, 1 = dark, 2 = no frames */
#define STUBW 76800
static uint8_t g_fbuf[STUBW];
static camera_fb_t g_fb = { g_fbuf, STUBW, 320, 240 };
static inline void cameraStart(void){}
static inline void cameraStop(void){}
static camera_fb_t* esp_camera_fb_get(void){
  if(g_camMode == 2) return nullptr;
  static uint32_t s = 999;
  for(size_t i = 0; i < STUBW; i++){
    s = s * 1103515245u + 12345u;
    if(g_camMode == 1){
      /* dark: 2.91% flip per frame -> 0.9434 frame-to-frame agreement,
         which is what the covered-lens hardware capture measured */
      g_fbuf[i] = (uint8_t)((((s >> 16) % 10000) < 291) ? ((i & 1) ^ 1) : (i & 1));
    } else {
      g_fbuf[i] = (uint8_t)(100 + ((s >> 16) & 31));
    }
  }
  return &g_fb;
}
static inline void esp_camera_fb_return(camera_fb_t*){}

/* sensor handle — the overlay page sets gain/exposure on the camera layer */
typedef int gainceiling_t;
struct sensor_t {
  int regs[256];                      /* for the restart tool's power probe */
  int (*set_exposure_ctrl)(sensor_t*,int);
  int (*set_gain_ctrl)(sensor_t*,int);
  int (*set_aec2)(sensor_t*,int);
  int (*set_aec_value)(sensor_t*,int);
  int (*set_agc_gain)(sensor_t*,int);
  int (*set_gainceiling)(sensor_t*,gainceiling_t);
  int (*set_reg)(sensor_t*,int,int,int);
  int (*get_reg)(sensor_t*,int,int);
};
static int g_camGain=-1, g_camAec=-1;
static int stubSetI(sensor_t*,int){ return 0; }
static int stubAec(sensor_t*,int v){ g_camAec=v; return 0; }
static int stubGain(sensor_t*,int v){ g_camGain=v; return 0; }
static int stubCeil(sensor_t*,gainceiling_t){ return 0; }
static int stubSetReg(sensor_t* s,int r,int,int v){ s->regs[r & 0xFF]=v; return 0; }
static int stubGetReg(sensor_t* s,int r,int){ return s->regs[r & 0xFF]; }
static sensor_t g_sens = { {0}, stubSetI, stubSetI, stubSetI, stubAec, stubGain,
                           stubCeil, stubSetReg, stubGetReg };
static sensor_t* esp_camera_sensor_get(void){ return &g_sens; }

/* ── RNG ──────────────────────────────────────────────────────────────────── */
static int g_seMode = 0;        /* 0 = ok, 1 = fail, 2 = constant */
static inline void esp_fill_random(void* p, size_t n){
  static uint32_t s = 777;
  uint8_t* b = (uint8_t*)p;
  for(size_t i = 0; i < n; i++){ s = s * 22695477u + 1u; b[i] = (uint8_t)(s >> 16); }
}
namespace favilla {
  static inline bool se_random(uint8_t* out, size_t n){
    if(g_seMode == 1) return false;
    if(g_seMode == 2){ memset(out, 0, n); return true; }
    static uint32_t s = 4242;
    for(size_t i = 0; i < n; i++){ s = s * 69069u + 5u; out[i] = (uint8_t)(s >> 13); }
    return true;
  }
}
#endif
