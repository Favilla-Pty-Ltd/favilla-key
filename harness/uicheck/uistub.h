// Compile-only stub of the firmware surface multisig_ui.inc touches.
// Catches syntax/type errors in the new UI code on the host. NOT a behaviour
// test and NOT used on device.
#pragma once
#include "Arduino.h"
#include <stdint.h>
#include <string.h>
struct QRCodeStub { uint8_t size; };
#define QRCode QRCodeStub
static inline int qrcode_getBufferSize(int v){ return 200*v; }
static inline int qrcode_initText(QRCode* q, uint8_t*, int, int, const char*){ q->size=29; return 0; }
static inline int qrcode_getModule(QRCode*, int, int){ return 1; }
#define ECC_LOW 0
struct Spr {
  void fillSprite(uint16_t){} void fillRect(int,int,int,int,uint16_t){}
  void fillRoundRect(int,int,int,int,int,uint16_t){} void drawString(const char*,int,int){}
  int textWidth(const char*){return 10;} void setTextColor(uint16_t){}
  void drawWideLine(int,int,int,int,int,uint16_t){} void pushSprite(int,int){}
  void drawFastHLine(int,int,int,uint16_t){} void fillCircle(int,int,int,uint16_t){}
};
static Spr spr;
struct Btn { bool isPressed(){return false;} bool isPressedFresh(unsigned long){return false;}
             float holdProgress(int){return 0;} void resetHold(){} void poll(){} };
static Btn btn1, btn2, btn3, btn4;
struct QRTFTStub { void showUrFrame(const char*, int, int){} };
static QRTFTStub qrDisp;
#define C_BG 0
#define C_FG 1
#define C_DIM 2
#define C_TEXT2 3
#define C_MUTED 4
#define C_RED 5
#define C_GREEN 6
#define C_AMBER 7
#define C_BORDER 8
#define C_BTC_ACCENT C_AMBER
#define C_QR_WHITE 9
#define F_HEAD 0
#define F_BODY 1
#define F_SMALL 2
#define F_MONO 3
#define F_HEAD_SM 4
static inline void fSet(int){} static inline void fEnd(){}
static inline void fDrawCentre(const char*, int, int){}
static inline void dispPush(){}
static inline void dispError(const char*){}
static inline bool errorPause(unsigned long ms=4000){ (void)ms; return true; }
static inline void dispSuccess(const char*, const char*, uint16_t c=0){ (void)c; }
static inline void dispSubMenu(const char*, const char**, int, int, uint16_t){}
static inline void uiHeader(const char*, uint16_t c=0){ (void)c; }
static inline void uiPill(int,int,int,int,uint16_t,uint16_t,const char*,bool g=false,uint16_t b=0){ (void)g;(void)b; }
static inline void showQR(const char*, const char* a=nullptr, const char* b=nullptr){ (void)a;(void)b; }
static inline void esp_task_wdt_reset(){}
static inline void delay(int){}
static inline void pwrBoost(){} static inline void pwrIdle(){}
static inline void autoNetCancel(){}
static inline void cameraStart(){} static inline void cameraStop(){}
static inline void clearButtonPending(){}
static inline void drainButtonsAfterTransition(unsigned long a=80, unsigned long b=0){ (void)a;(void)b; }
static inline bool qrScanOnce(){ return false; }
static inline void* ps_malloc(size_t n){ return malloc(n); }
#define QR_AIRGAP_SCAN_INTERVAL_MS 120
#define DISP_LOCK() do{}while(0)
#define DISP_UNLOCK() do{}while(0)
#define LOG_BOOT(...) do{}while(0)
static char qrResultBuf[1024];
static bool qrFound=false;
static bool g_airgapLivePreview=false;
static int g_airgapUrGot=0, g_airgapUrTotal=0;
static unsigned long g_ceremonyStart=0;
static int psbtDrawAddrWrapped(const char*, int, int y, uint16_t){ return y+20; }
static void drawTick(int,int,uint16_t){}
