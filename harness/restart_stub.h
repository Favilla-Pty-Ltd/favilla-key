/* restart_stub.h — extra host stand-ins for entropy_restart.h. Nothing ships. */
#ifndef RESTART_STUB_H
#define RESTART_STUB_H
#include "quad_stub.h"
#include <math.h>
#include <stdarg.h>

/* Serial */
struct SerialT {
  void print(const char* s){ fputs(s, stdout); }
  void println(const char* s){ puts(s); }
  int printf(const char* f, ...){ va_list a; va_start(a,f); int n=vprintf(f,a); va_end(a); return n; }
};
static SerialT Serial;

#define g_sensor g_sens   /* the shared handle lives in quad_stub.h */
static int g_railResets = 1;          /* 0 = sensor keeps state across a rail cut */


/* camera power helpers */
static int g_powerCycles = 0, g_suspends = 0, g_resumes = 0;
static int g_sensorConfigured = 1;   /* 0 = blank sensor: fb_get yields nothing */
static void cameraPowerDown(void){ g_powerCycles++; g_sensorConfigured = 0;
                                   if(g_railResets) memset(g_sensor.regs,0,sizeof g_sensor.regs); }
static bool cameraPowerUp(void){ return true; }
static void cameraSuspendHW(void){ g_suspends++; g_sensorConfigured = 0;
                                   if(g_railResets) memset(g_sensor.regs,0,sizeof g_sensor.regs); }
static bool cameraResumeHW(void){ g_resumes++; g_sensorConfigured = 1; return true; }

/* PSRAM + power-management stand-ins */
static inline void* ps_malloc(size_t n){ return malloc(n); }
static unsigned long lastActivity = 0;
static int g_wakeHold = 0;
static inline void pmHoldWake(void){ g_wakeHold++; }
static inline void pmReleaseWake(void){ if(g_wakeHold>0) g_wakeHold--; }
#endif
