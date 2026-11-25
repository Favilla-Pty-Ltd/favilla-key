// ─────────────────────────────────────────────────────────────────────────────
// ram_test.h — RAM TEST: prove the boot scrub clears what a life leaves behind
//                                                                   [BENCH ONLY]
// Settings > Device > RAM test   (bench env: pio run -e favilla_key_bench)
//
// Plants a canary across the places a secret really leaves residue, frees it
// (so it is exactly like leftover String copies / buffers), then soft-restarts.
// The next boot scans for it after bootRamScrub() and before any radio:
//
//   planted:  freed internal heap, freed PSRAM, 128 small String-sized blocks,
//             a dead stack frame
//   scanned:  ALL internal DRAM (raw, used + free), all free PSRAM
//
//   SCRUB run    expect 0 hits after restart, radios allowed
//   CONTROL run  the scrub is skipped for that one boot: expect hits > 0 in
//                internal DRAM, and the radio gate refuses WiFi (restart
//                screen). Battery pull afterwards.
//
// Any hit after a restart clears g_scrubOk, so the radio gate refuses that
// life: "anything other than 0 -> no WiFi". The canary is a 16-byte sequence
// derived from a random K, never stored whole in RAM while scanning, so the
// scanner cannot find itself. Nothing secret is involved.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_RAM_TEST_H
#define FAVILLA_RAM_TEST_H
#ifdef FAVILLA_BENCH_PROBES
#include "soc/soc.h"   // SOC_DRAM_LOW / SOC_DRAM_HIGH

extern bool g_scrubOk;

// Feed the task watchdog only if this task is subscribed to it: the boot-time
// scan runs before loop() subscribes, and an unsubscribed reset logs
// "task_wdt: task not found".
static inline void rtWdt(){ if(esp_task_wdt_status(NULL) == ESP_OK) esp_task_wdt_reset(); }
static inline uint32_t rtW(uint32_t K, uint32_t i){
  switch(i & 3){ case 0: return K; case 1: return ~K; case 2: return K ^ 0x5A5A5A5Au; default: return K * 2654435761u; }
}
static void rtFill(void* p, size_t len, uint32_t K){
  uint32_t* w = (uint32_t*)p; size_t n = len / 4;
  for(size_t i = 0; i < n; i++) w[i] = rtW(K, (uint32_t)i);
}
// count 16-byte canary sequences in [p, p+len), word aligned
static uint32_t rtScan(const void* p, size_t len, uint32_t K){
  const volatile uint32_t* w = (const volatile uint32_t*)p; size_t n = len / 4; uint32_t hits = 0;
  uint32_t k1 = ~K, k2 = K ^ 0x5A5A5A5Au, k3 = K * 2654435761u;
  for(size_t i = 0; i + 3 < n; i++){
    if(w[i] != K) continue;
    if(w[i + 1] == k1 && w[i + 2] == k2 && w[i + 3] == k3){ hits++; i += 3; }
  }
  return hits;
}
// Whole internal DRAM, used and free (what an RCE in this life could read).
// Walks IDF's own table of internal memory regions, clipped to the DRAM
// window, so nothing outside real RAM (e.g. SRAM handed to the data cache) is
// touched. Fallback without the table: the DRAM window minus its top 64 KB.
#if __has_include("heap_memory_layout.h")
#include "heap_memory_layout.h"
static uint32_t rtScanInternalRaw(uint32_t K){
  uint32_t hits = 0;
  for(size_t i = 0; i < soc_memory_region_count; i++){
    intptr_t a = soc_memory_regions[i].start, b = a + (intptr_t)soc_memory_regions[i].size;
    if(a < (intptr_t)SOC_DRAM_LOW)  a = SOC_DRAM_LOW;
    if(b > (intptr_t)SOC_DRAM_HIGH) b = SOC_DRAM_HIGH;
    if(b > a) hits += rtScan((const void*)a, (size_t)(b - a), K);
  }
  return hits;
}
#else
static uint32_t rtScanInternalRaw(uint32_t K){
  return rtScan((const void*)SOC_DRAM_LOW, (size_t)(SOC_DRAM_HIGH - SOC_DRAM_LOW - 0x10000), K);
}
#endif
// every free PSRAM block (borrowed, scanned, given back)
static uint32_t rtScanPsramFree(uint32_t K){
  static void* blk[256]; int n = 0; uint32_t hits = 0;
  while(n < 256){
    size_t sz = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if(sz < 64) break;
    void* p = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);
    if(!p){ sz -= 32; p = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM); }
    if(!p) break;
    hits += rtScan(p, sz, K); blk[n++] = p;
    rtWdt();
  }
  for(int i = 0; i < n; i++) heap_caps_free(blk[i]);
  return hits;
}
// fill free memory of one pool with the canary and free it again, leaving headroom
static size_t rtPlantPool(uint32_t caps, size_t headroom, uint32_t K){
  static void* blk[256]; int n = 0; size_t tot = 0;
  while(n < 256){
    size_t freeNow = heap_caps_get_free_size(caps);
    if(freeNow <= headroom) break;
    size_t sz = heap_caps_get_largest_free_block(caps);
    if(sz > freeNow - headroom) sz = freeNow - headroom;
    if(sz < 256) break;
    void* p = heap_caps_malloc(sz, caps);
    if(!p) break;
    rtFill(p, sz, K); tot += sz; blk[n++] = p;
    rtWdt();
  }
  for(int i = 0; i < n; i++) heap_caps_free(blk[i]);
  return tot;
}
static size_t __attribute__((noinline)) rtPlantStack(uint32_t K){
  volatile uint32_t buf[1024];   // 4 KB dead frame, like a seed[] / words[] local
  for(uint32_t i = 0; i < 1024; i++) buf[i] = rtW(K, i);
  return sizeof(buf);
}
static size_t rtPlantSmall(uint32_t K){
  static void* s[128]; size_t tot = 0;   // String-sized: 48 bytes = 3 canaries each
  for(int i = 0; i < 128; i++){ s[i] = malloc(48); if(s[i]){ rtFill(s[i], 48, K); tot += 48; } }
  for(int i = 0; i < 128; i++) if(s[i]){ free(s[i]); s[i] = nullptr; }
  return tot;
}

// Plant, prove it is there, record, restart. control=true skips the next scrub once.
static void rtPlantAndRestart(bool control){
  uint32_t K = esp_random() | 1u;
  Serial.printf("[RAMTEST] ===== planting canary (%s run) =====\n", control ? "CONTROL - scrub skipped next boot" : "SCRUB");
  size_t pSmall = rtPlantSmall(K);
  size_t pStack = rtPlantStack(K);
  size_t pInt   = rtPlantPool(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT, 48 * 1024, K);
  size_t pPs    = rtPlantPool(MALLOC_CAP_SPIRAM, 512 * 1024, K);
  uint32_t hInt = rtScanInternalRaw(K);
  uint32_t hPs  = rtScanPsramFree(K);
  Serial.printf("[RAMTEST] planted: %u KB internal heap, %u KB PSRAM, %u B small blocks, %u B stack\n",
                (unsigned)(pInt / 1024), (unsigned)(pPs / 1024), (unsigned)pSmall, (unsigned)pStack);
  Serial.printf("[RAMTEST] BEFORE restart: %u canaries in internal DRAM, %u in free PSRAM (must be > 0, or the plant failed)\n",
                (unsigned)hInt, (unsigned)hPs);
  Preferences p;
  if(p.begin("ramtest", false)){
    p.putUInt("K", K); p.putUChar("pending", 1); p.putUChar("mode", control ? 1 : 0);
    p.putUInt("bInt", hInt); p.putUInt("bPs", hPs); p.putUInt("pKB", (uint32_t)((pInt + pPs) / 1024));
    if(control) p.putUChar("skip", 1);
    p.end();
  }
  K = 0;
  Serial.println("[RAMTEST] restarting (soft) ..."); Serial.flush();
  delay(100);
  ESP.restart();
}

// Called from setup() after the scrub, before any radio. Logs, stores, and
// clears g_scrubOk on any hit.
static void ramTestBootCheck(){
  Preferences p;
  if(!p.begin("ramtest", false)) return;
  bool pending = p.getUChar("pending", 0) == 1;
  if(!pending){ p.end(); return; }
  uint32_t K = p.getUInt("K", 0);
  uint8_t mode = p.getUChar("mode", 0);
  p.putUChar("pending", 0);
  uint32_t hInt = rtScanInternalRaw(K);
  uint32_t hPs  = rtScanPsramFree(K);
  p.putUInt("aInt", hInt); p.putUInt("aPs", hPs); p.putUChar("done", 1);
  p.end();
  K = 0;
  Serial.printf("[RAMTEST] ===== AFTER soft restart (%s run) =====\n", mode ? "CONTROL, scrub skipped" : "SCRUB");
  Serial.printf("[RAMTEST] canaries found: %u in internal DRAM (used + free), %u in free PSRAM\n", (unsigned)hInt, (unsigned)hPs);
  if(hInt || hPs){
    g_scrubOk = false;
    Serial.printf("[RAMTEST] RESULT: leftovers SURVIVED the restart -> radio gate will REFUSE WiFi this life%s\n",
                  mode ? " (expected for the control run)" : " - SCRUB FAILED");
  } else {
    Serial.printf("[RAMTEST] RESULT: nothing survived%s\n", mode ? " (PSRAM/DRAM wiped by the boot path itself)" : " - scrub PASS");
  }
}

static void rtDraw(int sel){
  fEnd(); spr.fillSprite(C_BG);
  uiHeader("RAM TEST", C_AMBER);
  Preferences p; uint32_t bI = 0, bP = 0, aI = 0, aP = 0, kb = 0; uint8_t done = 0, mode = 0;
  if(p.begin("ramtest", true)){
    done = p.getUChar("done", 0); mode = p.getUChar("mode", 0);
    bI = p.getUInt("bInt", 0); bP = p.getUInt("bPs", 0); aI = p.getUInt("aInt", 0); aP = p.getUInt("aPs", 0); kb = p.getUInt("pKB", 0);
    p.end();
  }
  fSet(F_SMALL);
  char ln[40];
  if(done){
    spr.setTextColor(C_MUTED);
    snprintf(ln, sizeof ln, "Last: %s, %u KB planted", mode ? "CONTROL" : "SCRUB", (unsigned)kb); fDrawCentre(ln, 120, 44);
    spr.setTextColor(C_TEXT2);
    snprintf(ln, sizeof ln, "Before: %u DRAM  %u PSRAM", (unsigned)bI, (unsigned)bP); fDrawCentre(ln, 120, 64);
    spr.setTextColor((aI || aP) ? C_RED : C_GREEN);
    snprintf(ln, sizeof ln, "After:  %u DRAM  %u PSRAM", (unsigned)aI, (unsigned)aP); fDrawCentre(ln, 120, 84);
    snprintf(ln, sizeof ln, "WiFi this life: %s", g_scrubOk ? "allowed" : "REFUSED"); fDrawCentre(ln, 120, 104);
  } else {
    spr.setTextColor(C_MUTED); fDrawCentre("No result yet.", 120, 64);
  }
  const char* opt[2] = { "Plant + restart", "Control: no scrub" };
  for(int i = 0; i < 2; i++){
    int y = 134 + i * 30;
    spr.setTextColor(i == sel ? C_AMBER : C_TEXT2);
    fDrawCentre(opt[i], 120, y);
  }
  spr.setTextColor(C_DIM); fDrawCentre("OK = run   BACK = leave", 120, 210);
  fEnd(); dispPush();
}

static void runRamTest(){
  int sel = 0;
  rtDraw(sel);
  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    esp_task_wdt_reset();
    if(btn4.isPressed()) return;
    if(btn1.isPressed() || btn3.isPressed()){ sel ^= 1; rtDraw(sel); }
    if(btn2.isPressed()){
      spr.fillSprite(C_BG); uiHeader("RAM TEST", C_AMBER);
      fSet(F_BODY); spr.setTextColor(C_TEXT2); fDrawCentre("Planting, then restart", 120, 116); fEnd(); dispPush();
      rtPlantAndRestart(sel == 1);   // never returns
    }
    delay(10);
  }
}

#endif  // FAVILLA_BENCH_PROBES
#endif  // FAVILLA_RAM_TEST_H
