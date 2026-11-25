// =============================================================================
// vchan_hid.h - the Favilla channel: a vendor HID interface for the browser
// extension (WebHID) and later the Android app (Vault phase 5 stage 2, PROBE,
// 4 Nov 2026). Its own interface, never part of the keyboard: on a Mac,
// anything inside a keyboard interface needs Input Monitoring, and Chrome
// blocks keyboard collections from WebHID.
//
// 4 Nov 2026 (stage 2): PING as in the probe, plus the channel protocol
// (chan_proto.h framing; pairing and signed requests in chan_key.h, run by the
// vault glue in passkey_life.inc through g_onMsg). Any web page can ask the user
// to pick the KEY in WebHID's chooser, so nothing is accepted unpaired.
//
// Interface: HID, vendor usage page 0xFF46 usage 0x01, 64-byte input and
// output reports, no report IDs, interrupt IN and OUT, 1 ms. Registered in
// Arduino's MIDI slot (free; the slot is only a place in the configuration
// descriptor) so it lands after the serial port and before the keyboard.
// Endpoints: the ESP32-S3 has 4 IN endpoints besides EP0. With the USB serial
// port on they are full (serial x2, FIDO, keyboard), and 6d proved a 5th kills
// enumeration. So this interface exists only in builds with the serial port
// off (envs favilla_key_fido_vchan and favilla_key_fido_pmv, and later release):
// FIDO, this, keyboard. Served by our class driver (claims only its own interface).
//
// 11u (11 Nov 2026, Josh: "we need this all in one build"): the bench log and
// console ride on this interface too, BENCH BUILDS ONLY (FAVILLA_BENCH_PROBES),
// so the pm build can carry the channel without its serial port:
//  LOG (0x02)  the host pulls the KEY's log from a 16 KB PSRAM ring (the
//              UART0 loopback drain in main.cpp fills it): [0x02][cursor u32 LE]
//              [want u8 <= 32]. Answered with up to `want` reports of
//              [0x82][flags][len][next cursor u32 LE][57 bytes]; flags bit0 =
//              more waiting, bit1 = the cursor was behind the ring (lines lost).
//              Sent from the USB task as a chain (one report per IN completion),
//              so it works in every life, before the channel task exists.
//  CON (0x03)  one console line: [0x03][len][text]. Queued for the same readers
//              that take the serial console (CON_READ in main.cpp).
// Both are unauthenticated, like PING: any page the user picks in WebHID's
// chooser can read the bench log. Bench builds never ship (platformio.ini).
// =============================================================================
#pragma once
#if defined(FAVILLA_FIDO_PROBE) && defined(FAVILLA_VCHAN)   // the vchan and pmv envs (no serial port: the endpoints are full with it)
#include <Arduino.h>
#include "esp32-hal-tinyusb.h"
#include "tusb.h"
#include "device/usbd_pvt.h"
#include "chan_proto.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "kbd_hid.h"   // the other app driver, handed over together below

namespace vchan {

static const uint8_t REPORT_DESC[] = {
  0x06, 0x46, 0xFF,   // Usage Page (Vendor 0xFF46)
  0x09, 0x01,         // Usage (1: Favilla channel)
  0xA1, 0x01,         // Collection (Application)
  0x09, 0x02,         //   Usage (2: from the KEY)
  0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,   // 0..255, 8 bits, 64 of them
  0x81, 0x02,         //   Input (Data, Var, Abs)
  0x09, 0x03,         //   Usage (3: to the KEY)
  0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
  0x91, 0x02,         //   Output (Data, Var, Abs)
  0xC0                // End Collection
};
constexpr uint8_t PROTO = 1;            // probe protocol
constexpr uint8_t CMD_PING = 0x01, RSP_PING = 0x81, RSP_UNKNOWN = 0xFF;
constexpr uint8_t CMD_LOG = 0x02, RSP_LOG = 0x82, CMD_CON = 0x03;   // 11u, bench builds only
// 11eg (24 Nov 2026): ATT, the KEY's device (attestation) public key and its
// self-test signature, for the Forge. Request [0x04][part]; answer
// [0x84][state][part][32 or 33 bytes]:
//   part 0: the public key (33, SEC1 compressed), then the drop name (8, NUL padded)
//   part 1: the self-test signature r (32)     part 2: its s (32)
// The signature is over the fixed self-test vector (se_attest_selftest), made at
// boot, so the Forge can check the key really signs inside this KEY's SE.
// state 1 = present, 0 = not read yet (boot still running: ask again), 2 = none
// and making one failed. Every build with the channel and every life: answered
// from the USB task out of copies the boot made; no chip is touched here.
// Unauthenticated, like PING: nothing in it is secret.
constexpr uint8_t CMD_ATT = 0x04, RSP_ATT = 0x84;
static uint8_t s_attPk[33] = {0}, s_attSig[64] = {0};
static volatile uint8_t s_attState = 0;
static uint8_t s_attTx[64];
inline void setAttest(const uint8_t* pk33, const uint8_t* sig64, uint8_t state) {
  if (pk33) memcpy(s_attPk, pk33, 33);
  if (sig64) memcpy(s_attSig, sig64, 64);
  s_attState = state;
}

// 25 Nov 2026 (#74): WDT, the `wdt last` report, for builds without a serial
// console (release, pmv). Request [0x05]; answer, little-endian:
//   [0x85][reset reason (esp_reset_reason_t)][crumb valid 0/1]
//   [watchdog restarts since power on u32][uptime at the last one, ms u32]
//   [UI state then i32][I2C lock holder 16][display lock holder 16][CPU1 task 16]
// The crumb fields mean something only when valid is 1. Taken at boot, so it
// describes how this life started. Unauthenticated: task names, no secrets.
constexpr uint8_t CMD_WDT = 0x05, RSP_WDT = 0x85;
static uint8_t s_wdt[63] = {0};
static uint8_t s_wdtTx[64];
inline void setWdt(uint8_t reason, bool valid, uint32_t count, uint32_t upMs, int32_t state,
                   const char* i2c, const char* disp, const char* cpu1) {
  uint8_t* p = s_wdt;
  *p++ = RSP_WDT; *p++ = reason; *p++ = valid ? 1 : 0;
  memcpy(p, &count, 4); p += 4; memcpy(p, &upMs, 4); p += 4; memcpy(p, &state, 4); p += 4;
  strncpy((char*)p, valid ? i2c : "", 16); p += 16;
  strncpy((char*)p, valid ? disp : "", 16); p += 16;
  strncpy((char*)p, valid ? cpu1 : "", 16);
}

static uint8_t s_itf = 0xFF, s_epIn = 0, s_epOut = 0;
static volatile bool s_open = false, s_inBusy = false;
static uint8_t s_rx[64], s_tx[64];
#ifdef FAVILLA_BENCH_PROBES
#include <esp_system.h>   // 11ad: esp_reset_reason for the [PREV] banner
#include <esp_attr.h>
// ---- 11u: the bench log ring and the console line queue ----------------------
constexpr uint32_t LOG_CAP = 16384;      // PSRAM; a power of two
static uint8_t* s_log = nullptr;
static volatile uint32_t s_logW = 0;     // bytes ever written (monotonic); the ring holds the last LOG_CAP
static uint8_t s_logTx[64];              // the report in flight for a LOG chain (not s_tx: the channel task owns that)
static volatile uint32_t s_logCur = 0; static volatile uint8_t s_logLeft = 0;   // the chain: next cursor, reports still to send
static volatile uint32_t s_logPulls = 0, s_conLines = 0, s_conDrop = 0;
static char s_con[512]; static volatile uint16_t s_conW = 0, s_conR = 0;        // console bytes from the host, one producer (USB task) one consumer (main loop)
// 11ad (11 Nov 2026): the last words. The PSRAM ring is gone after a reset,
// so a crash took its own evidence with it (bench: the BTC door reset with
// nothing to read). A 2 KB mirror of the newest log bytes lives in RTC slow
// memory, which survives every reset but a power-off, and is replayed into
// the new ring at boot under a [PREV] banner with the reset reason.
constexpr uint32_t LW_CAP = 2048;
struct LastWords { uint32_t magic; uint32_t w; uint8_t ring[LW_CAP]; };
static RTC_NOINIT_ATTR LastWords s_lw;
inline bool logBegin() {
  if (s_log) return true;
  s_log = (uint8_t*)heap_caps_malloc(LOG_CAP, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_log) return false;
  if (s_lw.magic == 0x4C575631u && s_lw.w) {   // 'LWV1': a previous life left its last words
    const int rr = (int)esp_reset_reason();
    char head[96]; int hn = snprintf(head, sizeof head, "\n[PREV] ---- the last %u bytes of the previous life (reset reason %d: %s) ----\n",
                                      (unsigned)(s_lw.w < LW_CAP ? s_lw.w : LW_CAP), rr,
                                      rr == 1 ? "power on" : rr == 3 ? "software" : rr == 4 ? "PANIC" : rr == 5 ? "interrupt watchdog" : rr == 6 ? "task watchdog" : rr == 7 ? "other watchdog" : rr == 8 ? "deep sleep" : rr == 9 ? "brownout" : "other");
    uint32_t w = s_logW; for (int i = 0; i < hn; i++) s_log[(w + i) & (LOG_CAP - 1)] = (uint8_t)head[i]; s_logW = w + hn;
    const uint32_t n = s_lw.w < LW_CAP ? s_lw.w : LW_CAP, from = s_lw.w - n;
    w = s_logW; for (uint32_t i = 0; i < n; i++) s_log[(w + i) & (LOG_CAP - 1)] = s_lw.ring[(from + i) & (LW_CAP - 1)]; s_logW = w + n;
    static const char tail[] = "\n[PREV] ---- end of the previous life ----\n";
    w = s_logW; for (size_t i = 0; i < sizeof tail - 1; i++) s_log[(w + i) & (LOG_CAP - 1)] = (uint8_t)tail[i]; s_logW = w + (sizeof tail - 1);
  }
  s_lw.magic = 0x4C575631u; s_lw.w = 0;
  return true;
}
// Any task. Bytes beyond the ring's size overwrite the oldest.
inline void logPut(const uint8_t* b, size_t n) {
  if (!s_log || !n) return;
  uint32_t w = s_logW;
  for (size_t i = 0; i < n; i++) s_log[(w + i) & (LOG_CAP - 1)] = b[i];
  s_logW = w + (uint32_t)n;
  uint32_t lw = s_lw.w;
  for (size_t i = 0; i < n; i++) s_lw.ring[(lw + i) & (LW_CAP - 1)] = b[i];
  s_lw.w = lw + (uint32_t)n;
}
inline int conAvailable() { return (int)((uint16_t)(s_conW - s_conR) % sizeof s_con); }
inline int conRead() { if (s_conW == s_conR) return -1; char c = s_con[s_conR]; s_conR = (uint16_t)((s_conR + 1) % sizeof s_con); return (uint8_t)c; }
static void conPush(const uint8_t* t, size_t n) {   // USB task
  size_t room = sizeof s_con - 1 - (size_t)conAvailable();
  if (n + 1 > room) { s_conDrop++; return; }
  for (size_t i = 0; i < n; i++) { s_con[s_conW] = (char)t[i]; s_conW = (uint16_t)((s_conW + 1) % sizeof s_con); }
  s_con[s_conW] = '\n'; s_conW = (uint16_t)((s_conW + 1) % sizeof s_con);
  s_conLines++;
}
// One report of the LOG chain, from the USB task (the OUT handler or the IN
// completion). Claims the IN endpoint itself; the channel task's sendReport
// sees s_inBusy and waits its turn.
static void logNext(uint8_t rhport) {
  if (!s_logLeft || !s_open) { s_logLeft = 0; return; }
  if (!usbd_edpt_claim(rhport, s_epIn)) { s_logLeft = 0; return; }   // the channel task has it; the host pulls again
  uint32_t w = s_logW, cur = s_logCur; uint8_t flags = 0;
  if (w - cur > LOG_CAP) { cur = w - LOG_CAP; flags |= 2; }
  uint32_t have = w - cur, n = have > 57 ? 57 : have;
  memset(s_logTx, 0, 64);
  s_logTx[0] = RSP_LOG; s_logTx[2] = (uint8_t)n;
  for (uint32_t i = 0; i < n; i++) s_logTx[7 + i] = s_log[(cur + i) & (LOG_CAP - 1)];
  cur += n; memcpy(s_logTx + 3, &cur, 4);
  s_logLeft--;
  if (w - cur > 0 && s_logLeft) flags |= 1; else s_logLeft = 0;
  s_logTx[1] = flags; s_logCur = cur;
  s_inBusy = true;
  if (!usbd_edpt_xfer(rhport, s_epIn, s_logTx, 64)) { s_inBusy = false; usbd_edpt_release(rhport, s_epIn); s_logLeft = 0; }
}
#endif
static volatile uint32_t s_rxN = 0, s_txN = 0, s_txFail = 0, s_pings = 0, s_unknown = 0;
static uint32_t s_descErr = 0;

static uint16_t descCb(uint8_t* dst, uint8_t* itf) {
  uint8_t str = tinyusb_add_string_descriptor("Favilla KEY channel");
  uint8_t in = tinyusb_get_free_in_endpoint(), out = tinyusb_get_free_out_endpoint();
  if (!in || !out) s_descErr++;
  s_itf = *itf; s_epIn = (uint8_t)(0x80 | in); s_epOut = out;
  uint8_t d[TUD_HID_INOUT_DESC_LEN] = { TUD_HID_INOUT_DESCRIPTOR(*itf, str, HID_ITF_PROTOCOL_NONE, sizeof(REPORT_DESC), out, (uint8_t)(0x80 | in), 64, 1) };
  *itf += 1;
  memcpy(dst, d, sizeof d);
  return sizeof d;
}

static void primeOut(uint8_t rhport) { if (s_open && usbd_edpt_claim(rhport, s_epOut)) { if (!usbd_edpt_xfer(rhport, s_epOut, s_rx, 64)) usbd_edpt_release(rhport, s_epOut); } }
// 11eg: one ATT answer, from the USB task. If the IN endpoint is busy the host asks again.
static void attAnswer(uint8_t rhport, uint8_t part) {
  if (!s_open || s_inBusy || !usbd_edpt_claim(rhport, s_epIn)) return;
  memset(s_attTx, 0, 64);
  s_attTx[0] = RSP_ATT; s_attTx[1] = s_attState; s_attTx[2] = part;
  if (s_attState == 1) {
    if (part == 0) { memcpy(s_attTx + 3, s_attPk, 33); strncpy((char*)s_attTx + 36, FAVILLA_BENCH_DROP, 8); }
    else if (part == 1) memcpy(s_attTx + 3, s_attSig, 32);
    else if (part == 2) memcpy(s_attTx + 3, s_attSig + 32, 32);
  }
  s_inBusy = true;
  if (!usbd_edpt_xfer(rhport, s_epIn, s_attTx, 64)) { s_inBusy = false; usbd_edpt_release(rhport, s_epIn); }
}

static void wdtAnswer(uint8_t rhport) {
  if (!s_open || s_inBusy || !usbd_edpt_claim(rhport, s_epIn)) return;
  memset(s_wdtTx, 0, 64); memcpy(s_wdtTx, s_wdt, sizeof s_wdt);
  if (!s_wdtTx[0]) s_wdtTx[0] = RSP_WDT;   // boot has not filled it yet: all zero
  s_inBusy = true;
  if (!usbd_edpt_xfer(rhport, s_epIn, s_wdtTx, 64)) { s_inBusy = false; usbd_edpt_release(rhport, s_epIn); }
}

// ---- the channel task (4 Nov 2026, stage 2) ------------------------------------
// Reports arrive in the USB task (drvXfer) and are queued; this task answers
// PINGs, reassembles messages and hands each to the handler (the vault glue in
// passkey_life.inc). Replies go out through sendMsg from this task or the UI.
struct Rep { uint8_t b[64]; };
static QueueHandle_t s_q = nullptr;
static SemaphoreHandle_t s_txMx = nullptr;
void (*g_onMsg)(const uint8_t* m, size_t n) = nullptr;
static volatile uint32_t s_qDrop = 0, s_frameErr = 0, s_msgs = 0;
static bool sendReport(const uint8_t r[64]) {
  if (!s_open || !tud_mounted()) { s_txFail++; return false; }
  uint32_t t0 = millis();
  for (;;) {   // 11u: a LOG chain (USB task) may hold the endpoint for a few ms; wait for it rather than fail
    while (s_inBusy) { if (millis() - t0 > 300) { s_txFail++; return false; } vTaskDelay(1); }
    if (usbd_edpt_claim(0, s_epIn)) break;
    if (millis() - t0 > 300) { s_txFail++; return false; }
    vTaskDelay(1);
  }
  memcpy(s_tx, r, 64); s_inBusy = true;
  if (!usbd_edpt_xfer(0, s_epIn, s_tx, 64)) { s_inBusy = false; usbd_edpt_release(0, s_epIn); s_txFail++; return false; }
  t0 = millis();
  while (s_inBusy) { if (millis() - t0 > 300) { s_txFail++; return false; } vTaskDelay(1); }
  s_txN++;
  return true;
}
// One message, split into reports. Safe from any task.
inline bool sendMsg(const uint8_t* m, size_t n) {
  static uint8_t r[(chan::MSG_MAX / 62) + 2][64];
  if (!s_txMx) return false;
  xSemaphoreTake(s_txMx, portMAX_DELAY);
  int k = chan::fragment(m, n, r, (int)(sizeof r / 64));
  bool ok = k > 0;
  for (int i = 0; ok && i < k; i++) ok = sendReport(r[i]);
  xSemaphoreGive(s_txMx);
  return ok;
}
static void task(void*) {
  static chan::Reasm ra;
  Rep p;
  for (;;) {
    if (xQueueReceive(s_q, &p, portMAX_DELAY) != pdTRUE) continue;
    if (p.b[0] == CMD_PING) {
      s_pings++;
      uint8_t t[64] = {0};
      t[0] = RSP_PING; memcpy(t + 1, "FAVILLA", 7); t[8] = PROTO;
      memcpy(t + 9, p.b + 1, 8);   // the host's nonce, echoed
      strncpy((char*)t + 17, FAVILLA_BENCH_DROP, 8);
      uint32_t c = s_pings; memcpy(t + 25, &c, 4);
      if (s_txMx) { xSemaphoreTake(s_txMx, portMAX_DELAY); sendReport(t); xSemaphoreGive(s_txMx); }
      continue;
    }
    int n = ra.feed(p.b);
    if (n < 0) { s_frameErr++; continue; }
    if (n == 0) { if (p.b[0] != chan::F_START && p.b[0] != chan::F_CONT) s_unknown++; continue; }
    s_msgs++;
    if (g_onMsg) g_onMsg(ra.buf, (size_t)n);
  }
}
static void begin() {
  if (s_q) return;
  s_q = xQueueCreate(24, sizeof(Rep));
  s_txMx = xSemaphoreCreateMutex();
  if (xTaskCreatePinnedToCore(task, "vchan", 8192, nullptr, 4, nullptr, 0) != pdPASS) Serial.println("[VCHAN] USB CHANNEL TASK NOT STARTED (no RAM for its stack)");   // 11ak
}

static void drvInit() {}
static bool drvDeinit() { return true; }
static void drvReset(uint8_t) { s_open = false; s_inBusy = false; }
static uint16_t drvOpen(uint8_t rhport, tusb_desc_interface_t const* d, uint16_t maxLen) {
  if (d->bInterfaceNumber != s_itf || d->bInterfaceClass != TUSB_CLASS_HID) return 0;   // not ours
  uint16_t len = sizeof(tusb_desc_interface_t);
  const uint8_t* p = (const uint8_t*)d + len;
  if (len + 9 + 7 + 7 > maxLen) return 0;
  if (p[1] != HID_DESC_TYPE_HID) return 0;
  len += p[0]; p += p[0];
  for (int k = 0; k < 2; k++) {
    const tusb_desc_endpoint_t* ep = (const tusb_desc_endpoint_t*)p;
    if (ep->bDescriptorType != TUSB_DESC_ENDPOINT || !usbd_edpt_open(rhport, ep)) return 0;
    len += ep->bLength; p += ep->bLength;
  }
  s_open = true;
  // 8x (bench 5 Nov 2026, Josh: NOSTR signing slowed, then stopped, in this
  // build only): the task (8 KB stack) and its queue (1.5 KB) took about 10 KB
  // of internal RAM in EVERY life once the USB port opened, and a NOSTR life
  // with Wi-Fi has about 12 KB to spare. The channel serves the PASSKEY life
  // only (ruled 4 Nov), so the PASSKEY life starts them (passkeyLifeRun).
  // Until then reports are counted as dropped (s_qDrop) and the extension
  // retries.
  primeOut(rhport);
  return len;
}
static bool drvControl(uint8_t rhport, uint8_t stage, tusb_control_request_t const* r) {
  if (r->bmRequestType_bit.recipient != TUSB_REQ_RCPT_INTERFACE || (uint8_t)r->wIndex != s_itf) return false;
  if (stage != CONTROL_STAGE_SETUP) return true;
  static uint8_t buf[64];
  if (r->bmRequestType_bit.type == TUSB_REQ_TYPE_STANDARD) {
    if (r->bRequest == TUSB_REQ_GET_DESCRIPTOR && (r->wValue >> 8) == HID_DESC_TYPE_REPORT)
      return tud_control_xfer(rhport, r, (void*)REPORT_DESC, sizeof(REPORT_DESC));
    return false;
  }
  if (r->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS) return false;
  switch (r->bRequest) {
    case HID_REQ_CONTROL_SET_IDLE:   return tud_control_status(rhport, r);
    case HID_REQ_CONTROL_GET_REPORT: memset(buf, 0, 64); return tud_control_xfer(rhport, r, buf, r->wLength < 64 ? r->wLength : 64);
    case HID_REQ_CONTROL_SET_REPORT: return tud_control_xfer(rhport, r, buf, r->wLength < 64 ? r->wLength : 64);   // the channel uses the OUT endpoint; this is read and ignored
    default: return false;
  }
}
static bool drvXfer(uint8_t rhport, uint8_t ep, xfer_result_t res, uint32_t n) {
  if (ep == s_epIn) {
    s_inBusy = false;
#ifdef FAVILLA_BENCH_PROBES
    if (s_logLeft) logNext(rhport);   // 11u: the next report of a LOG chain
#endif
    return true;
  }
  if (ep != s_epOut) return false;
  if (res == XFER_RESULT_SUCCESS && n > 0) {
    s_rxN++;
    if (s_rx[0] == CMD_ATT) { attAnswer(rhport, n > 1 ? s_rx[1] : 0); primeOut(rhport); return true; }   // 11eg: every build, every life
    if (s_rx[0] == CMD_WDT) { wdtAnswer(rhport); primeOut(rhport); return true; }   // #74: every build with the channel
#ifdef FAVILLA_BENCH_PROBES
    // 11u: LOG and CON are answered here, in every life (no channel task needed).
    if (s_rx[0] == CMD_LOG && n >= 6) {
      s_logPulls++;
      if (!s_inBusy && !s_logLeft) { memcpy((void*)&s_logCur, s_rx + 1, 4); s_logLeft = s_rx[5] > 32 ? 32 : (s_rx[5] ? s_rx[5] : 1); logNext(rhport); }
      primeOut(rhport); return true;
    }
    if (s_rx[0] == CMD_CON && n >= 2) {
      size_t len = s_rx[1] > 62 ? 62 : s_rx[1];
      conPush(s_rx + 2, len);
      primeOut(rhport); return true;
    }
#endif
    Rep p; memset(p.b, 0, 64); memcpy(p.b, s_rx, n > 64 ? 64 : n);
    if (!s_q || xQueueSend(s_q, &p, 0) != pdTRUE) s_qDrop++;   // never block the USB task
  }
  primeOut(rhport);
  return true;
}

static const usbd_class_driver_t s_driver = {
  "FAVCHAN",
  drvInit, drvDeinit, drvReset, drvOpen, drvControl, drvXfer, nullptr, nullptr
};

struct Reg { Reg() { tinyusb_enable_interface(USB_INTERFACE_MIDI, TUD_HID_INOUT_DESC_LEN, descCb); } };
static Reg s_reg;

inline void status() {
  Serial.printf("[VCHAN] interface %u, IN 0x%02X OUT 0x%02X%s | open %d (host %d) | rx %lu tx %lu (failed %lu) | pings %lu, unknown %lu | msgs %lu, frame errors %lu, queue drops %lu\n",
                s_itf, s_epIn, s_epOut, s_descErr ? " | NO FREE ENDPOINT" : "", (int)s_open, (int)tud_mounted(),
                (unsigned long)s_rxN, (unsigned long)s_txN, (unsigned long)s_txFail, (unsigned long)s_pings, (unsigned long)s_unknown,
                (unsigned long)s_msgs, (unsigned long)s_frameErr, (unsigned long)s_qDrop);
#ifdef FAVILLA_BENCH_PROBES
  Serial.printf("[VCHAN] bench: log ring %s, %lu bytes written, %lu pulls | console lines %lu, dropped %lu\n",
                s_log ? "on" : "OFF", (unsigned long)s_logW, (unsigned long)s_logPulls, (unsigned long)s_conLines, (unsigned long)s_conDrop);
#endif
}

}  // namespace vchan

// TinyUSB asks for extra class drivers at stack init (weak in the prebuilt lib):
// the keyboard (kbd_hid.h) and this channel, each claiming only its own interface.
extern "C" usbd_class_driver_t const* usbd_app_driver_get_cb(uint8_t* driver_count) {
  static usbd_class_driver_t drivers[2];
  drivers[0] = kbd::s_driver; drivers[1] = vchan::s_driver;
  *driver_count = 2;
  return drivers;
}
#endif  // FAVILLA_FIDO_PROBE && FAVILLA_VCHAN
