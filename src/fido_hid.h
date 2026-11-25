// =============================================================================
// fido_hid.h — passkey door, steps 1 to 3b (29-30 Oct 2026). FIDO env only.
// =============================================================================
// Restorable passkeys (30 Oct 2026, spec v0.9): the SECOND kind, served in the
// NOSTR life with the KEY unlocked (backend pkrOpen). Two kinds, never mixed:
//   PASSKEY life -> device-bound, 16-byte IDs, the SE-generated keys below;
//   NOSTR life   -> restorable, 34-byte IDs (0x01 ver || 0x01 kind || nonce16
//                   || tag16), keys derived on the G0 from the words (PKSIGN).
// Each life ignores the other kind's IDs. Restorable credentials have no index:
// the G0 recognises its own IDs by the tag. authData flags carry BE=1 and
// BS=1 (backup eligible, backed up). Before the FIRST restorable registration
// of a wallet the KEY shows a one-time warning (ENTER accepts, BACK refuses).
// Step 3b (30 Oct 2026): the REAL door replaces the bench door. Credentials are
// made and used only while main.cpp reports the PASSKEY door open (the G0 holds
// PASSKEY for this power-on life and the passkey PIN was entered on the KEY);
// anywhere else makeCredential / getAssertion are refused at once. The SE side
// (passkey_door.inc) arms the real MODE_PCR in a passkey-PIN session, the G0
// mints V_3, the key signs, the latch is burned. The credential index is
// "passkeys" in NVS and each record carries the SE object generation it was
// made under, so a re-onboarded unit never trusts an old wallet's index.
// Silent checks (up=false) are capped per life (spec v1.0 section 8).
// Step 3a (30 Oct 2026): keepalives from their own task (kaTask), so they keep
// flowing while the SE works or waits for the I2C bus; getInfo reports the USB
// transport; every request carries a sequence number for the main loop's
// prompt overlay (fidoUiTick in main.cpp, which no longer blocks the loop).
// Step 1 (proven 30 Oct 2026): the KEY enumerates as a FIDO security key and
// answers CTAP2 getInfo; Windows reached makeCredential.
// Step 2 (this file): real register + sign-in on a BENCH door.
//   makeCredential (0x01): generates a P-256 key INSIDE the SE051 under the
//     passkey policy (bench PIN session: SIGN only while the bench latch == V),
//     returns "packed" self-attestation signed by that key.
//   getAssertion (0x02): signs with that key through the same mint -> sign ->
//     burn sequence as bench check 4.
//   Each one needs a press of ENTER on the KEY, with the website's id shown.
//   NOT in step 2: user verification (no PIN), discoverable/resident
//   credentials, clientPIN, reset, credential management, the real G0 door.
//   The bench door is the throwaway PIN 0x7000E0A1 + PCR 0x2000E0A0 from the
//   probes; the "G0 mint" is simulated by an anonymous reset + extend.
//   Credentials live at SE ids 0x2000E200 + slot (max 20, plus a free-memory
//   reserve), indexed in NVS namespace "fidobench".
//
// Strict input rule (spec section 6): CTAPHID INIT, PING, CANCEL and CBOR only;
// CTAP2 getInfo, makeCredential and getAssertion only. The CBOR reader below
// accepts definite-length items only, nests at most 6 deep, and checks every
// length against the bytes actually received before reading them.
//
// AAGUID is a random DEVELOPMENT value. The production AAGUID is chosen once,
// before any metadata is published.
// =============================================================================
#pragma once
#ifdef FAVILLA_FIDO_PROBE
#include "USB.h"
#include "esp_system.h"
#include "soc/rtc_cntl_reg.h"      // RTC_CNTL_OPTION1_REG / RTC_CNTL_FORCE_DOWNLOAD_BOOT
#include "soc/rtc_cntl_struct.h"   // RTCCNTL.usb_conf: which controller owns the internal USB PHY
#if __has_include("esp32s3/rom/usb/chip_usb_dw_wrapper.h")
#include "esp32s3/rom/usb/chip_usb_dw_wrapper.h"   // chip_usb_set_persist_flags
#define FIDO_HAVE_PERSIST_CLEAR 1
#endif
#include "USBHID.h"
#include <Preferences.h>
#include "mbedtls/sha256.h"
#include "esp_random.h"
#ifdef ARDUINO
#include "esp_heap_caps.h"
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "pk_records.h"                // 2 Nov 2026: RkAcct (passwordless passkey records)

namespace fido {

static const uint8_t AAGUID_DEV[16] = { 0xbb,0x64,0x54,0xdd,0xa9,0xa3,0x49,0x8b,0xb9,0xf9,0x7a,0x77,0xd7,0x69,0x9c,0xf7 };

// ---- CTAPHID ----------------------------------------------------------------
static const uint32_t CID_BROADCAST = 0xFFFFFFFFu;
static const uint8_t  CMD_PING = 0x01, CMD_INIT = 0x06, CMD_CBOR = 0x10, CMD_CANCEL = 0x11,
                      CMD_KEEPALIVE = 0x3B, CMD_ERROR = 0x3F;
static const uint8_t  ERR_INVALID_CMD = 0x01, ERR_INVALID_LEN = 0x03, ERR_INVALID_SEQ = 0x04,
                      ERR_MSG_TIMEOUT = 0x05, ERR_CHANNEL_BUSY = 0x06, ERR_INVALID_CHANNEL = 0x0B;
static const uint8_t  CAP_CBOR = 0x04, CAP_NMSG = 0x08;
static const uint8_t  KA_PROCESSING = 0x01, KA_UPNEEDED = 0x02;
// 9a (6 Nov 2026): CTAP over Bluetooth (ble_kbd.h). A whole Bluetooth request
// is turned into CTAPHID packets on this internal channel and queued for the
// same FIDO task, so USB and Bluetooth share one handler, one transaction at a
// time. Replies on this channel go to the Bluetooth side (g_bleTx), never USB.
// USB packets that name it are dropped on arrival.
static const uint32_t CID_BLE = 0xB1E0F1D0u;
static void (*g_bleTx)(uint8_t cmd, const uint8_t* data, size_t n) = nullptr;
static volatile bool g_bleUp = false;     // Bluetooth up in this life: getInfo lists "ble"

// ---- CTAP2 ------------------------------------------------------------------
static const uint8_t CTAP2_MAKE_CREDENTIAL = 0x01, CTAP2_GET_ASSERTION = 0x02, CTAP2_GET_INFO = 0x04;
static const uint8_t ST_OK = 0x00, ST_INVALID_COMMAND = 0x01, ST_INVALID_LENGTH = 0x03,
                     ST_INVALID_CBOR = 0x12, ST_MISSING_PARAMETER = 0x14, ST_CREDENTIAL_EXCLUDED = 0x19,
                     ST_UNSUPPORTED_ALGORITHM = 0x26, ST_OPERATION_DENIED = 0x27, ST_KEY_STORE_FULL = 0x28,
                     ST_UNSUPPORTED_OPTION = 0x2B, ST_INVALID_OPTION = 0x2C, ST_KEEPALIVE_CANCEL = 0x2D,
                     ST_NO_CREDENTIALS = 0x2E, ST_USER_ACTION_TIMEOUT = 0x2F,
                     ST_PIN_AUTH_INVALID = 0x33, ST_PIN_NOT_SET = 0x35, ST_UV_INVALID = 0x3F, ST_UV_BLOCKED = 0x3C, ST_OTHER = 0x7F;

static const size_t   MAX_MSG = 1024;
static const uint32_t MSG_TIMEOUT_MS = 3000;
static const uint32_t UP_TIMEOUT_MS  = 30000;
static const int      MAX_SLOTS = 20;                 // bench check 2: 25 fit; 20 leaves a reserve
static const int      FREE_RESERVE_BYTES = 2048;      // never let a passkey fill the SE (spec section 5)
static const uint32_t SLOT_OBJ_BASE = 0x2000E200u;

static const uint8_t REPORT_DESC[] = {
  0x06, 0xD0, 0xF1,  0x09, 0x01,  0xA1, 0x01,
  0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
  0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
  0xC0
};

// ---- the SE side, provided by main.cpp (I2C-locked wrappers) ----------------
struct Backend {
  bool (*keygen)(uint32_t obj, uint8_t pub65[65], uint16_t* sw);
  bool (*sign)(uint32_t obj, const uint8_t hash32[32], uint8_t* der, size_t* derLen, uint16_t* sw);
  void (*del)(uint32_t obj);
  int  (*freeBytes)();
  bool (*doorOpen)();      // step 3b: PASSKEY life + passkey PIN entered; nullptr = never open
  uint8_t (*gen)();        // step 3b: the live SE object generation (index records from another are ignored)
  // Restorable passkeys (30 Oct 2026). Results: 0 ok, else a pkr_* / G0 PK_E_* code (0xE4 = not ours for this site).
  bool (*pkrOpen)();       // NOSTR life, unlocked, master on the SE, G0 has PKSIGN
  int  (*pkrRegister)(const uint8_t rpIdHash[32], uint8_t id34[34], uint8_t pub65[65]);
  int  (*pkrSign)(const uint8_t rpIdHash[32], const uint8_t id34[34], const uint8_t h[32], uint8_t* der, size_t* derN);
  bool (*pkrAcked)();      // the one-time warning was accepted for this wallet
  void (*pkrAck)();
  // User verification (31 Oct 2026, Vault spec D3): built-in UV = the PIN of
  // the open life entered ON THE KEY within 10 minutes. Present = getInfo says
  // uv:true; fresh = within the window (else the KEY asks for the PIN, kind 2).
  bool (*uvFresh)();
  // Passwordless passkeys (2 Nov 2026, Vault spec phase 2): records sealed by
  // the G0 (pk_records.cpp). Results: a count, or a favilla::RK_E_* code (< 0).
  bool (*rkReady)();       // nvs_vault mounted, the G0 has VAULT, and this is not the PASSKEY life (lock state does not matter)
  int  (*rkCount)();
  int  (*rkRoom)(const char* site, size_t n, const uint8_t* handle, size_t hn);   // after the press: room, or a replacement
  int  (*rkFind)(const char* site, size_t n, favilla::RkAcct* out, int max);
  int  (*rkSave)(const char* site, size_t n, const uint8_t* handle, size_t hn, const char* name, size_t nn,
                 const char* disp, size_t dn, const uint8_t id34[34]);
  // 2 Nov 2026 (S2 follow-up): one passkey window for the G0 ops of one request
  // in the PASSKEY life (g0_window_batch_*). nullptr = none. No user waits inside.
  void (*batchBegin)();
  void (*batchEnd)();
  // 2 Nov 2026: a passkey request was refused because passkeys are closed in
  // this life (NOSTR life with the gate shut, or the KEY locked). The KEY says why.
  void (*refused)();
};
static Backend g_be = {};
static bool doorOpen() { return g_be.doorOpen && g_be.doorOpen(); }
// 2 Nov 2026 (2b): no longer excluded by the device-bound door. A PASSKEY life
// holds both kinds; new registrations there are restorable (ruling L3) and a
// sign-in goes to the kind its credential ID has (getAssertion below).
static bool pkrOpen() { return g_be.pkrOpen && g_be.pkrRegister && g_be.pkrSign && g_be.pkrOpen(); }
// No-username passkeys: the restorable door, plus the record store (both lives since 2b).
static bool rkStore() { return g_be.rkReady && g_be.rkFind && g_be.rkSave && g_be.rkRoom && g_be.pkrOpen && g_be.rkReady(); }
static bool rkOpen() { return pkrOpen() && rkStore(); }
// One window for the G0 ops between begin and end (PASSKEY life). end() before any wait for the owner.
struct WinBatch {
  bool on = false;
  WinBatch() { if (g_be.batchBegin) { g_be.batchBegin(); on = true; } }
  void end() { if (on) { on = false; if (g_be.batchEnd) g_be.batchEnd(); } }
  ~WinBatch() { end(); }
};
static const size_t  PKR_ID = 34;
static bool pkrIdShape(const uint8_t* id, size_t n) { return n == PKR_ID && id[0] == 0x01 && id[1] == 0x01; }
static uint8_t liveGen() { return g_be.gen ? g_be.gen() : 0xFF; }
static const int SILENT_PER_LIFE = 64;   // up=false answers per power-on life (spec v1.0 section 8)
static int g_silentLeft = SILENT_PER_LIFE;
// Restorable passkeys (review, 30 Oct 2026): every sign made BEFORE a press
// (finding the right ID, the excludeList probe) costs two SE writes. A host
// could ask and cancel forever, wearing the SE without a press. So these are
// budgeted per power-on life; an approved sign-in gives its one back.
static const int PRESIGN_PER_LIFE = 64;
static int g_presignLeft = PRESIGN_PER_LIFE;
static void setBackend(const Backend& b) { g_be = b; }

// ---- user presence, shown by the main loop (fidoUiTick in main.cpp) ---------
// 0 idle, 1 asking (main loop draws the screen), 2 approved, 3 refused, 4 withdrawn
// seq changes with every new request, so the main loop never mistakes a second
// request for the one it is already showing (step 3a: the prompt is an overlay).
// kind 0: the normal "Register with / Sign in to <site>" prompt;
// kind 1: the one-time restorable-passkey warning (main.cpp draws its text);
// kind 2: user verification - the PIN on the KEY (presence and verification in one).
// state 5 (kind 2 only): UV is off (3 wrong PINs, or no PIN on the KEY this unlock) -> UV_BLOCKED.
struct UpReq { volatile uint8_t state; char rp[256];   // 11cv: a whole DNS name (253), never cut on the prompt
                char what[24]; volatile uint32_t seq; volatile uint8_t kind; };
static UpReq g_up = { 0, {0}, {0}, 0, 0 };
// kind 3 (2 Nov 2026): the account picker for a sign-in with no username. The
// FIDO task fills g_pick before the request, the main loop draws it and writes
// the chosen row to sel before it sets state 2. Choosing is the presence.
static const int PICK_MAX = 8;
struct UpPick { volatile uint8_t n; volatile uint8_t sel; char name[PICK_MAX][48]; char sub[PICK_MAX][48]; };
static UpPick g_pick = {};

struct Pkt { uint8_t b[64]; };
static QueueHandle_t g_q = nullptr;
static volatile uint32_t g_rx = 0, g_dropped = 0, g_tx = 0, g_txfail = 0, g_getinfo = 0, g_made = 0, g_signed = 0;

static inline uint32_t rd32Raw(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
class Dev : public USBHIDDevice {
 public:
  USBHID hid;
  Dev() { static bool once = false; if (!once) { once = true; hid.addDevice(this, sizeof(REPORT_DESC)); } }
  uint16_t _onGetDescriptor(uint8_t* buf) override { memcpy(buf, REPORT_DESC, sizeof(REPORT_DESC)); return sizeof(REPORT_DESC); }
  void _onOutput(uint8_t report_id, const uint8_t* buf, uint16_t len) override {
    g_rx++;
    if (!g_q || len == 0) return;
    Pkt p; memset(p.b, 0, 64); memcpy(p.b, buf, len > 64 ? 64 : len);
    if (rd32Raw(p.b) == CID_BLE) { g_dropped++; return; }   // 9a: the Bluetooth channel is never reachable from USB
    if (xQueueSend(g_q, &p, 0) != pdTRUE) g_dropped++;
  }
  bool send(const uint8_t pkt[64]) {
    bool ok = hid.SendReport(0, pkt, 64, 200);
    if (ok) g_tx++; else g_txfail++;
    return ok;
  }
};
static Dev g_dev;

static void wr32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static uint32_t rd32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
// ---- keepalives from their own task (step 3a, 30 Oct 2026) ----------------------
// Spec section 10, check 4: keepalives must keep flowing while the SE works, so
// they come from a small task of their own, not from the code driving the SE.
// The FIDO task names the channel and status (kaBegin); any real reply on that
// channel stops them (sendMsgLocked). One mutex covers a whole message, so a
// keepalive can never land between the packets of a multi-packet reply.
static SemaphoreHandle_t g_txMx = nullptr;
static volatile uint32_t g_kaCid = 0;
static volatile uint8_t  g_kaSt = 0;
static void sendMsgLocked(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t n) {
  if (cmd != CMD_KEEPALIVE && cid == g_kaCid) g_kaCid = 0;   // the reply ends the keepalives
  if (cid == CID_BLE) { if (g_bleTx) g_bleTx(cmd, data, n); return; }   // 9a: Bluetooth replies leave by Bluetooth
  uint8_t pkt[64]; size_t off = 0; uint8_t seq = 0;
  memset(pkt, 0, 64); wr32(pkt, cid); pkt[4] = 0x80 | cmd; pkt[5] = n >> 8; pkt[6] = n & 0xFF;
  size_t k = n < 57 ? n : 57; if (k) memcpy(pkt + 7, data, k); off = k;
  g_dev.send(pkt);
  while (off < n) {
    memset(pkt, 0, 64); wr32(pkt, cid); pkt[4] = seq++ & 0x7F;
    k = (n - off) < 59 ? (n - off) : 59; memcpy(pkt + 5, data + off, k); off += k;
    g_dev.send(pkt);
  }
}
static void sendMsg(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t n) {
  if (g_txMx) xSemaphoreTake(g_txMx, portMAX_DELAY);
  sendMsgLocked(cid, cmd, data, n);
  if (g_txMx) xSemaphoreGive(g_txMx);
}
static void sendErr(uint32_t cid, uint8_t code) { sendMsg(cid, CMD_ERROR, &code, 1); }
static void sendStatus(uint32_t cid, uint8_t st) { sendMsg(cid, CMD_CBOR, &st, 1); }
static void keepalive(uint32_t cid, uint8_t st) { sendMsg(cid, CMD_KEEPALIVE, &st, 1); }
static void kaBegin(uint32_t cid, uint8_t st) { g_kaSt = st; g_kaCid = cid; }
static void kaEnd() { g_kaCid = 0; }
static void kaTask(void*) {
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(100));
    if (!g_kaCid) continue;
    xSemaphoreTake(g_txMx, portMAX_DELAY);
    uint32_t c = g_kaCid; uint8_t st = g_kaSt;     // re-read under the lock: the reply may just have gone
    if (c) sendMsgLocked(c, CMD_KEEPALIVE, &st, 1);
    xSemaphoreGive(g_txMx);
  }
}

// ---- strict CBOR reader -----------------------------------------------------
struct Cb { const uint8_t* p; const uint8_t* e; bool ok; };
static bool cbHdr(Cb& c, uint8_t& mt, uint64_t& arg) {
  if (!c.ok || c.p >= c.e) { c.ok = false; return false; }
  uint8_t ib = *c.p++; mt = ib >> 5; uint8_t ai = ib & 0x1F;
  if (ai < 24) { arg = ai; return true; }
  int n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
  if (!n || c.e - c.p < n) { c.ok = false; return false; }      // indefinite lengths and 28-30 refused
  arg = 0; for (int i = 0; i < n; i++) arg = (arg << 8) | *c.p++;
  return true;
}
static bool cbSkip(Cb& c, int depth) {
  if (depth > 6) { c.ok = false; return false; }
  uint8_t mt; uint64_t a; if (!cbHdr(c, mt, a)) return false;
  switch (mt) {
  case 0: case 1: case 7: return true;
  case 2: case 3: if ((uint64_t)(c.e - c.p) < a) { c.ok = false; return false; } c.p += a; return true;
  case 4: if (a > 64) { c.ok = false; return false; } for (uint64_t i = 0; i < a; i++) if (!cbSkip(c, depth + 1)) return false; return true;
  case 5: if (a > 64) { c.ok = false; return false; } for (uint64_t i = 0; i < 2 * a; i++) if (!cbSkip(c, depth + 1)) return false; return true;
  case 6: return cbSkip(c, depth + 1);
  }
  c.ok = false; return false;
}
// typed reads: return false (and poison c) on a type mismatch
static bool cbStr(Cb& c, uint8_t want, const uint8_t** s, size_t* n) {
  uint8_t mt; uint64_t a; if (!cbHdr(c, mt, a) || mt != want || (uint64_t)(c.e - c.p) < a) { c.ok = false; return false; }
  *s = c.p; *n = (size_t)a; c.p += a; return true;
}
static bool cbInt(Cb& c, int64_t* v) {
  uint8_t mt; uint64_t a; if (!cbHdr(c, mt, a) || (mt != 0 && mt != 1) || a > 0x7FFFFFFF) { c.ok = false; return false; }
  *v = mt == 0 ? (int64_t)a : -1 - (int64_t)a; return true;
}
static bool cbBool(Cb& c, bool* v) {
  uint8_t mt; uint64_t a; if (!cbHdr(c, mt, a) || mt != 7 || (a != 20 && a != 21)) { c.ok = false; return false; }
  *v = (a == 21); return true;
}
static bool cbCount(Cb& c, uint8_t want, uint64_t* n) {
  uint8_t mt; uint64_t a; if (!cbHdr(c, mt, a) || mt != want || a > 64) { c.ok = false; return false; }
  *n = a; return true;
}
static bool txtEq(const uint8_t* s, size_t n, const char* lit) { return strlen(lit) == n && !memcmp(s, lit, n); }

// ---- credential slots -------------------------------------------------------
// Record = gen(1) || credId(16) || rpIdHash(32). A record whose generation is
// not the live one belongs to a wiped wallet: it is ignored and its slot reused.
struct Slot { uint8_t used; uint8_t gen; uint8_t credId[16]; uint8_t rpIdHash[32]; };
static Slot g_slots[MAX_SLOTS];
static const char* IDX_NS = "passkeys";
static void slotsLoad() {
  Preferences p; p.begin(IDX_NS, true);
  for (int i = 0; i < MAX_SLOTS; i++) {
    char k[6]; snprintf(k, sizeof k, "s%d", i);
    uint8_t b[49]; g_slots[i].used = (p.getBytes(k, b, 49) == 49);
    if (g_slots[i].used) { g_slots[i].gen = b[0]; memcpy(g_slots[i].credId, b + 1, 16); memcpy(g_slots[i].rpIdHash, b + 17, 32); }
  }
  p.end();
}
static bool slotLive(int i) { return g_slots[i].used && g_slots[i].gen == liveGen() && liveGen() != 0xFF; }
static bool slotSave(int i) {
  Preferences p; if (!p.begin(IDX_NS, false)) return false;
  char k[6]; snprintf(k, sizeof k, "s%d", i);
  uint8_t b[49]; b[0] = g_slots[i].gen; memcpy(b + 1, g_slots[i].credId, 16); memcpy(b + 17, g_slots[i].rpIdHash, 32);
  bool ok = p.putBytes(k, b, 49) == 49; p.end(); return ok;
}
static int slotFind(const uint8_t* id, size_t n, const uint8_t rpIdHash[32]) {
  if (n != 16) return -1;
  for (int i = 0; i < MAX_SLOTS; i++)
    if (slotLive(i) && !memcmp(g_slots[i].credId, id, 16) && !memcmp(g_slots[i].rpIdHash, rpIdHash, 32)) return i;
  return -1;
}
static int slotsUsed() { int n = 0; for (int i = 0; i < MAX_SLOTS; i++) n += slotLive(i) ? 1 : 0; return n; }
static int slotsUsedRaw() { int n = 0; for (int i = 0; i < MAX_SLOTS; i++) n += g_slots[i].used; return n; }

// ---- user presence ------------------------------------------------------------
// Blocks this task (not the main loop) until ENTER / BACK on the KEY, a host
// CANCEL, or 30 s. KEEPALIVE(UPNEEDED) goes out at once and then every 100 ms
// from kaTask. Packets for other channels are answered CHANNEL_BUSY.
// 9g: split in two so a sign-in can show its prompt first and let the G0 sign
// while the owner reads it (upBegin, the signing, then upWait). A press made
// while the G0 is still signing is kept (state 2) and read by upWait.
static uint32_t g_upT0 = 0;
static void upBegin(uint32_t cid, const char* what, const uint8_t* rp, size_t rpLen, uint8_t kind = 0) {
  g_up.kind = kind;
  size_t n = rpLen < sizeof(g_up.rp) - 1 ? rpLen : sizeof(g_up.rp) - 1;
  memcpy(g_up.rp, rp, n); g_up.rp[n] = 0;
  strncpy(g_up.what, what, sizeof(g_up.what) - 1);
  g_up.seq++;
  g_up.state = 1;
  Serial.printf("[FIDO] waiting for ENTER on the KEY: %s %s\n", what, g_up.rp);
  keepalive(cid, KA_UPNEEDED); kaBegin(cid, KA_UPNEEDED);
  g_upT0 = millis();
}
// Takes the prompt down without an answer (the request failed while it showed).
static void upWithdraw(uint32_t cid) {
  if (g_up.state) { g_up.state = 4; vTaskDelay(pdMS_TO_TICKS(50)); g_up.state = 0; }
  kaBegin(cid, KA_PROCESSING);
}
static uint8_t upWait(uint32_t cid) {
  for (;;) {
    if (g_up.state == 2) { g_up.state = 0; kaBegin(cid, KA_PROCESSING); return ST_OK; }
    if (g_up.state == 3) { g_up.state = 0; kaBegin(cid, KA_PROCESSING); return ST_OPERATION_DENIED; }
    if (g_up.state == 5) { g_up.state = 0; kaBegin(cid, KA_PROCESSING); return ST_UV_BLOCKED; }   // UV turned off (3 wrong, or no PIN on the KEY this unlock): CTAP's 'UV blocked', so platforms stop retrying
    if (millis() - g_upT0 > UP_TIMEOUT_MS) { g_up.state = 4; vTaskDelay(pdMS_TO_TICKS(50)); g_up.state = 0; kaBegin(cid, KA_PROCESSING); return ST_USER_ACTION_TIMEOUT; }
    Pkt p;
    if (xQueueReceive(g_q, &p, pdMS_TO_TICKS(20)) == pdTRUE) {
      uint32_t pc = rd32(p.b);
      if (pc == cid && (p.b[4] & 0x80) && (p.b[4] & 0x7F) == CMD_CANCEL) {
        g_up.state = 4; vTaskDelay(pdMS_TO_TICKS(50)); g_up.state = 0; kaBegin(cid, KA_PROCESSING);
        Serial.println("[FIDO] host cancelled");
        return ST_KEEPALIVE_CANCEL;
      }
      if (pc != cid && pc != 0) sendErr(pc, ERR_CHANNEL_BUSY);
    }
  }
}
static uint8_t waitUp(uint32_t cid, const char* what, const uint8_t* rp, size_t rpLen, uint8_t kind = 0) {
  upBegin(cid, what, rp, rpLen, kind);
  return upWait(cid);
}

// Presence, and verification when the site asks for it (uv). Inside the 10
// minute window: the normal press, and the UV flag. Outside it: the PIN on the
// KEY, which is both. Never UV on a press alone.
static uint8_t askUser(uint32_t cid, const char* what, const uint8_t* rp, size_t rpLen, bool wantUv, bool* uv) {
  *uv = false;
  if (!wantUv) return waitUp(cid, what, rp, rpLen);
  if (!g_be.uvFresh) return ST_UNSUPPORTED_OPTION;
  uint8_t u;
  if (g_be.uvFresh()) { u = waitUp(cid, what, rp, rpLen); if (u) return u; if (!g_be.uvFresh()) u = waitUp(cid, "PIN for", rp, rpLen, 2); }
  else u = waitUp(cid, "PIN for", rp, rpLen, 2);
  if (u) return u;
  *uv = true;
  return ST_OK;
}

// ---- CBOR writers -------------------------------------------------------------
static size_t cbPutHdr(uint8_t* o, uint8_t mt, size_t n) {
  if (n < 24) { o[0] = (mt << 5) | n; return 1; }
  if (n < 256) { o[0] = (mt << 5) | 24; o[1] = n; return 2; }
  o[0] = (mt << 5) | 25; o[1] = n >> 8; o[2] = n & 0xFF; return 3;
}
static size_t cbPutBytes(uint8_t* o, const uint8_t* d, size_t n) { size_t k = cbPutHdr(o, 2, n); memcpy(o + k, d, n); return k + n; }
static size_t cbPutText(uint8_t* o, const char* s) { size_t n = strlen(s); size_t k = cbPutHdr(o, 3, n); memcpy(o + k, s, n); return k + n; }

// ---- getInfo ------------------------------------------------------------------
// { 1: ["FIDO_2_0"], 3: aaguid, 4: {"rk":false,"up":true,"plat":false}, 5: 1024, 9: ["usb"] }
// Step 2 advertises NO user verification ("uv" absent) and no resident keys:
// a site that requires either is refused cleanly instead of being half-served.
static size_t buildGetInfo(uint8_t* o) {
  size_t n = 0;
  o[n++] = ST_OK; o[n++] = 0xA5;
  o[n++] = 0x01; o[n++] = 0x81; n += cbPutText(o + n, "FIDO_2_0");
  o[n++] = 0x03; n += cbPutBytes(o + n, AAGUID_DEV, 16);
  const bool hasUv = g_be.uvFresh != nullptr;   // 31 Oct 2026: built-in UV (the PIN on the KEY)
  o[n++] = 0x04; o[n++] = hasUv ? 0xA4 : 0xA3;   // canonical key order: rk, up, uv, plat
  n += cbPutText(o + n, "rk"); o[n++] = rkStore() ? 0xF5 : 0xF4;   // 2 Nov 2026: true whenever the record store exists, locked or not (platforms cache getInfo; review)
  n += cbPutText(o + n, "up"); o[n++] = 0xF5;
  if (hasUv) { n += cbPutText(o + n, "uv"); o[n++] = 0xF5; }
  n += cbPutText(o + n, "plat"); o[n++] = 0xF4;
  o[n++] = 0x05; o[n++] = 0x19; o[n++] = (MAX_MSG >> 8) & 0xFF; o[n++] = MAX_MSG & 0xFF;
  if (g_bleUp) { o[n++] = 0x09; o[n++] = 0x82; n += cbPutText(o + n, "ble"); n += cbPutText(o + n, "usb"); }   // 9a
  else { o[n++] = 0x09; o[n++] = 0x81; n += cbPutText(o + n, "usb"); }   // step 3a: transports
  return n;
}

static void sha256(const uint8_t* a, size_t an, const uint8_t* b, size_t bn, uint8_t out[32]) {
  mbedtls_sha256_context s; mbedtls_sha256_init(&s); mbedtls_sha256_starts(&s, 0);
  mbedtls_sha256_update(&s, a, an); if (bn) mbedtls_sha256_update(&s, b, bn);
  mbedtls_sha256_finish(&s, out); mbedtls_sha256_free(&s);
}

// pinUvAuthParam handling shared by both commands (no clientPIN in step 2)
static uint8_t pinParamStatus(uint32_t cid, bool present, size_t len, const uint8_t* rp, size_t rpLen) {
  if (!present) return ST_OK;
  if (len == 0) { uint8_t u = waitUp(cid, "Select key", rp, rpLen); return u ? u : ST_PIN_NOT_SET; }
  return ST_PIN_AUTH_INVALID;
}

// ---- makeCredential -----------------------------------------------------------
static uint8_t g_resp[512];

// ---- restorable passkeys (NOSTR life) ----------------------------------------
// A fixed hash for "is this ID ours for this site?" (excludeList, and picking
// among several candidates). Signing it proves nothing to anyone: no site ever
// asks for it, and the G0 refuses the ID for any other site (tag).
static void pkrProbeHash(uint8_t h[32]) { sha256((const uint8_t*)"FAVILLA-PK-PROBE-v1", 19, nullptr, 0, h); }
// 1 ours, 0 not ours (the G0's tag check: 0xE4), -1 an error or the budget is spent.
static int pkrOurs(const uint8_t rpIdHash[32], const uint8_t* id) {
  if (g_presignLeft <= 0) { Serial.println("[FIDO] restorable: pre-press budget for this life is spent"); return -1; }
  g_presignLeft--;
  uint8_t h[32], der[80]; size_t dn = 0; pkrProbeHash(h);
  int r = g_be.pkrSign(rpIdHash, id, h, der, &dn);
  memset(der, 0, sizeof(der));
  return r == 0 ? 1 : r == 0xE4 ? 0 : -1;
}
// rk (2 Nov 2026): the account the site gave, for the record.
struct RkUser { bool rk; const uint8_t* id; size_t idN; const uint8_t* name; size_t nameN; const uint8_t* disp; size_t dispN; };
static void doMakeRestorable(uint32_t cid, const uint8_t* cdh, const uint8_t* rpId, size_t rpIdN, const uint8_t rpIdHash[32],
                             const uint8_t* const* excl, const size_t* exclN, int nExcl, bool optUv, const RkUser& ru) {
  int probes = 0;
  for (int i = 0; i < nExcl && probes < 4; i++) if (pkrIdShape(excl[i], exclN[i])) {
    probes++; keepalive(cid, KA_PROCESSING);
    int o = pkrOurs(rpIdHash, excl[i]);
    if (o < 0) { sendStatus(cid, ST_OTHER); Serial.println("[FIDO] restorable excludeList check failed: not registering"); return; }
    if (o == 1) {
      uint8_t u = waitUp(cid, "Already registered", rpId, rpIdN);
      sendStatus(cid, u ? u : ST_CREDENTIAL_EXCLUDED); return;
    }
  }
  if (g_be.pkrAcked && !g_be.pkrAcked()) {
    uint8_t u = waitUp(cid, "Restorable passkey", rpId, rpIdN, 1);
    if (u) { sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] restorable warning refused: not registered"); return; }
    if (g_be.pkrAck) g_be.pkrAck();
    Serial.println("[FIDO] restorable warning accepted for this wallet");
  }
  bool uv = false;
  { uint8_t u = askUser(cid, "Register with", rpId, rpIdN, optUv || ru.rk, &uv); if (u) { sendStatus(cid, u); return; } }   // rk: always UV (Vault spec D3, section 5)
  WinBatch wb;   // room, register, attestation sign and record save: one window
  if (ru.rk) {   // room for the record? Checked AFTER the press (review 2 Nov 2026: before it, any page could spend record opens with no press)
    keepalive(cid, KA_PROCESSING);
    int k = g_be.rkRoom((const char*)rpId, rpIdN, ru.id, ru.idN);
    if (k == favilla::RK_E_FULL) {
      wb.end();   // never hold the window across a wait
      waitUp(cid, "No room for", rpId, rpIdN);   // the KEY says so; the press only dismisses it
      sendStatus(cid, ST_KEY_STORE_FULL); Serial.printf("[FIDO] rk register refused: %d records, the most this KEY keeps\n", favilla::RK_MAX); return; }
    if (k == favilla::RK_E_BUDGET) { sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] rk register: this sitting's record opens are used - lock and unlock the KEY (or power cycle once the 4 refills are used)"); return; }
    if (k != 0) { sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] rk register: the site's records could not be checked (%s) - not registering, to avoid a duplicate\n", favilla::rk_err_name(k)); return; }
  }
  keepalive(cid, KA_PROCESSING);
  uint8_t id[PKR_ID], pub[65]; uint32_t t0 = millis();
  int r = g_be.pkrRegister(rpIdHash, id, pub);
  if (r != 0 || pub[0] != 0x04) { sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] restorable register failed: %02X\n", r); return; }
  // authData = rpIdHash | flags UP+BE+BS+AT | signCount 0 | AAGUID | 34 | id | COSE EC2 key
  uint8_t ad[200]; size_t an = 0;
  memcpy(ad, rpIdHash, 32); an = 32; ad[an++] = (uint8_t)(0x59 | (uv ? 0x04 : 0)); ad[an++] = 0; ad[an++] = 0; ad[an++] = 0; ad[an++] = 0;   // UP+BE+BS+AT, UV when verified
  memcpy(ad + an, AAGUID_DEV, 16); an += 16; ad[an++] = 0; ad[an++] = (uint8_t)PKR_ID; memcpy(ad + an, id, PKR_ID); an += PKR_ID;
  ad[an++] = 0xA5; ad[an++] = 0x01; ad[an++] = 0x02; ad[an++] = 0x03; ad[an++] = 0x26; ad[an++] = 0x20; ad[an++] = 0x01;
  ad[an++] = 0x21; ad[an++] = 0x58; ad[an++] = 0x20; memcpy(ad + an, pub + 1, 32); an += 32;
  ad[an++] = 0x22; ad[an++] = 0x58; ad[an++] = 0x20; memcpy(ad + an, pub + 33, 32); an += 32;
  uint8_t h[32]; sha256(ad, an, cdh, 32, h);
  uint8_t der[80]; size_t derN = 0;
  keepalive(cid, KA_PROCESSING);
  r = g_be.pkrSign(rpIdHash, id, h, der, &derN);
  if (r != 0) { sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] restorable attestation sign failed: %02X\n", r); return; }
  if (ru.rk) {   // the record goes in before the site is told: no record, no credential
    keepalive(cid, KA_PROCESSING);
    int e = g_be.rkSave((const char*)rpId, rpIdN, ru.id, ru.idN, (const char*)ru.name, ru.nameN, (const char*)ru.disp, ru.dispN, id);
    if (e != 0) { memset(der, 0, sizeof(der)); sendStatus(cid, e == favilla::RK_E_FULL ? ST_KEY_STORE_FULL : ST_OTHER); Serial.printf("[FIDO] rk record not saved (%s): not registered\n", favilla::rk_err_name(e)); return; }
  }
  size_t o_ = 0; uint8_t* o = g_resp;
  o[o_++] = ST_OK; o[o_++] = 0xA3;
  o[o_++] = 0x01; o_ += cbPutText(o + o_, "packed");
  o[o_++] = 0x02; o_ += cbPutBytes(o + o_, ad, an);
  o[o_++] = 0x03; o[o_++] = 0xA2; o_ += cbPutText(o + o_, "alg"); o[o_++] = 0x26; o_ += cbPutText(o + o_, "sig"); o_ += cbPutBytes(o + o_, der, derN);
  wb.end();
  sendMsg(cid, CMD_CBOR, o, o_);
  g_made++;
  Serial.printf("[FIDO] REGISTERED (restorable%s) %s, %lu ms on the KEY side (G0 + SE + recovery + attestation)\n", ru.rk ? ", no-username record saved" : "", g_up.rp, (unsigned long)(millis() - t0));
}
static void doAssertRestorable(uint32_t cid, const uint8_t* cdh, const uint8_t* rpId, size_t rpIdN, const uint8_t rpIdHash[32],
                               const uint8_t* const* allow, const size_t* allowN, int nAllow, bool optUp, bool optUv) {
  int cand[16], nc = 0;
  for (int i = 0; i < nAllow; i++) if (pkrIdShape(allow[i], allowN[i])) cand[nc++] = i;
  if (nc == 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.printf("[FIDO] getAssertion: no restorable credential offered (%d IDs)\n", nAllow); return; }
  if (!optUp && g_silentLeft <= 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.println("[FIDO] silent check refused: this life's cap is used up"); return; }
  // Sign FIRST, release only after the press. The G0 refuses an ID that is not
  // this KEY's for this site (tag), so this is also how the right credential is
  // found among several, with ONE G0 call per login and no press for an ID that
  // is not ours. A signature made before the press stays in this task's RAM and
  // is wiped if the press is refused; nothing leaves the KEY without it.
  const bool wantUv = optUv && optUp;   // UV only with a press (a silent check never claims it)
  uint8_t ad[37]; memcpy(ad, rpIdHash, 32); ad[32] = (uint8_t)((optUp ? 0x01 : 0x00) | (wantUv ? 0x04 : 0x00) | 0x18); ad[33] = 0; ad[34] = 0; ad[35] = 0; ad[36] = 0;   // UP (and UV) only when the press (or PIN) will be required before release; BE+BS; signCount 0
  uint8_t h[32]; sha256(ad, 37, cdh, 32, h);
  uint8_t der[80]; size_t derN = 0; uint32_t t0 = millis(); int which = -1;
  // 9g: the prompt goes up first and the G0 signs while the owner reads it
  // (bench 7 Nov 2026: the G0 takes 1.74 s, all of it before the prompt in 9f).
  // Not when the press must be the PIN (UV asked and the window has run out):
  // that prompt is a different screen, shown after the signing as before.
  const bool early = optUp && (!wantUv || (g_be.uvFresh && g_be.uvFresh()));
  if (early) upBegin(cid, "Sign in to", rpId, rpIdN);
  WinBatch wb;   // the candidates share one window
  for (int i = 0; i < nc && i < 4 && which < 0; i++) {
    if (!early) keepalive(cid, KA_PROCESSING);
    if (optUp) {
      if (g_presignLeft <= 0) { if (early) upWithdraw(cid); sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] restorable: pre-press budget for this life is spent - power cycle the KEY"); return; }
      g_presignLeft--;
    }
    int r = g_be.pkrSign(rpIdHash, allow[cand[i]], h, der, &derN);
    if (r == 0) which = cand[i];
    else if (r != 0xE4) { if (early) upWithdraw(cid); sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] restorable assertion failed: %02X\n", r); return; }
  }
  wb.end();   // before the press
  if (which < 0) { if (early) upWithdraw(cid); sendStatus(cid, ST_NO_CREDENTIALS); Serial.println("[FIDO] getAssertion: none of the offered restorable IDs is this KEY's for that site"); return; }
  uint32_t signMs = millis() - t0;
  if (early && g_up.state == 2) Serial.printf("[FIDO] pressed before the G0 finished (%lu ms)\n", (unsigned long)signMs);
  if (optUp) {
    bool uv = false;
    uint8_t u;
    if (early) {
      u = upWait(cid);
      if (!u && wantUv) {   // as askUser: the window can run out while the prompt shows
        if (g_be.uvFresh()) uv = true;
        else { u = waitUp(cid, "PIN for", rpId, rpIdN, 2); if (!u) uv = true; }
      }
    } else u = askUser(cid, "Sign in to", rpId, rpIdN, wantUv, &uv);
    if (u || (wantUv && !uv)) { memset(der, 0, sizeof(der)); sendStatus(cid, u ? u : ST_OPERATION_DENIED); return; }
    if (g_presignLeft < PRESIGN_PER_LIFE) g_presignLeft++;   // an approved sign-in gives its pre-press sign back
  }
  else g_silentLeft--;
  size_t o_ = 0; uint8_t* o = g_resp;
  o[o_++] = ST_OK; o[o_++] = 0xA3;
  o[o_++] = 0x01; o[o_++] = 0xA2; o_ += cbPutText(o + o_, "id"); o_ += cbPutBytes(o + o_, allow[which], PKR_ID); o_ += cbPutText(o + o_, "type"); o_ += cbPutText(o + o_, "public-key");
  o[o_++] = 0x02; o_ += cbPutBytes(o + o_, ad, 37);
  o[o_++] = 0x03; o_ += cbPutBytes(o + o_, der, derN);
  sendMsg(cid, CMD_CBOR, o, o_);
  memset(der, 0, sizeof(der));
  if (optUp) { g_signed++; Serial.printf("[FIDO] SIGNED IN (restorable) to %s, G0 %lu ms (%s)\n", g_up.rp, (unsigned long)signMs, early ? "while the prompt showed" : "before the prompt"); }
  else Serial.printf("[FIDO] silent check answered (restorable, User Present flag clear), %lu ms\n", (unsigned long)signMs);
}
// PSRAM first (internal RAM is short in WiFi hotspot mode), internal as a fallback.
static void* fidoPsCalloc(size_t n, size_t sz) {
#ifdef MALLOC_CAP_SPIRAM
  void* p = heap_caps_calloc(n, sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (p) return p;
#endif
  return calloc(n, sz);
}
// ---- getAssertion with no allowList: a passwordless passkey (2 Nov 2026) --------
// The KEY finds the site's records, the owner picks one on the KEY (that is the
// presence), the KEY always verifies (the 10-minute window, or the PIN), then
// signs with the restorable path and returns that credential and its account.
// Name and display name go out only after UV (CTAP).
// Silent check (up=false), 2 Nov 2026: Windows sends one before every
// no-username sign-in and gives up ("This security key doesn't look familiar")
// on "no credentials", so it is answered as other security keys answer it: an
// assertion for the first account, User Present flag clear, user id only (no
// name or display name), counted against this life's silent cap. A web page
// never sees it (browsers do not let pages ask up=false); software on the
// computer can learn whether the KEY has an account at a site it names, within
// the silent cap and the G0's lookup budget. Nothing is released with a press
// it did not get: a real sign-in still needs the picker and UV.
static void doAssertDiscoverable(uint32_t cid, const uint8_t* cdh, const uint8_t* rpId, size_t rpIdN, const uint8_t rpIdHash[32], bool optUp) {
  if (!rkOpen()) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.println("[FIDO] getAssertion: no username offered and the record store is off (partition table or G0 VAULT)"); return; }
  if (!optUp && g_silentLeft <= 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.println("[FIDO] silent check refused: this life's cap is used up"); return; }
  if (rpIdN > favilla::RK_SITE_MAX) { sendStatus(cid, ST_NO_CREDENTIALS); return; }
  // 2 Nov 2026: in PSRAM, taken on first use and kept (3.5 KB that internal RAM
  // needs in WiFi hotspot mode). Only the FIDO task gets here.
  static favilla::RkAcct* acc = nullptr;
  if (!acc) acc = (favilla::RkAcct*)fidoPsCalloc(PICK_MAX, sizeof(favilla::RkAcct));
  if (!acc) { sendStatus(cid, ST_OTHER); Serial.println("[FIDO] no-username sign-in: no memory"); return; }
  keepalive(cid, KA_PROCESSING);
  uint32_t t0 = millis();
  WinBatch wb;   // a silent check: find and sign in one window (ended before the picker otherwise)
  int n = g_be.rkFind((const char*)rpId, rpIdN, acc, PICK_MAX);
  if (n == favilla::RK_E_BUDGET) { sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] no-username sign-in: this sitting's record opens are used - lock and unlock the KEY (or power cycle once the 4 refills are used)"); return; }
  if (n <= 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.printf("[FIDO] no-username sign-in: no record for %.*s (%s)\n", (int)rpIdN, (const char*)rpId, n < 0 ? favilla::rk_err_name(n) : "none"); return; }
  uint32_t findMs = millis() - t0;
  if (optUp) wb.end();
  if (!optUp) {
    uint8_t ad[37]; memcpy(ad, rpIdHash, 32); ad[32] = 0x18; ad[33] = 0; ad[34] = 0; ad[35] = 0; ad[36] = 0;   // no UP, no UV; BE + BS; signCount 0
    uint8_t h[32]; sha256(ad, 37, cdh, 32, h);
    uint8_t der[80]; size_t derN = 0;
    keepalive(cid, KA_PROCESSING);
    int r = g_be.pkrSign(rpIdHash, acc[0].id34, h, der, &derN);
    if (r != 0) { memset(acc, 0, PICK_MAX * sizeof(favilla::RkAcct)); memset(der, 0, sizeof(der)); sendStatus(cid, ST_NO_CREDENTIALS); Serial.printf("[FIDO] silent check with no username: sign failed %02X\n", r); return; }
    wb.end();
    g_silentLeft--;
    size_t o_ = 0; uint8_t* o = g_resp;
    o[o_++] = ST_OK; o[o_++] = 0xA4;
    o[o_++] = 0x01; o[o_++] = 0xA2; o_ += cbPutText(o + o_, "id"); o_ += cbPutBytes(o + o_, acc[0].id34, PKR_ID); o_ += cbPutText(o + o_, "type"); o_ += cbPutText(o + o_, "public-key");
    o[o_++] = 0x02; o_ += cbPutBytes(o + o_, ad, 37);
    o[o_++] = 0x03; o_ += cbPutBytes(o + o_, der, derN);
    o[o_++] = 0x04; o[o_++] = 0xA1; o_ += cbPutText(o + o_, "id"); o_ += cbPutBytes(o + o_, acc[0].handle, acc[0].handleN);   // user id only: no name without UV
    sendMsg(cid, CMD_CBOR, o, o_);
    memset(der, 0, sizeof(der)); memset(g_resp, 0, sizeof(g_resp)); memset(acc, 0, PICK_MAX * sizeof(favilla::RkAcct));
    Serial.printf("[FIDO] silent check with no username answered (%d account(s), User Present flag clear, no names), %lu ms\n", n, (unsigned long)(millis() - t0));
    return;
  }
  g_pick.n = (uint8_t)n; g_pick.sel = 0;
  for (int i = 0; i < n; i++) {
    const char* a = acc[i].name[0] ? acc[i].name : acc[i].disp[0] ? acc[i].disp : "(no name)";
    const char* b = (acc[i].disp[0] && strcmp(acc[i].disp, a)) ? acc[i].disp : "";
    size_t la = favilla::rk_utf8_cut(a, strlen(a), sizeof(g_pick.name[i]) - 1), lb = favilla::rk_utf8_cut(b, strlen(b), sizeof(g_pick.sub[i]) - 1);   // never split a character
    memcpy(g_pick.name[i], a, la); g_pick.name[i][la] = 0;
    memcpy(g_pick.sub[i], b, lb);  g_pick.sub[i][lb] = 0;
  }
  auto wipe = [&]() { memset(acc, 0, PICK_MAX * sizeof(favilla::RkAcct)); memset((void*)&g_pick, 0, sizeof(g_pick)); };
  uint8_t u = waitUp(cid, "Sign in to", rpId, rpIdN, 3);
  if (u) { wipe(); sendStatus(cid, u); return; }
  int sel = g_pick.sel;
  if (sel < 0 || sel >= n) { wipe(); sendStatus(cid, ST_OTHER); return; }
  bool uv = false;
  if (g_be.uvFresh) {
    if (g_be.uvFresh()) uv = true;
    else { u = waitUp(cid, "PIN for", rpId, rpIdN, 2); if (u) { wipe(); sendStatus(cid, u); return; } uv = true; }
  }
  keepalive(cid, KA_PROCESSING);
  uint8_t ad[37]; memcpy(ad, rpIdHash, 32); ad[32] = (uint8_t)(0x01 | (uv ? 0x04 : 0x00) | 0x18); ad[33] = 0; ad[34] = 0; ad[35] = 0; ad[36] = 0;   // UP (+UV) + BE + BS, signCount 0
  uint8_t h[32]; sha256(ad, 37, cdh, 32, h);
  uint8_t der[80]; size_t derN = 0;
  int r = g_be.pkrSign(rpIdHash, acc[sel].id34, h, der, &derN);
  if (r != 0) { wipe(); memset(der, 0, sizeof(der)); sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] no-username sign-in: sign failed %02X\n", r); return; }
  const favilla::RkAcct& a = acc[sel];
  const bool sendName = uv && a.name[0], sendDisp = uv && a.disp[0];
  size_t o_ = 0; uint8_t* o = g_resp;
  o[o_++] = ST_OK; o[o_++] = 0xA4;
  o[o_++] = 0x01; o[o_++] = 0xA2; o_ += cbPutText(o + o_, "id"); o_ += cbPutBytes(o + o_, a.id34, PKR_ID); o_ += cbPutText(o + o_, "type"); o_ += cbPutText(o + o_, "public-key");
  o[o_++] = 0x02; o_ += cbPutBytes(o + o_, ad, 37);
  o[o_++] = 0x03; o_ += cbPutBytes(o + o_, der, derN);
  o[o_++] = 0x04; o[o_++] = (uint8_t)(0xA1 + (sendName ? 1 : 0) + (sendDisp ? 1 : 0));   // canonical order: id, name, displayName
  o_ += cbPutText(o + o_, "id"); o_ += cbPutBytes(o + o_, a.handle, a.handleN);
  if (sendName) { o_ += cbPutText(o + o_, "name"); o_ += cbPutText(o + o_, a.name); }
  if (sendDisp) { o_ += cbPutText(o + o_, "displayName"); o_ += cbPutText(o + o_, a.disp); }
  sendMsg(cid, CMD_CBOR, o, o_);
  memset(der, 0, sizeof(der)); memset(g_resp, 0, sizeof(g_resp));
  g_signed++;
  Serial.printf("[FIDO] SIGNED IN (no username) to %s, account %d of %d, %lu ms to find the records\n", g_up.rp, sel + 1, n, (unsigned long)findMs);
  wipe();
}
static void doMakeCredential(uint32_t cid, const uint8_t* d, size_t n) {
  Cb c = { d, d + n, true };
  uint64_t cnt; if (!cbCount(c, 5, &cnt)) { sendStatus(cid, ST_INVALID_CBOR); return; }
  const uint8_t* cdh = nullptr; size_t cdhN = 0;
  const uint8_t* rpId = nullptr; size_t rpIdN = 0;
  bool haveUser = false, haveParams = false, es256 = false;
  const uint8_t *uId = nullptr, *uName = nullptr, *uDisp = nullptr; size_t uIdN = 0, uNameN = 0, uDispN = 0;   // 2 Nov 2026: kept for rk
  bool optRk = false, optUv = false, optUp = true, pinPresent = false; size_t pinLen = 0;
  const uint8_t* excl[16]; size_t exclN[16]; int nExcl = 0;
  for (uint64_t i = 0; i < cnt && c.ok; i++) {
    int64_t key; if (!cbInt(c, &key)) break;
    switch (key) {
    case 1: cbStr(c, 2, &cdh, &cdhN); break;
    case 2: { uint64_t m; if (!cbCount(c, 5, &m)) break;
      for (uint64_t j = 0; j < m && c.ok; j++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
        if (txtEq(k, kn, "id")) cbStr(c, 3, &rpId, &rpIdN); else cbSkip(c, 2); }
      break; }
    case 3: { uint64_t m; if (!cbCount(c, 5, &m)) break; haveUser = true;
      for (uint64_t j = 0; j < m && c.ok; j++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
        if (txtEq(k, kn, "id")) cbStr(c, 2, &uId, &uIdN);
        else if (txtEq(k, kn, "name")) cbStr(c, 3, &uName, &uNameN);
        else if (txtEq(k, kn, "displayName")) cbStr(c, 3, &uDisp, &uDispN);
        else cbSkip(c, 2); }
      break; }
    case 4: { uint64_t a; if (!cbCount(c, 4, &a)) break; haveParams = true;
      for (uint64_t j = 0; j < a && c.ok; j++) { uint64_t m; if (!cbCount(c, 5, &m)) break;
        int64_t alg = 0; bool pk = false;
        for (uint64_t q = 0; q < m && c.ok; q++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
          if (txtEq(k, kn, "alg")) cbInt(c, &alg);
          else if (txtEq(k, kn, "type")) { const uint8_t* t; size_t tn; if (cbStr(c, 3, &t, &tn)) pk = txtEq(t, tn, "public-key"); }
          else cbSkip(c, 2); }
        if (alg == -7 && pk) es256 = true; }
      break; }
    case 5: { uint64_t a; if (!cbCount(c, 4, &a)) break;
      for (uint64_t j = 0; j < a && c.ok; j++) { uint64_t m; if (!cbCount(c, 5, &m)) break;
        for (uint64_t q = 0; q < m && c.ok; q++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
          if (txtEq(k, kn, "id")) { const uint8_t* s; size_t sn; if (cbStr(c, 2, &s, &sn) && nExcl < 16) { excl[nExcl] = s; exclN[nExcl] = sn; nExcl++; } }
          else cbSkip(c, 2); } }
      break; }
    case 7: { uint64_t m; if (!cbCount(c, 5, &m)) break;
      for (uint64_t j = 0; j < m && c.ok; j++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
        bool v = false;
        if (txtEq(k, kn, "rk")) { cbBool(c, &v); optRk = v; }
        else if (txtEq(k, kn, "uv")) { cbBool(c, &v); optUv = v; }
        else if (txtEq(k, kn, "up")) { cbBool(c, &v); optUp = v; }
        else cbSkip(c, 2); }
      break; }
    case 8: { const uint8_t* s; if (cbStr(c, 2, &s, &pinLen)) pinPresent = true; break; }
    default: cbSkip(c, 1); break;                      // 6 extensions, 9 protocol, unknown: ignored
    }
  }
  if (!c.ok || c.p != c.e) { sendStatus(cid, ST_INVALID_CBOR); Serial.println("[FIDO] makeCredential: bad CBOR"); return; }
  if (!cdh || !rpId || !haveUser || !haveParams) { sendStatus(cid, ST_MISSING_PARAMETER); return; }
  if (cdhN != 32 || rpIdN == 0 || rpIdN > 253) { sendStatus(cid, ST_INVALID_LENGTH); return; }
  const bool restorable = pkrOpen();
  if (!doorOpen() && !restorable) { if (g_be.refused) g_be.refused(); sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] makeCredential refused: passkeys are not open in this mode (PASSKEY mode with the PIN, or NOSTR mode unlocked with the NOSTR gate allowed)"); return; }
  { uint8_t st = pinParamStatus(cid, pinPresent, pinLen, rpId, rpIdN); if (st) { sendStatus(cid, st); return; } }
  if (!es256) { sendStatus(cid, ST_UNSUPPORTED_ALGORITHM); Serial.println("[FIDO] makeCredential: no ES256 offered"); return; }
  if (optRk && !restorable && rkStore()) { sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] makeCredential: rk refused, the KEY is locked or passkeys are off in this mode (PASSKEY mode, or NOSTR mode with the gate allowed)"); return; }
  if (optRk && !(restorable && rkOpen())) { sendStatus(cid, ST_UNSUPPORTED_OPTION); Serial.println("[FIDO] makeCredential: refused rk (no-username passkeys need a v13 G0, the record store and an open passkey copy)"); return; }
  if (optRk && (!uId || uIdN == 0 || uIdN > favilla::RK_HANDLE_MAX)) { sendStatus(cid, ST_INVALID_LENGTH); Serial.println("[FIDO] makeCredential: rk needs a user handle of 1..64 bytes"); return; }
  if (optRk && rpIdN > favilla::RK_SITE_MAX) { sendStatus(cid, ST_UNSUPPORTED_OPTION); Serial.printf("[FIDO] makeCredential: rk refused, site name over %u bytes\n", (unsigned)favilla::RK_SITE_MAX); return; }
  if (optUv && !g_be.uvFresh) { sendStatus(cid, ST_UNSUPPORTED_OPTION); return; }
  if (!optUp) { sendStatus(cid, ST_INVALID_OPTION); return; }
  uint8_t rpIdHash[32]; sha256(rpId, rpIdN, nullptr, 0, rpIdHash);
  if (restorable) {
    // Review (M4): in a PASSKEY life the excludeList may name a device-bound
    // credential on this KEY; CTAP requires CREDENTIAL_EXCLUDED, not a second one.
    if (doorOpen()) for (int i = 0; i < nExcl; i++) if (slotFind(excl[i], exclN[i], rpIdHash) >= 0) {
      uint8_t u = waitUp(cid, "Already registered", rpId, rpIdN);
      sendStatus(cid, u ? u : ST_CREDENTIAL_EXCLUDED); return;
    }
    RkUser ru = { optRk, uId, uIdN, uName, uNameN, uDisp, uDispN };
    doMakeRestorable(cid, cdh, rpId, rpIdN, rpIdHash, excl, exclN, nExcl, optUv, ru); return; }
  for (int i = 0; i < nExcl; i++) if (slotFind(excl[i], exclN[i], rpIdHash) >= 0) {
    uint8_t u = waitUp(cid, "Already registered", rpId, rpIdN);
    sendStatus(cid, u ? u : ST_CREDENTIAL_EXCLUDED); return;
  }
  int slot = -1; for (int i = 0; i < MAX_SLOTS; i++) if (!slotLive(i)) { slot = i; break; }
  if (slot < 0) { sendStatus(cid, ST_KEY_STORE_FULL); Serial.println("[FIDO] makeCredential: all slots used"); return; }
  if (!g_be.keygen || !g_be.sign) { sendStatus(cid, ST_OTHER); return; }
  { int fb = g_be.freeBytes ? g_be.freeBytes() : -1;
    if (fb >= 0 && fb < FREE_RESERVE_BYTES + 400) { sendStatus(cid, ST_KEY_STORE_FULL); Serial.printf("[FIDO] makeCredential: SE free %d below reserve\n", fb); return; } }
  bool uv = false;
  { uint8_t u = askUser(cid, "Register with", rpId, rpIdN, optUv, &uv); if (u) { sendStatus(cid, u); return; } }

  keepalive(cid, KA_PROCESSING);
  uint32_t obj = SLOT_OBJ_BASE + slot; uint8_t pub[65]; uint16_t sw = 0; uint32_t t0 = millis();
  if (!g_be.keygen(obj, pub, &sw) || pub[0] != 0x04) { sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] keygen failed SW %04X\n", sw); return; }
  uint8_t credId[16]; esp_fill_random(credId, 16);
  // authData = rpIdHash | flags UP+AT | signCount 0 | AAGUID | credIdLen | credId | COSE EC2 key
  uint8_t ad[160]; size_t an = 0;
  memcpy(ad, rpIdHash, 32); an = 32; ad[an++] = (uint8_t)(0x41 | (uv ? 0x04 : 0)); ad[an++] = 0; ad[an++] = 0; ad[an++] = 0; ad[an++] = 0;   // UP+AT, UV when verified
  memcpy(ad + an, AAGUID_DEV, 16); an += 16; ad[an++] = 0; ad[an++] = 16; memcpy(ad + an, credId, 16); an += 16;
  ad[an++] = 0xA5; ad[an++] = 0x01; ad[an++] = 0x02; ad[an++] = 0x03; ad[an++] = 0x26; ad[an++] = 0x20; ad[an++] = 0x01;
  ad[an++] = 0x21; ad[an++] = 0x58; ad[an++] = 0x20; memcpy(ad + an, pub + 1, 32); an += 32;
  ad[an++] = 0x22; ad[an++] = 0x58; ad[an++] = 0x20; memcpy(ad + an, pub + 33, 32); an += 32;
  // packed self-attestation: the new key signs authData || clientDataHash
  uint8_t h[32]; sha256(ad, an, cdh, 32, h);
  uint8_t der[80]; size_t derN = 0;
  keepalive(cid, KA_PROCESSING);
  if (!g_be.sign(obj, h, der, &derN, &sw)) { if (g_be.del) g_be.del(obj); sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] attestation sign failed SW %04X\n", sw); return; }
  g_slots[slot].used = 1; g_slots[slot].gen = liveGen(); memcpy(g_slots[slot].credId, credId, 16); memcpy(g_slots[slot].rpIdHash, rpIdHash, 32);
  if (!slotSave(slot)) { g_slots[slot].used = 0; if (g_be.del) g_be.del(obj); sendStatus(cid, ST_OTHER); Serial.println("[FIDO] NVS save failed"); return; }
  // { 1: "packed", 2: authData, 3: { "alg": -7, "sig": der } }
  size_t r = 0; uint8_t* o = g_resp;
  o[r++] = ST_OK; o[r++] = 0xA3;
  o[r++] = 0x01; r += cbPutText(o + r, "packed");
  o[r++] = 0x02; r += cbPutBytes(o + r, ad, an);
  o[r++] = 0x03; o[r++] = 0xA2; r += cbPutText(o + r, "alg"); o[r++] = 0x26; r += cbPutText(o + r, "sig"); r += cbPutBytes(o + r, der, derN);
  sendMsg(cid, CMD_CBOR, o, r);
  g_made++;
  Serial.printf("[FIDO] REGISTERED %s in slot %d (SE obj %08lX), %lu ms on the SE side\n", g_up.rp, slot, (unsigned long)obj, (unsigned long)(millis() - t0));
}

// ---- getAssertion -------------------------------------------------------------
static void doGetAssertion(uint32_t cid, const uint8_t* d, size_t n) {
  Cb c = { d, d + n, true };
  uint64_t cnt; if (!cbCount(c, 5, &cnt)) { sendStatus(cid, ST_INVALID_CBOR); return; }
  const uint8_t* rpId = nullptr; size_t rpIdN = 0; const uint8_t* cdh = nullptr; size_t cdhN = 0;
  const uint8_t* allow[16]; size_t allowN[16]; int nAllow = 0;
  bool optUv = false, optUp = true, optRk = false, pinPresent = false; size_t pinLen = 0;
  for (uint64_t i = 0; i < cnt && c.ok; i++) {
    int64_t key; if (!cbInt(c, &key)) break;
    switch (key) {
    case 1: cbStr(c, 3, &rpId, &rpIdN); break;
    case 2: cbStr(c, 2, &cdh, &cdhN); break;
    case 3: { uint64_t a; if (!cbCount(c, 4, &a)) break;
      for (uint64_t j = 0; j < a && c.ok; j++) { uint64_t m; if (!cbCount(c, 5, &m)) break;
        for (uint64_t q = 0; q < m && c.ok; q++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
          if (txtEq(k, kn, "id")) { const uint8_t* s; size_t sn; if (cbStr(c, 2, &s, &sn) && nAllow < 16) { allow[nAllow] = s; allowN[nAllow] = sn; nAllow++; } }
          else cbSkip(c, 2); } }
      break; }
    case 5: { uint64_t m; if (!cbCount(c, 5, &m)) break;
      for (uint64_t j = 0; j < m && c.ok; j++) { const uint8_t* k; size_t kn; if (!cbStr(c, 3, &k, &kn)) break;
        bool v = false;
        if (txtEq(k, kn, "uv")) { cbBool(c, &v); optUv = v; }
        else if (txtEq(k, kn, "up")) { cbBool(c, &v); optUp = v; }
        else if (txtEq(k, kn, "rk")) { cbBool(c, &v); optRk = v; }
        else cbSkip(c, 2); }
      break; }
    case 6: { const uint8_t* s; if (cbStr(c, 2, &s, &pinLen)) pinPresent = true; break; }
    default: cbSkip(c, 1); break;                      // 4 extensions, 7 protocol, unknown
    }
  }
  if (!c.ok || c.p != c.e) { sendStatus(cid, ST_INVALID_CBOR); Serial.println("[FIDO] getAssertion: bad CBOR"); return; }
  if (!rpId || !cdh) { sendStatus(cid, ST_MISSING_PARAMETER); return; }
  if (cdhN != 32 || rpIdN == 0 || rpIdN > 253) { sendStatus(cid, ST_INVALID_LENGTH); return; }
  const bool restorable = pkrOpen();
  if (!doorOpen() && !restorable) { if (g_be.refused) g_be.refused(); sendStatus(cid, ST_OPERATION_DENIED); Serial.println("[FIDO] getAssertion refused: passkeys are not open in this mode (PASSKEY mode with the PIN, or NOSTR mode unlocked with the NOSTR gate allowed)"); return; }
  { uint8_t st = pinParamStatus(cid, pinPresent, pinLen, rpId, rpIdN); if (st) { sendStatus(cid, st); return; } }
  if (optRk) { sendStatus(cid, ST_INVALID_OPTION); return; }
  if (optUv && !g_be.uvFresh) { sendStatus(cid, ST_UNSUPPORTED_OPTION); return; }
  // 2 Nov 2026 (2b): a PASSKEY life holds both kinds. A request that offers only
  // device-bound IDs (16 bytes) goes to the device-bound path below.
  bool anyPkr = false; for (int i = 0; i < nAllow; i++) if (pkrIdShape(allow[i], allowN[i])) anyPkr = true;
  // Review (M5): a mixed list whose device-bound ID is ours goes to the device-bound path.
  bool devHit = false;
  if (doorOpen() && nAllow > 0) { uint8_t rh0[32]; sha256(rpId, rpIdN, nullptr, 0, rh0); for (int i = 0; i < nAllow && !devHit; i++) if (slotFind(allow[i], allowN[i], rh0) >= 0) devHit = true; }
  if (restorable && !devHit && (nAllow == 0 || anyPkr || !doorOpen())) { uint8_t rh[32]; sha256(rpId, rpIdN, nullptr, 0, rh);
    if (nAllow == 0) { doAssertDiscoverable(cid, cdh, rpId, rpIdN, rh, optUp); return; }   // 2 Nov 2026: no username
    doAssertRestorable(cid, cdh, rpId, rpIdN, rh, allow, allowN, nAllow, optUp, optUv); return; }
  // up=false is the platform's silent "is this credential on this key?" check.
  // 30 Oct 2026: refusing it made Windows show "This security key doesn't look
  // familiar" and never send the real request. Answered the standard way: a
  // signature with the User Present flag CLEAR. Relying parties are required to
  // reject UP=0 as a login (WebAuthn: verify the UP bit), so it cannot sign you
  // in anywhere; it only tells the platform which key to ask. No screen, no press.
  uint8_t rpIdHash[32]; sha256(rpId, rpIdN, nullptr, 0, rpIdHash);
  int slot = -1, which = -1;
  for (int i = 0; i < nAllow && slot < 0; i++) { slot = slotFind(allow[i], allowN[i], rpIdHash); which = i; }
  if (slot < 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.printf("[FIDO] getAssertion: no credential here for that site (%d offered)\n", nAllow); return; }
  bool uv = false;
  if (optUp) { uint8_t u = askUser(cid, "Sign in to", rpId, rpIdN, optUv, &uv); if (u) { sendStatus(cid, u); return; } }
  else if (g_silentLeft <= 0) { sendStatus(cid, ST_NO_CREDENTIALS); Serial.println("[FIDO] silent check refused: this life's cap is used up"); return; }
  else g_silentLeft--;

  keepalive(cid, KA_PROCESSING);
  uint8_t ad[37]; memcpy(ad, rpIdHash, 32); ad[32] = (uint8_t)((optUp ? 0x01 : 0x00) | (uv ? 0x04 : 0x00)); ad[33] = 0; ad[34] = 0; ad[35] = 0; ad[36] = 0;   // UP only after a press, UV only after the PIN check; signCount 0
  uint8_t h[32]; sha256(ad, 37, cdh, 32, h);
  uint8_t der[80]; size_t derN = 0; uint16_t sw = 0; uint32_t t0 = millis();
  if (!g_be.sign || !g_be.sign(SLOT_OBJ_BASE + slot, h, der, &derN, &sw)) { sendStatus(cid, ST_OTHER); Serial.printf("[FIDO] assertion sign failed SW %04X\n", sw); return; }
  // { 1: {"id": credId, "type": "public-key"}, 2: authData, 3: signature }
  size_t r = 0; uint8_t* o = g_resp;
  o[r++] = ST_OK; o[r++] = 0xA3;
  o[r++] = 0x01; o[r++] = 0xA2; r += cbPutText(o + r, "id"); r += cbPutBytes(o + r, allow[which], 16); r += cbPutText(o + r, "type"); r += cbPutText(o + r, "public-key");
  o[r++] = 0x02; r += cbPutBytes(o + r, ad, 37);
  o[r++] = 0x03; r += cbPutBytes(o + r, der, derN);
  sendMsg(cid, CMD_CBOR, o, r);
  if (optUp) { g_signed++; Serial.printf("[FIDO] SIGNED IN to %s with slot %d, %lu ms on the SE side\n", g_up.rp, slot, (unsigned long)(millis() - t0)); }
  else Serial.printf("[FIDO] silent check answered for slot %d (User Present flag clear, not usable as a login), %lu ms\n", slot, (unsigned long)(millis() - t0));
}

// ---- one assembled message --------------------------------------------------
static uint32_t g_nextCid = 1;
static void handle(uint32_t cid, uint8_t cmd, const uint8_t* d, size_t n) {
  switch (cmd) {
  case CMD_INIT: {
    if (n != 8) { sendErr(cid, ERR_INVALID_LEN); return; }
    uint8_t r[17]; memcpy(r, d, 8);
    uint32_t newCid = (cid == CID_BROADCAST) ? g_nextCid++ : cid;
    if (g_nextCid == 0 || g_nextCid == CID_BROADCAST || g_nextCid == CID_BLE) g_nextCid = 1;   // 9a: never hand out the Bluetooth channel
    wr32(r + 8, newCid);
    r[12] = 2; r[13] = 0; r[14] = 4; r[15] = 0;        // CTAPHID v2, device version 0.4.0 (restorable passkeys)
    r[16] = CAP_CBOR | CAP_NMSG;
    sendMsg(cid, CMD_INIT, r, sizeof r);
    Serial.printf("[FIDO] INIT on %08lX -> channel %08lX\n", (unsigned long)cid, (unsigned long)newCid);
    return; }
  case CMD_PING: sendMsg(cid, CMD_PING, d, n); return;
  case CMD_CANCEL: return;
  case CMD_CBOR: {
    if (cid == CID_BROADCAST) { sendErr(cid, ERR_INVALID_CHANNEL); return; }
    if (n < 1) { sendErr(cid, ERR_INVALID_LEN); return; }
    switch (d[0]) {
    case CTAP2_GET_INFO: {
      if (n != 1) { sendStatus(cid, ST_INVALID_CBOR); return; }
      uint8_t r[96]; size_t rn = buildGetInfo(r); sendMsg(cid, CMD_CBOR, r, rn); g_getinfo++;
      Serial.printf("[FIDO] getInfo answered (%u bytes)\n", (unsigned)rn);
      return; }
    case CTAP2_MAKE_CREDENTIAL: Serial.printf("[FIDO] makeCredential (%u bytes)\n", (unsigned)n); kaBegin(cid, KA_PROCESSING); doMakeCredential(cid, d + 1, n - 1); kaEnd(); return;
    case CTAP2_GET_ASSERTION:   Serial.printf("[FIDO] getAssertion (%u bytes)\n", (unsigned)n);   kaBegin(cid, KA_PROCESSING); doGetAssertion(cid, d + 1, n - 1); kaEnd(); return;
    default:
      sendStatus(cid, ST_INVALID_COMMAND);
      Serial.printf("[FIDO] CTAP2 command 0x%02X refused (not in step 2)\n", d[0]);
      return;
    } }
  default:
    sendErr(cid, ERR_INVALID_CMD);
    Serial.printf("[FIDO] CTAPHID command 0x%02X refused\n", cmd);
    return;
  }
}

// ---- reassembly: one transaction at a time ----------------------------------
static uint8_t  g_buf[MAX_MSG];
static bool     g_busy = false;
static uint32_t g_cid = 0, g_t0 = 0;
static uint8_t  g_cmd = 0, g_seq = 0;
static size_t   g_len = 0, g_have = 0;

static void onPacket(const uint8_t* p) {
  uint32_t cid = rd32(p);
  if (cid == 0) return;
  if (p[4] & 0x80) {
    uint8_t cmd = p[4] & 0x7F; size_t len = ((size_t)p[5] << 8) | p[6];
    if (g_busy && cid != g_cid && !(cmd == CMD_INIT && cid == CID_BROADCAST)) { sendErr(cid, ERR_CHANNEL_BUSY); return; }
    if (cmd == CMD_INIT) g_busy = false;
    if (len > MAX_MSG) { sendErr(cid, ERR_INVALID_LEN); g_busy = false; return; }
    if (cid == CID_BROADCAST && cmd != CMD_INIT) { sendErr(cid, ERR_INVALID_CHANNEL); return; }
    size_t k = len < 57 ? len : 57;
    memcpy(g_buf, p + 7, k);
    g_cid = cid; g_cmd = cmd; g_len = len; g_have = k; g_seq = 0; g_t0 = millis();
    if (g_have >= g_len) { g_busy = false; handle(g_cid, g_cmd, g_buf, g_len); }
    else g_busy = true;
    return;
  }
  if (!g_busy || cid != g_cid) { if (g_busy) sendErr(cid, ERR_CHANNEL_BUSY); return; }
  if (p[4] != g_seq) { sendErr(cid, ERR_INVALID_SEQ); g_busy = false; return; }
  g_seq++;
  size_t k = (g_len - g_have) < 59 ? (g_len - g_have) : 59;
  memcpy(g_buf + g_have, p + 5, k); g_have += k;
  if (g_have >= g_len) { g_busy = false; handle(g_cid, g_cmd, g_buf, g_len); }
}

// ---- the way back to flashing (30 Oct 2026) ----------------------------------
// The FIDO env runs USB on the OTG controller (TinyUSB). The Arduino core's own
// "reboot to bootloader" (esptool's DTR/RTS reset, usb_persist_restart) brings
// the ROM loader up on OTG too, and on the bench PC that loader never
// enumerated ("Unknown USB Device (Device Descriptor Request Failed)"), which
// stranded a secure-boot unit on this firmware. Here the reboot first hands
// the internal USB PHY back to the USB-Serial/JTAG controller, the port the
// Forge flashes every day, then forces the ROM into download mode. The KEY
// comes back on its normal flashing port (the COM number the bench build uses).
// Arduino's own OTG reboot is switched off (enableReboot(false)); esptool's
// reset pattern is caught here instead and routed the same way.
static volatile bool g_toLoader = false;
static void restartToUsjLoader() {
  Serial.println("[FIDO] rebooting into the ROM loader on the USB-Serial/JTAG port - flash from the Forge on the KEY's normal flashing port");
  Serial.flush(); delay(150);
#ifdef FIDO_HAVE_PERSIST_CLEAR
  chip_usb_set_persist_flags(0);                 // no OTG persistence: the ROM must not pick OTG
#endif
  RTCCNTL.usb_conf.sw_hw_usb_phy_sel = 1;        // software decides who owns the PHY ...
  RTCCNTL.usb_conf.sw_usb_phy_sel = 0;           // ... and it is USB-Serial/JTAG
  REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
  esp_restart();
}
// esptool's reset patterns on a CDC port, as (dtr,rts) states with repeats
// dropped. Our TinyUSB device uses VID 303A / PID 1001, the same PID as the
// USB-Serial/JTAG port, so esptool may use either sequence:
//   classic reset:      (0,1) (1,1) (1,0) (0,0)
//   USB-JTAG reset:     (1,0) (1,1) (0,1) (0,0)
// A serial monitor opening or closing never produces either full sequence.
static uint8_t g_hist[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
static void onLineState(bool dtr, bool rts) {
  uint8_t st = (uint8_t)((dtr ? 2 : 0) | (rts ? 1 : 0));
  if (st == g_hist[3]) return;                       // repeats carry no information
  memmove(g_hist, g_hist + 1, 3); g_hist[3] = st;
  static const uint8_t CLASSIC[4] = { 1, 3, 2, 0 }, USJ[4] = { 2, 3, 1, 0 };
  if (!memcmp(g_hist, CLASSIC, 4) || !memcmp(g_hist, USJ, 4)) g_toLoader = true;
}
static void cdcEvent(void*, esp_event_base_t, int32_t id, void* data) {
  if (id != ARDUINO_USB_CDC_LINE_STATE_EVENT || !data) return;
  arduino_usb_cdc_event_data_t* d = (arduino_usb_cdc_event_data_t*)data;
  onLineState(d->line_state.dtr, d->line_state.rts);
}

// 9a: a whole Bluetooth request (already reassembled) into the FIDO task's
// queue as CTAPHID packets on CID_BLE. cmd is a CTAPHID command (CMD_CBOR,
// CMD_PING or CMD_CANCEL). Called from the Bluetooth host task; it waits up to
// 50 ms per packet for room (the FIDO task drains the queue as it goes).
static bool injectBle(uint8_t cmd, const uint8_t* d, size_t n) {
  if (!g_q || n > MAX_MSG) return false;
  Pkt p; memset(p.b, 0, 64); wr32(p.b, CID_BLE); p.b[4] = 0x80 | cmd; p.b[5] = n >> 8; p.b[6] = n & 0xFF;
  size_t k = n < 57 ? n : 57; if (k) memcpy(p.b + 7, d, k); size_t off = k; uint8_t seq = 0;
  if (xQueueSend(g_q, &p, pdMS_TO_TICKS(50)) != pdTRUE) { g_dropped++; return false; }
  while (off < n) {
    memset(p.b, 0, 64); wr32(p.b, CID_BLE); p.b[4] = seq++ & 0x7F;
    k = (n - off) < 59 ? (n - off) : 59; memcpy(p.b + 5, d + off, k); off += k;
    if (xQueueSend(g_q, &p, pdMS_TO_TICKS(50)) != pdTRUE) { g_dropped++; return false; }
  }
  return true;
}

static void task(void*) {
  Pkt p;
  for (;;) {
    if (g_toLoader) restartToUsjLoader();
    if (xQueueReceive(g_q, &p, pdMS_TO_TICKS(100)) == pdTRUE) onPacket(p.b);
    if (g_busy && millis() - g_t0 > MSG_TIMEOUT_MS) { sendErr(g_cid, ERR_MSG_TIMEOUT); g_busy = false; }
  }
}

// 10d (Josh, 9 Nov 2026: "fido is only in passkey door"). Two halves:
//  startUsb(): the USB side, every life. The FIDO interface is in the USB
//    descriptor from boot either way (Dev registers it when constructed); this
//    starts the HID object and the serial port's reboot handling (the OTG
//    reboot strands units, see restartToUsjLoader).
//  start(): the FIDO service: the slot index, the queue and the two tasks
//    (13 KB of stack in internal RAM). PASSKEY life only. Elsewhere a site's
//    request finds no queue and is dropped (every entry checks g_q), so the
//    browser waits and gives up, and that RAM stays free for Wi-Fi (the NOSTR
//    Wi-Fi life ran out of internal RAM and aborted in the PHY, 9 Nov).
static void startUsb() {
  static bool done = false; if (done) return; done = true;
  g_dev.hid.begin();
#if ARDUINO_USB_CDC_ON_BOOT   // 4 Nov 2026: the vchan env has no USB serial port (flash it with the boot strap held)
  Serial.enableReboot(false);                           // Arduino's OTG reboot strands units: see restartToUsjLoader
  Serial.onEvent(ARDUINO_USB_CDC_LINE_STATE_EVENT, cdcEvent);
#else
  // 6g (4 Nov 2026): its own product ID. This build's interface layout differs
  // from the serial-port build's, and Windows reused the cached per-interface
  // drivers for the same ID: the keyboard interface came up with no HID driver
  // ("Favilla KEY keyboard" under Universal Serial Bus devices) and could not type.
  USB.PID(0x1F01);   // bench only, under Espressif's 303A
  USB.begin();   // 6f: with the serial port on, the core starts USB at boot; without it nothing did (6e: no USB at all)
#endif
}
static void start() {
  if (g_q) return;
  startUsb();
  slotsLoad();
  g_q = xQueueCreate(16, sizeof(Pkt));
  g_txMx = xSemaphoreCreateMutex();
  if (xTaskCreatePinnedToCore(task, "fido", 10240, nullptr, 5, nullptr, 0) != pdPASS) Serial.println("[FIDO] USB TASK NOT STARTED (no RAM for its stack)");   // 11ak
  if (xTaskCreatePinnedToCore(kaTask, "fidoka", 3072, nullptr, 6, nullptr, 0) != pdPASS) Serial.println("[FIDO] keepalive task not started (no RAM)");
  Serial.printf("[FIDO] step 3b: FIDO HID up (real PASSKEY door, no UV, no resident keys) | %d index record(s)\n", slotsUsedRaw());
}
// Without the FIDO task (any life but PASSKEY), the serial port's "reboot to
// the loader" request is acted on here, from the loop (10d).
static void pollLoader() { if (g_toLoader && !g_q) restartToUsjLoader(); }
static void status() {
  Serial.printf("[FIDO] hid ready %d | door %s | packets in %lu (dropped %lu) | reports out %lu (failed %lu) | getInfo %lu | registered %lu | signed %lu | slots %d/%d | silent left %d | pre-press left %d\n",
                (int)g_dev.hid.ready(), doorOpen() ? "OPEN" : pkrOpen() ? "RESTORABLE (NOSTR life)" : "closed", (unsigned long)g_rx, (unsigned long)g_dropped, (unsigned long)g_tx, (unsigned long)g_txfail,
                (unsigned long)g_getinfo, (unsigned long)g_made, (unsigned long)g_signed, slotsUsed(), MAX_SLOTS, g_silentLeft, g_presignLeft);
}
// Bench: forget every credential (NVS index) and delete their SE keys.
static void wipe() {
  Preferences p; if (p.begin(IDX_NS, false)) { p.clear(); p.end(); }
  for (int i = 0; i < MAX_SLOTS; i++) { if (g_be.del) g_be.del(SLOT_OBJ_BASE + i); g_slots[i].used = 0; }
  Serial.println("[FIDO] all passkey credentials wiped (NVS index + SE keys)");
}

}  // namespace fido
#endif  // FAVILLA_FIDO_PROBE
