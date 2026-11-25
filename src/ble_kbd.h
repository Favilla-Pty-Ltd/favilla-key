// =============================================================================
// ble_kbd.h - the KEY as a Bluetooth keyboard (Vault phase 6, 4 Nov 2026).
// =============================================================================
// Ruled (Josh, 4 Nov 2026): a lasting setting, OFF by default, read at power-on;
// Bluetooth exists only in a PASSKEY life that started with the setting on.
// NOSTR, Bitcoin and the air-gap life never have it, whatever the setting says.
//
// HOW "NEVER" IS HELD
//  The barrier is ONE choke point: the link wraps esp_bt_controller_init (the
//  only caller in the Bluetooth library is NimBLE's port init; checked in the
//  image) and the wrapper refuses unless g_btLife is set. g_btLife is set once,
//  in a PASSKEY life that started with the setting on, and never cleared.
//  Memory is separate and is about RAM, not safety (review, 4 Nov 2026: the
//  release sets no flag that would stop a later init). btInUse() answers the
//  Arduino core before setup(): setting off, the core hands the controller's
//  memory back to the heap at once; on, it is kept until the life is known and
//  handed back there unless this is a Bluetooth PASSKEY life (blekLifeDecide).
//
// PAIRING (numeric comparison, LE Secure Connections, bonded)
//  A phone can pair only while PAIR A PHONE is open on the KEY (90 s). The phone
//  and the KEY show the same 6 digits; ENTER on the KEY accepts. The KEY keeps
//  its own list of the phones it confirmed: the identity address AND a hash of
//  the bond's keys (LTK, IRK) as they were when the owner confirmed. Every
//  encrypted link is checked against it: the stored bond must still hash the
//  same and be Secure Connections, authenticated, 16-byte key. A copied address
//  with new keys (review, 4 Nov 2026: a peer can claim a known phone's identity
//  in a fresh pairing, or pair by passkey with the never-shown passkey), Just
//  Works, a passkey method, a pairing outside the window: refused, bond deleted.
//  The store never evicts a confirmed phone to make room, and a known phone
//  re-pairing outside the window is ignored, not deleted (both were denial of
//  service in the library's defaults).
//
// TYPING
//  The same layout table and the same rules as USB (kbd_layout.h): every
//  character is checked first, nothing is typed if one cannot be, and nothing
//  is typed except after a press on the KEY. Reports go out as notifications on
//  the HID input report, which needs an encrypted link.
// =============================================================================
#pragma once
extern const char g_fwDrop[];   // 8y: the bench drop name (main.cpp)
#include "services/gatt/ble_svc_gatt.h"   // 8y: ble_svc_gatt_changed
#if defined(FAVILLA_FIDO_PROBE) && defined(FAVILLA_BLE_KBD)
#include <Arduino.h>
#include <sys/time.h>   // 9j: settimeofday (the clock from the phone)
#include <nvs.h>
#include <esp_random.h>   // 11dp: esp_fill_random (the random static address)
#include <esp_bt.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include "services/gap/ble_svc_gap.h"
#include <BLESecurity.h>
#include "host/ble_gap.h"
#include "host/ble_store.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_gatt.h"
#include "host/ble_att.h"   // 9a: ble_att_mtu
#include "kbd_layout.h"
#include "chan_proto.h"   // 8z7: the phone's sign-in request uses the USB channel's body rules and status codes
#include <mbedtls/sha256.h>
#include <mbedtls/platform_util.h>

extern bool g_btLife;   // main.cpp: set once, in a PASSKEY life with the setting on

// 8b (bench, 4 Nov 2026: drop 8a restarted the KEY as Bluetooth started). Where
// the start got to, and what any crash was, kept in RTC memory across the
// restart (main.cpp prints it at the next boot and skips Bluetooth for that
// life if the last start never finished, so the KEY cannot loop).
struct BtCrumbs { uint32_t magic; uint32_t stage; uint32_t panics; int32_t exc; uint32_t addr; uint32_t pcs[12]; char reason[48]; };
extern BtCrumbs g_btCrumbs;
constexpr uint32_t BT_CRUMB_MAGIC = 0xB7C0DE5Au;
inline void crumb(uint32_t st) {
  g_btCrumbs.magic = BT_CRUMB_MAGIC; g_btCrumbs.stage = st;
  // 8d: internal RAM at every step (8c ran out of it in the attribute table)
  Serial.printf("[BT] stage %lu: internal free %u, largest %u\n", (unsigned long)st, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
}

namespace blek {

// ---- the setting (default nvs partition, namespace favbt) ---------------------
// The default partition because btInUse() reads it before setup(), when only
// that partition is open.
inline bool settingOn() {
  nvs_handle_t h; uint8_t v = 0;
  if (nvs_open("favbt", NVS_READONLY, &h) == ESP_OK) { nvs_get_u8(h, "on", &v); nvs_close(h); }
  return v == 1;
}
inline bool settingSet(bool on) {
  nvs_handle_t h;
  if (nvs_open("favbt", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t e = nvs_set_u8(h, "on", on ? 1 : 0);
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  return e == ESP_OK;
}

// 9c (Josh, 6 Nov 2026): the keyboard is its own setting, read at power-on with
// the Bluetooth one. Off: the KEY offers no keyboard service at all, so a phone
// never loses its own keyboard to it; the iPhone app gets passwords by AutoFill
// (fillSend) and passkeys by CTAP, the link can stay up, and the KEY advertises
// the whole life so the app connects at once. On (the default, as before 9c):
// the KEY is also a Bluetooth keyboard for phones and computers without the app.
inline bool kbSettingOn() {
  nvs_handle_t h; uint8_t v = 1;
  if (nvs_open("favbt", NVS_READONLY, &h) == ESP_OK) { nvs_get_u8(h, "kb", &v); nvs_close(h); }
  return v != 0;
}
inline bool kbSettingSet(bool on) {
  nvs_handle_t h;
  if (nvs_open("favbt", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t e = nvs_set_u8(h, "kb", on ? 1 : 0);
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  return e == ESP_OK;
}
// 11dp (23 Nov 2026, UX drop 2): the KEY's Bluetooth identity. An iPhone keeps
// its bond per peer address and no app can clear it, so after Forget all phones
// the old entry in iOS Settings blocked a new pairing until the owner removed it
// by hand. The chip's public address is kept until the first forget (phones
// already paired stay paired); each forget then makes a fresh random static
// address, saved in favbt/"addr", and the name gains its last four hex digits
// ("Favilla KEY 3F9A") so the new KEY is a new device to the phone. The app
// finds the KEY by its service or the "Favilla KEY" prefix, so it still matches.
static uint8_t s_addr[6]; static bool s_addrRnd = false; static char s_name[20] = "Favilla KEY";
inline bool addrValid(const uint8_t a[6]) {   // random static: the top two bits set, the other 46 not all 0 or all 1
  if ((a[5] & 0xC0) != 0xC0) return false;
  bool z = (a[5] & 0x3F) == 0, o = (a[5] & 0x3F) == 0x3F;
  for (int i = 0; i < 5; i++) { z = z && a[i] == 0; o = o && a[i] == 0xFF; }
  return !z && !o;
}
inline void identName() {
  if (s_addrRnd) snprintf(s_name, sizeof s_name, "Favilla KEY %02X%02X", s_addr[1], s_addr[0]);
  else snprintf(s_name, sizeof s_name, "Favilla KEY");
}
inline void identLoad() {
  nvs_handle_t h; size_t n = sizeof s_addr; s_addrRnd = false;
  if (nvs_open("favbt", NVS_READONLY, &h) == ESP_OK) {
    if (nvs_get_blob(h, "addr", s_addr, &n) == ESP_OK && n == sizeof s_addr && addrValid(s_addr)) s_addrRnd = true;
    nvs_close(h);
  }
  identName();
}
inline bool identNew() {
  uint8_t a[6];
  do { esp_fill_random(a, sizeof a); a[5] |= 0xC0; } while (!addrValid(a));
  nvs_handle_t h;
  if (nvs_open("favbt", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t e = nvs_set_blob(h, "addr", a, sizeof a);
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  if (e != ESP_OK) return false;
  memcpy(s_addr, a, sizeof a); s_addrRnd = true; identName();
  return true;
}
inline const char* name() { return s_name; }
inline bool identApply() {   // after init, before any advertising: the random address, if there is one
  if (!s_addrRnd) return true;
  return BLEDevice::setOwnAddr(s_addr) && BLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
}

static bool s_kbOn = true;   // this life's keyboard (read at start)
inline bool kbOn() { return s_kbOn; }

// ---- the phones the owner confirmed ---------------------------------------------
constexpr int MAX_PEERS = 2;   // re-review (4 Nov 2026): each phone keeps up to 3 subscription records (Service Changed, battery, keyboard) and the prebuilt store holds 8, so a third phone could lose its keyboard subscription
struct Peer { uint8_t used, type, val[6]; uint8_t hash[32]; };   // hash of the bond's keys when the owner confirmed it
static Peer s_peers[MAX_PEERS];
static bool s_peersLoaded = false;
inline void peersLoad() {
  if (s_peersLoaded) return;
  s_peersLoaded = true;
  memset(s_peers, 0, sizeof s_peers);
  nvs_handle_t h; size_t n = sizeof s_peers;
  if (nvs_open("favbt", NVS_READONLY, &h) == ESP_OK) {
    if (nvs_get_blob(h, "peers", s_peers, &n) != ESP_OK || n != sizeof s_peers) memset(s_peers, 0, sizeof s_peers);
    nvs_close(h);
  }
}
inline bool peersSave() {
  nvs_handle_t h;
  if (nvs_open("favbt", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t e = nvs_set_blob(h, "peers", s_peers, sizeof s_peers);
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  return e == ESP_OK;
}
inline int peersCount() { peersLoad(); int n = 0; for (auto& p : s_peers) n += p.used ? 1 : 0; return n; }
inline int peerIndex(const ble_addr_t& a) {
  peersLoad();
  for (int i = 0; i < MAX_PEERS; i++) if (s_peers[i].used && s_peers[i].type == a.type && !memcmp(s_peers[i].val, a.val, 6)) return i;
  return -1;
}
inline bool peerKnown(const ble_addr_t& a) { return peerIndex(a) >= 0; }
// Add or re-confirm (a phone already on the list that paired again in the window).
inline bool peerPut(const ble_addr_t& a, const uint8_t h[32]) {
  peersLoad();
  int i = peerIndex(a);
  if (i < 0) for (int j = 0; j < MAX_PEERS; j++) if (!s_peers[j].used) { i = j; break; }
  if (i < 0) return false;   // full
  s_peers[i].used = 1; s_peers[i].type = a.type; memcpy(s_peers[i].val, a.val, 6); memcpy(s_peers[i].hash, h, 32);
  return peersSave();
}
// The bond as stored now, hashed; and whether it is strong enough to serve.
inline bool bondRead(const ble_addr_t& a, uint8_t h[32], bool* strong) {
  struct ble_store_key_sec k; memset(&k, 0, sizeof k); k.peer_addr = a;
  struct ble_store_value_sec v; memset(&v, 0, sizeof v);
  if (ble_store_read_peer_sec(&k, &v) != 0) { *strong = false; return false; }
  *strong = v.sc && v.authenticated && v.key_size == 16 && v.ltk_present;
  mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  const uint8_t tag[] = "FAVILLA-BT-BOND-1";
  mbedtls_sha256_update(&c, tag, sizeof tag - 1);
  mbedtls_sha256_update(&c, &a.type, 1); mbedtls_sha256_update(&c, a.val, 6);
  mbedtls_sha256_update(&c, v.ltk, 16);
  uint8_t ip = v.irk_present ? 1 : 0; mbedtls_sha256_update(&c, &ip, 1);
  if (ip) mbedtls_sha256_update(&c, v.irk, 16);
  mbedtls_sha256_finish(&c, h); mbedtls_sha256_free(&c);
  mbedtls_platform_zeroize(&v, sizeof v);
  return true;
}
inline bool hashEq(const uint8_t* a, const uint8_t* b) { uint8_t d = 0; for (int i = 0; i < 32; i++) d |= a[i] ^ b[i]; return d == 0; }

// ---- state (written by the NimBLE host task, read by the screens) ---------------
static volatile bool s_up = false, s_conn = false, s_secure = false;
static volatile uint16_t s_h = 0xFFFF;
static volatile uint32_t s_readyAt = 0;      // when the current phone became able to type (typer picks the latest)
static int8_t s_linkSlow = -1;   // 9v: -1 not asked on this link, 0 fast, 1 slow (linkParams)
static uint32_t s_linkAskAt = 0, s_linkLogAt = 0;
static volatile uint32_t s_winUntil = 0;     // the pairing window
static volatile uint8_t  s_ask = 0;          // numeric comparison: 0 none, 1 on the KEY's screen
static volatile uint16_t s_askConn = 0xFFFF; // 8e: the link the comparison belongs to (answered with ble_sm_inject_io)
static volatile uint32_t s_code = 0;
static volatile bool     s_cmpOk = false;    // a comparison was accepted on the KEY on this connection
static volatile bool     s_fresh = false;    // a pairing ran on this connection (comparison or passkey method)
static volatile bool     s_forgetting = false;
// 8m (Josh, 5 Nov 2026: a connected Bluetooth keyboard hides the phone's own
// keyboard). The link is made only to type: the KEY does not advertise at rest;
// a press that types to the phone wakes it (s_wake), and 3 s after the last
// typing (8n; at once after Enter) the KEY drops the link, so the phone's own
// keyboard comes back.
static volatile uint32_t s_wakeUntil = 0;    // advertising to let a paired phone reconnect, until then
static volatile uint32_t s_lastType = 0;     // the last typing over Bluetooth (the link is dropped 10 s after)
static BLEServer* s_srv = nullptr;
inline bool wantAdv();
static volatile bool     s_sub = false;      // the phone subscribed to the keyboard report (typing is thrown away before that)
static volatile uint8_t  s_lastPair = 0;     // 0 nothing, 1 paired, 2 refused (for the pair screen)
static SemaphoreHandle_t s_askSem = nullptr;
static uint16_t s_inHandle = 0;
static uint16_t s_batHandle = 0;
static uint32_t s_sent = 0, s_fail = 0, s_dropped = 0;
// 9c: the sign-in answer characteristic (8f1a0004) and its subscription
static uint16_t s_fillHandle = 0;
// 9g: the app channel (8f1a0005 in, 8f1a0006 out). Whole chan messages in
// 64-byte reports (chan::F_START / F_CONT); a write or a notification carries
// one or more whole reports. The logic (pairing, macs, what each request does)
// is ble_app.inc's, reached through these hooks; this file only moves bytes.
static uint16_t s_aOutHandle = 0;
static volatile bool s_aSub = false;
static uint8_t* s_aRx = nullptr;    // reassembly (PSRAM, APP_MAX)
static uint8_t* s_aMsg = nullptr;   // the message handed to the app task (PSRAM, APP_MAX)
static chan::AppRx s_aRxs;   // 9u: the reassembly state (chan::appRxFeed)
static volatile size_t s_aMsgLen = 0;           // non-zero: a message waits for the app task
static TaskHandle_t s_aTask = nullptr;
static SemaphoreHandle_t s_aTxMx = nullptr;
static volatile bool s_ctapApp = false;         // the FIDO request in progress came by the app channel: its replies go back there
static void (*s_appOnMsg)(const uint8_t* m, size_t n) = nullptr;   // on the app task
static int  (*s_appCount)() = nullptr;                              // paired app installs (raw paths shut when > 0)
static void (*s_appCtapTx)(uint8_t cmd, const uint8_t* d, size_t n) = nullptr;   // the FIDO task's replies, for the app channel
static bool (*s_appFillTx)(uint8_t status, const char* user, const char* pass) = nullptr;   // a FILL answer, for the app channel
inline bool appLocked() { return s_appCount && s_appCount() > 0; }
// 9k (issue #7): the NOSTR Bluetooth life. No keyboard, and only the app
// channel's pairing, HELLO, TIME and API: the raw sign-in and FIDO paths are
// refused (ATT 0x84, not here) - passkeys and passwords are the PASSKEY life's.
static bool s_nostrLife = false;
inline void setNostrLife(bool on) { s_nostrLife = on; }
inline bool nostrLife() { return s_nostrLife; }
static volatile bool s_fillSub = false;
// 9a: CTAP over Bluetooth state (see the FIDO section below)
static uint16_t s_fStHandle = 0, s_vStHandle = 0;          // status characteristics (0xFFFD, Favilla)
static volatile bool s_fSub = false, s_vSub = false;        // the phone subscribed to them
static volatile uint16_t s_fidoVia = 0;                      // the status handle the current request came in on
static volatile uint32_t s_fidoUntil = 0;                    // hold the link while a request is open (35 s), 3 s after its reply
static uint8_t* s_rx = nullptr;                              // reassembly (PSRAM, made at the first start)
static uint8_t* s_wb = nullptr;                              // one control point write (PSRAM): the host task's stack is 5 KB
static size_t s_rxLen = 0, s_rxHave = 0; static uint8_t s_rxCmd = 0, s_rxSeq = 0; static bool s_rxOn = false; static uint32_t s_rxT = 0;

inline bool windowOpen() { return s_winUntil && (int32_t)(s_winUntil - millis()) > 0; }
inline bool ready() { return s_up && s_conn && s_secure && s_sub && s_inHandle; }

// Keyboard report map: report ID 1, 8-byte boot-style input (modifiers, reserved,
// six keys). No LED output report (8j, bench 5 Nov 2026): in NimBLE mode the
// library silently drops a second characteristic with the same UUID (0x2A4D), so
// the output report the map declared never existed in the attribute table, and
// the iPhone would not use a HID service whose map and reports disagree. The KEY
// never reads Caps Lock anyway.
static const uint8_t REPORT_MAP[] = {
  0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
  0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
  0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
  0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
  0xC0
};

// ---- callbacks ---------------------------------------------------------------------
// Refuse a link. Its bond is deleted only when it cannot be a confirmed phone's:
// never confirmed, or stored keys that differ from the confirmed ones (then the
// store already holds someone else's). A link that dropped before encryption
// keeps the bond (re-review, 4 Nov 2026: deleting there let a dropped
// connection, or anyone using a phone's address, wipe that phone's pairing).
static void refuseLink(uint16_t conn, const ble_addr_t& a, const char* why, bool deleteBond) {
  Serial.printf("[BT] link refused: %s%s\n", why, deleteBond ? " (its bond deleted)" : "");
  s_lastPair = 2; s_secure = false;
  ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
  if (deleteBond) { ble_addr_t c = a; ble_store_util_delete_peer(&c); }
}
// ---- 9j (7 Nov 2026, Josh): the KEY's clock from the phone ------------------------
// A PASSKEY life has no network, and only a battery pull leaves NOSTR, so the
// one-time codes take the time from the paired iPhone: iOS serves the standard
// Current Time Service (0x1805) to a bonded, encrypted accessory. On every
// secure connect (at most every 10 min) the KEY, as a GATT client on the same
// link, reads Local Time Information (0x2A0F, the zone and summer offsets) and
// Current Time (0x2A2B, the phone's local time) and sets its clock to UTC.
// Nothing else is read. A phone that lies about the time gets at most the codes
// the G0's window allows (VAULT TOTP: -60 s, +1200 s from the last one served).
static volatile uint32_t s_ctsAt = 0;   // when the last read finished (ms)
struct Cts { uint16_t conn, start, end, hCur, hLoc; int8_t tz; uint8_t dst; bool haveLoc; };
static Cts s_cts = {};
static const ble_uuid16_t U_CTS = BLE_UUID16_INIT(0x1805), U_CTS_CUR = BLE_UUID16_INIT(0x2A2B), U_CTS_LOC = BLE_UUID16_INIT(0x2A0F);   // C++: no compound literals
static int64_t ctsCivil(int y, int m, int d){   // days since 1970-01-01 (Howard Hinnant's days_from_civil)
  y -= m <= 2; const int era = (y >= 0 ? y : y - 399) / 400; const unsigned yoe = (unsigned)(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1; const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return (int64_t)era * 146097 + (int64_t)doe - 719468;
}
static int ctsReadCur(uint16_t conn, const struct ble_gatt_error* e, struct ble_gatt_attr* a, void*){
  if (e->status != 0 || !a) { Serial.printf("[BT] phone time: Current Time not read (status %d)\n", e->status); return 0; }
  uint8_t b[10] = {0}; uint16_t n = 0;
  if (ble_hs_mbuf_to_flat(a->om, b, sizeof b, &n) != 0 || n < 7) { Serial.printf("[BT] phone time: Current Time too short (%u bytes)\n", (unsigned)n); return 0; }
  const int y = b[0] | (b[1] << 8), mo = b[2], d = b[3], hh = b[4], mi = b[5], ss = b[6];
  if (y < 2024 || y > 2100 || mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mi > 59 || ss > 59) { Serial.printf("[BT] phone time: not a valid date\n"); return 0; }
  if (!s_cts.haveLoc) { Serial.printf("[BT] phone time: no time zone from the phone (0x2A0F), the clock is not set\n"); return 0; }
  const int64_t local = ctsCivil(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss;
  const int64_t utc = local - (int64_t)s_cts.tz * 900 - (int64_t)s_cts.dst * 900;
  const time_t was = time(nullptr);
  const int64_t off = (int64_t)was - utc;
  if (was < 1700000000 || off > 2 || off < -2) {
    struct timeval tv = { (time_t)utc, 0 }; settimeofday(&tv, nullptr);
    if (was < 1700000000) Serial.printf("[BT] clock set from the phone (it was not known): %04d-%02d-%02d %02d:%02d:%02d local, zone %+d min\n", y, mo, d, hh, mi, ss, (int)(s_cts.tz + s_cts.dst) * 15);
    else Serial.printf("[BT] clock set from the phone (it was %lld s %s)\n", (long long)(off < 0 ? -off : off), off < 0 ? "behind" : "ahead");
  } else Serial.printf("[BT] clock checked against the phone: within 2 s\n");
  s_ctsAt = millis(); (void)conn;
  return 0;
}
static int ctsReadLoc(uint16_t conn, const struct ble_gatt_error* e, struct ble_gatt_attr* a, void*){
  if (e->status == 0 && a) {
    uint8_t b[2] = {0}; uint16_t n = 0;
    if (ble_hs_mbuf_to_flat(a->om, b, sizeof b, &n) == 0 && n == 2 && (int8_t)b[0] != -128 && b[1] != 255) { s_cts.tz = (int8_t)b[0]; s_cts.dst = b[1]; s_cts.haveLoc = true; }
  }
  if (s_cts.hCur) ble_gattc_read(conn, s_cts.hCur, ctsReadCur, nullptr);
  return 0;
}
static int ctsChr(uint16_t conn, const struct ble_gatt_error* e, const struct ble_gatt_chr* c, void*){
  if (e->status == 0 && c) {
    if (ble_uuid_cmp(&c->uuid.u, &U_CTS_CUR.u) == 0) s_cts.hCur = c->val_handle;
    if (ble_uuid_cmp(&c->uuid.u, &U_CTS_LOC.u) == 0) s_cts.hLoc = c->val_handle;
    return 0;
  }
  if (e->status != BLE_HS_EDONE) { Serial.printf("[BT] phone time: characteristics not found (status %d)\n", e->status); return 0; }
  if (!s_cts.hCur) { Serial.printf("[BT] phone time: the phone has no Current Time characteristic\n"); return 0; }
  if (s_cts.hLoc) ble_gattc_read(conn, s_cts.hLoc, ctsReadLoc, nullptr);
  else ble_gattc_read(conn, s_cts.hCur, ctsReadCur, nullptr);
  return 0;
}
static int ctsSvc(uint16_t conn, const struct ble_gatt_error* e, const struct ble_gatt_svc* sv, void*){
  if (e->status == 0 && sv) { s_cts.start = sv->start_handle; s_cts.end = sv->end_handle; return 0; }
  if (e->status != BLE_HS_EDONE || !s_cts.start) { Serial.printf("[BT] phone time: the phone offers no Current Time Service (status %d)\n", e->status); return 0; }
  ble_gattc_disc_all_chrs(conn, s_cts.start, s_cts.end, ctsChr, nullptr);
  return 0;
}
// From the host task, once a confirmed phone's link is secure.
// 9t (bench, 8 Nov 2026): the app's log showed links at ATT MTU 23 when its
// first requests went in, and answers on them never came (the app channel needs
// 67: one 64-byte report plus 3). Ask for the bigger MTU ourselves as soon as
// the link is secure, instead of waiting for the phone to, and (in appSend)
// wait for it before giving an answer up.
static void mtuAsk(uint16_t conn){
  const int rc = ble_gattc_exchange_mtu(conn, nullptr, nullptr);
  if (rc != 0 && rc != BLE_HS_EALREADY) Serial.printf("[BT] MTU exchange not started (rc %d), MTU now %u\n", rc, (unsigned)ble_att_mtu(conn));
}
static void ctsStart(uint16_t conn){
  if (s_ctsAt && millis() - s_ctsAt < 600000UL && time(nullptr) > 1700000000) return;
  memset(&s_cts, 0, sizeof s_cts); s_cts.conn = conn;
  const int rc = ble_gattc_disc_svc_by_uuid(conn, &U_CTS.u, ctsSvc, nullptr);
  if (rc) Serial.printf("[BT] phone time: could not ask (rc %d)\n", rc);
}
class SecCb : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() override { return 0; }      // the KEY has no keypad: never used with our I/O capability
  void onPassKeyNotify(uint32_t) override { s_fresh = true; }   // a passkey method: never confirmed on the KEY, so refused below
  bool onSecurityRequest() override { return true; }
  bool onConfirmPIN(uint32_t) override { return false; }   // 8e: comparisons are answered in gapEvent / answer(); never reached
  bool onAuthorizationRequest(uint16_t, uint16_t, bool) override { return true; }
  void onAuthenticationComplete(ble_gap_conn_desc* d) override {
    if (!d) return;
    const ble_addr_t a = d->peer_id_addr;
    const int i = peerIndex(a);
    if (!d->sec_state.encrypted) { refuseLink(d->conn_handle, a, "not encrypted", i < 0 && !s_cmpOk); return; }
    uint8_t h[32]; bool strong = false;
    const bool have = bondRead(a, h, &strong);
    const bool keysDiffer = (i >= 0) && have && !hashEq(h, s_peers[i].hash);
    if (!have || !strong || !d->sec_state.authenticated || !d->sec_state.bonded) {
      refuseLink(d->conn_handle, a, "not a Secure Connections, authenticated, 16-byte bond", have && (i < 0 || keysDiffer) && !(s_cmpOk && windowOpen()));
      mbedtls_platform_zeroize(h, 32); return; }
    // A pairing the owner confirmed on the KEY in this window: add, or re-confirm a known phone.
    if (s_cmpOk && windowOpen()) {
      if (peerPut(a, h)) { s_conn = true; s_h = d->conn_handle; s_secure = true; s_readyAt = millis(); s_lastPair = 1; Serial.printf("[BT] phone paired and saved (%d of %d)\n", peersCount(), MAX_PEERS); mtuAsk(d->conn_handle); ctsStart(d->conn_handle); }
      else refuseLink(d->conn_handle, a, "phone list full or not saved", i < 0);
      mbedtls_platform_zeroize(h, 32); return;
    }
    // Otherwise only a known phone, with the very keys the owner confirmed, and no new pairing on this link.
    if (i >= 0 && !s_fresh && hashEq(h, s_peers[i].hash)) {
      s_conn = true; s_h = d->conn_handle; s_secure = true; s_readyAt = millis();   // 8r: the link is the one that encrypted, whatever order the events came in
      Serial.printf("[BT] a paired phone connected (its confirmed keys)\n");
      mtuAsk(d->conn_handle);     // 9t: the app channel needs MTU 67 or more
      ctsStart(d->conn_handle);   // 9j: the clock from the phone
    } else refuseLink(d->conn_handle, a, i < 0 ? "a phone the KEY never confirmed" : keysDiffer ? "keys differ from the ones confirmed" : "a new pairing nobody confirmed on the KEY", i < 0 || keysDiffer);
    mbedtls_platform_zeroize(h, 32);
  }
};
inline void advFast();   // 9m: defined with the pairing window; the disconnect handler restarts fast advertising
class SrvCb : public BLEServerCallbacks {
  // 8q (bench, 5 Nov 2026): the library's onConnect can arrive AFTER the
  // encryption and subscribe events of the same link (seen on fast iPhone
  // reconnects); resetting the link state here undid them and the KEY waited
  // 10 s for what had happened. The state is reset on NimBLE's own CONNECT
  // event in gapEvent, which comes first; this only logs.
  void onConnect(BLEServer*, ble_gap_conn_desc*) override {}
  void onDisconnect(BLEServer*, ble_gap_conn_desc* d) override {
    if (d && s_h != 0xFFFF && d->conn_handle != s_h) { Serial.printf("[BT] a second link %u closed (the keyboard link %u stays)\n", (unsigned)d->conn_handle, (unsigned)s_h); return; }   // 8r
    s_conn = false; s_secure = false; s_sub = false; s_cmpOk = false; s_fresh = false; s_h = 0xFFFF; s_ask = 0; s_code = 0;
    s_linkSlow = -1;   // 9v: a new link starts with the phone's own parameters
    s_fSub = false; s_vSub = false; s_fillSub = false; s_aSub = false; s_aRxs.want = 0; s_rxOn = false; s_fidoUntil = 0;   // 9a, 9c, 9g
    Serial.printf("[BT] disconnected\n");
    if (!s_forgetting && wantAdv()) advFast();   // 8m: only while pairing or waking (re-review: never mid-forget); 9m: fast for 30 s, then slow
  }
};
// Review (4 Nov 2026), denial of service in the library's defaults:
// - the store full: NimBLE evicted the oldest bond, a confirmed phone, for any
//   stranger's pairing. Here only a bond the KEY never confirmed makes room;
//   otherwise the write (and so the stranger's pairing) fails.
static int storeStatus(struct ble_store_status_event* ev, void*) {
  if (!ev || ev->event_code != BLE_STORE_EVENT_OVERFLOW) return 0;
  ble_addr_t a[8]; int n = 0;
  if (ble_store_util_bonded_peers(a, &n, 8) == 0)
    for (int i = 0; i < n; i++) if (!peerKnown(a[i])) { ble_store_util_delete_peer(&a[i]); Serial.printf("[BT] store full: removed a bond the KEY never confirmed\n"); return 0; }
  Serial.printf("[BT] store full: refusing the write (confirmed phones are never evicted)\n");
  return BLE_HS_ESTORE_CAP;
}
// - repeat pairing: the library deleted a known phone's bond before any check,
//   for anyone using its address. The connection's event callback is the one
//   handed to ble_gap_adv_start, so the link wraps that and answers this one
//   event first: ignored unless PAIR A PHONE is open.
static ble_gap_event_fn* s_libCb = nullptr;
static void* s_libArg = nullptr;
static int gapEvent(struct ble_gap_event* e, void* arg) {
  // 8r (bench, 5 Nov 2026, 8q still failed): the CONNECT for a link can come
  // after that link's encryption and subscription (the same handle), so it must
  // never undo them. A link is reset only when a DIFFERENT link connects while
  // none is secure; a second link while one is secure is left alone.
  if (e && e->type == BLE_GAP_EVENT_CONNECT && e->connect.status == 0) {
    const uint16_t c = e->connect.conn_handle;
    if (s_secure && s_conn && c == s_h) Serial.printf("[BT] connect event for link %u after it was already secure (kept)\n", (unsigned)c);
    else if (s_secure && s_conn) Serial.printf("[BT] a second link %u while link %u is secure (ignored)\n", (unsigned)c, (unsigned)s_h);
    else { s_conn = true; s_secure = false; s_sub = false; s_cmpOk = false; s_fresh = false; s_h = c; s_fSub = false; s_vSub = false; s_fillSub = false; s_aSub = false; s_aRxs.want = 0; s_rxOn = false; s_fidoUntil = 0;
           Serial.printf("[BT] connected, link %u (waiting for encryption)\n", (unsigned)c); }
  }
  // 8g (bench, 5 Nov 2026: connected and secure, never subscribed): every
  // subscribe the phone makes, to which handle, and why.
  if (e && e->type == BLE_GAP_EVENT_SUBSCRIBE && s_inHandle && e->subscribe.attr_handle == s_inHandle && (s_h == 0xFFFF || e->subscribe.conn_handle == s_h)) {
    s_sub = e->subscribe.cur_notify != 0;   // 8k: the keyboard service is the KEY's own now; its subscription is read here
    Serial.printf("[BT] keyboard reports %s by the phone\n", s_sub ? "subscribed" : "unsubscribed");
  }
  if (e && e->type == BLE_GAP_EVENT_SUBSCRIBE && (s_h == 0xFFFF || e->subscribe.conn_handle == s_h)) {   // 9a
    if (s_fStHandle && e->subscribe.attr_handle == s_fStHandle) { s_fSub = e->subscribe.cur_notify != 0; Serial.printf("[BT] FIDO status (0xFFFD) %s\n", s_fSub ? "subscribed" : "unsubscribed"); }
    if (s_vStHandle && e->subscribe.attr_handle == s_vStHandle) { s_vSub = e->subscribe.cur_notify != 0; Serial.printf("[BT] FIDO status (Favilla) %s\n", s_vSub ? "subscribed" : "unsubscribed"); }
    // 9b (bench, 6 Nov 2026: the link dropped every few seconds while a person
    // typed the first request by hand): subscribing to a FIDO status is itself
    // the start of a request, so it holds the link for 35 s like a write does.
    if ((s_fStHandle && e->subscribe.attr_handle == s_fStHandle && s_fSub) || (s_vStHandle && e->subscribe.attr_handle == s_vStHandle && s_vSub))
      s_fidoUntil = millis() + 35000;
    if (s_aOutHandle && e->subscribe.attr_handle == s_aOutHandle) {   // 9g
      s_aSub = e->subscribe.cur_notify != 0; if (s_aSub) s_fidoUntil = millis() + 35000;
      Serial.printf("[BT] app channel (8f1a0006) %s\n", s_aSub ? "subscribed" : "unsubscribed"); }
    if (s_fillHandle && e->subscribe.attr_handle == s_fillHandle) {   // 9c
      s_fillSub = e->subscribe.cur_notify != 0; if (s_fillSub) s_fidoUntil = millis() + 35000;
      Serial.printf("[BT] sign-in answers (8f1a0004) %s\n", s_fillSub ? "subscribed" : "unsubscribed"); }
  }
  if (e && e->type == BLE_GAP_EVENT_SUBSCRIBE)
    Serial.printf("[BT] subscribe event: handle %u (keyboard report is %u), notify %u -> %u, indicate %u -> %u, reason %u\n",
                  (unsigned)e->subscribe.attr_handle, (unsigned)s_inHandle, (unsigned)e->subscribe.prev_notify, (unsigned)e->subscribe.cur_notify,
                  (unsigned)e->subscribe.prev_indicate, (unsigned)e->subscribe.cur_indicate, (unsigned)e->subscribe.reason);
  // 8f (bench, 5 Nov 2026): NOT on BLE_GAP_EVENT_PARING_COMPLETE. NimBLE raises
  // it for every security procedure, the encryption a paired phone restores on
  // reconnect included, so every reconnect was refused as "a new pairing". A
  // new pairing changes the keys, and the key hash check catches that; a Just
  // Works pairing is refused as unauthenticated. s_fresh stays for the passkey
  // and comparison events only.
  // 8e (bench, 5 Nov 2026: the KEY showed the digits, the phone never did). The
  // library answers a comparison by blocking the host task in onConfirmPIN until
  // it returns, so the pairing stalled while the owner looked at the KEY. The
  // comparison is now answered later, from the screen, with ble_sm_inject_io
  // (NimBLE's own way): the host task is never held.
  if (e && e->type == BLE_GAP_EVENT_PASSKEY_ACTION && e->passkey.params.action == BLE_SM_IOACT_NUMCMP) {
    s_fresh = true;
    const uint16_t c = e->passkey.conn_handle;
    if (!windowOpen()) {
      struct ble_sm_io io; memset(&io, 0, sizeof io); io.action = BLE_SM_IOACT_NUMCMP; io.numcmp_accept = 0;
      ble_sm_inject_io(c, &io);
      Serial.printf("[BT] pairing refused: no PAIR A PHONE window open\n");
      return 0;
    }
    s_cmpOk = false; s_askConn = c; s_code = e->passkey.params.numcmp % 1000000; s_ask = 1;
    Serial.printf("[BT] numeric comparison on the KEY's screen\n");
    return 0;
  }
  if (e && e->type == BLE_GAP_EVENT_REPEAT_PAIRING && !windowOpen()) {
    Serial.printf("[BT] repeat pairing ignored: no PAIR A PHONE window open (the bond is kept)\n");
    return BLE_GAP_REPEAT_PAIRING_IGNORE;
  }
  return s_libCb ? s_libCb(e, s_libArg) : 0;
}

// ---- the KEY's own HID, battery and device-information services (8k) ------------
// Bench, 5 Nov 2026 (iPhone 11, iOS 27): with the library's BLEHIDDevice the
// phone paired, subscribed to the battery, and never to the keyboard report.
// In NimBLE mode that class leaves every HID characteristic open (permissions
// are a no-op there), drops any second report, adds a Protocol Mode
// characteristic (which tells a host the device does boot protocol, with no
// boot report to go with it), writes the PnP ID big-endian, and leaves the GAP
// Appearance at 0. These services are defined here directly on NimBLE, the way
// HID keyboards that work with iPhones are built: every HID characteristic
// needs the encrypted link, report mode only (no Protocol Mode), a PnP ID in
// little-endian, Device Information and Battery as HOGP requires, and the GAP
// Appearance set to keyboard.
enum : uintptr_t { A_HIDINFO = 1, A_MAP, A_CTRL, A_IN, A_IN_REF, A_PNP, A_MANUF, A_BAT, A_PROBE, A_REQ,
                   A_FCP, A_FST, A_FCPLEN, A_FREV, A_VCP, A_VST, A_VCPLEN, A_FILL, A_AIN, A_AOUT };   // 9g: A_AIN / A_AOUT, the app channel   // 8z7: A_REQ; 9a: the FIDO characteristics
static volatile uint32_t s_probeReads = 0;   // 8y: reads of the Favilla service (the iPhone app's probe)

// ---- the iPhone app's sign-in request (8z7, 6 Nov 2026) --------------------------
// The Favilla sheet in Safari (the iPhone app's AutoFill extension) writes the
// site iOS gave it. Ruled (Josh, 6 Nov 2026): the KEY types the login, the same
// rule as the USB channel, so nothing goes back to the phone but a status: never
// a password, a username or a site name the KEY holds.
//  - Accepted only on the confirmed, encrypted phone link (s_secure, its handle).
//  - Write body: [0x31 SIGN_IN][sLen][site][uLen = 0]  (chan::parseLogin rules).
//  - The write's answer: success = the ask is queued for the KEY's screen; ATT
//    error 0x80 + chan::Status otherwise (busy, locked, bad request, not here).
//  - The PASSKEY life takes it from the home screen (or any menu, which leaves
//    for it, like a browser's explicit ask), shows the matches and types the one
//    the owner picks on the phone. An ask not taken in 30 s is dropped.
enum : uint8_t { RQ_NONE = 0, RQ_QUEUED = 2, RQ_RUNNING = 4 };
struct PhoneReq { volatile uint8_t kind; uint8_t fill; uint16_t conn; uint32_t at; uint8_t peer[7]; char site[chan::FIELD_MAX + 1]; char user[chan::FIELD_MAX + 1]; uint8_t app; };   // 9g: app = the ask came by the app channel (its answer goes back there)   // 9d: user (FILL only), the bonded phone's identity
// 9c: [0x34 FILL][sLen][site][uLen = 0] asks the same, but the login the owner
// picks on the KEY goes back to the app on 8f1a0004 for iOS AutoFill instead of
// being typed (Josh, 6 Nov 2026; replaces 8z7's "nothing goes back" for FILL only).
constexpr uint8_t C_FILL = 0x34;
static PhoneReq s_req = {};
static portMUX_TYPE s_reqMux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t (*s_reqGate)() = nullptr;   // the life: chan::S_OK, or why it cannot take one now
static volatile uint32_t s_reqCount = 0;
inline bool reqQueued() { return s_req.kind == RQ_QUEUED; }
// The life takes the queued ask: copies the site out and marks it running.
inline bool reqTake(char* site, size_t cap, bool* fill = nullptr, char* user = nullptr, size_t ucap = 0, uint8_t* peer = nullptr) {
  bool got = false;
  taskENTER_CRITICAL(&s_reqMux);
  if (fill) *fill = s_req.fill != 0;
  if (user && ucap) { size_t n = strnlen(s_req.user, sizeof s_req.user); if (n >= ucap) n = ucap - 1; memcpy(user, s_req.user, n); user[n] = 0; }   // 9d
  if (peer) memcpy(peer, s_req.peer, 7);
  memset(s_req.user, 0, sizeof s_req.user);
  if (s_req.kind == RQ_QUEUED && cap) {
    size_t n = strnlen(s_req.site, sizeof s_req.site); if (n >= cap) n = cap - 1;
    memcpy(site, s_req.site, n); site[n] = 0;
    s_req.kind = RQ_RUNNING; got = true;
  }
  memset(s_req.site, 0, sizeof s_req.site);
  taskEXIT_CRITICAL(&s_reqMux);
  return got;
}
inline void reqDone() { taskENTER_CRITICAL(&s_reqMux); s_req.kind = RQ_NONE; memset(s_req.site, 0, sizeof s_req.site); memset(s_req.user, 0, sizeof s_req.user); taskEXIT_CRITICAL(&s_reqMux); }
inline bool reqExpire(bool* wasFill = nullptr) {   // 9c: true when one was dropped (and whether it was a FILL, which is answered)
  bool dropped = false, f = false;
  taskENTER_CRITICAL(&s_reqMux);
  if (s_req.kind == RQ_QUEUED && millis() - s_req.at > 30000UL) { s_req.kind = RQ_NONE; memset(s_req.site, 0, sizeof s_req.site); memset(s_req.user, 0, sizeof s_req.user); dropped = true; f = s_req.fill != 0; }
  taskEXIT_CRITICAL(&s_reqMux);
  if (dropped) Serial.printf("[BT] phone sign-in ask dropped: not taken in 30 s\n");
  if (wasFill) *wasFill = f;
  return dropped;
}
// On the NimBLE host task. Returns 0 (queued) or an ATT error.
static int phoneRequest(uint16_t conn, struct os_mbuf* om) {
  if (!(s_conn && s_secure && conn == s_h)) return 0x80 + chan::S_NOT_PAIRED;   // only the confirmed phone's encrypted link
  if (s_nostrLife) return 0x80 + chan::S_NOT_HERE;   // 9k: passwords are the PASSKEY life's
  if (appLocked()) { Serial.printf("[BT] raw sign-in ask refused: an app is paired (use the app channel)\n"); return 0x80 + chan::S_APP_ONLY; }   // 9g
  uint8_t b[1 + 2 + 2 * chan::FIELD_MAX];
  const uint16_t len = OS_MBUF_PKTLEN(om);
  if (len < 4 || len > sizeof b) return 0x80 + chan::S_BAD_REQUEST;
  uint16_t n = 0;
  if (ble_hs_mbuf_to_flat(om, b, sizeof b, &n) != 0 || n != len) return BLE_ATT_ERR_UNLIKELY;
  char site[chan::FIELD_MAX + 1], user[chan::FIELD_MAX + 1];
  const bool fill = b[0] == C_FILL;   // 9c
  const bool ok = (b[0] == chan::C_SIGN_IN || fill) && chan::parseLogin(b + 1, n - 1, site, user) && (fill || !user[0]);   // 9d: FILL may name the account
  mbedtls_platform_zeroize(b, sizeof b);
  if (!ok) { mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user); return 0x80 + chan::S_BAD_REQUEST; }
  const uint8_t g = s_reqGate ? s_reqGate() : (uint8_t)chan::S_NOT_HERE;
  if (g != chan::S_OK) { mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user); Serial.printf("[BT] phone sign-in ask refused (status %u)\n", (unsigned)g); return 0x80 + g; }
  bool busy;
  taskENTER_CRITICAL(&s_reqMux);
  busy = s_req.kind != RQ_NONE;
  uint8_t pid[7] = {0};   // 9d: the bond (identity address), which outlives a reconnect; the link handle does not
  { struct ble_gap_conn_desc d; if (ble_gap_conn_find(conn, &d) == 0) { pid[0] = d.peer_id_addr.type; memcpy(pid + 1, d.peer_id_addr.val, 6); } }
  if (!busy) { memcpy(s_req.site, site, sizeof s_req.site); memcpy(s_req.user, user, sizeof s_req.user); memcpy(s_req.peer, pid, 7); s_req.at = millis(); s_req.fill = fill ? 1 : 0; s_req.app = 0; s_req.conn = conn; s_req.kind = RQ_QUEUED; }
  taskEXIT_CRITICAL(&s_reqMux);
  const size_t sl = strlen(site);
  mbedtls_platform_zeroize(site, sizeof site); mbedtls_platform_zeroize(user, sizeof user);
  if (busy) { Serial.printf("[BT] phone sign-in ask refused: one is already on the KEY\n"); return 0x80 + chan::S_BUSY; }
  const uint32_t k = s_reqCount + 1; s_reqCount = k;   // the host task is the only writer
  Serial.printf("[BT] phone sign-in ask #%lu queued (%u characters, link %u, %s)\n", (unsigned long)k, (unsigned)sl, (unsigned)conn, fill ? "fill: the login goes back to the app" : "typed by the KEY");
  if (fill) s_fidoUntil = millis() + 120000;   // 9c: hold the link while the owner picks on the KEY
  return 0;
}

// 9c: the answer to a FILL ask, as notifications on 8f1a0004, from the life's
// task (never the host task). Frames as the FIDO ones: first [0x84][len hi]
// [len lo][body...], then [seq][body...]. Body: [status] and, for status 0,
// [uLen][username][pLen][password]. Sent only on the link the ask came from,
// encrypted and confirmed, subscribed. The frame buffer is wiped after.
inline uint16_t fidoFrag();
inline bool fillSend(uint8_t status, const char* user, const char* pass) {
  if (s_req.app) { s_fidoUntil = millis() + 10000; return s_appFillTx && s_appFillTx(status, user, pass); }   // 9g: the app channel's answer (encrypted)
  const uint16_t h = s_fillHandle;
  if (!(s_up && s_conn && s_secure && h && s_fillSub && s_h == s_req.conn)) { Serial.printf("[BT] sign-in answer not sent: the app's link is gone\n"); return false; }
  uint8_t body[3 + 2 * 128 + 2]; size_t n = 0;
  body[n++] = status;
  if (status == 0 && user && pass) {
    const size_t ul = strnlen(user, 128), pl = strnlen(pass, 128);
    body[n++] = (uint8_t)ul; memcpy(body + n, user, ul); n += ul;
    body[n++] = (uint8_t)pl; memcpy(body + n, pass, pl); n += pl;
  }
  const size_t f = fidoFrag();
  uint8_t fr[512]; size_t k = (n < f - 3) ? n : f - 3, off = 0; uint8_t seq = 0; bool ok = true;
  fr[0] = 0x84; fr[1] = n >> 8; fr[2] = n & 0xFF; memcpy(fr + 3, body, k); off = k;
  size_t fl = 3 + k;
  for (;;) {
    bool sent = false;
    for (int tries = 0; tries < 200 && !sent; tries++) {   // 9k: up to 1 s a notification (an API answer is many of them)
      if (!(s_conn && s_secure && s_fillSub)) break;
      struct os_mbuf* om = ble_hs_mbuf_from_flat(fr, fl);
      if (!om) { delay(5); continue; }
      int rc = ble_gatts_notify_custom(s_h, h, om);
      if (rc == 0) sent = true; else if (rc == BLE_HS_ENOMEM || rc == BLE_HS_EBUSY) delay(5); else break;
    }
    if (!sent) { ok = false; break; }
    if (off >= n) break;
    k = (n - off) < f - 1 ? (n - off) : f - 1;
    fr[0] = seq++ & 0x7F; memcpy(fr + 1, body + off, k); off += k; fl = 1 + k;
  }
  mbedtls_platform_zeroize(body, sizeof body); mbedtls_platform_zeroize(fr, sizeof fr);
  s_fidoUntil = millis() + 10000;
  Serial.printf("[BT] sign-in answer to the app: status %u%s, %s\n", (unsigned)status, status == 0 ? " (the login)" : "", ok ? "sent" : "NOT sent");
  return ok;
}

// ---- 9a (6 Nov 2026): CTAP over Bluetooth ------------------------------------------
// The FIDO Bluetooth transport (CTAP 2.1, section 11.4), served twice with the
// same framing: on the standard FIDO service 0xFFFD, and on the Favilla service
// (8f1a0010 control point, 8f1a0011 status, 8f1a0012 control point length;
// 8f1a0003 to 000f are left for the iPhone app's sign-in channel)
// because iOS may keep 0xFFFD from apps. Only a phone the owner confirmed, on
// its encrypted, confirmed link, is served (s_secure and the link's handle);
// everything else is refused at the write. A whole request is reassembled here
// and handed to the FIDO task (fido::injectBle), which serves USB too, one
// transaction at a time; its replies come back through bleTx as notifications
// on the status characteristic the request came in on.
//   frames: first   [cmd][len hi][len lo][data...]   cmd: 0x81 PING, 0x83 MSG, 0xBE CANCEL
//           next    [seq 0x00..0x7F][data...]       replies: 0x82 KEEPALIVE, 0x83 MSG, 0xBF ERROR
static volatile uint32_t s_fidoIn = 0, s_fidoOut = 0, s_fidoErr = 0;
constexpr uint8_t B_PING = 0x81, B_KEEPALIVE = 0x82, B_MSG = 0x83, B_CANCEL = 0xBE, B_ERROR = 0xBF;
constexpr uint8_t BE_INVALID_CMD = 0x01, BE_INVALID_LEN = 0x03, BE_INVALID_SEQ = 0x04, BE_REQ_TIMEOUT = 0x05, BE_BUSY = 0x06, BE_OTHER = 0x7F;
inline bool fidoActive() { return s_fidoUntil && (int32_t)(s_fidoUntil - millis()) > 0; }
inline uint16_t fidoFrag() { uint16_t m = (s_h != 0xFFFF) ? ble_att_mtu(s_h) : 23; if (m < 23) m = 23; uint16_t f = m - 3; return f > 512 ? 512 : f; }
// One notification; from the FIDO task it waits for room (up to ~200 ms), from the host task it tries once.
static bool fidoNotify(const uint8_t* b, size_t n, bool fromHost) {
  const uint16_t h = s_fidoVia;
  for (int tries = 0; tries < (fromHost ? 1 : 40); tries++) {
    if (!(s_conn && s_secure && h && ((h == s_fStHandle && s_fSub) || (h == s_vStHandle && s_vSub)))) return false;
    struct os_mbuf* om = ble_hs_mbuf_from_flat(b, n);
    if (!om) { if (!fromHost) delay(5); continue; }
    int rc = ble_gatts_notify_custom(s_h, h, om);
    if (rc == 0) return true;
    if (rc == BLE_HS_ENOMEM || rc == BLE_HS_EBUSY) { if (!fromHost) delay(5); continue; }
    return false;
  }
  return false;
}
// From the FIDO task only (its stack is 10 KB).
static void fidoSend(uint8_t bcmd, const uint8_t* d, size_t n) {
  const size_t f = fidoFrag();
  uint8_t fr[512]; size_t k = (n < f - 3) ? n : f - 3;
  fr[0] = bcmd; fr[1] = n >> 8; fr[2] = n & 0xFF; if (k) memcpy(fr + 3, d, k);
  bool ok = fidoNotify(fr, 3 + k, false); size_t off = k; uint8_t seq = 0;
  while (ok && off < n) {
    k = (n - off) < f - 1 ? (n - off) : f - 1;
    fr[0] = seq++ & 0x7F; memcpy(fr + 1, d + off, k); off += k;
    ok = fidoNotify(fr, 1 + k, false);
  }
  if (bcmd != B_KEEPALIVE) { if (ok) s_fidoOut++; else s_fidoErr++; s_fidoUntil = millis() + 10000; }   // 9b: 10 s after a reply (3 s cut a second request typed by hand)
}
// From the host task: a framing error, one 4-byte frame, one try.
static void fidoError(uint8_t code) {
  const uint8_t fr[4] = { B_ERROR, 0, 1, code };
  if (!fidoNotify(fr, 4, true)) s_fidoErr++;
  s_fidoUntil = millis() + 3000;
}
// The FIDO task's replies on CID_BLE (fido::g_bleTx).
static void bleTx(uint8_t cmd, const uint8_t* d, size_t n) {
  if (s_ctapApp) { if (s_appCtapTx) s_appCtapTx(cmd, d, n); if (cmd != fido::CMD_KEEPALIVE) s_fidoUntil = millis() + 10000; return; }   // 9g
  uint8_t b;
  switch (cmd) {
    case fido::CMD_CBOR: b = B_MSG; break;
    case fido::CMD_KEEPALIVE: b = B_KEEPALIVE; break;
    case fido::CMD_PING: b = B_PING; break;
    case fido::CMD_ERROR: {
      const uint8_t c = n ? d[0] : BE_OTHER;
      const uint8_t m = (c == fido::ERR_CHANNEL_BUSY) ? BE_BUSY : (c == fido::ERR_MSG_TIMEOUT) ? BE_REQ_TIMEOUT : (c == fido::ERR_INVALID_LEN) ? BE_INVALID_LEN :
                        (c == fido::ERR_INVALID_SEQ) ? BE_INVALID_SEQ : (c == fido::ERR_INVALID_CMD) ? BE_INVALID_CMD : BE_OTHER;
      fidoSend(B_ERROR, &m, 1); return; }
    default: return;
  }
  fidoSend(b, d, n);
}
// A control point write (host task). Returns an ATT error, or 0.
static int fidoWrite(uint16_t conn, struct os_mbuf* om, uint16_t statusHandle) {
  if (!(s_conn && s_secure && conn == s_h)) return BLE_ATT_ERR_INSUFFICIENT_AUTHEN;   // a confirmed phone's own link only
  if (!s_rx || !s_wb) return BLE_ATT_ERR_INSUFFICIENT_RES;
  if (s_nostrLife) return 0x80 + chan::S_NOT_HERE;   // 9k: passkeys are the PASSKEY life's
  if (appLocked()) return 0x80 + chan::S_APP_ONLY;   // 9g: an app is paired: CTAP only through the app channel
  uint8_t* b = s_wb; uint16_t n = 0;
  if (OS_MBUF_PKTLEN(om) > 512 || ble_hs_mbuf_to_flat(om, b, 512, &n) != 0 || n == 0) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
  s_fidoVia = statusHandle; s_fidoUntil = millis() + 35000;
  const uint32_t now = millis();
  if (s_rxOn && now - s_rxT > 3000) s_rxOn = false;   // a request left half-sent is dropped
  if (b[0] & 0x80) {
    if (n < 3) { fidoError(BE_INVALID_LEN); s_rxOn = false; return 0; }
    const size_t len = ((size_t)b[1] << 8) | b[2];
    if (len > fido::MAX_MSG) { fidoError(BE_INVALID_LEN); s_rxOn = false; return 0; }
    const size_t k = (size_t)(n - 3) < len ? (size_t)(n - 3) : len;
    memcpy(s_rx, b + 3, k);
    s_rxCmd = b[0]; s_rxLen = len; s_rxHave = k; s_rxSeq = 0; s_rxOn = true; s_rxT = now;
  } else {
    if (!s_rxOn || b[0] != s_rxSeq) { fidoError(BE_INVALID_SEQ); s_rxOn = false; return 0; }
    s_rxSeq = (s_rxSeq + 1) & 0x7F; s_rxT = now;
    const size_t k = (size_t)(n - 1) < (s_rxLen - s_rxHave) ? (size_t)(n - 1) : (s_rxLen - s_rxHave);
    memcpy(s_rx + s_rxHave, b + 1, k); s_rxHave += k;
  }
  if (s_rxHave < s_rxLen) return 0;
  s_rxOn = false; s_fidoIn++;
  const uint8_t c = s_rxCmd == B_MSG ? fido::CMD_CBOR : s_rxCmd == B_PING ? fido::CMD_PING : s_rxCmd == B_CANCEL ? fido::CMD_CANCEL : 0;
  if (!c) { fidoError(BE_INVALID_CMD); return 0; }
  if (c == fido::CMD_CBOR) Serial.printf("[BT] FIDO request over Bluetooth: %u bytes, command 0x%02X\n", (unsigned)s_rxLen, s_rxLen ? s_rx[0] : 0);
  s_ctapApp = false;   // 9g
  if (!fido::injectBle(c, s_rx, s_rxLen)) fidoError(BE_BUSY);
  return 0;
}
// ---- 9g: the app channel's bytes ------------------------------------------------------
// One whole message out as 64-byte reports, packed into as few notifications as
// the link allows (a whole number of reports each). From the app task, the FIDO
// task or the life's task; one message at a time (s_aTxMx).
inline bool appSend(const uint8_t* m, size_t n) {
  if (!n || n > chan::APP_MAX || !s_aTxMx) return false;
  const uint16_t h = s_aOutHandle;
  // 9t: MTU under 67 (the exchange not done yet on a fresh link): wait up to
  // 2 s for it rather than dropping the answer without a word.
  size_t per = fidoFrag() / chan::REPORT;
  if (per == 0) {
    const uint32_t tw = millis();
    while (per == 0 && millis() - tw < 2000 && s_conn) { delay(20); per = fidoFrag() / chan::REPORT; }
    Serial.printf("[BT] app answer waited %lu ms for the MTU: now %u%s\n", (unsigned long)(millis() - tw), (unsigned)(s_h != 0xFFFF ? ble_att_mtu(s_h) : 0), per ? "" : " (too small, answer dropped)");
    if (per == 0) return false;
  }
  const int need = n <= 61 ? 1 : 1 + (int)((n - 61 + 61) / 62);
  uint8_t fr[8 * 64]; bool ok = true;
  xSemaphoreTake(s_aTxMx, portMAX_DELAY);
  size_t off = 0; int idx = 0; int nNotify = 0, nRetry = 0, nHeapWait = 0, lastRc = 0;   // 9o: what went to the stack, for the log
  const uint32_t tSend = millis();
  while (ok && idx < need) {
    size_t k = 0;
    while (k < per && k < 8 && idx < need) {
      uint8_t* r = fr + k * 64; memset(r, 0, 64);
      if (idx == 0) { r[0] = chan::F_START; r[1] = (uint8_t)n; r[2] = (uint8_t)(n >> 8); size_t c = n < 61 ? n : 61; memcpy(r + 3, m, c); off = c; }
      else { r[0] = chan::F_CONT; r[1] = (uint8_t)idx; size_t c = n - off; if (c > 62) c = 62; memcpy(r + 2, m + off, c); off += c; }
      k++; idx++;
    }
    bool sent = false;
    // 9q (bench, 8 Nov 2026: a 1202-byte answer, only its first notification
    // reached the app). The stack's buffers free only as the radio sends them;
    // a big answer on a slow link can need far longer than the old 40 x 5 ms.
    // Wait up to 3 s for each notification, while the link lasts.
    const uint32_t tNote = millis();
    while (!sent && millis() - tNote < 3000) {
      if (!(s_conn && s_secure && h && s_aSub)) break;
      // 9r: the controller copies each packet into a buffer it takes from
      // internal RAM as the packet goes in (no static transmit buffers in the
      // stock core), and a packet it has no room for never reaches the air:
      // the stack still says "queued". Pace: after the first two, give the
      // radio a connection event per notification, and while the largest free
      // internal block is short of this notification plus some overhead, wait
      // for it to come back (up to 0.5 s, then send anyway).
      if (nNotify >= 2 && millis() - tNote < 20) { delay(2); continue; }
      if (millis() - tNote < 500 && heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < k * 64 + 256) { nHeapWait++; delay(5); continue; }
      struct os_mbuf* om = ble_hs_mbuf_from_flat(fr, k * 64);
      if (!om) { nRetry++; delay(5); continue; }
      int rc = ble_gatts_notify_custom(s_h, h, om); lastRc = rc;
      if (rc == 0) { sent = true; nNotify++; } else if (rc == BLE_HS_ENOMEM || rc == BLE_HS_EBUSY) { nRetry++; delay(5); } else break;
    }
    ok = sent;
  }
  xSemaphoreGive(s_aTxMx);
  // 9o (bench, 8 Nov 2026: a 1168-byte /api/sign answer "sent", the app never
  // took it and dropped the link 6 s later). Every answer over one report says
  // how it went out, so the next log shows whether the stack refused part of it.
  if (need > 1 || !ok)
    Serial.printf("[BT] app answer: %u bytes, %d reports in %d notification%s of up to %u reports (MTU %u), %d retr%s, %d heap wait%s, %s (rc %d) in %lu ms, internal heap %u free, largest %u\n",
                  (unsigned)n, need, nNotify, nNotify == 1 ? "" : "s", (unsigned)(per < 8 ? per : 8), (unsigned)(s_h != 0xFFFF ? ble_att_mtu(s_h) : 0),
                  nRetry, nRetry == 1 ? "y" : "ies", nHeapWait, nHeapWait == 1 ? "" : "s", ok ? "all queued" : "NOT all queued", lastRc, (unsigned long)(millis() - tSend),
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  mbedtls_platform_zeroize(fr, sizeof fr);
  return ok;
}
// A write to 8f1a0005 (host task): one or more whole 64-byte reports. A complete
// message goes to the app task; one waits at a time (the app sends the next
// request after its answer, or a CANCEL, which is small).
static int appWrite(uint16_t conn, struct os_mbuf* om) {
  if (!(s_conn && s_secure && conn == s_h)) return BLE_ATT_ERR_INSUFFICIENT_AUTHEN;   // a confirmed phone's own link only
  if (!s_aRx || !s_aMsg || !s_aTask) return BLE_ATT_ERR_INSUFFICIENT_RES;
  const uint16_t len = OS_MBUF_PKTLEN(om);
  if (len == 0 || len % chan::REPORT || len > 8 * chan::REPORT) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
  uint8_t b[8 * 64]; uint16_t n = 0;
  if (ble_hs_mbuf_to_flat(om, b, sizeof b, &n) != 0 || n != len) return BLE_ATT_ERR_UNLIKELY;
  s_fidoUntil = millis() + 35000;
  const uint32_t now = millis();
  int rc = 0;
  for (uint16_t o = 0; o < n && rc == 0; o += 64) {
    // 9u: the reassembly is chan::appRxFeed (chan_proto.h, fuzzed on a host)
    const int f = chan::appRxFeed(s_aRxs, s_aRx, b + o, now);
    if (f < 0) { rc = 0x80 + chan::S_BAD_REQUEST; break; }
    if (f == 1) {
      if (s_aMsgLen) { rc = 0x80 + chan::S_BUSY; break; }   // the app task has not taken the last one
      memcpy(s_aMsg, s_aRx, s_aRxs.want); s_aMsgLen = s_aRxs.want; s_aRxs.want = 0;
      xTaskNotifyGive(s_aTask);
    }
  }
  mbedtls_platform_zeroize(b, sizeof b);
  return rc;
}
static void appTask(void*) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    const size_t n = s_aMsgLen;
    if (!n) continue;
    if (s_appOnMsg) s_appOnMsg(s_aMsg, n);
    mbedtls_platform_zeroize(s_aMsg, n);
    s_aMsgLen = 0;
  }
}
// The app channel's CTAP request into the FIDO task (its replies come back by s_appCtapTx).
inline bool appCtap(uint8_t cmd, const uint8_t* d, size_t n) { s_ctapApp = true; s_fidoUntil = millis() + 35000; return fido::injectBle(cmd, d, n); }
// The app channel's FILL ask, queued like a raw one. Returns chan::S_OK or why not.
inline uint8_t appFill(const char* site, const char* user) {
  if (!(s_conn && s_secure)) return chan::S_NOT_PAIRED;
  const uint8_t g = s_reqGate ? s_reqGate() : (uint8_t)chan::S_NOT_HERE;
  if (g != chan::S_OK) return g;
  bool busy;
  uint8_t pid[7] = {0};
  { struct ble_gap_conn_desc d; if (ble_gap_conn_find(s_h, &d) == 0) { pid[0] = d.peer_id_addr.type; memcpy(pid + 1, d.peer_id_addr.val, 6); } }
  taskENTER_CRITICAL(&s_reqMux);
  busy = s_req.kind != RQ_NONE;
  if (!busy) { snprintf(s_req.site, sizeof s_req.site, "%s", site); snprintf(s_req.user, sizeof s_req.user, "%s", user); memcpy(s_req.peer, pid, 7); s_req.at = millis(); s_req.fill = 1; s_req.app = 1; s_req.conn = s_h; s_req.kind = RQ_QUEUED; }
  taskEXIT_CRITICAL(&s_reqMux);
  if (busy) return chan::S_BUSY;
  const uint32_t k = s_reqCount + 1; s_reqCount = k;
  Serial.printf("[BT] app channel sign-in ask #%lu queued (%u characters)\n", (unsigned long)k, (unsigned)strlen(site));
  s_fidoUntil = millis() + 120000;
  return chan::S_OK;
}
static int gattAccess(uint16_t conn, uint16_t, struct ble_gatt_access_ctxt* c, void* arg) {
  const uintptr_t w = (uintptr_t)arg;
  if (c->op == BLE_GATT_ACCESS_OP_READ_CHR || c->op == BLE_GATT_ACCESS_OP_READ_DSC) {
    int rc = 0;
    switch (w) {
      case A_HIDINFO: { const uint8_t v[4] = { 0x11, 0x01, 0x00, 0x02 }; rc = os_mbuf_append(c->om, v, 4); } break;   // HID 1.11, no country, normally connectable
      case A_MAP:     rc = os_mbuf_append(c->om, REPORT_MAP, sizeof REPORT_MAP); break;
      case A_IN:      { const uint8_t v[8] = { 0 }; rc = os_mbuf_append(c->om, v, 8); } break;                          // never a keystroke on read
      case A_IN_REF:  { const uint8_t v[2] = { 1, 0x01 }; rc = os_mbuf_append(c->om, v, 2); } break;                    // report ID 1, input
      case A_PNP:     { const uint8_t v[7] = { 0x02, 0x3A, 0x30, 0x02, 0x1F, 0x00, 0x01 }; rc = os_mbuf_append(c->om, v, 7); } break;   // USB-IF source, VID 0x303A, PID 0x1F02, v1.0 (little-endian)
      case A_MANUF:   { static const char m[] = "Favilla"; rc = os_mbuf_append(c->om, m, sizeof m - 1); } break;
      case A_BAT:     { const uint8_t v = 100; rc = os_mbuf_append(c->om, &v, 1); } break;
      case A_PROBE:   {   // 8y: the Favilla app's probe. Encrypted read only: proves the app reached THIS KEY on the bonded link.
        char t[48]; const uint32_t n = ++s_probeReads;
        int k = snprintf(t, sizeof t, "FAVILLA KEY %s read %lu", g_fwDrop, (unsigned long)n);
        rc = os_mbuf_append(c->om, t, k);
        Serial.printf("[BT] app probe read #%lu (link %u)\n", (unsigned long)n, (unsigned)conn);
      } break;
      case A_FCPLEN: case A_VCPLEN: {   // 9a: the largest control point write, big-endian
        const uint16_t m = ble_att_mtu(conn); const uint16_t f = (m > 3 ? m - 3 : 20) > 512 ? 512 : (m > 3 ? m - 3 : 20);
        const uint8_t v[2] = { (uint8_t)(f >> 8), (uint8_t)f }; rc = os_mbuf_append(c->om, v, 2); } break;
      case A_FREV: { const uint8_t v = 0x20; rc = os_mbuf_append(c->om, &v, 1); } break;   // FIDO2 only
      default: return BLE_ATT_ERR_UNLIKELY;
    }
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
  }
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_CTRL) return 0;   // suspend / exit suspend: nothing to do
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_REQ) return phoneRequest(conn, c->om);   // 8z7
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_FCP) return fidoWrite(conn, c->om, s_fStHandle);   // 9a
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_AIN) return appWrite(conn, c->om);   // 9g
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_VCP) return fidoWrite(conn, c->om, s_vStHandle);   // 9a
  if (c->op == BLE_GATT_ACCESS_OP_WRITE_CHR && w == A_FREV) {   // 9a: only FIDO2 (0x20) may be selected
    uint8_t v = 0; uint16_t n = 0;
    if (ble_hs_mbuf_to_flat(c->om, &v, 1, &n) != 0 || n != 1) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    return v == 0x20 ? 0 : BLE_ATT_ERR_VALUE_NOT_ALLOWED;
  }
  if (c->op == BLE_GATT_ACCESS_OP_READ_CHR && (w == A_FST || w == A_VST || w == A_FILL || w == A_AIN || w == A_AOUT)) return BLE_ATT_ERR_READ_NOT_PERMITTED;
  return BLE_ATT_ERR_UNLIKELY;
}
static const ble_uuid16_t U_HID = BLE_UUID16_INIT(0x1812), U_DIS = BLE_UUID16_INIT(0x180A), U_BAS = BLE_UUID16_INIT(0x180F),
  U_HIDINFO = BLE_UUID16_INIT(0x2A4A), U_MAP = BLE_UUID16_INIT(0x2A4B), U_CTRL = BLE_UUID16_INIT(0x2A4C), U_REPORT = BLE_UUID16_INIT(0x2A4D),
  U_REPREF = BLE_UUID16_INIT(0x2908), U_PNP = BLE_UUID16_INIT(0x2A50), U_MANUF = BLE_UUID16_INIT(0x2A29), U_BATLVL = BLE_UUID16_INIT(0x2A19);
// 8y: the Favilla service, for the iPhone app (iOS hides the HID service from apps).
// Service 8f1a0001-6b2e-4c8d-9a3e-5f7c2d1e0b4a; probe 8f1a0002-6b2e-4c8d-9a3e-5f7c2d1e0b4a;
// 8z7: sign-in request 8f1a0003-6b2e-4c8d-9a3e-5f7c2d1e0b4a (write with response, encrypted).
static const ble_uuid128_t U_FAV = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x01, 0x00, 0x1a, 0x8f);
static const ble_uuid128_t U_FAV_PROBE = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x02, 0x00, 0x1a, 0x8f);
static const ble_uuid128_t U_FAV_REQ = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x03, 0x00, 0x1a, 0x8f);
static const ble_uuid128_t U_FAV_FILL = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x04, 0x00, 0x1a, 0x8f);   // 9c: the sign-in answer (notify)
static const ble_uuid128_t U_FAV_AIN  = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x05, 0x00, 0x1a, 0x8f);   // 9g: app channel in (write)
static const ble_uuid128_t U_FAV_AOUT = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x06, 0x00, 0x1a, 0x8f);   // 9g: app channel out (notify)
// 9a: CTAP on the Favilla service (8f1a0010 / 0011 / 0012) and on the FIDO service.
static const ble_uuid128_t U_FAV_CP    = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x10, 0x00, 0x1a, 0x8f);
static const ble_uuid128_t U_FAV_ST    = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x11, 0x00, 0x1a, 0x8f);
static const ble_uuid128_t U_FAV_CPLEN = BLE_UUID128_INIT(0x4a, 0x0b, 0x1e, 0x2d, 0x7c, 0x5f, 0x3e, 0x9a, 0x8d, 0x4c, 0x2e, 0x6b, 0x12, 0x00, 0x1a, 0x8f);
static const ble_uuid16_t  U_FIDO = BLE_UUID16_INIT(0xFFFD);
// F1D0FFF1..4-DEB4-4A6A-9D4D-D97DA6E2A6E9 (control point, status, control point length, service revision bitfield)
static const ble_uuid128_t U_FIDO_CP    = BLE_UUID128_INIT(0xe9, 0xa6, 0xe2, 0xa6, 0x7d, 0xd9, 0x4d, 0x9d, 0x6a, 0x4a, 0xb4, 0xde, 0xf1, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t U_FIDO_ST    = BLE_UUID128_INIT(0xe9, 0xa6, 0xe2, 0xa6, 0x7d, 0xd9, 0x4d, 0x9d, 0x6a, 0x4a, 0xb4, 0xde, 0xf2, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t U_FIDO_CPLEN = BLE_UUID128_INIT(0xe9, 0xa6, 0xe2, 0xa6, 0x7d, 0xd9, 0x4d, 0x9d, 0x6a, 0x4a, 0xb4, 0xde, 0xf3, 0xff, 0xd0, 0xf1);
static const ble_uuid128_t U_FIDO_REV   = BLE_UUID128_INIT(0xe9, 0xa6, 0xe2, 0xa6, 0x7d, 0xd9, 0x4d, 0x9d, 0x6a, 0x4a, 0xb4, 0xde, 0xf4, 0xff, 0xd0, 0xf1);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"   // cpfd (format descriptors) left empty
static struct ble_gatt_dsc_def s_inDsc[] = {
  { (ble_uuid_t*)&U_REPREF, BLE_ATT_F_READ | BLE_ATT_F_READ_ENC, 0, gattAccess, (void*)A_IN_REF },
  { nullptr, 0, 0, nullptr, nullptr } };
static struct ble_gatt_chr_def s_hidChrs[] = {
  { (ble_uuid_t*)&U_HIDINFO, gattAccess, (void*)A_HIDINFO, nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_MAP,     gattAccess, (void*)A_MAP,     nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_CTRL,    gattAccess, (void*)A_CTRL,    nullptr, BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_REPORT,  gattAccess, (void*)A_IN,      s_inDsc, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_READ_ENC, 0, (uint16_t*)&s_inHandle },
  { nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr } };
static struct ble_gatt_chr_def s_disChrs[] = {
  { (ble_uuid_t*)&U_PNP,   gattAccess, (void*)A_PNP,   nullptr, BLE_GATT_CHR_F_READ, 0, nullptr },
  { (ble_uuid_t*)&U_MANUF, gattAccess, (void*)A_MANUF, nullptr, BLE_GATT_CHR_F_READ, 0, nullptr },
  { nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr } };
static struct ble_gatt_chr_def s_basChrs[] = {
  { (ble_uuid_t*)&U_BATLVL, gattAccess, (void*)A_BAT, nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY, 0, &s_batHandle },
  { nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr } };
static struct ble_gatt_chr_def s_favChrs[] = {
  { (ble_uuid_t*)&U_FAV_PROBE, gattAccess, (void*)A_PROBE, nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_FAV_REQ,   gattAccess, (void*)A_REQ,   nullptr, BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },   // 8z7: write only, never read
  { (ble_uuid_t*)&U_FAV_FILL,  gattAccess, (void*)A_FILL,  nullptr, BLE_GATT_CHR_F_NOTIFY, 0, &s_fillHandle },   // 9c: notify only
  { (ble_uuid_t*)&U_FAV_AIN,   gattAccess, (void*)A_AIN,   nullptr, BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },   // 9g: app channel in; 11ad: write without response too, so a 31 KB VAULT_PUT is not 165 round trips
  { (ble_uuid_t*)&U_FAV_AOUT,  gattAccess, (void*)A_AOUT,  nullptr, BLE_GATT_CHR_F_NOTIFY, 0, &s_aOutHandle },   // 9g: app channel out
  { (ble_uuid_t*)&U_FAV_CP,    gattAccess, (void*)A_VCP,    nullptr, BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },   // 9a
  { (ble_uuid_t*)&U_FAV_ST,    gattAccess, (void*)A_VST,    nullptr, BLE_GATT_CHR_F_NOTIFY, 0, &s_vStHandle },
  { (ble_uuid_t*)&U_FAV_CPLEN, gattAccess, (void*)A_VCPLEN, nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC, 0, nullptr },
  { nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr } };
static struct ble_gatt_chr_def s_fidoChrs[] = {   // 9a: the standard FIDO service
  { (ble_uuid_t*)&U_FIDO_CP,    gattAccess, (void*)A_FCP,    nullptr, BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_FIDO_ST,    gattAccess, (void*)A_FST,    nullptr, BLE_GATT_CHR_F_NOTIFY, 0, &s_fStHandle },
  { (ble_uuid_t*)&U_FIDO_CPLEN, gattAccess, (void*)A_FCPLEN, nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC, 0, nullptr },
  { (ble_uuid_t*)&U_FIDO_REV,   gattAccess, (void*)A_FREV,   nullptr, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC, 0, nullptr },
  { nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr } };
static const struct ble_gatt_svc_def s_svcs[] = {
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_DIS, nullptr, s_disChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_BAS, nullptr, s_basChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_HID, nullptr, s_hidChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_FAV, nullptr, s_favChrs },   // 8y
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_FIDO, nullptr, s_fidoChrs },  // 9a
  { 0, nullptr, nullptr, nullptr } };
static const struct ble_gatt_svc_def s_svcsNoKbd[] = {   // 9c: the keyboard setting off: no HID service at all
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_DIS, nullptr, s_disChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_BAS, nullptr, s_basChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_FAV, nullptr, s_favChrs },
  { BLE_GATT_SVC_TYPE_PRIMARY, (ble_uuid_t*)&U_FIDO, nullptr, s_fidoChrs },
  { 0, nullptr, nullptr, nullptr } };
#pragma GCC diagnostic pop

// ---- start (once, in a Bluetooth PASSKEY life) --------------------------------------
inline void advFast();
// 9m (8 Nov 2026, power): Apple's advertising pattern (QA1931): 20 ms for the
// first 30 s after a start, a disconnect, a pairing window or a wake, then
// 318.75 ms (one of Apple's exact values) until the next. The radio sends about
// 15 times less often while it waits; a phone that comes back after a long gap
// may take up to about half a second longer to find the KEY.
static uint32_t s_advFastUntil = 0; static bool s_advSlow = false;
// 11cr (Josh, 22 Nov 2026, dark census in the NOSTR Bluetooth life: 28.7 mA,
// bt holding the chip awake 24%, the radio's sleep timer firing 28.6 times a
// second = the 20-30 ms advertising): "try 152.5 then 318.75". While the screen
// is dark and no phone is connected, the NOSTR Bluetooth life advertises at
// NOSTR_DARK_ADV (0.625 ms units). A wake goes straight back to 20-30 ms.
// The PASSKEY life keeps its own pattern (9m).
#ifndef NOSTR_DARK_ADV
#define NOSTR_DARK_ADV 244   // 152.5 ms, one of Apple's values (QA1931); next to try: 510 = 318.75 ms
#endif
static bool s_dark = false;
#ifdef FAVILLA_RF_TEST
// 15 Nov 2026 (EMC lab build only): mode F holds the 20-30 ms interval, never
// the 30 s slowdown; and the transmit power is set to +9 dBm and read back at
// every start instead of resting on the sdkconfig default
// (CONFIG_BT_CTRL_DFT_TX_POWER_LEVEL_P9). The release builds are unchanged.
static bool s_rfHoldFast = false;
inline void rfHoldFast(bool on) { s_rfHoldFast = on; }
inline int pwrLvlDbm(esp_power_level_t l) { return l == ESP_PWR_LVL_INVALID ? -99 : l >= ESP_PWR_LVL_P20 ? 20 : -24 + 3 * (int)l; }
// Default (connections take it, and the LE transmitter test), advertising, scanning.
inline bool rfPowerSet() {
  const esp_err_t e1 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
  const esp_err_t e2 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  const esp_err_t e3 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, ESP_PWR_LVL_P9);
  const int d = pwrLvlDbm(esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_DEFAULT));
  const int a = pwrLvlDbm(esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_ADV));
  const int s = pwrLvlDbm(esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_SCAN));
  Serial.printf("[RFDIAG] BLE TX req=+9 dBm set=%s/%s/%s got default=%+d adv=%+d scan=%+d dBm\n",
                esp_err_to_name(e1), esp_err_to_name(e2), esp_err_to_name(e3), d, a, s);
  return e1 == ESP_OK && e2 == ESP_OK && e3 == ESP_OK && d == 9 && a == 9 && s == 9;
}
inline int rfPowerDbm() { return pwrLvlDbm(esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_ADV)); }
#endif
inline void advConfig() {   // 11dp: also after a forget, when the name changed
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->reset();   // takes the name from the GAP service
  if (s_kbOn) { adv->setAppearance(0x03C1); adv->addServiceUUID(BLEUUID((uint16_t)0x1812)); }   // keyboard
  else adv->addServiceUUID(BLEUUID("8f1a0001-6b2e-4c8d-9a3e-5f7c2d1e0b4a"));   // 9c: the app finds the KEY by its own service
  adv->setScanResponse(true);
}
inline bool start() {
  if (s_up) return true;
  if (!g_btLife) return false;
  peersLoad();
  s_kbOn = kbSettingOn() && !s_nostrLife;   // 9c; 9k: never a keyboard in the NOSTR Bluetooth life
  crumb(1);
  if (!s_askSem) s_askSem = xSemaphoreCreateBinary();   // 8t: start can run again after a scan
  if (!s_askSem) { crumb(99); Serial.printf("[BT] could not start (no semaphore)\n"); return false; }
  crumb(2);
  identLoad();   // 11dp
  BLEDevice::init(s_name);
  crumb(3);
  if (!BLEDevice::getInitialized()) { crumb(99); Serial.printf("[BT] could not start: the Bluetooth host did not initialise (internal free %u)\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL)); return false; }   // review: never build on a host that failed
  if (!identApply()) { Serial.printf("[BT] the KEY's own random address was not taken: using the chip's address this start\n"); s_addrRnd = false; identName(); ble_svc_gap_device_name_set(s_name); }   // 11dp
#ifdef FAVILLA_RF_TEST
  rfPowerSet();   // EMC lab build: +9 dBm explicitly, read back and logged
#endif
  ble_hs_cfg.store_status_cb = storeStatus;   // after init: the library sets its own there
  static SecCb s_secCb; static SrvCb s_srvCb;   // 8u: made once; a heap copy per start sat in the middle of the freed region
  BLEDevice::setSecurityCallbacks(&s_secCb);
  BLESecurity::setPassKey(false);             // review: no passkey method is ever confirmed, but never the library's fixed 123456
  BLESecurity::regenPassKeyOnConnect(true);
  BLESecurity::setAuthenticationMode(true, true, true);   // bond, MITM (a person confirms), Secure Connections
  BLESecurity::setCapability(ESP_IO_CAP_IO);              // display + yes/no: numeric comparison
  BLESecurity::setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  BLESecurity::setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  crumb(4);
  BLEServer* srv = BLEDevice::createServer(); s_srv = srv;
  if (!srv) { crumb(99); Serial.printf("[BT] could not start (no server)\n"); return false; }
  srv->setCallbacks(&s_srvCb);
  crumb(5);
  // 8k: the KEY's own services (see s_svcs). Added after createServer (which
  // resets the GATT server) and before the first advertising start (which
  // starts it).
  { const struct ble_gatt_svc_def* sv = s_kbOn ? s_svcs : s_svcsNoKbd;   // 9c
    int rc = ble_gatts_count_cfg(sv); if (rc == 0) rc = ble_gatts_add_svcs(sv);
    if (rc) { crumb(99); Serial.printf("[BT] could not start: services not added (rc %d)\n", rc); return false; } }
  crumb(6);
  ble_svc_gap_device_appearance_set(s_kbOn ? 0x03C1 : 0x0000);   // keyboard, in the GAP service too (it was 0); 9c: generic without it
  crumb(7);
  advConfig();
  crumb(8);
  srv->start();   // 8m: the GATT server starts; advertising waits for a pairing window or a typing
  {   // 8y: the attribute table grew (the Favilla service). A phone that bonded with
      // the old table keeps its cached copy until told; say so once per layout.
    const uint8_t DB_LAYOUT = s_kbOn ? 7 : 8;   // 7/8: 9g (app channel 0005 / 0006 added); 1: 8k-8x; 2: 8y (Favilla service appended); 3: 8z7 (sign-in request added); 4: 9a (FIDO on the Favilla service, the FIDO service); 5/6: 9c (sign-in answer added; 6 = no keyboard service)
    nvs_handle_t h; uint8_t v = 0;
    if (nvs_open("favbt", NVS_READWRITE, &h) == ESP_OK) {
      nvs_get_u8(h, "dbv", &v);
      if (v != DB_LAYOUT) { ble_svc_gatt_changed(0x0001, 0xFFFF); nvs_set_u8(h, "dbv", DB_LAYOUT); nvs_commit(h); Serial.printf("[BT] attribute table changed (layout %u -> %u): phones told to look again\n", (unsigned)v, (unsigned)DB_LAYOUT); }
      nvs_close(h);
    }
  }
  if (!s_rx) s_rx = (uint8_t*)heap_caps_malloc(fido::MAX_MSG, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);   // 9a: once, in PSRAM
  if (!s_wb) s_wb = (uint8_t*)heap_caps_malloc(512, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_aRx) s_aRx = (uint8_t*)heap_caps_malloc(chan::APP_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);   // 9g
  if (!s_aMsg) s_aMsg = (uint8_t*)heap_caps_malloc(chan::APP_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_aTxMx) s_aTxMx = xSemaphoreCreateMutex();
  if (!s_aTask && s_aRx && s_aMsg && xTaskCreatePinnedToCore(appTask, "btapp", s_nostrLife ? 10240 : 7168, nullptr, 2, &s_aTask, s_nostrLife ? 0 : 1) != pdPASS) {   // 11ak: say so, or the app channel is silently dead
    s_aTask = nullptr; Serial.printf("[BT] APP CHANNEL TASK NOT STARTED (no RAM for its stack) | internal free %u largest %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  }
  fido::g_bleTx = bleTx; fido::g_bleUp = (s_rx != nullptr && s_wb != nullptr);
  crumb(20);   // done (99: failed cleanly; 1-8: in progress)
  s_up = true;
  if (!s_kbOn) advFast();   // 9c: no keyboard to take from the phone, so the KEY is findable the whole life
  Serial.printf("[BT] Bluetooth up, keyboard %s (%s), %d phone(s) paired, report handle %u | internal free %u, largest %u\n",
                s_kbOn ? "ON" : "OFF", s_kbOn ? "silent until a pairing window or a typing" : "advertising for the app the whole life", peersCount(), (unsigned)s_inHandle, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  return true;
}

// 8b: Bluetooth starts on its own task (8d: 8 KB, internal RAM is tight). BLEDevice::init waits for the host to
// sync in a loop that never feeds the task watchdog, and the PASSKEY life runs
// on the Arduino loop task (8 KB stack, watched). On its own task (16 KB, not
// watched) a slow or failed start cannot stop the life or its watchdog.
static volatile uint32_t s_startAt = 0;
static void startTask(void*) { start(); vTaskDelete(nullptr); }
inline void startAsync() {
  if (s_up || s_startAt) return;
  s_startAt = millis();
  if (xTaskCreatePinnedToCore(startTask, "btstart", 8192, nullptr, 3, nullptr, 1) != pdPASS) { crumb(99); s_startAt = 0; Serial.printf("[BT] could not start (no task)\n"); }
}
inline bool starting() { return s_startAt && !s_up && g_btCrumbs.stage != 99; }

// 8t (bench, 5 Nov 2026: "[CAM] start blocked, only 31732 contiguous"): the
// camera's cold start needs a 34 KB block that Bluetooth breaks up. A scan in a
// Bluetooth life stops Bluetooth first (the stack and controller deinit, the
// memory comes back), and the life starts it again once the scan is over. Bonds
// and the confirmed list are in flash and survive; a phone reconnects as usual.
static volatile bool s_paused = false;
inline void windowClose();
inline void pauseForCamera() {
  if (!s_up) return;
  Serial.printf("[BT] paused for a camera scan | internal free %u, largest %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
  windowClose(); s_wakeUntil = 0; s_lastType = 0;
  if (s_conn && s_h != 0xFFFF) { ble_gap_terminate(s_h, BLE_ERR_REM_USER_CONN_TERM); for (uint32_t t0 = millis(); s_conn && millis() - t0 < 1000; ) delay(10); }
  s_up = false; s_conn = false; s_secure = false; s_sub = false; s_h = 0xFFFF; s_srv = nullptr; s_inHandle = 0;
  fido::g_bleUp = false; s_fSub = false; s_vSub = false; s_fillSub = false; s_rxOn = false; s_fidoUntil = 0; s_fStHandle = 0; s_vStHandle = 0; s_fillHandle = 0;   // 9a, 9c
  BLEDevice::deinit(false);   // stack and controller off; the memory goes back to the heap (not released for good)
  s_paused = true; s_startAt = 0;
  // 8u (bench log 5 Nov: "stopped | free 128628, largest 31732", then 36852 a
  // moment later): the Bluetooth host and controller tasks are deleted by
  // deinit, but their stacks go back to the heap only when the idle task runs.
  // Until then a dead stack sits in the middle of the camera's block. Give the
  // idle tasks time (up to 500 ms) for the block to come back whole.
  for (uint32_t t0 = millis(); millis() - t0 < 500; ) {
    if (heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) >= 36000) break;
    vTaskDelay(pdMS_TO_TICKS(20));
  }
  Serial.printf("[BT] stopped | internal free %u, largest %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
}
inline void resumeAfterCamera() {
  if (!s_paused) return;
  s_paused = false;
  Serial.printf("[BT] starting again after the scan\n");
  startAsync();
}

// ---- the pairing window (PAIR A PHONE) -------------------------------------------
inline bool wantAdv() { return !s_kbOn || windowOpen() || (s_wakeUntil && (int32_t)(s_wakeUntil - millis()) > 0); }   // 9c: always without the keyboard
inline bool nostrDarkAdv() {
#ifdef FAVILLA_RF_TEST
  if (s_rfHoldFast) return false;   // EMC mode F: held fast
#endif
  return s_nostrLife && s_dark && !windowOpen();
}
inline void advFast() {
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  if (nostrDarkAdv()) {   // 11cr: a disconnect in the dark restarts at the dark interval
    adv->stop();
    adv->setMinInterval(NOSTR_DARK_ADV); adv->setMaxInterval(NOSTR_DARK_ADV);
    BLEDevice::startAdvertising();
    s_advFastUntil = millis() + 30000UL; s_advSlow = true;
    return;
  }
  adv->setMinInterval(0x20); adv->setMaxInterval(0x30);   // 20-30 ms: a bonded phone finds it in a second or two
  BLEDevice::startAdvertising();
  s_advFastUntil = millis() + 30000UL; s_advSlow = false;   // 9m
}
// 11cr: from the screen's dim and wake hooks (any loop, menus included).
inline void setDark(bool dark) {
  if (dark == s_dark) return;
  s_dark = dark;
  if (!s_up || !s_nostrLife || s_conn || s_forgetting || !wantAdv()) return;
  advFast();   // picks the dark interval or 20-30 ms from s_dark
  Serial.printf("[BT] advertising %s (screen %s)\n", dark ? "slowed for the dark" : "back to 20-30 ms", dark ? "dark" : "lit");
}
// 9m: after 30 s of fast advertising with nobody connecting, the slow interval.
inline void advSlowTick(uint32_t now) {
  if (s_conn || s_advSlow || !s_advFastUntil || (int32_t)(s_advFastUntil - now) > 0 || !wantAdv() || s_forgetting) return;
#ifdef FAVILLA_RF_TEST
  if (s_rfHoldFast) { s_advFastUntil = now + 5000UL; return; }   // EMC mode F: held fast
#endif
  if (windowOpen()) { s_advFastUntil = now + 5000UL; return; }   // PAIR A PHONE stays fast
  // 11g (Josh, 9 Nov 2026: "if someone turns bunker mode on in the app we can
  // compromise with power"): the NOSTR Bluetooth life is the Bluetooth bunker;
  // the phone connects for every request, and the slow interval made it wait
  // seconds to find the KEY. Stay at 20-30 ms there.
  if (s_nostrLife) { s_advFastUntil = now + 5000UL; return; }
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->stop();
  adv->setMinInterval(510); adv->setMaxInterval(510);   // 318.75 ms (0.625 ms units), exactly Apple's value
  BLEDevice::startAdvertising();
  s_advSlow = true;
  Serial.printf("[BT] advertising slowed to 318.75 ms (nobody connected in 30 s)\n");
}
inline void windowOpenFor(uint32_t ms) { s_lastPair = 0; s_winUntil = millis() + ms; if (!s_conn) advFast(); Serial.printf("[BT] pairing window open (%lu s)\n", (unsigned long)(ms / 1000)); }
// A typing for the phone: let it reconnect (up to ms).
inline void wake(uint32_t ms) {
  if (!s_up) return;
  s_wakeUntil = millis() + ms; s_lastType = 0;   // 8o: the idle timer starts at the typing, never at the wake (8n dropped slow reconnects mid-connect)
  if (!s_conn) { advFast(); Serial.printf("[BT] waking the phone link\n"); }
}
inline void noteTyped() { s_lastType = millis(); s_wakeUntil = 0; }
// 8n (Josh: dropping 10 s after typing was too slow). Drop the link now: after a
// typing that ended with Enter (the login is submitted) the phone gets its
// keyboard back at once. A short grace lets the last key reports go out.
inline void release() {
  if (!s_up || !s_conn || windowOpen() || s_ask != 0 || fidoActive()) return;
  delay(300);
  s_lastType = 0; s_wakeUntil = 0;
  Serial.printf("[BT] link dropped after the login was submitted\n");
  if (s_h != 0xFFFF) ble_gap_terminate(s_h, BLE_ERR_REM_USER_CONN_TERM);
}
// From the life's loop: stop advertising when nothing needs it, and drop the
// link 10 s after the last typing (the phone's own keyboard comes back).
// 9v (power, 8 Nov 2026: 26 mA dimmed in the NOSTR Bluetooth life with the
// iPhone connected). An idle link wakes the radio on every connection event,
// every 15 to 30 ms. When nothing interactive is going on, ask the phone to let
// the KEY skip up to 4 events in a row (peripheral latency); the KEY still
// sends at once when it has something, and a write from the phone waits at most
// (4 + 1) x 45 ms. Within Apple's accessory rules: interval min >= 15 ms, min +
// 15 ms <= max, latency <= 30, max x (latency + 1) <= 2 s, timeout 2 to 6 s and
// over 3 x max x (latency + 1). A passkey, a fill or typing gets the fast link
// back (latency 0) while it lasts; the app channel's requests do not need it.
static void linkParams(uint32_t now) {
  if (!(s_conn && s_secure) || s_h == 0xFFFF || now - s_readyAt < 3000) return;   // leave the phone's own setup alone
  const bool busy = s_wakeUntil != 0 || fidoActive() || windowOpen() || s_ask != 0;
  const int8_t want = busy ? 0 : 1;
  if (want != s_linkSlow && now - s_linkAskAt > 2000) {
    struct ble_gap_upd_params p = {};
    if (want) { p.itvl_min = 24; p.itvl_max = 36; p.latency = 4; }   // 30 to 45 ms, skip up to 4
    else      { p.itvl_min = 12; p.itvl_max = 24; p.latency = 0; }   // 15 to 30 ms, every event
    p.supervision_timeout = 400;                                      // 4 s
    const int rc = ble_gap_update_params(s_h, &p);
    s_linkAskAt = now; s_linkLogAt = now + 3000;
    if (rc == 0) s_linkSlow = want;
    Serial.printf("[BT] asked the phone for a %s link (%s)%s\n", want ? "slow" : "fast", want ? "30-45 ms, skip 4" : "15-30 ms", rc ? " - refused by the stack" : "");
  }
  if (s_linkLogAt && (int32_t)(now - s_linkLogAt) >= 0) {
    s_linkLogAt = 0; struct ble_gap_conn_desc d;
    if (ble_gap_conn_find(s_h, &d) == 0) Serial.printf("[BT] link now: interval %.2f ms, latency %u, timeout %u ms\n", d.conn_itvl * 1.25f, (unsigned)d.conn_latency, (unsigned)d.supervision_timeout * 10);
  }
}
inline void tick() {
  if (!s_up) return;
  const uint32_t now = millis();
  if (s_wakeUntil && (int32_t)(s_wakeUntil - now) <= 0) s_wakeUntil = 0;
  if (!s_conn && !wantAdv() && !s_forgetting) { static uint32_t last = 0; if (now - last > 1000) { last = now; BLEDevice::stopAdvertising(); } }
  advSlowTick(now);   // 9m
  linkParams(now);    // 9v
  if (!s_kbOn) return;   // 9c: no keyboard: the link never takes the phone's keyboard, so it is never dropped for it
  const bool waking = s_wakeUntil != 0 || fidoActive();   // a typing is waiting, or a FIDO request is open (9a): never drop it
  if (s_conn && !waking && !windowOpen() && s_ask == 0 && s_lastType && now - s_lastType > 3000UL) {   // 8n: 3 s (was 10): a second typing reconnects in a second or two
    s_lastType = 0; s_wakeUntil = 0;
    Serial.printf("[BT] link dropped 3 s after it went idle (the phone's own keyboard comes back)\n");
    if (s_h != 0xFFFF) ble_gap_terminate(s_h, BLE_ERR_REM_USER_CONN_TERM);
  }
  // a phone that connected on its own (not to type, not pairing) is let go after 3 s too
  if (s_conn && !waking && !s_lastType && !windowOpen() && s_ask == 0) { s_lastType = now; }
}
// 11cs: the link the phone actually agreed to, for the Battery page's dark view
// ("30ms skip4"). False with no secure link.
inline bool linkInfo(char* out, size_t n) {
  if (!(s_up && s_conn) || s_h == 0xFFFF) return false;
  struct ble_gap_conn_desc d;
  if (ble_gap_conn_find(s_h, &d) != 0) return false;
  snprintf(out, n, "%.1fms skip%u %s", d.conn_itvl * 1.25f, (unsigned)d.conn_latency, s_linkSlow == 1 ? "asked" : "fast");
  return true;
}
// Answer the comparison on the screen (from the UI task; NimBLE takes its own lock).
inline void answer(bool yes) {
  if (s_ask != 1) return;
  const uint16_t c = s_askConn;
  s_ask = 0; s_code = 0;
  const bool ok = yes && windowOpen();
  if (ok) s_winUntil = millis() + 35000UL;   // re-review: an ENTER late in the 90 s still has time to finish (the pair screen closes it after)
  s_cmpOk = ok;
  struct ble_sm_io io; memset(&io, 0, sizeof io); io.action = BLE_SM_IOACT_NUMCMP; io.numcmp_accept = ok ? 1 : 0;
  const int rc = ble_sm_inject_io(c, &io);
  Serial.printf("[BT] numeric comparison %s on the KEY (rc %d)\n", ok ? "accepted" : "refused", rc);
}
inline void windowClose() { if (s_ask == 1) answer(false); s_winUntil = 0; s_cmpOk = false; }   // review: a confirmation never outlives its window
inline bool askPending(uint32_t* code) { if (s_ask != 1) return false; if (code) *code = s_code; return true; }

// Forget every phone: the confirmed list, every bond (with its resolving-list
// entry), and the current link. Advertising is stopped first so nothing
// reconnects in between (review, 4 Nov 2026).
inline bool forgetAll() {
  peersLoad();
  memset(s_peers, 0, sizeof s_peers);
  bool ok = peersSave();
  if (s_up) {
    s_forgetting = true;
    BLEDevice::getAdvertising()->stop();
    if (s_conn && s_h != 0xFFFF) ble_gap_terminate(s_h, BLE_ERR_REM_USER_CONN_TERM);
    for (uint32_t t0 = millis(); s_conn && millis() - t0 < 3000; ) delay(20);
    ble_addr_t a[8]; int n = 0;
    if (ble_store_util_bonded_peers(a, &n, 8) == 0) for (int i = 0; i < n; i++) ble_gap_unpair(&a[i]);
  }
  // 11dp: a new address and name, so a phone that still holds the old bond
  // sees a new device and pairs without a trip to its Bluetooth settings.
  bool fresh = identNew(), now = false;
  if (fresh && s_up && !s_conn) {
    now = identApply() && ble_svc_gap_device_name_set(s_name) == 0;
    advConfig();
  }
  if (s_up) { s_forgetting = false; if (wantAdv()) advFast(); }
  Serial.printf("[BT] all phones forgotten%s; %s%s%s\n", ok ? "" : " (the list did not save)",
                !fresh ? "the new address did not save" : "now ", fresh ? s_name : "", !fresh ? "" : now || !s_up ? "" : " from the next start");
  return ok;
}

// ---- typing ----------------------------------------------------------------------
static bool sendReport(uint8_t mod, uint8_t usage) {
  uint8_t r[8] = { mod, 0, usage, 0, 0, 0, 0, 0 };
  for (int tries = 0; tries < 40; tries++) {
    if (!ready()) { s_fail++; return false; }
    struct os_mbuf* om = ble_hs_mbuf_from_flat(r, sizeof r);
    if (!om) { delay(5); continue; }
    int rc = ble_gatts_notify_custom(s_h, s_inHandle, om);   // consumes om whatever the result
    if (rc == 0) { s_sent++; return true; }
    if (rc == BLE_HS_ENOMEM || rc == BLE_HS_EBUSY) { s_dropped++; delay(5); continue; }
    s_fail++; return false;
  }
  s_fail++;
  return false;
}
// As kbd::type: 0 ok, n > 0 untypable characters (listed in bad), -1 no phone, -2 stopped part way.
inline int type(const char* s, size_t len, char* bad, size_t badCap) {
  int n = kbd::untypable(s, len, bad, badCap);
  if (n) return n;
  if (!ready()) return -1;
  for (size_t i = 0; i < len; i++) {
    kbd::Key k = kbd::keyFor(s[i]);
    // 8s (bench, 5 Nov 2026, iPhone Notes: "...icloud.co<Tab>m<password>" twice
    // in 14): iOS takes Tab and Enter on a faster path than text, so a Tab right
    // after a letter can overtake it. In a login form that would put the last
    // letter of the username into the password box. The KEY lets the text
    // settle before Tab or Enter, and after them before the next letter.
    const bool control = (s[i] == '\t' || s[i] == '\n');
    if (control) delay(200);
    if (!sendReport(k.shift ? 0x02 : 0x00, k.usage)) { sendReport(0, 0); return -2; }
    delay(15);   // 8o: one report per connection event or so (iOS runs 15-30 ms); 8 ms could crowd reports
    if (!sendReport(0, 0)) return -2;   // release: repeated letters need it
    delay(control ? 200 : 15);
  }
  return 0;
}
// 8g, bench only: send a fixed word to the connected, encrypted phone whether
// or not it has subscribed, to see if it takes keystrokes at all. Never a stored
// password: the caller passes a constant.
inline void benchTest() {
  if (!(s_up && s_conn && s_secure && s_inHandle)) { Serial.printf("[BT] test: no encrypted phone link\n"); return; }
  const bool was = s_sub; s_sub = true;
  int r = type("favilla", 7, nullptr, 0);
  s_sub = was;
  Serial.printf("[BT] test typed \"favilla\" to the phone: %s (reports %lu, failed %lu, waited %lu)\n", r == 0 ? "sent" : "failed", (unsigned long)s_sent, (unsigned long)s_fail, (unsigned long)s_dropped);
}
// 8i, bench only: where each characteristic really is in the attribute table
// (NimBLE's own lookup), against the handles the library reports.
inline void benchGatt() {
  if (!s_up) { Serial.printf("[BT] gatt: Bluetooth is not up\n"); return; }
  struct P { uint16_t svc, chr; const char* name; } ps[] = {
    {0x1801, 0x2a05, "service changed"}, {0x180a, 0x2a50, "PnP ID"}, {0x180a, 0x2a29, "manufacturer"},
    {0x1812, 0x2a4a, "HID info"}, {0x1812, 0x2a4b, "report map"}, {0x1812, 0x2a4c, "HID control"},
    {0x1812, 0x2a4e, "protocol mode"}, {0x1812, 0x2a4d, "first report"}, {0x180f, 0x2a19, "battery level"} };
  for (auto& x : ps) {
    ble_uuid16_t su = BLE_UUID16_INIT(0), cu = BLE_UUID16_INIT(0); su.value = x.svc; cu.value = x.chr;
    uint16_t def = 0, val = 0; int rc = ble_gatts_find_chr(&su.u, &cu.u, &def, &val);
    Serial.printf("[BT] gatt %04x/%04x %-16s decl %u value %u (rc %d)\n", x.svc, x.chr, x.name, def, val, rc);
  }
  Serial.printf("[BT] gatt KEY: keyboard input report %u, battery level %u\n", (unsigned)s_inHandle, (unsigned)s_batHandle);
}
inline void status() {
  Serial.printf("[BT] life %d | setting %d | start stage %lu | up %d | connected %d | secure %d | subscribed %d | window %d | phones %d | reports %lu, failed %lu, waited %lu | internal free %u\n",
                (int)g_btLife, (int)settingOn(), (unsigned long)g_btCrumbs.stage, (int)s_up, (int)s_conn, (int)s_secure, (int)s_sub, (int)windowOpen(), peersCount(),
                (unsigned long)s_sent, (unsigned long)s_fail, (unsigned long)s_dropped, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
  Serial.printf("[BT] keyboard %s | sign-in answers subscribed %d | FIDO over Bluetooth: status subscribed 0xFFFD %d, Favilla %d | requests %lu, replies %lu, failed %lu | MTU %u\n",
                s_kbOn ? "on" : "off", (int)s_fillSub, (int)s_fSub, (int)s_vSub, (unsigned long)s_fidoIn, (unsigned long)s_fidoOut, (unsigned long)s_fidoErr, (unsigned)(s_h != 0xFFFF ? ble_att_mtu(s_h) : 0));   // 9a
}

}  // namespace blek

// The wrap (-Wl,--wrap=ble_gap_adv_start, FIDO envs): every advertising start
// gets gapEvent in front of the library's handler (see above).
extern "C" int __real_ble_gap_adv_start(uint8_t own_addr_type, const ble_addr_t* direct_addr, int32_t duration_ms, const struct ble_gap_adv_params* adv_params, ble_gap_event_fn* cb, void* cb_arg);
extern "C" int __wrap_ble_gap_adv_start(uint8_t own_addr_type, const ble_addr_t* direct_addr, int32_t duration_ms, const struct ble_gap_adv_params* adv_params, ble_gap_event_fn* cb, void* cb_arg) {
  blek::s_libCb = cb; blek::s_libArg = cb_arg;
  return __real_ble_gap_adv_start(own_addr_type, direct_addr, duration_ms, adv_params, blek::gapEvent, nullptr);
}
#endif  // FAVILLA_FIDO_PROBE && FAVILLA_BLE_KBD
