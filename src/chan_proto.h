// chan_proto.h - the Favilla channel protocol (Vault phase 5 stage 2, 4 Nov 2026).
// Pure C++: no Arduino, no mbedTLS. The caller supplies HMAC-SHA256 (and does
// the ECDH), so the same code runs on the KEY and in the host tests, and the
// extension's chan.js implements the same bytes (cross-checked in the tests).
//
// TRANSPORT: 64-byte HID reports. A message (1..MSG_MAX bytes) is split:
//   start  [0]=0x10 [1..2]=total length LE [3..63]  = first 61 bytes
//   cont   [0]=0x11 [1]=index 1,2,..       [2..63]  = next 62 bytes each
// The probe's PING (report [0]=0x01) stays as a single raw report.
//
// PAIRING (numeric comparison, Josh 4 Nov 2026): only while the KEY's pairing
// window is open (Settings > Browsers > PAIR A BROWSER, 90 s), ONE attempt per
// window, with a commitment first (review 4 Nov 2026: without it a man in the
// middle could grind keys until both codes match):
//   ext -> KEY  PAIR_COMMIT [0x20][C 32]  C = HMAC("FAVILLA-COMMIT-1", extPub || nonce16)
//   KEY -> ext  PAIR_KEY    [0xA0][keyPub 65][clientId 8]   (a fresh key per window)
//   ext -> KEY  PAIR_REVEAL [0x22][extPub 65][nonce 16]     (KEY checks C)
//   both: Z = ECDH; PRK = HMAC(salt "FAVILLA-CHAN-1", Z)
//         K    = HMAC(PRK, "key"  || extPub || keyPub || 0x01)        (32 bytes)
//         code = BE32(HMAC(PRK, "code" || extPub || keyPub || 0x01)[0..3]) mod 1,000,000
//   The KEY shows the code and stores the browser only on ENTER (codes match).
//   KEY -> ext  PAIR_DONE   [0xA1][clientId 8][status][mac16]  mac over "RSP"|| the bytes before it
//
// REQUESTS (paired): [cmd][clientId 8][ctr u32 LE][body][mac16]
//   mac = HMAC(K, "REQ" || everything before the mac)[0..15]
//   ctr must be greater than the last accepted one for that client (no replay).
// REPLIES / EVENTS: [rsp][clientId 8][ctr echo][body][mac16], mac over "RSP" || ...
//
//   HELLO     0x30  body: -                      reply 0xB0 [status][life][drop 8][pair id 8] (11ah: pair id = dev_pair_pub[0..7])
//   SIGN_IN   0x31  body: [sLen][site][uLen][user]  reply 0xB1 [status]; later event 0xB2 [status]
//   NEW_LOGIN 0x32  same body as SIGN_IN            reply 0xB1 [status]; later event 0xB2 [status]
//   AUTO      0x33  same body: the extension saw a login form by itself. The KEY
//                   shows nothing unless it holds a strong match (event 0xB2
//                   no-match otherwise), never leaves a menu for it, and drops
//                   it as busy after 10 s if the home screen is not reached.
// The KEY never sends a password, a username it holds, or a site name it holds.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace chan {

constexpr size_t APP_MAX = 40960;  // 9g: a whole CTAP message (1024) plus header and mac; 9k: an API call (32 KB body, path, headers). PSRAM buffers.
constexpr size_t API_BODY_MAX = 32768;   // 9k: request and answer bodies
constexpr size_t REPORT = 64, MSG_MAX = 512, PUB = 65, ID = 8, MAC = 16, KEYLEN = 32, FIELD_MAX = 100;
enum : uint8_t {
  F_START = 0x10, F_CONT = 0x11, RAW_PING = 0x01,
  C_PAIR_COMMIT = 0x20, C_PAIR_REVEAL = 0x22, C_HELLO = 0x30, C_SIGN_IN = 0x31, C_NEW_LOGIN = 0x32, C_AUTO_SIGN_IN = 0x33,
  R_PAIR_KEY = 0xA0, R_PAIR_DONE = 0xA1, R_HELLO = 0xB0, R_ACK = 0xB1, R_EVENT = 0xB2, R_ERR = 0xBF,
  // 9f (7 Nov 2026): the iPhone app's channel over Bluetooth (docs/BLE_PASSKEY_PROTOCOL.md, "The app channel")
  C_FILL = 0x34, C_CTAP = 0x35, C_CTAP_CANCEL = 0x36, C_LIST = 0x37, C_OTP = 0x38, C_TIME = 0x39, C_API = 0x3A,   // 9i: C_OTP; 9j: C_TIME
  R_LOGIN = 0xB3, R_CTAP = 0xB4, R_KEEPALIVE = 0xB5, R_LIST = 0xB6, R_OTP = 0xB7, R_API = 0xB8,
  // 10p (issue #11): the Bluetooth bunker, NOSTR Bluetooth life only
  C_NIP46 = 0x3B, C_NIP46_POLL = 0x3C, C_BUNKER_INFO = 0x3D, R_NIP46 = 0xB9, R_BUNKER_INFO = 0xBA,
  // 11i (issue #11, path B): the KEY wakes the app over Bluetooth
  C_NUDGE_SET = 0x3E, R_NUDGE = 0xBB,
  // 11q: vault backup and restore through the phone (the app is the relay courier)
  C_VAULT_INFO = 0x3F, C_VAULT_GET = 0x40, C_VAULT_DONE = 0x41, C_VAULT_PUT = 0x42,
  R_VAULT_INFO = 0xBC, R_VAULT_CHUNK = 0xBD, R_VAULT_PUT = 0xBE,
  // 11s: password health. SHOW puts an entry on the KEY's screen; HEALTH is the breach check (k-anonymity)
  C_SHOW = 0x43, C_HEALTH = 0x44, R_HEALTH = 0xC0,
  // 11z (11 Nov 2026): the browser channel asks for a one-time code to be TYPED
  // (the site's second step): [sLen][site][unix time 8, big endian][flags]; flags
  // bit0 automatic (silent when no code is linked or matches), bit1 press Enter
  // after the digits. Answered like SIGN_IN: R_ACK now, R_EVENT when typed.
  C_CODE_TYPE = 0x45,
  // 11ab (issue #15): the app's "Check breaches" asks the KEY to score up to [max]
  // never-assessed entries first (the PWA's Check all): [max 1] -> R_ACK
  // [status][opening][unseen u16 LE]. Both lives, the PIN of the life in.
  C_ASSESS = 0x46,
  // 11ax (12 Nov 2026, issue #30): VAULT mode edits from the app's Accounts page,
  // the PWA's /api/vault/pw/save, /delete-many and /result over the channel.
  // The KEY shows the entry and waits for a held ENTER, as for the PWA.
  //  PW_SAVE    [id 8][sLen][site][uLen][user][pLen][pass][nLen][note]; the BODY
  //             is encrypted with encBody, cmd 0x47 in place of the rsp byte
  //             (the only request body that is). id all zero = a new entry.
  //  PW_DELETE  [n][id 8 x n], n 1..20, one held ENTER (2 s) for the lot.
  //  PW_RESULT  no body -> R_ACK [state][id 8][reason] (see PwState).
  //  ASSESS_ONE [id 8] -> R_ACK, encrypted, [status][state][prefix 3]: state 1
  //             opening it (ask again), 2 prefix ready, 3 verdict known (11ay).
  C_PW_SAVE = 0x47, C_PW_DELETE = 0x48, C_PW_RESULT = 0x49, C_ASSESS_ONE = 0x4A,
  // 11bf (16 Nov 2026): import from another manager's export, VAULT mode only
  // (G0 v19 seals an import only in a PASSKEY life). The PWA's import window
  // over the channel: the passkey PIN on the KEY opens it, then entries go in
  // one at a time with no press each.
  //  IMPORT_BEGIN  no body -> R_ACK [status]; the KEY asks for the passkey PIN.
  //  IMPORT_ITEM   BODY encrypted (cmd 0x4C in the rsp place), see parseImportItem
  //                -> R_ACK [status]: S_OK queued (watch IMPORT_STATUS), S_BUSY
  //                8 are waiting (11bh; 11bf: one) - send it again shortly.
  //  IMPORT_STATUS no body -> R_ACK [state][reason][saved u16 LE][failed u16 LE][last]
  //                11bh appends [queued][skipped u16 LE][done u16 LE][n][n results, oldest first]
  //  IMPORT_END    no body -> R_ACK [status][saved u16 LE][failed u16 LE]; closes the window.
  C_IMPORT_BEGIN = 0x4B, C_IMPORT_ITEM = 0x4C, C_IMPORT_STATUS = 0x4D, C_IMPORT_END = 0x4E,
  // 11bi (17 Nov 2026, issue #38): iPhone AutoFill's "suggest a strong password".
  //  GEN_PW [kind][minLen][maxLen][required][allowed][sLen][specials], VAULT
  //  life, no press, nothing stored -> R_GEN_PW (encrypted) [status][pLen][password].
  //  See parseGenPw and pwgen::generateRules.
  C_GEN_PW = 0x4F, R_GEN_PW = 0xC1,
  // 11bt (19 Nov 2026, issue #39): CIPHER's daily block through the phone, NOSTR
  // Bluetooth life. CIPHER_DAY [the text GET favillakey.io/api/cipher/day answered,
  // "<height>,<160 hex>", 1..199 bytes] -> R_ACK [status][height u32 LE]: S_OK the
  // KEY checked it (proof of work, floor, height, age) and keeps it for DAILY,
  // S_BAD_REQUEST it did not pass. No PIN needed: the block is public. The KEY
  // asks for one with bit2 (0x04) of R_NUDGE's third byte.
  C_CIPHER_DAY = 0x50,
};
// 11bi (issue #38): PW_SAVE's optional trailing flags byte (after the note).
constexpr uint8_t NUDGE_CIPHER_DAY = 0x04;   // 11bt: R_NUDGE third byte, bit2: "send me today's CIPHER block"
constexpr uint8_t PW_KEEP_OLD = 0x01;   // a change of password keeps the old one as "<site> (old)" (CHANGE PASSWORD, 11az)
// 11bi: GEN_PW's rules. Class bits as pwgen: 1 lower, 2 upper, 4 digit, 8 special.
constexpr uint8_t GEN_STRONG = 0x01, GEN_ALNUM = 0x02;
constexpr size_t GEN_SPECIALS_MAX = 32, GEN_LEN_MIN = 8, GEN_LEN_MAX = 64;
static const char GEN_DEFAULT_SPECIALS[] = "-!@#$%^&*_+=?";
struct GenPwRules { uint8_t kind, minLen, maxLen, required, allowed, sN; char specials[GEN_SPECIALS_MAX + 1]; };
// 11bf: IMPORT_STATUS's state byte.
enum ImportState : uint8_t {
  IMP_NONE = 0,      // no import from this app install since the KEY started
  IMP_ASKING = 1,    // the KEY is asking for the passkey PIN (or about to)
  IMP_OPEN = 2,      // the window is open and nothing is being sealed: send the next item
  IMP_WORKING = 3,   // sealing the last item sent
  IMP_CLOSED = 4,    // the window closed; reason: S_OK the app ended it, S_CANCELLED BACK on the KEY,
                     // S_LOCKED the KEY locked, S_BUSY a website's prompt took the screen, S_TIMEOUT_IDLE 10 min idle
  IMP_REFUSED = 5,   // the window never opened; reason: S_CANCELLED BACK or 90 s on the PIN screen,
                     // S_PIN_WRONG three wrong PINs, S_STORAGE the G0 refused to open it, S_USED already used this power-on
};
// 11bf: IMPORT_ITEM kinds and limits.
constexpr uint8_t IMPORT_PW = 1, IMPORT_OTP = 2;
constexpr size_t IMPORT_SECRET_MAX = 64;   // otpauth::SECRET_MAX: the decoded (raw) secret
// 11ax: PW_SAVE field limits (pk_records.h RK_SITE_MAX / RK_PW_FIELD_MAX; the
// KEY also checks the sealed record's total, rk_pw_check). PW_DELETE's batch.
constexpr size_t VAULT_SITE_MAX = 199, VAULT_FIELD_MAX = 128, PW_DELETE_MAX = 20;
// 11ax: PW_RESULT's state byte.
enum PwState : uint8_t {
  PW_ASKING = 0,     // on the KEY's screen (or queued for it)
  PW_DONE = 1,       // saved or deleted; id = the entry's id (new or unchanged; zero for a delete)
  PW_DECLINED = 2,   // BACK on the KEY
  PW_TIMEOUT = 3,    // nobody answered in 60 s
  PW_CHANGED = 4,    // the entry changed or went meanwhile: LIST again
  PW_FAILED = 5,     // the KEY could not do it; reason = a Status (S_VAULT_FULL, S_BUDGET, S_TOO_LONG, S_BUSY)
  PW_NONE = 6,       // no job from this app install since the KEY started
};
constexpr size_t VAULT_CHUNK = 40000;   // 11q: bytes of the frame per R_VAULT_CHUNK (fits APP_MAX with header and mac)
enum Status : uint8_t {
  S_OK = 0,            // hello: paired and listening; ack: shown on the KEY
  S_TYPED = 1,         // event: the KEY typed it
  S_CANCELLED = 2,     // event: BACK on the KEY, or it timed out
  S_NO_MATCH = 3,      // event: no saved login for that site
  S_NOT_HERE = 4,      // only in a life with no radios (PASSKEY now; air-gap NOSTR later)
  S_LOCKED = 5,        // the passkey PIN has not been entered
  S_BUSY = 6,          // the KEY is showing something else
  S_BAD_REQUEST = 7,   // malformed body (site/user rules)
  S_NOT_PAIRED = 8,    // unknown client, or the mac is wrong
  S_REPLAY = 9,        // counter not above the last one
  S_PAIR_CLOSED = 10,  // pairing window not open
  S_PAIR_REFUSED = 11, // BACK on the code screen
  S_FULL = 12,         // no room for another browser
  S_SAVED = 13,        // event (new login): saved, not typed yet
  S_STORAGE = 14,      // the KEY could not store the counter: nothing done
  S_APP_ONLY = 15,     // 9g: an app is paired over Bluetooth, so the raw Bluetooth paths are shut (use the app channel)
  S_VAULT_FULL = 16,   // 11ax: no room for another record (RK_MAX)
  S_BUDGET = 17,       // 11ax: this sitting's record-open budget is used: lock and unlock (or power cycle)
  S_TOO_LONG = 18,     // 11ax: a field, or the whole record, is too long
  S_USED = 19,         // 11bf: the import window was already opened this power-on life (the G0 allows one)
  S_NO_WINDOW = 20,    // 11bf: no import window is open for this app install
  S_PIN_WRONG = 21,    // 11bf: three wrong PINs on the import PIN screen
  S_TIMEOUT_IDLE = 22, // 11bf: the import window closed after 10 minutes without an item
  S_EXISTS = 23,       // 11bh: an imported entry whose site and username are already on the KEY: the KEY's entry was kept
};
constexpr size_t NONCE = 16, COMMIT = 32;
// life byte in HELLO: what the KEY is in now
enum Life : uint8_t { L_PASSKEY_LOCKED = 1, L_PASSKEY_READY = 2, L_NOSTR = 3, L_OTHER = 4 };

typedef bool (*HmacFn)(const uint8_t* key, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]);

inline bool ctEq(const uint8_t* a, const uint8_t* b, size_t n){ uint8_t d = 0; for(size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }
inline void put32(uint8_t* p, uint32_t v){ p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
inline uint32_t get32(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

// ---- framing -----------------------------------------------------------------
struct Reasm {
  uint8_t buf[MSG_MAX]; size_t want = 0, have = 0; uint8_t next = 0;
  void reset(){ want = have = 0; next = 0; }
  // Feed one 64-byte report. Returns the message length when one is complete, 0
  // when more is needed (or the report was not a frame), -1 on a framing error.
  int feed(const uint8_t r[REPORT]){
    if(r[0] == F_START){
      size_t len = (size_t)r[1] | ((size_t)r[2] << 8);
      reset();
      if(len == 0 || len > MSG_MAX) return -1;
      want = len; size_t n = len < 61 ? len : 61; memcpy(buf, r + 3, n); have = n; next = 1;
      if(have == want){ int out = (int)want; want = 0; return out; }
      return 0;
    }
    if(r[0] == F_CONT){
      if(!want || r[1] != next){ reset(); return -1; }
      size_t n = want - have; if(n > 62) n = 62; memcpy(buf + have, r + 2, n); have += n; next++;
      if(have == want){ int out = (int)want; want = 0; return out; }
      return 0;
    }
    return 0;
  }
};
// Split msg into reports. Returns the number written (<= maxReports), 0 if it does not fit.
inline int fragment(const uint8_t* msg, size_t len, uint8_t (*out)[REPORT], int maxReports){
  if(len == 0 || len > MSG_MAX) return 0;
  int need = len <= 61 ? 1 : 1 + (int)((len - 61 + 62 - 1) / 62);
  if(need > maxReports) return 0;
  memset(out, 0, (size_t)need * REPORT);
  out[0][0] = F_START; out[0][1] = (uint8_t)len; out[0][2] = (uint8_t)(len >> 8);
  size_t n = len < 61 ? len : 61; memcpy(out[0] + 3, msg, n); size_t off = n;
  for(int i = 1; i < need; i++){ out[i][0] = F_CONT; out[i][1] = (uint8_t)i; size_t m = len - off; if(m > 62) m = 62; memcpy(out[i] + 2, msg + off, m); off += m; }
  return need;
}

// ---- pairing derivation ----------------------------------------------------------
inline bool derive(HmacFn h, const uint8_t z[32], const uint8_t extPub[PUB], const uint8_t keyPub[PUB], uint8_t k[KEYLEN], uint32_t* code){
  static const char SALT[] = "FAVILLA-CHAN-1";
  uint8_t prk[32], t[32], info[4 + 2 * PUB + 1];
  if(!h((const uint8_t*)SALT, sizeof(SALT) - 1, z, 32, prk)) return false;
  memcpy(info, "key", 3); memcpy(info + 3, extPub, PUB); memcpy(info + 3 + PUB, keyPub, PUB); info[3 + 2 * PUB] = 1;
  if(!h(prk, 32, info, 3 + 2 * PUB + 1, k)) return false;
  memcpy(info, "code", 4); memcpy(info + 4, extPub, PUB); memcpy(info + 4 + PUB, keyPub, PUB); info[4 + 2 * PUB] = 1;
  if(!h(prk, 32, info, 4 + 2 * PUB + 1, t)) return false;
  *code = (((uint32_t)t[0] << 24) | ((uint32_t)t[1] << 16) | ((uint32_t)t[2] << 8) | t[3]) % 1000000u;
  memset(prk, 0, 32); memset(t, 0, 32);
  return true;
}

// C = HMAC("FAVILLA-COMMIT-1", extPub || nonce)
inline bool commitment(HmacFn h, const uint8_t extPub[PUB], const uint8_t nonce[NONCE], uint8_t out[COMMIT]){
  static const char K[] = "FAVILLA-COMMIT-1";
  uint8_t d[PUB + NONCE]; memcpy(d, extPub, PUB); memcpy(d + PUB, nonce, NONCE);
  return h((const uint8_t*)K, sizeof(K) - 1, d, sizeof d, out);
}
// mac16 of (dir || data[0..n)), dir = "REQ" or "RSP"
inline bool mac16(HmacFn h, const uint8_t k[KEYLEN], const char* dir, const uint8_t* d, size_t n, uint8_t out[MAC]){
  uint8_t tmp[MSG_MAX + 3], full[32];
  if(n > MSG_MAX) return false;
  memcpy(tmp, dir, 3); memcpy(tmp + 3, d, n);
  if(!h(k, KEYLEN, tmp, n + 3, full)) return false;
  memcpy(out, full, MAC); memset(full, 0, 32);
  return true;
}

// ---- 9f: encrypted bodies (the app channel) ------------------------------------------
// A reply body that carries a secret (a login, a list) is XORed with a keystream
// before buildRsp() macs it (encrypt, then mac). The keystream is unique per
// reply because (rsp, client, request counter) never repeats for one key: the
// KEY sends at most one reply of each kind per request, and counters only grow.
//   Ke      = HMAC(K, "FAVILLA-CHAN-ENC-1")
//   block i = HMAC(Ke, rsp || clientId 8 || ctr u32 LE || i u8), 32 bytes, i = 0, 1, ..
// Same call encrypts and decrypts.
// 11ad (11 Nov 2026, issue #9's "protocol change to follow"): blocks 0..254
// keep the one-byte index, so every answer up to 8160 bytes is byte for byte
// what it was; block 255 and up take [0xFF][i u16 LE] instead, so an answer
// can be as long as a body field allows (65535). Before this a decrypted DM
// over 8 KB was never sent at all and the app timed out (bench, 11 Nov).
inline bool encBody(HmacFn h, const uint8_t k[KEYLEN], uint8_t rsp, const uint8_t id[ID], uint32_t ctr, uint8_t* d, size_t n){
  static const char L[] = "FAVILLA-CHAN-ENC-1";
  if(n > 65535u) return false;
  uint8_t ke[32], in[1 + ID + 4 + 3], ks[32];
  if(!h(k, KEYLEN, (const uint8_t*)L, sizeof(L) - 1, ke)) return false;
  in[0] = rsp; memcpy(in + 1, id, ID); put32(in + 1 + ID, ctr);
  for(size_t off = 0, i = 0; off < n; off += 32, i++){
    size_t inN = 1 + ID + 4 + 1;
    if(i < 255){ in[1 + ID + 4] = (uint8_t)i; }
    else { in[1 + ID + 4] = 0xFF; in[1 + ID + 5] = (uint8_t)i; in[1 + ID + 6] = (uint8_t)(i >> 8); inN += 2; }
    if(!h(ke, 32, in, inN, ks)){ memset(ke, 0, 32); return false; }
    size_t m = n - off < 32 ? n - off : 32;
    for(size_t j = 0; j < m; j++) d[off + j] ^= ks[j];
  }
  memset(ke, 0, 32); memset(ks, 0, 32);
  return true;
}

// ---- requests --------------------------------------------------------------------
struct Req { uint8_t cmd; uint8_t id[ID]; uint32_t ctr; const uint8_t* body; size_t bodyLen; };
// Split a request's header; true when it is long enough to hold header + mac.
inline bool splitReq(const uint8_t* m, size_t n, Req* r){
  if(n < 1 + ID + 4 + MAC) return false;
  r->cmd = m[0]; memcpy(r->id, m + 1, ID); r->ctr = get32(m + 1 + ID);
  r->body = m + 1 + ID + 4; r->bodyLen = n - (1 + ID + 4 + MAC);
  return true;
}
// Check the mac (k from the client table) and the counter. Returns S_OK, S_NOT_PAIRED or S_REPLAY.
inline Status verifyReq(HmacFn h, const uint8_t* m, size_t n, const uint8_t k[KEYLEN], uint32_t lastCtr){
  uint8_t mac[MAC];
  if(n < 1 + ID + 4 + MAC || !mac16(h, k, "REQ", m, n - MAC, mac) || !ctEq(mac, m + n - MAC, MAC)) return S_NOT_PAIRED;
  if(get32(m + 1 + ID) <= lastCtr) return S_REPLAY;
  return S_OK;
}
// Build a reply/event: [rsp][id][ctr][body][mac]. Returns its length, 0 on overflow.
inline size_t buildRsp(HmacFn h, const uint8_t k[KEYLEN], uint8_t rsp, const uint8_t id[ID], uint32_t ctr, const uint8_t* body, size_t bl, uint8_t* out, size_t cap){
  size_t n = 1 + ID + 4 + bl;
  if(n + MAC > cap || n + MAC > MSG_MAX) return 0;
  out[0] = rsp; memcpy(out + 1, id, ID); put32(out + 1 + ID, ctr); if(bl) memcpy(out + 1 + ID + 4, body, bl);
  if(!mac16(h, k, "RSP", out, n, out + n)) return 0;
  return n + MAC;
}
// SIGN_IN / NEW_LOGIN body: [sLen][site][uLen][user][fields?]. Site 1..100,
// user 0..100, printable US keyboard text only. site/user need FIELD_MAX + 1
// bytes. 11aw (12 Nov 2026): an optional last byte says what the page shows,
// so a two-page sign-in (Proton: username, Continue, then the password) gets
// the right half typed: FIELDS_BOTH 0 (or absent), FIELDS_USER 1 (a username
// box and no password box), FIELDS_PASS 2 (a password box and no username
// box). Anything else is a bad request.
// 11az (13 Nov 2026): NEW_LOGIN's last byte may instead describe a sign-up or
// change-password form, with FORM_KNOWN (bit 7) set. The page's boxes in order:
// the first (a username box on a sign-up page, the current password on a change
// page), the new password, the confirm box. FORM_CONFIRM: a confirm box is
// there. FORM_CURRENT: the first box is the current password (a change of a
// saved login). FORM_USER: the first box is a username box. FORM_SPLIT1: Tab from
// the first box does not reach the new one. FORM_SPLIT2: Tab from the new box
// does not reach the confirm box. Bits 5 and 6 are zero. chan_key refuses a FORM
// byte on a sign-in, and a FIELDS byte other than 0 on a new login.
enum : uint8_t { FIELDS_BOTH = 0, FIELDS_USER = 1, FIELDS_PASS = 2 };
enum : uint8_t { FORM_KNOWN = 0x80, FORM_CONFIRM = 0x01, FORM_CURRENT = 0x02, FORM_USER = 0x04, FORM_SPLIT1 = 0x08, FORM_SPLIT2 = 0x10 };
inline bool formByte(uint8_t f){ return (f & 0xE0) == FORM_KNOWN; }
inline bool parseLogin(const uint8_t* b, size_t n, char* site, char* user, uint8_t* fields = nullptr){
  site[0] = user[0] = 0; if(fields) *fields = FIELDS_BOTH;
  if(n < 2) return false;
  size_t sl = b[0]; if(sl < 1 || sl > FIELD_MAX || 1 + sl + 1 > n) return false;
  size_t ul = b[1 + sl]; if(ul > FIELD_MAX) return false;
  if(1 + sl + 1 + ul == n - 1){ uint8_t f = b[n - 1]; if(f > FIELDS_PASS && !formByte(f)) return false; if(fields) *fields = f; n--; }
  if(1 + sl + 1 + ul != n) return false;
  for(size_t i = 0; i < sl; i++){ uint8_t c = b[1 + i]; if(c < 0x20 || c > 0x7E) return false; }
  for(size_t i = 0; i < ul; i++){ uint8_t c = b[2 + sl + i]; if(c < 0x20 || c > 0x7E) return false; }
  bool any = false; for(size_t i = 0; i < sl; i++) if(b[1 + i] != ' ') any = true;
  if(!any) return false;
  memcpy(site, b + 1, sl); site[sl] = 0; memcpy(user, b + 2 + sl, ul); user[ul] = 0;
  return true;
}

// 11ax: PW_SAVE's (decrypted) body. Text is UTF-8 with no control characters
// (the PWA's JSON strings carry the same); site 1..VAULT_SITE_MAX bytes, the
// others 0..VAULT_FIELD_MAX. Outputs are NUL-terminated; caps must be at least
// the limits + 1. Nothing is written on failure past the NULs.
inline bool utf8Text(const uint8_t* p, size_t n){
  size_t i = 0;
  while(i < n){
    const uint8_t c = p[i];
    if(c < 0x80){ if(c < 0x20 || c == 0x7F) return false; i++; continue; }
    size_t k; uint8_t lo = 0x80, hi = 0xBF;          // continuation bytes; the first one's range is narrowed below
    if(c >= 0xC2 && c <= 0xDF) k = 1;
    else if(c >= 0xE0 && c <= 0xEF){ k = 2; if(c == 0xE0) lo = 0xA0; if(c == 0xED) hi = 0x9F; }   // no overlongs, no surrogates
    else if(c >= 0xF0 && c <= 0xF4){ k = 3; if(c == 0xF0) lo = 0x90; if(c == 0xF4) hi = 0x8F; }   // no overlongs, nothing above U+10FFFF
    else return false;
    if(k > n - i - 1) return false;
    if(p[i + 1] < lo || p[i + 1] > hi) return false;
    for(size_t j = 2; j <= k; j++) if((p[i + j] & 0xC0) != 0x80) return false;
    if(k == 1 && c == 0xC2 && p[i + 1] < 0xA0) return false;   // C1 controls U+0080..U+009F
    i += k + 1;
  }
  return true;
}
// 11bi: an optional [flags] byte may follow the note (PW_KEEP_OLD); unknown bits
// are refused, so an app can tell a KEY that ignores a flag from one that has it.
inline bool parsePwSave(const uint8_t* b, size_t n, uint8_t id[ID], char* site, char* user, char* pass, char* note, uint8_t* flags = nullptr){
  site[0] = user[0] = pass[0] = note[0] = 0; if(flags) *flags = 0;
  if(n < ID + 4) return false;
  size_t o = ID;
  char* out[4] = { site, user, pass, note };
  const size_t lim[4] = { VAULT_SITE_MAX, VAULT_FIELD_MAX, VAULT_FIELD_MAX, VAULT_FIELD_MAX };
  size_t at[4], len[4];
  for(int f = 0; f < 4; f++){
    if(o >= n) return false;
    len[f] = b[o++]; at[f] = o;
    if(len[f] > lim[f] || o + len[f] > n) return false;
    if(!utf8Text(b + o, len[f])) return false;
    o += len[f];
  }
  uint8_t fl = 0;
  if(o + 1 == n){ fl = b[o++]; if(fl & ~PW_KEEP_OLD) return false; }
  if(o != n || len[0] < 1) return false;
  memcpy(id, b, ID); if(flags) *flags = fl;
  for(int f = 0; f < 4; f++){ memcpy(out[f], b + at[f], len[f]); out[f][len[f]] = 0; }
  return true;
}

// 11bi (issue #38): GEN_PW's body, [kind][minLen][maxLen][required][allowed][sLen][specials].
// kind 1 strong, 2 letters and digits only (the special bit is dropped from both
// class sets). Lengths 8..64, min <= max. required within allowed, and allowed
// must hold a letter or digit class. specials: printable ASCII that is not a
// letter, digit or space, up to 32, duplicates dropped; sLen 0 = the default
// set. Specials are ignored unless allowed has the special bit.
inline bool parseGenPw(const uint8_t* b, size_t n, GenPwRules* r){
  memset(r, 0, sizeof *r);
  if(n < 6) return false;
  const uint8_t kind = b[0], mn = b[1], mx = b[2], sl = b[5];
  uint8_t req = b[3], alw = b[4];
  if(kind != GEN_STRONG && kind != GEN_ALNUM) return false;
  if(mn < GEN_LEN_MIN || mx > GEN_LEN_MAX || mn > mx) return false;
  if((req | alw) & ~0x0F) return false;
  if(sl > GEN_SPECIALS_MAX || n != 6u + sl) return false;
  if(kind == GEN_ALNUM){ req &= 0x07; alw &= 0x07; }
  if((req & ~alw) || !(alw & 0x07)) return false;
  for(size_t i = 0; i < sl; i++){
    const uint8_t c = b[6 + i];
    if(c < 0x21 || c > 0x7E) return false;
    if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return false;
    bool dup = false; for(size_t k = 0; k < r->sN; k++) if((uint8_t)r->specials[k] == c) dup = true;
    if(!dup) r->specials[r->sN++] = (char)c;
  }
  if(alw & 0x08){ if(!r->sN){ memcpy(r->specials, GEN_DEFAULT_SPECIALS, sizeof GEN_DEFAULT_SPECIALS - 1); r->sN = sizeof GEN_DEFAULT_SPECIALS - 1; } }
  else { memset(r->specials, 0, sizeof r->specials); r->sN = 0; }
  r->specials[r->sN] = 0;
  r->kind = kind; r->minLen = mn; r->maxLen = mx; r->required = req; r->allowed = alw;
  return true;
}

// 11bf: IMPORT_ITEM's (decrypted) body.
//   [1][sLen][site][uLen][user][pLen][pass][nLen][note]   a password; pass 1..128
//   [2][sLen][site][aLen][acct][digits][period][kLen][secret]   a one-time code
//      (TOTP, SHA1): digits 6..8, period 1..255 s, secret the raw bytes (the app
//      decodes the export's base32) 1..64.
// Text as PW_SAVE: UTF-8, no control characters, site 1..VAULT_SITE_MAX, the
// rest 0..VAULT_FIELD_MAX. Caps of the outputs must be at least the limits + 1.
struct ImportItem {
  uint8_t kind;
  char site[VAULT_SITE_MAX + 1], user[VAULT_FIELD_MAX + 1], pass[VAULT_FIELD_MAX + 1], note[VAULT_FIELD_MAX + 1];   // user = acct for a code
  uint8_t secret[IMPORT_SECRET_MAX]; size_t secretN; uint8_t digits, period;
};
inline bool parseImportItem(const uint8_t* b, size_t n, ImportItem* it){
  memset(it, 0, sizeof *it);
  if(n < 1) return false;
  const uint8_t kind = b[0];
  size_t o = 1;
  auto field = [&](char* out, size_t lim, size_t minLen) -> bool {
    if(o >= n) return false;
    const size_t L = b[o++];
    if(L < minLen || L > lim || o + L > n) return false;
    if(!utf8Text(b + o, L)) return false;
    memcpy(out, b + o, L); out[L] = 0; o += L;
    return true;
  };
  if(kind == IMPORT_PW){
    if(!field(it->site, VAULT_SITE_MAX, 1) || !field(it->user, VAULT_FIELD_MAX, 0) || !field(it->pass, VAULT_FIELD_MAX, 1) || !field(it->note, VAULT_FIELD_MAX, 0) || o != n){ memset(it, 0, sizeof *it); return false; }
  } else if(kind == IMPORT_OTP){
    if(!field(it->site, VAULT_SITE_MAX, 1) || !field(it->user, VAULT_FIELD_MAX, 0) || o + 3 > n){ memset(it, 0, sizeof *it); return false; }
    it->digits = b[o++]; it->period = b[o++];
    const size_t k = b[o++];
    if(it->digits < 6 || it->digits > 8 || it->period < 1 || k < 1 || k > IMPORT_SECRET_MAX || o + k != n){ memset(it, 0, sizeof *it); return false; }
    memcpy(it->secret, b + o, k); it->secretN = k;
  } else return false;
  bool any = false; for(const char* p = it->site; *p; p++) if(*p != ' ') any = true;   // a site of spaces only names nothing
  if(!any){ memset(it, 0, sizeof *it); return false; }
  it->kind = kind;
  return true;
}

// ---- the Bluetooth app channel (9g), pure so the fuzzers run the real code (9u) ----
// Reassembly of 64-byte reports into a message of up to APP_MAX bytes in rx
// (which holds APP_MAX). feed: 0 = more to come, 1 = a whole message of want
// bytes is in rx (the state is reset), -1 = a bad report (the state is reset).
struct AppRx { size_t want = 0, have = 0; uint8_t next = 0; uint32_t t = 0; };
inline int appRxFeed(AppRx& s, uint8_t* rx, const uint8_t r[REPORT], uint32_t now){
  if (s.want && now - s.t > 3000) s.want = 0;   // a message left half-sent is dropped
  if (r[0] == F_START) {
    const size_t L = (size_t)r[1] | ((size_t)r[2] << 8);
    if (L == 0 || L > APP_MAX) { s.want = 0; return -1; }
    s.want = L; s.have = L < 61 ? L : 61; memcpy(rx, r + 3, s.have); s.next = 1; s.t = now;
  } else if (r[0] == F_CONT) {
    if (!s.want || r[1] != s.next) { s.want = 0; return -1; }
    size_t c = s.want - s.have; if (c > 62) c = 62; memcpy(rx + s.have, r + 2, c); s.have += c; s.next++; s.t = now;
  } else { s.want = 0; return -1; }
  return s.want && s.have == s.want ? 1 : 0;
}
// An API request body (9k): [method 1][pathLen 2 LE][path?query][hCount 1]
// ([id 1][len 2 LE][value]) x hCount [bodyLen 2 LE][body]. Path printable
// 0x21..0x7E, 1..2048, starting /api/; header ids 1 (session) 2 (auth) 3
// (counter), each up to 1024; the body up to API_BODY_MAX and exactly the rest.
struct ApiReq { uint8_t meth; const char* full; size_t fullLen, pathLen; const char* hv[4]; size_t hl[4]; const uint8_t* body; size_t bodyLen; };
inline uint16_t rd16le(const uint8_t* p){ return (uint16_t)(p[0] | (p[1] << 8)); }
inline bool apiDecode(const uint8_t* b, size_t n, ApiReq* q){
  memset(q, 0, sizeof *q); size_t o = 0;
  if (n < 1 + 2 + 1 + 2) return false;
  q->meth = b[o++]; if (q->meth != 0x01 && q->meth != 0x02) return false;
  const size_t pl = rd16le(b + o); o += 2;
  if (pl < 1 || pl > 2048 || o + pl + 1 > n) return false;
  q->full = (const char*)b + o; q->fullLen = pl; q->pathLen = pl; o += pl;
  for (size_t i = 0; i < pl; i++) { const uint8_t c = (uint8_t)q->full[i]; if (c < 0x21 || c > 0x7E) return false; if (c == '?' && q->pathLen == pl) q->pathLen = i; }
  if (q->pathLen < 5 || memcmp(q->full, "/api/", 5) != 0) return false;
  const uint8_t hn = b[o++];
  for (uint8_t k = 0; k < hn; k++) {
    if (o + 3 > n) return false;
    const uint8_t id = b[o]; const size_t vl = rd16le(b + o + 1); o += 3;
    if (vl > 1024 || o + vl > n) return false;
    if (id < 1 || id > 3) return false;
    q->hv[id] = (const char*)b + o; q->hl[id] = vl; o += vl;   // a repeated id: the last one counts (as before)
  }
  if (o + 2 > n) return false;
  q->bodyLen = rd16le(b + o); o += 2;
  if (q->bodyLen > API_BODY_MAX || o + q->bodyLen != n) return false;
  q->body = b + o;
  return true;
}

}  // namespace chan
