// =============================================================================
// pk_records.h - passwordless passkey records (2 Nov 2026, Vault spec v0.15,
// phase 2, rulings P1 to P4).
// =============================================================================
// A record is what the KEY needs to sign in with no username: the site, the
// account (user handle, name, display name) and the restorable credential ID.
// It holds nothing that signs: the key is still derived on the G0 from the ID.
//
// Sealed by the G0 (VAULT SEAL, P1) and kept in their own NVS partition
// "nvs_vault" (P2), one blob per slot. Each sealed blob starts with a clear
// header the G0 MACs: id (8) | updated (4) | kind (1) | site tag (8). The
// index (headers only) lives in RAM; opening a record costs one of the G0's
// 32 OPENs per power-on life, so opened records are cached in RAM until the
// KEY locks (P3) and rk_forget_cache() wipes them.
//
// Plaintext (kind 1): [siteLen][site][hLen][handle][nLen][name][dLen][display]
//                     [nonce16][tag16][created4]
// Plaintext (kind 2, phase 4, Vault spec 7f): [siteLen][site][uLen][username]
//                     [pLen][password][nLen][note][policy4][created4][updated4]
// Passwords are never cached: each one is opened when it is used and wiped.
// Thread safety: one mutex around everything (the FIDO task and the main
// loop's Settings page both call in).
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace favilla {

constexpr int    RK_MAX        = 400;   // records on the KEY, passkeys and passwords together (Vault spec 7f, P4-1: was 50; 11dr: was 200, nvs_vault 256 KB)
constexpr int    RK_OLD_MAX    = 200;   // 11dr: the cap before; per-slot tables written then hold this many rows
constexpr size_t RK_SITE_MAX   = 199;   // so a full record fits the G0's 431-byte plaintext
constexpr size_t RK_HANDLE_MAX = 64;    // CTAP: user.id is at most 64 bytes
constexpr size_t RK_NAME_MAX   = 64;    // name and display name, cut on a UTF-8 boundary
constexpr uint8_t RK_KIND_PASSKEY = 1;
constexpr uint8_t RK_KIND_TOTP = 3;       // 9i (7 Nov 2026, G0 v17): one-time code secrets; the G0 never opens them to the ESP32
constexpr uint8_t RK_KIND_RECOVERY = 4;   // 11aa (11 Nov 2026): a site's recovery codes (the one-time strings handed out when two-step is turned on)
constexpr uint8_t RK_KIND_PASSWORD = 2;   // phase 4 (Vault spec 7f): held, merged and backed up from this build; screens follow

constexpr size_t RK_PW_FIELD_MAX = 128;   // username, password and note, each (Vault spec 7f)
constexpr size_t RK_PT_MAX       = 431;   // the G0's largest plaintext (VLT_PT_MAX)

struct RkAcct {
  int      slot;
  uint8_t  handle[RK_HANDLE_MAX]; uint8_t handleN;
  char     name[RK_NAME_MAX + 1];
  char     disp[RK_NAME_MAX + 1];
  char     site[RK_SITE_MAX + 1];
  uint8_t  id34[34];
  uint32_t updated;
};

// A password entry, opened. Holds the password in clear: wipe it with
// rk_pw_wipe() as soon as it has been used.
struct RkPass {
  int      slot;              // -1 for a new entry
  uint8_t  origin;            // 11s: where the password came from (RK_ORIGIN_*), kept in the health table, never sealed
  uint32_t updated, created, policy;
  char     site[RK_SITE_MAX + 1];
  char     user[RK_PW_FIELD_MAX + 1];
  char     pass[RK_PW_FIELD_MAX + 1];
  char     note[RK_PW_FIELD_MAX + 1];
};

enum {
  RK_OK = 0,
  RK_E_NOVAULT = -1,   // no nvs_vault partition (partition table not reflashed) or the G0 has no VAULT
  RK_E_FULL    = -2,   // RK_MAX records and none to replace
  RK_E_G0      = -3,   // the G0 refused (rk_last_res() has its code) or could not be reached
  RK_E_BUDGET  = -4,   // this life's OPEN budget is spent: power cycle
  RK_E_SIZE    = -5,   // a field is too long for a record
  RK_E_NVS     = -6,   // the blob could not be written
  RK_E_FORMAT  = -7,   // an opened record does not parse (never expected)
  RK_E_EXISTS  = -8,   // 11bh: an import found this site and username already on the KEY and kept the KEY's entry
};

bool        rk_mount();          // setup(): mount nvs_vault (non-fatal), false = partition missing
bool        rk_ready();          // partition mounted and the G0 has VAULT
int         rk_count();          // PASSKEY records on the KEY (loads the index on first use)
int         rk_count_all();      // every record, any kind (what RK_MAX limits)
// Every account for this site, opened (from the cache when possible). Returns
// how many were written to out (at most max), or an RK_E_* code.
int         rk_find(const char* site, size_t siteN, RkAcct* out, int max);
// Save a record; the same site and user handle replaces the old one (CTAP).
int         rk_save(const char* site, size_t siteN, const uint8_t* handle, size_t handleN,
                    const char* name, size_t nameN, const char* disp, size_t dispN, const uint8_t id34[34]);
// Before a registration, after the owner's press: RK_OK when there is room or
// this site + user handle already has a record (it will be replaced),
// RK_E_FULL, or an error if any record of the site could not be opened.
int         rk_room(const char* site, size_t siteN, const uint8_t* handle, size_t handleN);
// Settings page: the i-th record in slot order (opens it if not cached), and
// its slot without opening it (to delete a record that cannot be opened).
int         rk_at(int i, RkAcct* out);   // the i-th PASSKEY record (passwords are skipped)
int         rk_slot_at(int i);
int         rk_delete(int slot);
constexpr int RK_UB_MAX = 16;   // usernames book (4 Nov 2026): the owner's own list for the New password picker
int         rk_ub_list(char (*out)[RK_PW_FIELD_MAX + 1], int max);   // sealed with K_IDX; -1 = the index key is not open
int         rk_ub_add(const char* user);   // newest first, no duplicates; RK_E_FULL past RK_UB_MAX
int         rk_ub_del(int i);
int         rk_delete_many(const int* slots, const uint8_t (*ids)[8], int n, int* deleted, int* skipped);   // 4 Nov 2026: one tombstone write, one index write; ids may be null
void        rk_forget_cache();   // every lock: wipe opened records and site tags from RAM
void        rk_wipe_all();       // wallet wipe: every record gone
uint8_t     rk_last_res();       // the G0's last VAULT result code
int         rk_open_left();      // OPENs left this life as last reported by the G0 (-1 unknown)
// 25 Nov 2026: room to save. The G0 reports OPENs left but not TAGs left, and a
// SEAL (every save) spends a TAG, so the TAGs are counted here: full at a PIN
// entered on the KEY (rk_budget_refilled), one less per TAG or SEAL that went
// through. Only a guide (an ESP32 restart starts it full again); the G0 decides.
int         rk_tag_left();       // TAGs left this sitting as counted here (-1: no limit)
void        rk_budget_refilled();// a right PIN on the KEY: the G0 refilled both budgets
bool        rk_save_room(int saves, int opens);   // enough for that many saves and opens?
// 25 Nov 2026 (G0 v24): the vault limit is the owner's, Settings > Open limit.
// 0 = no limit (the default), else 8, 16, 32, 64 or 128 opens and site tags per
// sitting. A stricter one applies at once; a looser one (or none) from the next
// power-on. A G0 before v24 has a fixed 32 (now = next = 32, RK_E_NOVAULT to set).
struct RkLimit { int now, next, openLeft, tagLeft, refills, refillsMax; };   // left: -1 = no limit
int         rk_limit_read(RkLimit* o);
int         rk_limit_set(uint8_t lim, RkLimit* o);   // straight after a right g0_uv_check (nothing in between)
const char* rk_err_name(int e);
size_t      rk_utf8_cut(const char* s, size_t n, size_t max);   // largest length <= max that ends on a character boundary
// Phase 3 (2 Nov 2026): relay backup. The body is the sealed records exactly
// as stored plus tombstones; nothing is opened to build or merge it.
// foreign: records of a kind this firmware does not hold; full: no room. Either
// means this KEY cannot represent the whole backup, so it must not publish.
// future: records or tombstones dated more than a day ahead of the clock (ignored).
struct RkImport { int added, removed, same, skipped, full, foreign, future, failed; };
bool        rk_dirty();          // a change the relay backup does not have yet
// After a backup a relay accepted: clears "dirty" only if nothing changed
// since the export that produced gen (review 2 Nov 2026). false = still dirty.
bool        rk_set_clean(uint32_t gen);
int         rk_export(uint8_t* out, size_t cap, size_t* outN, int* nrec, int* ntomb, uint32_t* gen);
int         rk_import(const uint8_t* in, size_t n, RkImport* st);

// ---- Phase 4 (3 Nov 2026, Vault spec 7f): password entries (kind 2) ----------
// Same store, budget, backup and tombstones as passkey records. rk_delete()
// deletes either kind by slot.
int         rk_pw_count();                     // password entries on the KEY
int         rk_pw_slot_at(int i);              // slot of the i-th entry, without opening it
int         rk_pw_open(int i, RkPass* out);    // the i-th entry, opened (one OPEN, never cached)
// RK_OK, or RK_E_SIZE if the fields cannot be sealed together (an empty
// site or password, a field over RK_PW_FIELD_MAX, or more than RK_PT_MAX in all).
int         rk_pw_check(size_t siteN, size_t userN, size_t passN, size_t noteN);
// Save an entry. in->slot >= 0 and a password there: that entry is replaced
// (an edit, the id is kept). Otherwise the same site and username replaces
// the old entry, or a new one is added. created 0: set to now. On RK_OK,
// *slotOut (if given) is the slot written.
int         rk_pw_save(const RkPass* in, int* slotOut);
void        rk_pw_wipe(RkPass* p);
// v15 (3 Nov 2026, Vault spec 7f P4-8): an entry's site and username without
// its password, from the G0's LABEL op (800 per power-on life from G0 v23, 400 before; never an OPEN).
// Cached in PSRAM until the KEY locks; a cached label is only used while the
// slot still holds the same id and time. RK_E_NOVAULT if the G0 is older than v15.
struct RkLabel { int slot; uint8_t id8[8]; uint32_t updated; char site[RK_SITE_MAX + 1]; char user[RK_PW_FIELD_MAX + 1]; };
int         rk_pw_label(int i, RkLabel* out);
// Password entry indices (as rk_pw_open / rk_pw_label take them), most recently
// changed first. Returns how many were written. Opens nothing.
int         rk_pw_order(int* idx, int max);
bool        rk_pw_label_cached(int i);   // true if rk_pw_label(i) would answer from the cache (no G0 call)
// The i-th entry's index for (slot, id) as the PWA names it; -1 if that slot
// no longer holds that entry (deleted, or replaced by another).
int         rk_pw_index_of(int slot, const uint8_t id8[8]);
bool        rk_pw_id_of(int slot, uint8_t id8[8]);   // the id of the entry in slot (clear header, no G0 call)
// v15 VAULT op 5 (Vault spec 7f, P4-4): open this life's import window. Call
// straight after a right g0_uv_check. Out: SEALs and TAGs left in the window.
int         rk_pw_import_window(int* sealsLeft, int* tagsLeft);
// ---- P4-10 (3 Nov 2026, Vault spec): the sealed site index --------------------
// Site names (first RK_IDX_SITE bytes) under AES-256-GCM with K_IDX, in
// nvs_vault. K_IDX is unwrapped by the secure element at unlock and handed in;
// rk_forget_cache (every lock) wipes it and the names. Saves and deletes keep
// the index current; a LABEL heals any entry that is missing or out of date.
constexpr size_t RK_IDX_SITE = 64;
uint32_t    rk_lock_epoch();                                  // read before an unwrap, hand to rk_idx_open
int         rk_idx_open(const uint8_t k[32], uint8_t gen, uint32_t epoch);   // names now known, or -1 (also if the KEY locked since epoch was read)
bool        rk_idx_have_key();
bool        rk_idx_get_key(uint8_t out[32]);                 // for wrapping it under another SE key
void        rk_idx_batch(bool on);                           // an import: one write at the end (and when turned off)
void        rk_idx_flush();                                  // write pending changes now (labels heal in RAM until then)
constexpr size_t RK_IDX_WRAP = 64;                           // IV16 || AES(key, K_IDX)32 || check value16
bool        rk_idx_wrap_get(char which, uint8_t out64[RK_IDX_WRAP]);  // 'P' (under K_PK) or 'N' (under K_IXN), stored in nvs_vault
bool        rk_idx_wrap_put(char which, const uint8_t in64[RK_IDX_WRAP]);
void        rk_idx_kcv(const uint8_t k[32], uint8_t out16[16]);   // review (4): HMAC check value of K_IDX
bool        rk_idx_kcv_ok(const uint8_t k[32], const uint8_t kcv16[16]);
void        rk_idx_wrap_del(char which);
bool        rk_pw_site(int i, char* out, size_t cap, bool* pending, bool* cut);   // full name from a label, else the index's; false = not known yet
bool        rk_pw_site_known(int i);
struct RkRow { int slot; uint8_t id8[8]; char site[RK_SITE_MAX + 1]; char user[RK_PW_FIELD_MAX + 1]; bool nameKnown, userKnown, pending, cut; uint8_t health; };
// ---- 11s (10 Nov 2026, Josh): password health ---------------------------------
// One byte per entry, kept in the clear in nvs_vault beside the record (keyed by
// the entry's id, so a reused slot never inherits it). Computed when the KEY
// holds the password anyway: at every seal, at every OPEN (a login), and by a
// slow backfill of entries it has never seen (a few OPENs per sitting). The
// password itself, and its hash, never reach flash: the SHA-1s live in RAM
// until the KEY locks, for the reuse check and the breach check.
//   bits 0-1 strength: 0 unknown, 1 weak, 2 fair, 3 strong
//   bits 2-3 origin:   0 unknown, 1 made on this KEY, 2 the owner's own (typed, scanned, sent by the phone), 3 imported
//   bit 4 reused (another entry has the same password)   bit 5 seen in a breach
//   bit 6 breach check done                              bit 7 a one-time code is linked to this entry (11v)
enum : uint8_t { RK_ORIGIN_UNKNOWN = 0, RK_ORIGIN_KEY = 1, RK_ORIGIN_OWN = 2, RK_ORIGIN_IMPORT = 3 };
enum : uint8_t { RK_H_STRENGTH = 0x03, RK_H_ORIGIN = 0x0C, RK_H_REUSED = 0x10, RK_H_BREACHED = 0x20, RK_H_CHECKED = 0x40, RK_H_TOTP = 0x80 };
uint8_t     rk_pw_health(int i);                       // the i-th entry's health byte (0 = nothing known)
uint8_t     rk_pw_health_slot(int slot);
// The breach check (Have I Been Pwned, k-anonymity): the KEY hands out the
// 20-bit SHA-1 prefixes of the passwords it holds in RAM and has not checked;
// the phone fetches each bucket and hands back the suffixes; the KEY matches.
int         rk_health_prefixes(uint8_t (*out)[3], int max);   // distinct prefixes still to check (no entry attached)
// suffixes: n * 18 bytes, the 35 hex digits of each bucket line packed high nibble
// first with a trailing zero nibble. Returns how many entries were decided.
// 11bc (13 Nov 2026): a bucket may come in parts (the busy ones hold about
// 2,000 lines, more than one request carries): last false marks a part with
// more to follow; a hit is remembered, and the verdict is recorded when the
// last part arrives (last true, the default, is a whole bucket as before).
// 24 Nov 2026: a whole bucket (all its parts) with fewer than this many
// suffixes is refused: no verdict, returns -1. Real ranges hold hundreds.
constexpr uint32_t RK_HEALTH_MIN_BUCKET = 100;
int         rk_health_bucket(const uint8_t prefix[3], const uint8_t* suffixes, int n, bool last = true);   // entries decided, or -1: refused, bucket too small
int         rk_health_pending();                       // entries with a hash in RAM and no breach verdict yet
// Backfill: open one entry the KEY has never assessed (unknown strength, or no
// hash in RAM for the breach check). One OPEN from the sitting's budget; false when
// there is nothing to do. Callers keep it to a few per sitting.
bool        rk_health_backfill_one();
int         rk_health_recheck_clean();                 // 24 Nov 2026 bench: "checked, clean" back to pending (breached kept); -1 if not mounted
// 11ax (issue #30): assess one password entry now (one OPEN from the sitting's
// budget, only if it has neither a hash in RAM nor a breach verdict).
// 1 opened, 0 nothing to do, -1 not a password slot, else an RK_E_* error.
int         rk_health_assess_slot(int slot);
// 11ay: what the breach check needs for one entry. 1 = a hash in RAM and no
// verdict: prefix (20 bits, as rk_health_prefixes packs it) filled; 2 = the
// verdict is known (nothing to fetch); 0 = not assessed yet; -1 = not a password.
int         rk_health_prefix_of(int slot, uint8_t prefix[3]);
int         rk_pw_index_of_id(const uint8_t id8[8]);   // the index of the entry with this id, -1 if none
int         rk_health_unseen();                        // entries with no hash in RAM and no breach verdict (what the backfill still has to open)
int         rk_pw_rows(RkRow* out, int max);
// ---- 11aa (11 Nov 2026, Josh): site recovery codes (kind 4) ---------------------
// One record per site: [sLen][site][uLen][user][n][used lo][used hi][len][code]...
// sealed by the G0 like a password (the ESP32 holds nothing in the clear but the
// site tag). Linked to the password entry by that tag (the same site string gives
// the same tag), so the link survives a restore with no table. Reading costs one
// OPEN; crossing a code off is one OPEN and a re-seal. A small clear table keeps
// "n codes, k used" per record so the password page can say it without an OPEN.
constexpr int    RK_RC_MAX = 16;    // codes per record
constexpr size_t RK_RC_LEN = 24;    // characters per code
struct RkRecovery { int slot; char site[RK_SITE_MAX + 1]; char user[RK_PW_FIELD_MAX + 1]; int n; uint16_t used; char code[RK_RC_MAX][RK_RC_LEN + 1]; };
int         rk_rc_save(const char* site, const char* user, const char (*codes)[RK_RC_LEN + 1], int n, int* slotOut = nullptr);   // replaces the site's set
int         rk_rc_slot_for_pw(int pwSlot);               // the recovery record with this entry's site tag, -1 if none
bool        rk_rc_counts(int slot, int* n, int* used);   // from the clear table; false after a restore until the record is opened once
int         rk_rc_open(int slot, RkRecovery* out);       // one OPEN
int         rk_rc_mark_used(RkRecovery* rc, int i);      // from a record just opened: a re-seal (no second OPEN); rc->used follows
void        rk_rc_wipe(RkRecovery* r);
// ---- 9i (7 Nov 2026, G0 v17): one-time codes (kind 3) -------------------------
// [siteLen][site][aLen][account][kLen][secret][digits][period]. The secret goes
// in once (rk_totp_save, from an otpauth:// QR) and never comes back: the G0
// computes the code (VAULT TOTP) and its OPEN refuses kind 3. Listed by LABEL.
constexpr size_t RK_TOTP_SECRET_MAX = 64;
struct RkTotp { int slot; char site[RK_SITE_MAX + 1]; char acct[RK_PW_FIELD_MAX + 1]; bool known; };
int         rk_totp_count();
int         rk_totp_save(const char* site, const char* acct, const uint8_t* secret, size_t secretN, uint8_t digits, uint8_t period, int* slotOut = nullptr);
// ---- 11v (11 Nov 2026, Josh: "how do we make 2fa link to an account") ------
// A code linked to a password entry. An ESP32-side table in nvs_vault ("tlnk",
// code id8 || entry id8 per code slot, like the health table): no G0 change, the
// secret stays where it is. A link holds only while both ids still match their
// slots, so a deleted or restored record never inherits one. Health bit 7
// (RK_H_TOTP) on the entry's row and LIST v2 byte tells the KEY's lists and the
// phone that a code is there.
int         rk_totp_link(int totpSlot, int pwSlot);     // pwSlot -1 unlinks
int         rk_totp_linked_pw(int totpSlot);            // the password slot it is linked to, -1 if none
int         rk_pw_totp_slot(int pwSlot);                // the code slot linked to this password, -1 if none
int         rk_totp_rows(RkTotp* out, int max);              // site and account by LABEL (cached), oldest first
int         rk_totp_code(int slot, uint64_t unixTime, uint32_t* code, uint8_t* digits, uint8_t* period = nullptr);   // one OPEN from the sitting's budget
int         rk_totp_find(const char* site, size_t n, int* slots, int max);   // slots whose site matches (by the label, no OPEN)   // every password row, newest first, in one lock (the phone's list)
bool        rk_pw_row(int i, RkRow* out);   // one locked read: slot and id always; the name (index or label) and username (label) when known
int         rk_label_left();     // LABELs left this life as last reported by the G0 (-1 unknown)
const char* rk_hint();           // a line for the owner when the last G0 refusal has a known cause, else ""

}  // namespace favilla
