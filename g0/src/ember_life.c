/* ember_life.c — see ember_life.h. 28 Oct 2026. */
#include "ember_life.h"
#include "sha256.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include <string.h>

static const char HEX[] = "0123456789abcdef";
static int hexval(uint8_t c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1; }

/* Bounded decimal run at *p: 1..maxd digits, no leading zero (except "0"),
 * value < 2^32, followed by ','. Advances *p past the comma. */
static int digits(const uint8_t *s, size_t len, size_t *p, unsigned maxd, uint32_t *out) {
    size_t i = *p; uint64_t v = 0; unsigned n = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') { if (++n > maxd) return -1; v = v * 10 + (s[i] - '0'); i++; }
    if (n == 0 || (n > 1 && s[*p] == '0') || v > 0xFFFFFFFFu || i >= len || s[i] != ',') return -1;
    *out = (uint32_t)v; *p = i + 1;
    return 0;
}

int el_check(const secp256k1_context *ctx, const uint8_t *s, size_t len, const uint8_t sig[64],
             const uint8_t owner[32], el_event_t *ev) {
    size_t p;
    memset(ev, 0, sizeof(*ev));
    if (len < 4 + 64 + 2 + 2 + 2 + 2 || len > EL_MAX) return EL_E_LEN;
    if (memcmp(s, "[0,\"", 4) != 0 || s[68] != '"' || s[69] != ',' || s[len - 1] != ']') return EL_E_SHAPE;
    for (int i = 0; i < 32; i++)
        if (s[4 + 2 * i] != HEX[owner[i] >> 4] || s[5 + 2 * i] != HEX[owner[i] & 15]) return EL_E_KEY;
    p = 70;
    if (digits(s, len, &p, 10, &ev->created_at) || digits(s, len, &p, 5, &ev->kind)) return EL_E_SHAPE;
    int type;
    if (ev->kind == EL_PULSE_KIND) {
        /* exactly ,[],"<64 hex>"]  -- the comma after kind is already consumed */
        if (len != p + 4 + 64 + 2 || memcmp(s + p, "[],\"", 4) != 0 || s[p + 4 + 64] != '"') return EL_E_SHAPE;
        for (int i = 0; i < 32; i++) {           /* display order in the content, internal order kept */
            int hi = hexval(s[p + 4 + 2 * i]), lo = hexval(s[p + 5 + 2 * i]);
            if (hi < 0 || lo < 0) return EL_E_SHAPE;
            ev->block[31 - i] = (uint8_t)(hi << 4 | lo);
        }
        type = EL_PULSE;
    } else if (ev->kind == 1 || ev->kind == 30023 || ev->kind == 0 || ev->kind == 3) {
        type = EL_NOTE;
    } else return EL_E_KIND;
    sha256(s, len, ev->id);
    secp256k1_xonly_pubkey pk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &pk, owner)) return EL_E_KEY;
    if (!secp256k1_schnorrsig_verify(ctx, sig, ev->id, 32, &pk)) return EL_E_SIG;
    return type;
}

int el_note_height(uint32_t created_at, uint32_t tip, uint32_t tip_time, uint32_t floor_height, uint32_t *h) {
    if (created_at > tip_time + EL_FUTURE_SECS) return EL_E_FUTURE;
    if (created_at >= tip_time) { *h = tip; return 0; }
    uint32_t back = (tip_time - created_at + 599u) / 600u;      /* round toward older */
    *h = (back >= tip - floor_height) ? floor_height : tip - back;
    return 0;
}

size_t el_pulse_serialise(const uint8_t owner[32], uint32_t created_at, const uint8_t block[32], uint8_t *o, size_t cap) {
    uint8_t num[11]; int n; size_t k = 0;
    if (cap < 4 + 64 + 2 + 11 + 6 + 4 + 64 + 2) return 0;
    memcpy(o + k, "[0,\"", 4); k += 4;
    for (int i = 0; i < 32; i++) { o[k++] = HEX[owner[i] >> 4]; o[k++] = HEX[owner[i] & 15]; }
    o[k++] = '"'; o[k++] = ',';
    n = 0; do { num[n++] = (uint8_t)('0' + created_at % 10); created_at /= 10; } while (created_at);
    while (n) o[k++] = num[--n];
    o[k++] = ',';
    uint32_t kd = EL_PULSE_KIND; n = 0; do { num[n++] = (uint8_t)('0' + kd % 10); kd /= 10; } while (kd);
    while (n) o[k++] = num[--n];
    memcpy(o + k, ",[],\"", 5); k += 5;
    for (int i = 31; i >= 0; i--) { o[k++] = HEX[block[i] >> 4]; o[k++] = HEX[block[i] & 15]; }
    o[k++] = '"'; o[k++] = ']';
    return k;
}
