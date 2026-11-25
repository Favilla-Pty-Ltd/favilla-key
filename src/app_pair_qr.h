// app_pair_qr.h - the Favilla app's pairing QR, scanned by the KEY (11ah,
// 11 Nov 2026, issue #22). The app draws it while PAIR A PHONE is open; the
// KEY's camera reads the app's channel key and nonce, and a REVEAL carrying
// the same values is accepted without the code screen. The wire protocol is
// unchanged (COMMIT / PAIR_KEY / REVEAL / PAIR_DONE, chan_key.h).
//
//   favilla:pair?v=1&p=<extPub 65 bytes uncompressed P-256, 130 hex>&n=<nonce 16 bytes, 32 hex>
//
// v must be 1; p and n required, hex either case; a repeated key is refused;
// unknown keys are ignored. No dependencies: host-tested (tests/app_pair_qr).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace apppairqr {

enum Result : int { NOT_PAIR = 0, OK = 1, E_VERSION = -1, E_NO_KEY = -2, E_NO_NONCE = -3, E_BAD = -4, E_REPEAT = -5 };

inline bool isPair(const char* in, size_t n){
  static const char P[] = "favilla:pair?";
  const size_t pn = sizeof(P) - 1;
  if(n < pn) return false;
  for(size_t i = 0; i < pn; i++){ char c = in[i]; if(c >= 'A' && c <= 'Z') c = (char)(c + 32); if(c != P[i]) return false; }
  return true;
}
inline int hexv(char c){
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
inline bool unhex(const char* s, size_t n, uint8_t* out, size_t want){
  if(n != want * 2) return false;
  for(size_t i = 0; i < want; i++){ int a = hexv(s[2 * i]), b = hexv(s[2 * i + 1]); if(a < 0 || b < 0) return false; out[i] = (uint8_t)(a * 16 + b); }
  return true;
}
// extPub: 65 bytes, 0x04 first. nonce: 16 bytes.
inline int parse(const char* in, size_t n, uint8_t extPub[65], uint8_t nonce[16]){
  if(!isPair(in, n)) return NOT_PAIR;
  memset(extPub, 0, 65); memset(nonce, 0, 16);
  size_t i = sizeof("favilla:pair?") - 1;
  bool v = false, p = false, nn = false; int ver = -1;
  while(i < n){
    size_t e = i; while(e < n && in[e] != '&') e++;
    size_t eq = i; while(eq < e && in[eq] != '=') eq++;
    if(eq == e || eq == i) return E_BAD;
    const char* key = in + i; const size_t kl = eq - i; const char* val = in + eq + 1; const size_t vl = e - eq - 1;
    if(kl == 1 && key[0] == 'v'){ if(v) return E_REPEAT; v = true; ver = (vl == 1 && val[0] >= '0' && val[0] <= '9') ? val[0] - '0' : -1; }
    else if(kl == 1 && key[0] == 'p'){ if(p) return E_REPEAT; p = true; if(!unhex(val, vl, extPub, 65) || extPub[0] != 0x04) return E_BAD; }
    else if(kl == 1 && key[0] == 'n'){ if(nn) return E_REPEAT; nn = true; if(!unhex(val, vl, nonce, 16)) return E_BAD; }
    i = e + 1;
  }
  if(ver != 1) return E_VERSION;
  if(!p) return E_NO_KEY;
  if(!nn) return E_NO_NONCE;
  return OK;
}
inline const char* errText(int r){
  switch(r){
    case E_VERSION:  return "A newer pairing QR. Update the KEY.";
    case E_NO_KEY:   return "The QR has no key";
    case E_NO_NONCE: return "The QR has no nonce";
    case E_BAD:      return "The QR is malformed";
    case E_REPEAT:   return "The QR is malformed";
    default:         return "Not a pairing QR";
  }
}

}  // namespace apppairqr
