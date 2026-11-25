// recovery_qr.h - a site's recovery codes as a QR for the KEY to scan (11aa,
// 11 Nov 2026). Made by the PWA, the extension popup or the iPhone app from the
// codes the site shows when two-step is turned on; scanned from the password
// entry on the KEY (PASSWORD > UP > RECOVERY CODES > ADD BY QR) and sealed.
//
//   favilla:recovery?v=1&s=<site>&u=<username>&c=<code>,<code>,...
//
// Percent-encoded values, as the login QR (login_qr.h: same decoder, same
// rules). v must be 1; s required; u optional; c required: 1 to 16 codes of 1
// to 24 printable characters each, comma separated, spaces removed. A repeated
// key is refused. No dependencies: host-tested beside login_qr.
#pragma once
#include "login_qr.h"

namespace recoveryqr {

constexpr int CODES_MAX = 16;
constexpr size_t CODE_LEN = 24;
enum Result : int { NOT_RECOVERY = 0, OK = 1, E_VERSION = -1, E_NO_SITE = -2, E_NO_CODES = -3, E_BAD_TEXT = -4, E_TOO_LONG = -5, E_REPEAT = -6, E_TOO_MANY = -7 };
inline const char* errText(int r){
  switch(r){
    case E_VERSION:  return "A newer recovery QR. Update the KEY.";
    case E_NO_SITE:  return "The QR has no site";
    case E_NO_CODES: return "The QR has no codes";
    case E_BAD_TEXT: return "Only plain US keyboard text";
    case E_TOO_LONG: return "A code or name is too long";
    case E_REPEAT:   return "The QR is malformed";
    case E_TOO_MANY: return "More than 16 codes";
    default:         return "Not a recovery QR";
  }
}
inline bool isRecovery(const char* in, size_t n){
  static const char P[] = "favilla:recovery?";
  const size_t pn = sizeof(P) - 1;
  return n >= pn && loginqr::ieq(in, pn, P);
}
struct Out { char site[loginqr::FIELD_MAX + 1]; char user[loginqr::FIELD_MAX + 1]; int n; char code[CODES_MAX][CODE_LEN + 1]; };
inline int parse(const char* in, size_t n, Out* o){
  memset(o, 0, sizeof *o);
  if(!isRecovery(in, n)) return NOT_RECOVERY;
  const char* q = in + 17; const char* end = in + n;
  bool gotV = false, gotS = false, gotU = false, gotC = false; int r = OK;
  while(q < end && r == OK){
    const char* amp = q; while(amp < end && *amp != '&') amp++;
    const char* eq = q; while(eq < amp && *eq != '=') eq++;
    size_t kn = (size_t)(eq - q);
    const char* val = eq < amp ? eq + 1 : amp; size_t vn = (size_t)(amp - val);
    if(kn == 0 && vn == 0){ q = amp + 1; continue; }
    if(loginqr::ieq(q, kn, "v")){ if(gotV){ r = E_REPEAT; break; } gotV = true; if(!(vn == 1 && val[0] == '1')){ r = E_VERSION; break; } }
    else if(loginqr::ieq(q, kn, "s")){ if(gotS){ r = E_REPEAT; break; } gotS = true; int d = loginqr::decode(val, vn, o->site); if(d < 0){ r = d; break; } }
    else if(loginqr::ieq(q, kn, "u")){ if(gotU){ r = E_REPEAT; break; } gotU = true; int d = loginqr::decode(val, vn, o->user); if(d < 0){ r = d; break; } }
    else if(loginqr::ieq(q, kn, "c")){
      if(gotC){ r = E_REPEAT; break; } gotC = true;
      // the whole list decoded first (commas are literal in it), then split
      char all[CODES_MAX * (CODE_LEN + 1) + 1]; size_t a = 0;
      for(size_t i = 0; i < vn; i++){
        char c = val[i];
        if(c == '%'){ if(i + 2 >= vn){ r = E_BAD_TEXT; break; } int h = loginqr::hexv(val[i + 1]), l = loginqr::hexv(val[i + 2]); if(h < 0 || l < 0){ r = E_BAD_TEXT; break; } c = (char)(h * 16 + l); i += 2; }
        if((unsigned char)c < 0x20 || (unsigned char)c > 0x7E){ r = E_BAD_TEXT; break; }
        if(c == ' ') continue;
        if(a + 1 >= sizeof all){ r = E_TOO_LONG; break; }
        all[a++] = c;
      }
      if(r != OK) break;
      all[a] = 0;
      size_t p = 0;
      while(p <= a){
        size_t e = p; while(e < a && all[e] != ',') e++;
        const size_t l = e - p;
        if(l){
          if(o->n >= CODES_MAX){ r = E_TOO_MANY; break; }
          if(l > CODE_LEN){ r = E_TOO_LONG; break; }
          memcpy(o->code[o->n], all + p, l); o->code[o->n][l] = 0; o->n++;
        }
        p = e + 1;
      }
      memset(all, 0, sizeof all);
    }
    q = amp + 1;
  }
  if(r == OK && !gotV) r = E_VERSION;
  if(r == OK && !o->site[0]) r = E_NO_SITE;
  if(r == OK && o->n == 0) r = E_NO_CODES;
  if(r != OK) memset(o, 0, sizeof *o);
  return r;
}

}  // namespace recoveryqr
