// otpauth.h - read an otpauth://totp/ QR for the KEY's one-time codes (9i,
// 7 Nov 2026). Pure C++, host-tested (tests/otpauth_test.cpp). Only what the G0
// computes: TOTP, HMAC-SHA1, 6 to 8 digits, a period of 1 to 255 s. The secret
// is base32 (RFC 4648, any case, padding and spaces allowed), 1 to 64 bytes.
//   otpauth://totp/Issuer:account?secret=JBSW...&issuer=Issuer&digits=6&period=30
// site = the issuer parameter, else the label's part before ':', else the label;
// account = the label's part after ':' (or the whole label when there is no
// issuer to split off). %XX is decoded in the label and the parameters.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace otpauth {

enum Err { OK = 0, NOT_OTP, HOTP, ALGO, NO_SECRET, BAD_SECRET, DIGITS, PERIOD, TOO_LONG };
constexpr size_t FIELD_MAX = 100, SECRET_MAX = 64;
struct Entry { char site[FIELD_MAX + 1]; char acct[FIELD_MAX + 1]; uint8_t secret[SECRET_MAX]; size_t secretN; uint8_t digits, period; };

inline const char* errText(int e){
  switch(e){
    case NOT_OTP: return "Not a one-time code QR";
    case HOTP: return "Counter codes (HOTP) are not supported";
    case ALGO: return "Only SHA1 codes are supported";
    case NO_SECRET: return "The QR has no secret";
    case BAD_SECRET: return "The secret is not valid base32";
    case DIGITS: return "Codes must have 6 to 8 digits";
    case PERIOD: return "The code period must be 1 to 255 s";
    case TOO_LONG: return "A name in the QR is too long";
    default: return "";
  }
}
inline int hexv(char c){ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
// Decode %XX from s[0..n) into out (cap incl. NUL). False if it does not fit or a byte is not printable.
inline bool pct(const char* s, size_t n, char* out, size_t cap){
  size_t o = 0;
  for(size_t i = 0; i < n; i++){
    char c = s[i];
    if(c == '%' && i + 2 < n + 0 && hexv(s[i + 1]) >= 0 && hexv(s[i + 2]) >= 0){ c = (char)(hexv(s[i + 1]) * 16 + hexv(s[i + 2])); i += 2; }
    if((uint8_t)c < 0x20 || (uint8_t)c > 0x7E) return false;
    if(o + 1 >= cap) return false;
    out[o++] = c;
  }
  out[o] = 0; return true;
}
inline void trim(char* s){ size_t n = strlen(s), a = 0; while(a < n && s[a] == ' ') a++; while(n > a && s[n - 1] == ' ') n--; memmove(s, s + a, n - a); s[n - a] = 0; }
inline bool ieq(const char* a, size_t an, const char* b){ size_t bn = strlen(b); if(an != bn) return false; for(size_t i = 0; i < an; i++){ char x = a[i], y = b[i]; if(x >= 'A' && x <= 'Z') x += 32; if(y >= 'A' && y <= 'Z') y += 32; if(x != y) return false; } return true; }
inline int b32(const char* s, size_t n, uint8_t* out, size_t cap, size_t* outN){
  uint32_t acc = 0; int bits = 0; size_t o = 0; bool any = false;
  for(size_t i = 0; i < n; i++){
    char c = s[i]; int v;
    if(c == '=' || c == ' ') continue;
    if(c >= 'a' && c <= 'z') c -= 32;
    if(c >= 'A' && c <= 'Z') v = c - 'A'; else if(c >= '2' && c <= '7') v = c - '2' + 26; else return BAD_SECRET;
    acc = (acc << 5) | (uint32_t)v; bits += 5; any = true;
    if(bits >= 8){ bits -= 8; if(o >= cap) return BAD_SECRET; out[o++] = (uint8_t)(acc >> bits); }
  }
  acc = 0;
  if(!any || o == 0) return NO_SECRET;
  *outN = o; return OK;
}
inline int parse(const char* u, size_t n, Entry* e){
  memset(e, 0, sizeof *e); e->digits = 6; e->period = 30;
  static const char P[] = "otpauth://";
  if(n < sizeof(P) - 1 || !ieq(u, sizeof(P) - 1, P)) return NOT_OTP;
  size_t i = sizeof(P) - 1;
  if(n >= i + 5 && ieq(u + i, 5, "totp/")) i += 5;
  else if(n >= i + 5 && ieq(u + i, 5, "hotp/")) return HOTP;
  else return NOT_OTP;
  size_t q = i; while(q < n && u[q] != '?') q++;
  char label[2 * FIELD_MAX + 2];
  if(!pct(u + i, q - i, label, sizeof label)) return TOO_LONG;
  char issuer[FIELD_MAX + 1] = {0}; bool haveSecret = false; int r = OK;
  for(size_t p = q + 1; p < n && r == OK; ){
    size_t e2 = p; while(e2 < n && u[e2] != '&') e2++;
    size_t eq = p; while(eq < e2 && u[eq] != '=') eq++;
    const char* k = u + p; size_t kn = eq - p; const char* v = eq < e2 ? u + eq + 1 : u + e2; size_t vn = eq < e2 ? e2 - eq - 1 : 0;
    char val[FIELD_MAX * 2 + 1];
    if(!pct(v, vn, val, sizeof val)) r = TOO_LONG;
    else if(ieq(k, kn, "secret")){ r = b32(val, strlen(val), e->secret, SECRET_MAX, &e->secretN); haveSecret = r == OK; }
    else if(ieq(k, kn, "issuer")){ if(strlen(val) > FIELD_MAX) r = TOO_LONG; else strcpy(issuer, val); }
    else if(ieq(k, kn, "algorithm")){ if(!ieq(val, strlen(val), "SHA1")) r = ALGO; }
    else if(ieq(k, kn, "digits")){ int d = 0; for(const char* c = val; *c; c++){ if(*c < '0' || *c > '9' || d > 99){ d = 0; break; } d = d * 10 + (*c - '0'); } if(d < 6 || d > 8) r = DIGITS; else e->digits = (uint8_t)d; }
    else if(ieq(k, kn, "period")){ int d = 0; for(const char* c = val; *c; c++){ if(*c < '0' || *c > '9' || d > 999){ d = 0; break; } d = d * 10 + (*c - '0'); } if(d < 1 || d > 255) r = PERIOD; else e->period = (uint8_t)d; }
    memset(val, 0, sizeof val);
    p = e2 + 1;
  }
  if(r != OK){ memset(e, 0, sizeof *e); return r; }
  if(!haveSecret){ memset(e, 0, sizeof *e); return NO_SECRET; }
  char* colon = strchr(label, ':');
  char site[2 * FIELD_MAX + 2], acct[2 * FIELD_MAX + 2];
  if(colon){ *colon = 0; strcpy(site, label); strcpy(acct, colon + 1); }
  else { site[0] = 0; strcpy(acct, label); }
  trim(site); trim(acct); trim(issuer);
  if(issuer[0]) strcpy(site, issuer);
  if(!site[0]){ strcpy(site, acct); acct[0] = 0; }
  if(!site[0]){ memset(e, 0, sizeof *e); return TOO_LONG; }
  if(strlen(site) > FIELD_MAX || strlen(acct) > FIELD_MAX){ memset(e, 0, sizeof *e); return TOO_LONG; }
  strcpy(e->site, site); strcpy(e->acct, acct);
  return OK;
}
// Does a saved code's site (an issuer such as "GitHub") belong to the site a
// phone asked for (a domain such as "github.com" or "www.github.com", or an app
// name)? Case and spaces ignored; the domain's first label after "www." counts.
inline bool siteMatch(const char* saved, const char* asked){
  char a[FIELD_MAX + 1], b[FIELD_MAX + 1]; size_t an = 0, bn = 0;
  for(const char* c = saved; *c && an < FIELD_MAX; c++) if(*c != ' '){ char x = *c; if(x >= 'A' && x <= 'Z') x += 32; a[an++] = x; }
  for(const char* c = asked; *c && bn < FIELD_MAX; c++) if(*c != ' '){ char x = *c; if(x >= 'A' && x <= 'Z') x += 32; b[bn++] = x; }
  a[an] = 0; b[bn] = 0;
  if(!an || !bn) return false;
  if(!strcmp(a, b)) return true;
  const char* d = b; if(!strncmp(d, "www.", 4)) d += 4;
  const char* dot = strchr(d, '.');
  if(dot && (size_t)(dot - d) == an && !strncmp(d, a, an)) return true;   // "github" for github.com
  const char* sd = strchr(a, '.'); if(sd && !strcmp(a, d)) return true;  // the saved site is the domain itself
  return false;
}

}  // namespace otpauth
