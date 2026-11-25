// login_qr.h - the Favilla login QR (Vault phase 5, P5-1 ruled 4 Nov 2026).
//
//   favilla:login?v=1&s=<site>&u=<username>
//
// Percent-encoded values. v must be 1. s (site or app) is required, u
// (username) is optional. Keys and the scheme are matched without case, so a
// QR app that upper-cases text (alphanumeric mode) still reads. Unknown keys
// are ignored, so a later field does not break an older KEY, except p (or
// pass / password): a login QR never carries a password, and one that tries
// is refused. A repeated key is refused. Decoded values must be printable US
// keyboard text (0x20..0x7E), the site 1..100 characters, the username
// 0..100. '+' is a literal plus (usernames like a+b@x.com), never a space.
//
// No dependencies: host-tested and fuzzed (e3b/host/loginqr_host.cpp).
#pragma once
#include <stddef.h>
#include <string.h>
#include <stdio.h>

namespace loginqr {

constexpr size_t FIELD_MAX = 100;

enum Result : int {
  NOT_LOGIN = 0,      // not a login QR (treat it as plain text)
  OK = 1,
  E_VERSION = -1,     // v missing or not 1
  E_NO_SITE = -2,     // s missing or empty
  E_PASSWORD = -3,    // carries a password field
  E_BAD_TEXT = -4,    // bad percent escape, or a character the KEY cannot type
  E_TOO_LONG = -5,    // a field over 100 characters
  E_REPEAT = -6,      // a key given twice
};

inline const char* errText(int r){
  switch(r){
    case E_VERSION:  return "A newer login QR. Update the KEY.";
    case E_NO_SITE:  return "The login QR has no site";
    case E_PASSWORD: return "A login QR must not hold a password";
    case E_BAD_TEXT: return "Only plain US keyboard text";
    case E_TOO_LONG: return "Site or username over 100";
    case E_REPEAT:   return "The login QR is malformed";
    default:         return "Not a login QR";
  }
}

inline char lower(char c){ return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
inline bool ieq(const char* a, size_t an, const char* b){ size_t bn = strlen(b); if(an != bn) return false; for(size_t i = 0; i < an; i++) if(lower(a[i]) != b[i]) return false; return true; }
inline int hexv(char c){ if(c >= '0' && c <= '9') return c - '0'; c = lower(c); if(c >= 'a' && c <= 'f') return c - 'a' + 10; return -1; }

// True when the text starts with the login scheme (any case).
inline bool isLogin(const char* in, size_t n){
  static const char P[] = "favilla:login?";
  const size_t pn = sizeof(P) - 1;
  return n >= pn && ieq(in, pn, P);
}

// Decode one value into out (cap >= FIELD_MAX + 1). Returns its length, or a negative Result.
inline int decode(const char* v, size_t n, char* out){
  size_t o = 0;
  for(size_t i = 0; i < n; i++){
    char c = v[i];
    if(c == '%'){
      if(i + 2 >= n) return E_BAD_TEXT;   // needs two hex digits after it
      int h = hexv(v[i + 1]), l = hexv(v[i + 2]);
      if(h < 0 || l < 0) return E_BAD_TEXT;
      c = (char)(h * 16 + l); i += 2;
    }
    if((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) return E_BAD_TEXT;
    if(o >= FIELD_MAX) return E_TOO_LONG;
    out[o++] = c;
  }
  out[o] = 0;
  return (int)o;
}

// Parse in[0..n). site and user each need FIELD_MAX + 1 bytes. On anything but
// OK both are left empty.
inline int parse(const char* in, size_t n, char* site, char* user){
  site[0] = 0; user[0] = 0;
  if(!isLogin(in, n)) return NOT_LOGIN;
  const char* q = in + 14; const char* end = in + n;
  bool gotV = false, gotS = false, gotU = false; int r = OK;
  while(q < end){
    const char* amp = q; while(amp < end && *amp != '&') amp++;
    const char* eq = q; while(eq < amp && *eq != '=') eq++;
    size_t kn = (size_t)(eq - q);
    const char* val = eq < amp ? eq + 1 : amp; size_t vn = (size_t)(amp - val);
    if(kn == 0 && vn == 0){ q = amp + 1; continue; }   // "&&" or a trailing '&'
    if(ieq(q, kn, "p") || ieq(q, kn, "pass") || ieq(q, kn, "password") || ieq(q, kn, "pw")){ r = E_PASSWORD; break; }
    if(ieq(q, kn, "v")){
      if(gotV){ r = E_REPEAT; break; } gotV = true;
      if(!(vn == 1 && val[0] == '1')){ r = E_VERSION; break; }
    } else if(ieq(q, kn, "s")){
      if(gotS){ r = E_REPEAT; break; } gotS = true;
      int d = decode(val, vn, site); if(d < 0){ r = d; break; }
    } else if(ieq(q, kn, "u")){
      if(gotU){ r = E_REPEAT; break; } gotU = true;
      int d = decode(val, vn, user); if(d < 0){ r = d; break; }
    }
    // other keys: ignored (a later version's field)
    q = amp + 1;
  }
  if(r == OK && !gotV) r = E_VERSION;
  if(r == OK && !site[0]) r = E_NO_SITE;
  if(r != OK){ memset(site, 0, FIELD_MAX + 1); memset(user, 0, FIELD_MAX + 1); }
  return r;
}

// ---- Sign in by QR (stage 1, 4 Nov 2026) ------------------------------------
// How well a saved entry's site name fits the site a login QR names.
//   3 exact      "github.com" and "GitHub.com/", "https://www.github.com"
//   2 domain     "github.com" and "gist.github.com" (one inside the other, on a dot)
//   1 close      "GitHub" or "github.io" and "github.com" (same main name): listed, never picked alone
//   0 none       "github-login.com" and "github.com"
// Names are compared without case, scheme, "www.", port or path.
constexpr size_t LQ_NAME_MAX = 128;
inline void norm(const char* in, char* out, size_t cap){
  size_t n = 0; const char* p = in;
  while(*p == ' ') p++;
  if(!strncmp(p, "http://", 7) || !strncmp(p, "HTTP://", 7)) p += 7; else if(!strncmp(p, "https://", 8) || !strncmp(p, "HTTPS://", 8)) p += 8;
  if((p[0] == 'w' || p[0] == 'W') && (p[1] == 'w' || p[1] == 'W') && (p[2] == 'w' || p[2] == 'W') && p[3] == '.') p += 4;
  for(; *p && *p != '/' && *p != '?' && *p != '#' && n + 1 < cap; p++) out[n++] = lower(*p);
  while(n && (out[n - 1] == ' ' || out[n - 1] == '.')) n--;
  out[n] = 0;
  char* c = strchr(out, ':'); if(c && !strchr(out, ' ')){ bool port = c[1] != 0; for(char* d = c + 1; *d; d++) if(*d < '0' || *d > '9') port = false; if(port) *c = 0; }
}
inline bool endsDot(const char* a, const char* b){   // a ends with "." + b
  size_t an = strlen(a), bn = strlen(b);
  return an > bn + 1 && a[an - bn - 1] == '.' && !strcmp(a + an - bn, b);
}
// The main name of a host: "github" for gist.github.com, "bbc" for bbc.co.uk.
// A name with no dot is itself with spaces and punctuation taken out ("My Bank" -> "mybank").
inline void mainName(const char* h, char* out, size_t cap){
  out[0] = 0;
  if(!strchr(h, '.')){ size_t n = 0; for(const char* p = h; *p && n + 1 < cap; p++) if((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')) out[n++] = *p; out[n] = 0; return; }
  const char* lab[16]; size_t len[16]; int k = 0; const char* s = h;
  for(const char* p = h; ; p++){ if(*p == '.' || !*p){ if(k < 16){ lab[k] = s; len[k] = (size_t)(p - s); k++; } if(!*p) break; s = p + 1; } }
  if(k < 2) return;
  int m = k - 2;
  if(k >= 3 && len[k - 1] == 2 && len[k - 2] <= 3) m = k - 3;   // co.uk, com.au, org.nz
  size_t n = len[m] < cap - 1 ? len[m] : cap - 1; memcpy(out, lab[m], n); out[n] = 0;
}
// The address to save on a login: the registrable name ("cloudflare.com" for
// dash.cloudflare.com, "bbc.co.uk" for www.bbc.co.uk). An address the main-name
// rule cannot split (an IP, "localhost") is kept whole.
inline void savedName(const char* host, char* out, size_t cap){
  char h[LQ_NAME_MAX]; norm(host, h, sizeof h); out[0] = 0;
  const char* lab[16]; int k = 0; lab[k++] = h;
  for(const char* p = h; *p && k < 16; p++) if(*p == '.') lab[k++] = p + 1;
  bool ip = true; for(const char* p = h; *p; p++) if(!((*p >= '0' && *p <= '9') || *p == '.')) ip = false;
  int m = k - 2;
  if(k >= 3 && strlen(lab[k - 1]) == 2 && (size_t)(lab[k - 1] - lab[k - 2] - 1) <= 3) m = k - 3;
  const char* r = (ip || k < 2 || m < 0) ? h : lab[m];
  snprintf(out, cap, "%s", r);
}
inline int siteMatch(const char* saved, const char* want){
  char a[LQ_NAME_MAX], b[LQ_NAME_MAX];
  norm(saved, a, sizeof a); norm(want, b, sizeof b);
  if(!a[0] || !b[0]) return 0;
  if(!strcmp(a, b)) return 3;
  if(strchr(a, '.') && strchr(b, '.') && (endsDot(a, b) || endsDot(b, a))){
    char ma[LQ_NAME_MAX], mb[LQ_NAME_MAX]; mainName(a, ma, sizeof ma); mainName(b, mb, sizeof mb);
    if(ma[0] && !strcmp(ma, mb)) return 2;                        // never "co.uk" inside "bbc.co.uk"
  }
  char ma[LQ_NAME_MAX], mb[LQ_NAME_MAX]; mainName(a, ma, sizeof ma); mainName(b, mb, sizeof mb);
  if(strlen(ma) >= 3 && !strcmp(ma, mb)) return 1;
  // 11av (12 Nov 2026): one main name beginning the other, five or more
  // characters in common, is a close name too: "protonmail.com" for
  // account.proton.me, "googleusercontent.com" for google.com. A close name
  // is only ever LISTED for the user to pick (never typed by itself), so a
  // lookalike gains nothing from it; "github" and "gitlab" share three and
  // stay apart.
  { size_t la = strlen(ma), lb = strlen(mb), c = 0;
    while(c < la && c < lb && ma[c] == mb[c]) c++;
    if(c >= 5 && (c == la || c == lb)) return 1; }
  return 0;
}

}  // namespace loginqr
