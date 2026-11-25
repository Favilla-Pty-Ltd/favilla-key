// libFuzzer (9u): otpauth::parse (a two-step QR read by the camera) and siteMatch.
#include "otpauth.h"
#include <cstdlib>
#include <cstdio>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  char* u = (char*)malloc(n + 1); memcpy(u, d, n); u[n] = 0;
  otpauth::Entry e; const int r = otpauth::parse(u, n, &e);
  if(r == otpauth::OK){
    if(strlen(e.site) < 1 || strlen(e.site) > otpauth::FIELD_MAX || strlen(e.acct) > otpauth::FIELD_MAX) abort();
    if(e.secretN < 1 || e.secretN > otpauth::SECRET_MAX || e.digits < 6 || e.digits > 8 || e.period < 1) abort();
    (void)otpauth::siteMatch(e.site, e.acct);
  }
  const size_t h = n / 2; char a[256], b[256]; snprintf(a, sizeof a, "%.*s", (int)(h < 255 ? h : 255), u); snprintf(b, sizeof b, "%s", u + h);
  (void)otpauth::siteMatch(a, b);
  free(u); return 0;
}
