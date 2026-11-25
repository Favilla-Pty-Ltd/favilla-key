// libFuzzer (9u): the login QR parser (login_qr.h).
#include <stdint.h>
#include "login_qr.h"
#include <cstdlib>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  char* in = (char*)malloc(n + 1); memcpy(in, d, n); in[n] = 0;
  const size_t cap = loginqr::FIELD_MAX + 1;   // what the KEY passes: ASan sees a write past it
  char* site = (char*)calloc(cap, 1); char* user = (char*)calloc(cap, 1);
  if(loginqr::parse(in, n, site, user) >= 0 && (strnlen(site, cap) == cap || strnlen(user, cap) == cap)) abort();
  free(site); free(user); free(in); return 0;
}
