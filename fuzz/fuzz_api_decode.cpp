// libFuzzer (9u): chan::apiDecode on any body, the decoder behind API 0x3A.
#include "chan_proto.h"
#include <cstdlib>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  uint8_t* b = (uint8_t*)malloc(n ? n : 1); memcpy(b, d, n);   // its own allocation, so ASan sees a read past the end
  chan::ApiReq a;
  if(chan::apiDecode(b, n, &a)){
    if(a.pathLen < 5 || memcmp(a.full, "/api/", 5) || a.pathLen > a.fullLen) abort();
    for(size_t i = 0; i < a.fullLen; i++) if((uint8_t)a.full[i] < 0x21 || (uint8_t)a.full[i] > 0x7E) abort();
    if(a.body + a.bodyLen != b + n) abort();
  }
  free(b); return 0;
}
