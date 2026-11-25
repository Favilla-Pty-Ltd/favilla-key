// libFuzzer (9u): the UR decoder (animated QR: ur:crypto-psbt and ur:bytes).
// The input is lines, one QR's text each, fed through ur_feed like the scan
// loop; a finished message is unwrapped and parsed as a PSBT.
#include "ur_psbt.h"
#include <cstdlib>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  static ur_decoder_t dec; ur_decoder_reset(&dec);
  size_t o = 0; int parts = 0;
  while (o < n && parts < 64) {
    size_t e = o; while (e < n && d[e] != '\n') e++;
    char* line = (char*)malloc(e - o + 1); memcpy(line, d + o, e - o); line[e - o] = 0;
    const int r = ur_feed(&dec, line); free(line); parts++;
    if (r == 1) {
      static uint8_t msg[UR_MAX_MESSAGE + 64], raw[UR_MAX_MESSAGE];
      const int mn = ur_decoder_result(&dec, msg, sizeof msg);
      if (mn > (int)sizeof msg) abort();
      if (mn > 0) {
        const int pn = ur_extract_psbt(msg, (size_t)mn, raw, sizeof raw);
        if (pn > 0) { static psbt_t p; memset(&p, 0, sizeof p); (void)psbt_parse(raw, (size_t)pn, &p); }
        (void)ur_extract_bytes(msg, (size_t)mn, raw, sizeof raw);
      }
      ur_decoder_reset(&dec);
    }
    o = e + 1;
  }
  return 0;
}
