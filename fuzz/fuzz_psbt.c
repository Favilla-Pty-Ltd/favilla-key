/* libFuzzer (9u): psbt_parse, the ESP32's read of a PSBT for the review
 * screens (the G0 signs; what the ESP32 shows comes from this parser). */
#include "psbt.h"
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  uint8_t* b = (uint8_t*)malloc(n ? n : 1); memcpy(b, d, n);
  static psbt_t p; memset(&p, 0, sizeof p);
  (void)psbt_parse(b, n, &p);
  free(b); return 0;
}
