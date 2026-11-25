/* libFuzzer (9u): quirc_decode, the QR decoder behind every scan. A camera
 * frame is attacker-controlled (any QR held up to the KEY), and after the grid
 * is sampled everything turns on these cells: format and version bits, Reed-
 * Solomon, the data segments. Input: [size code][cell bitmap]. */
#include "quirc.h"
#include <string.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  if (n < 1) return 0;
  struct quirc_code* c = (struct quirc_code*)calloc(1, sizeof *c);
  struct quirc_data* q = (struct quirc_data*)calloc(1, sizeof *q);
  c->size = 17 + 4 * (1 + d[0] % 40);   /* versions 1..40 */
  size_t m = n - 1; if (m > sizeof c->cell_bitmap) m = sizeof c->cell_bitmap;
  memcpy(c->cell_bitmap, d + 1, m);
  (void)quirc_decode(c, q);
  if (q->payload_len < 0 || q->payload_len > (int)sizeof q->payload) abort();
  free(c); free(q); return 0;
}
