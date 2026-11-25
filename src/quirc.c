/* quirc -- QR-code recognition library
 * Copyright (C) 2010-2012 Daniel Beer <dlbeer@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include "quirc_internal.h"
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <stdio.h>

const char *quirc_version(void)
{
  return "1.0";
}

//static struct quirc _q;
struct quirc *quirc_new(void)
{
  struct quirc *q = ps_malloc(sizeof(*q));

  if (!q)
    return NULL;

  memset(q, 0, sizeof(*q));
  return q;
}

void quirc_destroy(struct quirc *q)
{
  if (!q)   /* 11bl (issue #47 item 11): checked before the first use */
    return;
  if (q->image)
    free(q->image);
  if (sizeof(*q->image) != sizeof(*q->pixels))
    if (q->pixels)
      free(q->pixels);
  free(q);
}

//static quirc_pixel_t img_buf[320*240];
int quirc_resize(struct quirc *q, int w, int h)
{
  if (q->image)
  {
    free(q->image);
  }
  // 16 Sep 2026: the image buffer IS the flood-fill working array (pixels alias
  // it), and quirc_end() walks it at random. In PSRAM that measured 280 ms per
  // 320x240 frame on the S3; the same walk from internal SRAM is several times
  // faster. Use internal RAM when it fits with a safety margin (the bunker TLS
  // handshake and the camera driver both need internal headroom), else PSRAM
  // as before. Caller crops the frame so the request is small enough to fit.
  #ifndef QUIRC_INTERNAL_MARGIN
  #define QUIRC_INTERNAL_MARGIN (40 * 1024)
  #endif
  size_t need = (size_t)w * (size_t)h;
  size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  uint8_t *new_image = NULL;
  const char *where = "psram";
  if (largest >= need + QUIRC_INTERNAL_MARGIN) {
    new_image = heap_caps_malloc(need, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (new_image) where = "INTERNAL";
  }
  if (!new_image) new_image = ps_malloc(need);
  printf("[QMEM] quirc image %ux%u (%u bytes) in %s (internal largest was %u)\n",
         (unsigned)w, (unsigned)h, (unsigned)need, where, (unsigned)largest);

  if (!new_image)
    return -1;

  if (sizeof(*q->image) != sizeof(*q->pixels))
  { //should gray, 1==1
    size_t new_size = w * h * sizeof(quirc_pixel_t);
    if (q->pixels)
      free(q->pixels);
    quirc_pixel_t *new_pixels = ps_malloc(new_size);
    if (!new_pixels)
    {
      free(new_image);
      return -1;
    }
    q->pixels = new_pixels;
  }
  q->image = new_image;
  q->w = w;
  q->h = h;
  return 0;
}

int quirc_count(const struct quirc *q)
{
  return q->num_grids;
}

static const char *const error_table[] = {
    [QUIRC_SUCCESS] = "Success",
    [QUIRC_ERROR_INVALID_GRID_SIZE] = "Invalid grid size",
    [QUIRC_ERROR_INVALID_VERSION] = "Invalid version",
    [QUIRC_ERROR_FORMAT_ECC] = "Format data ECC failure",
    [QUIRC_ERROR_DATA_ECC] = "ECC failure",
    [QUIRC_ERROR_UNKNOWN_DATA_TYPE] = "Unknown data type",
    [QUIRC_ERROR_DATA_OVERFLOW] = "Data overflow",
    [QUIRC_ERROR_DATA_UNDERFLOW] = "Data underflow"};

const char *quirc_strerror(quirc_decode_error_t err)
{
  if (err >= 0 && err < sizeof(error_table) / sizeof(error_table[0]))
    return error_table[err];

  return "Unknown error";
}
