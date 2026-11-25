/* quirc - QR-code recognition library
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

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "openmv/fmath.h"
#include "openmv/collections.h"
#include "quirc_internal.h"

/* QUIRC_ROBUST_CELL: master switch for the V22.3 rounded-QR read path. Must be
 * defined HERE, before threshold()/read_cell() both reference it. 1 = grayscale
 * per-module local threshold (rounded-corner fix); 0 = stock quirc behaviour. */
#ifndef QUIRC_ROBUST_CELL
#define QUIRC_ROBUST_CELL 1
#endif

/************************************************************************
 * Linear algebra routines
 */

static int line_intersect(const struct quirc_point *p0,
                          const struct quirc_point *p1,
                          const struct quirc_point *q0,
                          const struct quirc_point *q1,
                          struct quirc_point *r)
{
  /* (a, b) is perpendicular to line p */
  int a = -(p1->y - p0->y);
  int b = p1->x - p0->x;

  /* (c, d) is perpendicular to line q */
  int c = -(q1->y - q0->y);
  int d = q1->x - q0->x;

  /* e and f are dot products of the respective vectors with p and q */
  int e = a * p1->x + b * p1->y;
  int f = c * q1->x + d * q1->y;

  /* Now we need to solve:
     *     [a b] [rx]   [e]
     *     [c d] [ry] = [f]
     *
     * We do this by inverting the matrix and applying it to (e, f):
     *       [ d -b] [e]   [rx]
     * 1/det [-c  a] [f] = [ry]
     */
  int det = (a * d) - (b * c);

  if (!det)
    return 0;

  r->x = (d * e - b * f) / det;
  r->y = (-c * e + a * f) / det;

  return 1;
}

static void perspective_setup(float *c,
                              const struct quirc_point *rect,
                              float w, float h)
{
  float x0 = rect[0].x;
  float y0 = rect[0].y;
  float x1 = rect[1].x;
  float y1 = rect[1].y;
  float x2 = rect[2].x;
  float y2 = rect[2].y;
  float x3 = rect[3].x;
  float y3 = rect[3].y;

  float wden = w * (x2 * y3 - x3 * y2 + (x3 - x2) * y1 + x1 * (y2 - y3));
  float hden = h * (x2 * y3 + x1 * (y2 - y3) - x3 * y2 + (x3 - x2) * y1);

  c[0] = (x1 * (x2 * y3 - x3 * y2) + x0 * (-x2 * y3 + x3 * y2 + (x2 - x3) * y1) +
          x1 * (x3 - x2) * y0) /
         wden;
  c[1] = -(x0 * (x2 * y3 + x1 * (y2 - y3) - x2 * y1) - x1 * x3 * y2 + x2 * x3 * y1 + (x1 * x3 - x2 * x3) * y0) / hden;
  c[2] = x0;
  c[3] = (y0 * (x1 * (y3 - y2) - x2 * y3 + x3 * y2) + y1 * (x2 * y3 - x3 * y2) +
          x0 * y1 * (y2 - y3)) /
         wden;
  c[4] = (x0 * (y1 * y3 - y2 * y3) + x1 * y2 * y3 - x2 * y1 * y3 +
          y0 * (x3 * y2 - x1 * y2 + (x2 - x3) * y1)) /
         hden;
  c[5] = y0;
  c[6] = (x1 * (y3 - y2) + x0 * (y2 - y3) + (x2 - x3) * y1 + (x3 - x2) * y0) / wden;
  c[7] = (-x2 * y3 + x1 * y3 + x3 * y2 + x0 * (y1 - y2) - x3 * y1 + (x2 - x1) * y0) /
         hden;
}

static void perspective_map(const float *c,
                            float u, float v, struct quirc_point *ret)
{
  float den = c[6] * u + c[7] * v + 1.0;
  float x = (c[0] * u + c[1] * v + c[2]) / den;
  float y = (c[3] * u + c[4] * v + c[5]) / den;

  /* 11bl (issue #47 item 7): degenerate geometry gives NaN or a value no
   * int holds, and converting that is undefined behaviour (and products of
   * huge coordinates overflow int later, in find_alignment_pattern). Map
   * anything outside +-8192, far beyond any camera frame, to a point off the
   * image: every pixel read is bounds-checked, so the candidate simply fails
   * to decode. */
  if (!(x > -8192.0f && x < 8192.0f)) x = -1.0f;
  if (!(y > -8192.0f && y < 8192.0f)) y = -1.0f;

  ret->x = fast_roundf(x);
  ret->y = fast_roundf(y);
}

static void perspective_unmap(const float *c,
                              const struct quirc_point *in,
                              float *u, float *v)
{
  float x = in->x;
  float y = in->y;
  float den = -c[0] * c[7] * y + c[1] * c[6] * y + (c[3] * c[7] - c[4] * c[6]) * x +
              c[0] * c[4] - c[1] * c[3];

  *u = -(c[1] * (y - c[5]) - c[2] * c[7] * y + (c[5] * c[7] - c[4]) * x + c[2] * c[4]) /
       den;
  *v = (c[0] * (y - c[5]) - c[2] * c[6] * y + (c[5] * c[6] - c[3]) * x + c[2] * c[3]) /
       den;
}

/************************************************************************
 * Span-based floodfill routine
 */

typedef void (*span_func_t)(void *user_data, int y, int left, int right);

typedef struct xylf
{
  int16_t x, y, l, r;
} __attribute__((aligned(8)))
xylf_t;

//计算该区域的面积，from是像素颜色，to是区块标号，user_data是申请的区块结构体，func是计算面积的函数
static void flood_fill_seed(struct quirc *q, int x, int y, int from, int to,
                            span_func_t func, void *user_data,
                            int depth)
{
  (void)depth; // unused

  lifo_t lifo;
  size_t lifo_len;
  lifo_alloc_all(&lifo, &lifo_len, sizeof(xylf_t));
  //late in first out. 申请xylf_t的lifo，一次申请完，长度存储在lifo_len中

  for (;;)
  {
    int left = x;
    int right = x;
    int i;
    quirc_pixel_t *row = q->pixels + y * q->w; //行起始地址
                                               //查找左右边界
    while (left > 0 && row[left - 1] == from)
      left--;

    while (right < q->w - 1 && row[right + 1] == from)
      right++;

    /* Fill the extent 对应像素标记为区块号*/
    for (i = left; i <= right; i++)
      row[i] = to;
    //累加区域内的像素点数作为面积
    if (func)
      func(user_data, y, left, right);

    for (;;)
    {
      if (lifo_size(&lifo) < lifo_len)
      { //栈中的数量
        /* Seed new flood-fills */
        if (y > 0)
        { //查找上一行有没有在同一区域的点
          row = q->pixels + (y - 1) * q->w;

          bool recurse = false;
          for (i = left; i <= right; i++)
            if (row[i] == from)
            { //相同区域，则入栈原来的区块
              xylf_t context;
              context.x = x;
              context.y = y;
              context.l = left;
              context.r = right;
              lifo_enqueue(&lifo, &context);
              //mp_printf(&mp_plat_print, "#x=%x,y=%d;x1=%d,y1=%d\n",x,y,i,y-1);
              x = i;
              y = y - 1;
              recurse = true;
              break;
            }
          if (recurse)
            break;
        }
        //查找下一行有没有在同一区域的点
        if (y < q->h - 1)
        {
          row = q->pixels + (y + 1) * q->w;

          bool recurse = false;
          for (i = left; i <= right; i++)
            if (row[i] == from)
            {
              xylf_t context;
              context.x = x;
              context.y = y;
              context.l = left;
              context.r = right;
              lifo_enqueue(&lifo, &context);
              //mp_printf(&mp_plat_print, "#x=%x,y=%d;x1=%d,y1=%d\n",x,y,i,y+1);
              x = i;
              y = y + 1;
              recurse = true;
              break;
            }
          if (recurse)
            break;
        }
      }

      if (!lifo_size(&lifo))
      {
        lifo_free(&lifo); //如果最起始为止就没找到，那么返回
        return;
      }
      //本次迭代，往上，往下找边界（相同颜色像素点），直到找不到为止
      //找到边界后，出栈上层像素点，回退回去
      xylf_t context;
      lifo_dequeue(&lifo, &context); //这里存疑，如果都没有的话，dequeue就会反向溢出吧。。
      x = context.x;
      y = context.y;
      left = context.l;
      right = context.r;
      //mp_printf(&mp_plat_print, "#deq: x=%x,y=%d\n",x,y);
    } //找到相同from，break到这外面
  }
}

/************************************************************************
 * Adaptive thresholding
 */

#define THRESHOLD_S_MIN 1
#define THRESHOLD_S_DEN 8
#define THRESHOLD_T 5

#if QUIRC_ROBUST_CELL
/* V22.3: grayscale snapshot for per-module local thresholding in read_cell.
 * threshold() below overwrites q->pixels (== q->image on this build) with 1-bit
 * BLACK/WHITE in place, DESTROYING the grayscale. Confirmed via RC5: voting on
 * the post-threshold 1-bit pixels can't recover rounded modules because the loss
 * already happened at this global threshold. So we stash the grayscale HERE,
 * before the overwrite, and read_cell thresholds each module locally from it —
 * working with real intensity where the rounded-corner information still exists.
 * One QVGA-sized PSRAM buffer, allocated once, never freed (8MB PSRAM; matches
 * the persistent-quirc strategy). g_qgray_w/h record the valid dimensions. */
#include <stdlib.h>   /* for the PSRAM alloc helper / size */
extern void *ps_malloc(size_t);   /* ESP-IDF/Arduino PSRAM allocator */
static uint8_t *g_qgray = NULL;
static int g_qgray_cap = 0;
static int g_qgray_w = 0, g_qgray_h = 0;
static void quirc_snapshot_gray(struct quirc *q)
{
  int n = q->w * q->h;
  if (g_qgray_cap < n)
  {
    if (g_qgray) free(g_qgray);
    g_qgray = (uint8_t *)ps_malloc(n);
    g_qgray_cap = g_qgray ? n : 0;
  }
  if (g_qgray)
  {
    memcpy(g_qgray, q->image, n);   /* image still grayscale at this point */
    g_qgray_w = q->w;
    g_qgray_h = q->h;
  }
  else
  {
    g_qgray_w = g_qgray_h = 0;      /* alloc failed -> read_cell falls back */
  }
}
#endif

static void threshold(struct quirc *q)
{
#if QUIRC_ROBUST_CELL
  quirc_snapshot_gray(q);   /* capture grayscale BEFORE the in-place overwrite */
#endif
  int x, y;
  int avg_w = 0;
  int avg_u = 0;
  int threshold_s = q->w / THRESHOLD_S_DEN;
  quirc_pixel_t *row = q->pixels;

  /*
     * Ensure a sane, non-zero value for threshold_s.
     *
     * threshold_s can be zero if the image width is small. We need to avoid
     * SIGFPE as it will be used as divisor.
     */
  if (threshold_s < THRESHOLD_S_MIN)
    threshold_s = THRESHOLD_S_MIN;

  for (y = 0; y < q->h; y++)
  {
    int row_average[q->w];

    memset(row_average, 0, sizeof(row_average));

    for (x = 0; x < q->w; x++)
    {
      int w, u;

      if (y & 1)
      {
        w = x;
        u = q->w - 1 - x;
      }
      else
      {
        w = q->w - 1 - x;
        u = x;
      }

      avg_w = (avg_w * (threshold_s - 1)) /
                  threshold_s +
              row[w];
      avg_u = (avg_u * (threshold_s - 1)) /
                  threshold_s +
              row[u];

      row_average[w] += avg_w;
      row_average[u] += avg_u;
    }

    for (x = 0; x < q->w; x++)
    {
      if (row[x] < row_average[x] *
                       (100 - THRESHOLD_T) / (200 * threshold_s))
        row[x] = QUIRC_PIXEL_BLACK;
      else
        row[x] = QUIRC_PIXEL_WHITE;
    }

    row += q->w;
  }
}

static void area_count(void *user_data, int y, int left, int right)
{
  ((struct quirc_region *)user_data)->count += right - left + 1;
}

static int region_code(struct quirc *q, int x, int y)
{ //region指的是QRcode的区域，成员为区域的坐标，像素面积，是否顶点
  int pixel;
  struct quirc_region *box;
  int region;

  if (x < 0 || y < 0 || x >= q->w || y >= q->h)
    return -1;

  pixel = q->pixels[y * q->w + x];
  //预先判断非正常的像素情况，退出
  if (pixel >= QUIRC_PIXEL_REGION)
    return pixel;

  if (pixel == QUIRC_PIXEL_WHITE)
    return -1;

  if (q->num_regions >= QUIRC_MAX_REGIONS)
    return -1;
  //新建一个区域
  region = q->num_regions;
  box = &q->regions[q->num_regions++];

  memset(box, 0, sizeof(*box));

  box->seed.x = x;
  box->seed.y = y;
  box->capstone = -1;
  //计算该区域的面积
  flood_fill_seed(q, x, y, pixel, region, area_count, box, 0);

  return region;
}

struct polygon_score_data
{
  struct quirc_point ref;

  int scores[4];
  struct quirc_point *corners;
} __attribute__((aligned(8)));

static void find_one_corner(void *user_data, int y, int left, int right)
{
  struct polygon_score_data *psd =
      (struct polygon_score_data *)user_data;
  int xs[2] = {left, right};
  int dy = y - psd->ref.y;
  int i;

  for (i = 0; i < 2; i++)
  {
    int dx = xs[i] - psd->ref.x;
    int d = dx * dx + dy * dy;

    if (d > psd->scores[0])
    {
      psd->scores[0] = d;
      psd->corners[0].x = xs[i];
      psd->corners[0].y = y;
    }
  }
}

static void find_other_corners(void *user_data, int y, int left, int right)
{
  struct polygon_score_data *psd =
      (struct polygon_score_data *)user_data;
  int xs[2] = {left, right};
  int i;

  for (i = 0; i < 2; i++)
  {
    int up = xs[i] * psd->ref.x + y * psd->ref.y;
    int right = xs[i] * -psd->ref.y + y * psd->ref.x;
    int scores[4] = {up, right, -up, -right};
    int j;

    for (j = 0; j < 4; j++)
    {
      if (scores[j] > psd->scores[j])
      {
        psd->scores[j] = scores[j];
        psd->corners[j].x = xs[i];
        psd->corners[j].y = y;
      }
    }
  }
}

static void find_region_corners(struct quirc *q,
                                int rcode, const struct quirc_point *ref,
                                struct quirc_point *corners)
{
  struct quirc_region *region = &q->regions[rcode];
  struct polygon_score_data psd;
  int i;

  memset(&psd, 0, sizeof(psd));
  psd.corners = corners;

  memcpy(&psd.ref, ref, sizeof(psd.ref));
  psd.scores[0] = -1;
  flood_fill_seed(q, region->seed.x, region->seed.y,
                  rcode, QUIRC_PIXEL_BLACK,
                  find_one_corner, &psd, 0);

  psd.ref.x = psd.corners[0].x - psd.ref.x;
  psd.ref.y = psd.corners[0].y - psd.ref.y;

  for (i = 0; i < 4; i++)
    memcpy(&psd.corners[i], &region->seed,
           sizeof(psd.corners[i]));

  i = region->seed.x * psd.ref.x + region->seed.y * psd.ref.y;
  psd.scores[0] = i;
  psd.scores[2] = -i;
  i = region->seed.x * -psd.ref.y + region->seed.y * psd.ref.x;
  psd.scores[1] = i;
  psd.scores[3] = -i;

  flood_fill_seed(q, region->seed.x, region->seed.y,
                  QUIRC_PIXEL_BLACK, rcode,
                  find_other_corners, &psd, 0);
}

static void record_capstone(struct quirc *q, int ring, int stone)
{
  struct quirc_region *stone_reg = &q->regions[stone];
  struct quirc_region *ring_reg = &q->regions[ring];
  struct quirc_capstone *capstone;
  int cs_index;

  if (q->num_capstones >= QUIRC_MAX_CAPSTONES)
    return;

  cs_index = q->num_capstones;
  capstone = &q->capstones[q->num_capstones++];

  memset(capstone, 0, sizeof(*capstone));

  capstone->qr_grid = -1;
  capstone->ring = ring;
  capstone->stone = stone;
  stone_reg->capstone = cs_index;
  ring_reg->capstone = cs_index;

  /* Find the corners of the ring */
  find_region_corners(q, ring, &stone_reg->seed, capstone->corners);

#if QUIRC_ROBUST_CELL
  /* V22.6 ROUNDED-FINDER SQUARE RECONSTRUCTION.
   * The finders on this QR are heavily rounded "squircles" (confirmed from the
   * device screenshots), not squares with lightly nicked corners. find_region_
   * corners() returns the extreme black pixel per diagonal; on a big rounded
   * shape those points are pulled INWARD and the resulting quad is both shrunk
   * and slightly skewed. perspective_setup() then builds the finder transform
   * from that bad quad, mis-registering the whole grid -> data modules (which are
   * square and fine) get sampled off-centre -> ECC fails. The user confirmed that
   * squaring the 3 finders makes it scan.
   *
   * Reliable facts about a symmetric rounded finder:
   *   - its CENTROID matches the square it's based on (rounding is symmetric),
   *   - the TRUE square corner is at least as far from the centroid as the
   *     furthest detected (inset) corner.
   * So: keep the centroid, find the max corner radius, and REBUILD all four
   * corners as a regular axis-consistent square at that radius — preserving each
   * corner's diagonal direction (TL/TR/BR/BL ordering from find_region_corners).
   * This regularizes the skewed inset quad into the clean square the finder is
   * based on, with NO tuning constant. Touches only the 3 finders. */
  {
    int cx = (capstone->corners[0].x + capstone->corners[1].x +
              capstone->corners[2].x + capstone->corners[3].x) / 4;
    int cy = (capstone->corners[0].y + capstone->corners[1].y +
              capstone->corners[2].y + capstone->corners[3].y) / 4;

    /* max |dx| and |dy| over the 4 corners -> half-extent of the true square.
     * Using per-axis max (not diagonal radius) reconstructs an axis-aligned-ish
     * square that tolerates the finder being rotated in the frame, because each
     * corner keeps the SIGN of its own offset (its quadrant) below. */
    int hx = 0, hy = 0, k3;
    for (k3 = 0; k3 < 4; k3++) {
      int adx = capstone->corners[k3].x - cx; if (adx < 0) adx = -adx;
      int ady = capstone->corners[k3].y - cy; if (ady < 0) ady = -ady;
      if (adx > hx) hx = adx;
      if (ady > hy) hy = ady;
    }
    /* Rebuild each corner at (centroid +/- half-extent), keeping the sign of that
     * corner's original offset so TL/TR/BR/BL stay in their quadrants. */
    for (k3 = 0; k3 < 4; k3++) {
      int sx = (capstone->corners[k3].x >= cx) ? 1 : -1;
      int sy = (capstone->corners[k3].y >= cy) ? 1 : -1;
      int nx = cx + sx * hx;
      int ny = cy + sy * hy;
      if (nx < 0) nx = 0;
      if (nx >= q->w) nx = q->w - 1;
      if (ny < 0) ny = 0;
      if (ny >= q->h) ny = q->h - 1;
      capstone->corners[k3].x = nx;
      capstone->corners[k3].y = ny;
    }
  }
#endif

  /* Set up the perspective transform and find the center */
  perspective_setup(capstone->c, capstone->corners, 7.0, 7.0);
  perspective_map(capstone->c, 3.5, 3.5, &capstone->center);
}

static void test_capstone(struct quirc *q, int x, int y, int *pb)
{
  int ring_right = region_code(q, x - pb[4], y);                                //x-pb[4]是标记环右边的左侧
  int stone = region_code(q, x - pb[4] - pb[3] - pb[2], y);                     //实心点左侧
  int ring_left = region_code(q, x - pb[4] - pb[3] - pb[2] - pb[1] - pb[0], y); //环左侧
  struct quirc_region *stone_reg;
  struct quirc_region *ring_reg;
  int ratio;
  //以下检测顶点标记是否符合规范，环称为ring，中间称为stone
  if (ring_left < 0 || ring_right < 0 || stone < 0)
    return;

  /* Left and ring of ring should be connected */
  if (ring_left != ring_right)
    return;

  /* Ring should be disconnected from stone */
  if (ring_left == stone)
    return;

  stone_reg = &q->regions[stone];
  ring_reg = &q->regions[ring_left];

  /* Already detected */
  if (stone_reg->capstone >= 0 || ring_reg->capstone >= 0)
    return;

  /* Ratio should ideally be 37.5 中间实心点占面积比例应该在37.5%左右*/
  ratio = stone_reg->count * 100 / ring_reg->count;
  if (ratio < 10 || ratio > 70)
    return;

  record_capstone(q, ring_left, stone);
}

static void finder_scan(struct quirc *q, int y)
{
  quirc_pixel_t *row = q->pixels + y * q->w;
  int x;
  int last_color = 0;
  int run_length = 0;
  int run_count = 0;
  int pb[5]; //means QRcode's pixel width

  memset(pb, 0, sizeof(pb));
  for (x = 0; x < q->w; x++)
  {
    int color = row[x] ? 1 : 0;

    if (x && color != last_color)
    {                                         // color is different
      memmove(pb, pb + 1, sizeof(pb[0]) * 4); //left move in one data
      pb[4] = run_length;                     //run how many pix to get different color
      run_length = 0;
      run_count++; //get more than 5 time color jump

      if (!color && run_count >= 5)
      { // find the marker of QRcode(three corner's marker)
        static int check[5] = {1, 1, 3, 1, 1};
        int avg, err;
        int i;
        int ok = 1;

        avg = (pb[0] + pb[1] + pb[3] + pb[4]) / 4;
        err = avg * 3 / 4;

        for (i = 0; i < 5; i++)
          if (pb[i] < check[i] * avg - err ||
              pb[i] > check[i] * avg + err)
            ok = 0;

        if (ok)
          test_capstone(q, x, y, pb);
      }
    }

    run_length++;
    last_color = color;
  }
}

static void find_alignment_pattern(struct quirc *q, int index)
{
  struct quirc_grid *qr = &q->grids[index];
  struct quirc_capstone *c0 = &q->capstones[qr->caps[0]];
  struct quirc_capstone *c2 = &q->capstones[qr->caps[2]];
  struct quirc_point a;
  struct quirc_point b;
  struct quirc_point c;
  int size_estimate;
  int step_size = 1;
  int dir = 0;
  float u, v;

  /* Grab our previous estimate of the alignment pattern corner */
  memcpy(&b, &qr->align, sizeof(b));

  /* Guess another two corners of the alignment pattern so that we
     * can estimate its size.
     */
  perspective_unmap(c0->c, &b, &u, &v);
  perspective_map(c0->c, u, v + 1.0, &a);
  perspective_unmap(c2->c, &b, &u, &v);
  perspective_map(c2->c, u + 1.0, v, &c);

  size_estimate = abs((a.x - b.x) * -(c.y - b.y) +
                      (a.y - b.y) * (c.x - b.x));

  /* Spiral outwards from the estimate point until we find something
     * roughly the right size. Don't look too far from the estimate
     * point.
     */
  while (step_size * step_size < size_estimate * 100)
  {
    static const int dx_map[] = {1, 0, -1, 0};
    static const int dy_map[] = {0, -1, 0, 1};
    int i;

    for (i = 0; i < step_size; i++)
    {
      int code = region_code(q, b.x, b.y);

      if (code >= 0)
      {
        struct quirc_region *reg = &q->regions[code];

        if (reg->count >= size_estimate / 2 &&
            reg->count <= size_estimate * 2)
        {
          qr->align_region = code;
          return;
        }
      }

      b.x += dx_map[dir];
      b.y += dy_map[dir];
    }

    dir = (dir + 1) % 4;
    if (!(dir & 1))
      step_size++;
  }
}

static void find_leftmost_to_line(void *user_data, int y, int left, int right)
{
  struct polygon_score_data *psd =
      (struct polygon_score_data *)user_data;
  int xs[2] = {left, right};
  int i;

  for (i = 0; i < 2; i++)
  {
    int d = -psd->ref.y * xs[i] + psd->ref.x * y;

    if (d < psd->scores[0])
    {
      psd->scores[0] = d;
      psd->corners[0].x = xs[i];
      psd->corners[0].y = y;
    }
  }
}

/* Do a Bresenham scan from one point to another and count the number
 * of black/white transitions.
 */
static int timing_scan(const struct quirc *q,
                       const struct quirc_point *p0,
                       const struct quirc_point *p1)
{
  int n = p1->x - p0->x;
  int d = p1->y - p0->y;
  int x = p0->x;
  int y = p0->y;
  int *dom, *nondom;
  int dom_step;
  int nondom_step;
  int a = 0;
  int i;
  int run_length = 0;
  int count = 0;

  if (p0->x < 0 || p0->y < 0 || p0->x >= q->w || p0->y >= q->h)
    return -1;
  if (p1->x < 0 || p1->y < 0 || p1->x >= q->w || p1->y >= q->h)
    return -1;

  if (abs(n) > abs(d))
  {
    int swap = n;

    n = d;
    d = swap;

    dom = &x;
    nondom = &y;
  }
  else
  {
    dom = &y;
    nondom = &x;
  }

  if (n < 0)
  {
    n = -n;
    nondom_step = -1;
  }
  else
  {
    nondom_step = 1;
  }

  if (d < 0)
  {
    d = -d;
    dom_step = -1;
  }
  else
  {
    dom_step = 1;
  }

  x = p0->x;
  y = p0->y;
  for (i = 0; i <= d; i++)
  {
    int pixel;

    if (y < 0 || y >= q->h || x < 0 || x >= q->w)
      break;

    pixel = q->pixels[y * q->w + x];

    if (pixel)
    {
      if (run_length >= 2)
        count++;
      run_length = 0;
    }
    else
    {
      run_length++;
    }

    a += n;
    *dom += dom_step;
    if (a >= d)
    {
      *nondom += nondom_step;
      a -= d;
    }
  }

  return count;
}

/* Try the measure the timing pattern for a given QR code. This does
 * not require the global perspective to have been set up, but it
 * does require that the capstone corners have been set to their
 * canonical rotation.
 *
 * For each capstone, we find a point in the middle of the ring band
 * which is nearest the centre of the code. Using these points, we do
 * a horizontal and a vertical timing scan.
 */
static int measure_timing_pattern(struct quirc *q, int index)
{
  struct quirc_grid *qr = &q->grids[index];
  int i;
  int scan;
  int ver;
  int size;

  for (i = 0; i < 3; i++)
  {
    static const float us[] = {6.5, 6.5, 0.5};
    static const float vs[] = {0.5, 6.5, 6.5};
    struct quirc_capstone *cap = &q->capstones[qr->caps[i]];

    perspective_map(cap->c, us[i], vs[i], &qr->tpep[i]);
  }

  qr->hscan = timing_scan(q, &qr->tpep[1], &qr->tpep[2]);
  qr->vscan = timing_scan(q, &qr->tpep[1], &qr->tpep[0]);

  scan = qr->hscan;
  if (qr->vscan > scan)
    scan = qr->vscan;

  /* If neither scan worked, we can't go any further. */
  if (scan < 0)
    return -1;

  /* Choose the nearest allowable grid size */
  size = scan * 2 + 13;
  ver = (size - 15) / 4;
  qr->grid_size = ver * 4 + 17;

#if QUIRC_ROBUST_CELL
  /* V22.4 GRID STABILIZATION (rounded-finder jitter fix) — now TOGGLEABLE.
   * QUIRC_GRID_HISTORY gates the cross-frame grid-size memory. Set to 0 to test
   * whether the recurring-size lock from frame 1 (which fills the ring with 53)
   * is holding frame 2 to a registration that suits frame 1 but not frame 2.
   * With it OFF, each frame uses ONLY its own raw timing-count grid size — fully
   * per-frame, zero carry-over. If frame 2 decodes with this OFF, the shared
   * history was the culprit (user's hypothesis confirmed) and we make it per-code
   * rather than global. If frame 2 still fails, the history was innocent. */
  #ifndef QUIRC_GRID_HISTORY
  #define QUIRC_GRID_HISTORY 0
  #endif
#if QUIRC_GRID_HISTORY
  /* On rounded "designer" QRs the timing-pattern transition count is unstable
   * frame-to-frame (observed grid_size jitter 33/37/41/49/53 on the same code),
   * because rounded modules blur where one timing cell ends and the next begins,
   * so timing_scan() miscounts differently each frame. Since we scan MANY frames
   * of the SAME static code, the TRUE size is the one that recurs. Keep a short
   * ring of recent grid_size results and prefer the recurring one. */
  {
    #define GS_HIST 12
    static int gs_ring[GS_HIST] = {0};
    static int gs_pos = 0;
    int raw = qr->grid_size;
    if (raw >= 21 && raw <= 177) {
      gs_ring[gs_pos] = raw;
      gs_pos = (gs_pos + 1) % GS_HIST;
    }
    int best = 0, bestN = 0, i2;
    for (i2 = 0; i2 < GS_HIST; i2++) {
      int v = gs_ring[i2];
      if (v < 21) continue;
      int n2 = 0, j2;
      for (j2 = 0; j2 < GS_HIST; j2++)
        if (gs_ring[j2] == v) n2++;
      if (n2 > bestN) { bestN = n2; best = v; }
    }
    if (best && bestN >= 3) {
      int rawN = 0, k2;
      for (k2 = 0; k2 < GS_HIST; k2++)
        if (gs_ring[k2] == raw) rawN++;
      if (best != raw && bestN >= rawN * 2) {
        ver = (best - 17) / 4;
        qr->grid_size = ver * 4 + 17;
      }
    }
    #undef GS_HIST
  }
#endif
#endif

  return 0;
}

/* Read a cell from a grid using the currently set perspective
 * transform. Returns +/- 1 for black/white, 0 for cells which are
 * out of image bounds.
 */
/* QUIRC_ROBUST_CELL: when set, read_cell samples MULTIPLE points clustered in
 * the module CENTRE and takes a majority vote, instead of reading the single
 * geometric-centre pixel. Rounded "designer" QR modules (e.g. Blue Wallet) keep
 * a solid centre and only round the CORNERS; a single centre sample can still
 * land on a sub-pixel-shifted edge and flip, but a centre-clustered vote reads
 * the solid interior and ignores the rounded corners entirely. This is the same
 * multi-point idea quirc already uses in fitness_cell() for grid scoring — here
 * we apply it to the actual data read. Offsets are kept tight around 0.5 (NOT
 * out to 0.3/0.7 like fitness_cell) so we sample only the solid centre and never
 * reach into a neighbour module or a rounded corner. */

static int read_cell(const struct quirc *q, int index, int x, int y)
{
  const struct quirc_grid *qr = &q->grids[index];
  struct quirc_point p;

#if QUIRC_ROBUST_CELL
  /* V22.3 BUILD-PROOF (no serial — USB corrupts capture): the first time this
   * robust path runs, raise a flag that main.cpp shows as " RC5" on the airgap
   * scan TFT footer, right next to the id=/c=/FAIL text. If you scan and never
   * see RC5 on screen, this file is NOT compiled in. Remove before ship. */
  {
    extern volatile int g_robustCellLive;
    g_robustCellLive = 1;
  }
  /* V22.3 GRAYSCALE LOCAL THRESHOLD.
   * RC5 confirmed: voting on the global-threshold 1-bit pixels still fails on
   * rounded modules, because the loss happened at the global threshold. So decide
   * each module here, from the grayscale snapshot taken before that threshold:
   *   - sample THIS module's centre grayscale (tight 5-tap average -> robust mean
   *     of the solid core, ignoring rounded corners),
   *   - sample the 8 NEIGHBOUR module centres' grayscale -> local reference mean,
   *   - module is BLACK if its centre is darker than the local mean by a margin.
   * A per-module local threshold tracks illumination/rounding far better than one
   * global pass. If the snapshot is unavailable, fall back to stock single-pixel. */
  if (g_qgray && g_qgray_w == q->w && g_qgray_h == q->h)
  {
    const uint8_t *gray = g_qgray;
    const int W = q->w, H = q->h;

    /* mean grayscale of a module's solid centre (5 tight taps around cx,cy) */
    #define QGRAY_CENTRE_MEAN(cellx, celly, outval, outok)                    \
      do {                                                                    \
        static const float _ox[5] = {0.5f,0.34f,0.66f,0.5f, 0.5f };           \
        static const float _oy[5] = {0.5f,0.5f, 0.5f, 0.34f,0.66f};           \
        int _sum = 0, _cnt = 0, _k;                                           \
        struct quirc_point _pp;                                              \
        for (_k = 0; _k < 5; _k++) {                                          \
          perspective_map(qr->c, (cellx) + _ox[_k], (celly) + _oy[_k], &_pp); \
          if (_pp.y < 0 || _pp.y >= H || _pp.x < 0 || _pp.x >= W) continue;   \
          _sum += gray[_pp.y * W + _pp.x]; _cnt++;                            \
        }                                                                     \
        if (_cnt) { (outval) = _sum / _cnt; (outok) = 1; }                    \
        else { (outval) = 0; (outok) = 0; }                                   \
      } while (0)

    int self, selfok;
    QGRAY_CENTRE_MEAN(x, y, self, selfok);
    if (!selfok)
      return 0;   /* this module maps off-image -> behave like stock OOB */

    /* local reference: mean of the 8 surrounding module centres (those in-image).
     * Using module centres (not raw pixels) keeps the reference on the same grid
     * scale and naturally spans both black and white neighbours -> a good local
     * midpoint for this region of the code. */
    static const int dx[8] = {-1, 0, 1, -1, 1, -1, 0, 1};
    static const int dy[8] = {-1, -1, -1, 0, 0, 1, 1, 1};
    int refsum = 0, refcnt = 0, j;
    for (j = 0; j < 8; j++)
    {
      int nv, nok;
      QGRAY_CENTRE_MEAN(x + dx[j], y + dy[j], nv, nok);
      if (nok) { refsum += nv; refcnt++; }
    }

    int localmean = refcnt ? (refsum / refcnt) : self;
    /* margin: small fraction of the local mean so near-tie modules bias by the
     * global sense. ~6% (THRESHOLD_T-style) keeps it close to quirc's own bias. */
    int margin = localmean * 6 / 100;

    #undef QGRAY_CENTRE_MEAN

    if (self < localmean - margin)
      return 1;    /* clearly darker than local region -> BLACK */
    if (self > localmean + margin)
      return -1;   /* clearly lighter -> WHITE */
    /* ambiguous: fall back to the simple self-vs-localmean sign */
    return (self < localmean) ? 1 : -1;
  }
  /* --- fallback: grayscale snapshot unavailable, use stock single-pixel read --- */
  perspective_map(qr->c, x + 0.5, y + 0.5, &p);
  if (p.y < 0 || p.y >= q->h || p.x < 0 || p.x >= q->w)
    return 0;
  return q->pixels[p.y * q->w + p.x] ? 1 : -1;
#else
  perspective_map(qr->c, x + 0.5, y + 0.5, &p);
  if (p.y < 0 || p.y >= q->h || p.x < 0 || p.x >= q->w)
    return 0;

  return q->pixels[p.y * q->w + p.x] ? 1 : -1;
#endif
}

static int fitness_cell(const struct quirc *q, int index, int x, int y)
{
  const struct quirc_grid *qr = &q->grids[index];
  int score = 0;
  int u, v;

  for (v = 0; v < 3; v++)
    for (u = 0; u < 3; u++)
    {
      static const float offsets[] = {0.3, 0.5, 0.7};
      struct quirc_point p;

      perspective_map(qr->c, x + offsets[u],
                      y + offsets[v], &p);
      if (p.y < 0 || p.y >= q->h || p.x < 0 || p.x >= q->w)
        continue;

      if (q->pixels[p.y * q->w + p.x])
        score++;
      else
        score--;
    }

  return score;
}

static int fitness_ring(const struct quirc *q, int index, int cx, int cy,
                        int radius)
{
  int i;
  int score = 0;

  for (i = 0; i < radius * 2; i++)
  {
    score += fitness_cell(q, index, cx - radius + i, cy - radius);
    score += fitness_cell(q, index, cx - radius, cy + radius - i);
    score += fitness_cell(q, index, cx + radius, cy - radius + i);
    score += fitness_cell(q, index, cx + radius - i, cy + radius);
  }

  return score;
}

static int fitness_apat(const struct quirc *q, int index, int cx, int cy)
{
  return fitness_cell(q, index, cx, cy) -
         fitness_ring(q, index, cx, cy, 1) +
         fitness_ring(q, index, cx, cy, 2);
}

static int fitness_capstone(const struct quirc *q, int index, int x, int y)
{
  x += 3;
  y += 3;

  return fitness_cell(q, index, x, y) +
         fitness_ring(q, index, x, y, 1) -
         fitness_ring(q, index, x, y, 2) +
         fitness_ring(q, index, x, y, 3);
}

/* Compute a fitness score for the currently configured perspective
 * transform, using the features we expect to find by scanning the
 * grid.
 */
static int fitness_all(const struct quirc *q, int index)
{
  const struct quirc_grid *qr = &q->grids[index];
  int version = (qr->grid_size - 17) / 4;
  const struct quirc_version_info *info = &quirc_version_db[version];
  int score = 0;
  int i, j;
  int ap_count;

  /* Check the timing pattern */
  for (i = 0; i < qr->grid_size - 14; i++)
  {
    int expect = (i & 1) ? 1 : -1;

    score += fitness_cell(q, index, i + 7, 6) * expect;
    score += fitness_cell(q, index, 6, i + 7) * expect;
  }

  /* Check capstones */
  score += fitness_capstone(q, index, 0, 0);
  score += fitness_capstone(q, index, qr->grid_size - 7, 0);
  score += fitness_capstone(q, index, 0, qr->grid_size - 7);

  if (version < 0 || version > QUIRC_MAX_VERSION)
    return score;

  /* Check alignment patterns */
  ap_count = 0;
  while ((ap_count < QUIRC_MAX_ALIGNMENT) && info->apat[ap_count])
    ap_count++;

  for (i = 1; i + 1 < ap_count; i++)
  {
    score += fitness_apat(q, index, 6, info->apat[i]);
    score += fitness_apat(q, index, info->apat[i], 6);
  }

  for (i = 1; i < ap_count; i++)
    for (j = 1; j < ap_count; j++)
      score += fitness_apat(q, index,
                            info->apat[i], info->apat[j]);
  //mp_printf(&mp_plat_print, "##score=%d\n",score);
  return score;
}

static void jiggle_perspective(struct quirc *q, int index)
{
  struct quirc_grid *qr = &q->grids[index];
  int best = fitness_all(q, index);
  int pass;
  float adjustments[8];
  int i;

  for (i = 0; i < 8; i++)
    adjustments[i] = qr->c[i] * 0.02;

  for (pass = 0; pass < 5; pass++)
  {
    for (i = 0; i < 16; i++)
    {
      int j = i >> 1;
      int test;
      float old = qr->c[j];
      float step = adjustments[j];
      float new;

      if (i & 1)
        new = old + step;
      else
        new = old - step;

      qr->c[j] = new;
      test = fitness_all(q, index);

      if (test > best)
        best = test;
      else
        qr->c[j] = old;
    }

    for (i = 0; i < 8; i++)
      adjustments[i] *= 0.5;
  }
}

/* Once the capstones are in place and an alignment point has been
 * chosen, we call this function to set up a grid-reading perspective
 * transform.
 */
static void setup_qr_perspective(struct quirc *q, int index)
{
  struct quirc_grid *qr = &q->grids[index];
  struct quirc_point rect[4];

  /* Set up the perspective map for reading the grid */
  memcpy(&rect[0], &q->capstones[qr->caps[1]].corners[0],
         sizeof(rect[0]));
  memcpy(&rect[1], &q->capstones[qr->caps[2]].corners[0],
         sizeof(rect[0]));
  memcpy(&rect[2], &qr->align, sizeof(rect[0]));
  memcpy(&rect[3], &q->capstones[qr->caps[0]].corners[0],
         sizeof(rect[0]));
  perspective_setup(qr->c, rect, qr->grid_size - 7, qr->grid_size - 7);

  jiggle_perspective(q, index);
}

/* Rotate the capstone with so that corner 0 is the leftmost with respect
 * to the given reference line.
 */
static void rotate_capstone(struct quirc_capstone *cap,
                            const struct quirc_point *h0,
                            const struct quirc_point *hd)
{
  struct quirc_point copy[4];
  int j;
  int best = 0;
  int best_score = 0;

  for (j = 0; j < 4; j++)
  {
    struct quirc_point *p = &cap->corners[j];
    int score = (p->x - h0->x) * -hd->y +
                (p->y - h0->y) * hd->x;

    if (!j || score < best_score)
    {
      best = j;
      best_score = score;
    }
  }

  /* Rotate the capstone */
  for (j = 0; j < 4; j++)
    memcpy(&copy[j], &cap->corners[(j + best) % 4],
           sizeof(copy[j]));
  memcpy(cap->corners, copy, sizeof(cap->corners));
  perspective_setup(cap->c, cap->corners, 7.0, 7.0);
}

static void record_qr_grid(struct quirc *q, int a, int b, int c)
{
  struct quirc_point h0, hd;
  int i;
  int qr_index;
  struct quirc_grid *qr;

  if (q->num_grids >= QUIRC_MAX_GRIDS)
    return;

  /* Construct the hypotenuse line from A to C. B should be to
     * the left of this line.
     */
  memcpy(&h0, &q->capstones[a].center, sizeof(h0));
  hd.x = q->capstones[c].center.x - q->capstones[a].center.x;
  hd.y = q->capstones[c].center.y - q->capstones[a].center.y;

  /* Make sure A-B-C is clockwise */
  if ((q->capstones[b].center.x - h0.x) * -hd.y +
          (q->capstones[b].center.y - h0.y) * hd.x >
      0)
  {
    int swap = a;

    a = c;
    c = swap;
    hd.x = -hd.x;
    hd.y = -hd.y;
  }

  /* Record the grid and its components */
  qr_index = q->num_grids;
  qr = &q->grids[q->num_grids++];

  memset(qr, 0, sizeof(*qr));
  qr->caps[0] = a;
  qr->caps[1] = b;
  qr->caps[2] = c;
  qr->align_region = -1;

  /* Rotate each capstone so that corner 0 is top-left with respect
     * to the grid.
     */
  for (i = 0; i < 3; i++)
  {
    struct quirc_capstone *cap = &q->capstones[qr->caps[i]];

    rotate_capstone(cap, &h0, &hd);
    cap->qr_grid = qr_index;
  }

  /* Check the timing pattern. This doesn't require a perspective
     * transform.
     */
  if (measure_timing_pattern(q, qr_index) < 0)
    goto fail;

  /* Make an estimate based for the alignment pattern based on extending
     * lines from capstones A and C.
     */
  if (!line_intersect(&q->capstones[a].corners[0],
                      &q->capstones[a].corners[1],
                      &q->capstones[c].corners[0],
                      &q->capstones[c].corners[3],
                      &qr->align))
    goto fail;

  /* On V2+ grids, we should use the alignment pattern. */
  if (qr->grid_size > 21)
  {
    /* Try to find the actual location of the alignment pattern. */
    find_alignment_pattern(q, qr_index);

    /* Find the point of the alignment pattern closest to the
         * top-left of the QR grid.
         */
    if (qr->align_region >= 0)
    {
      struct polygon_score_data psd;
      struct quirc_region *reg =
          &q->regions[qr->align_region];

      /* Start from some point inside the alignment pattern */
      memcpy(&qr->align, &reg->seed, sizeof(qr->align));

      memcpy(&psd.ref, &hd, sizeof(psd.ref));
      psd.corners = &qr->align;
      psd.scores[0] = -hd.y * qr->align.x +
                      hd.x * qr->align.y;

      flood_fill_seed(q, reg->seed.x, reg->seed.y,
                      qr->align_region, QUIRC_PIXEL_BLACK,
                      NULL, NULL, 0);
      flood_fill_seed(q, reg->seed.x, reg->seed.y,
                      QUIRC_PIXEL_BLACK, qr->align_region,
                      find_leftmost_to_line, &psd, 0);
    }
  }

  setup_qr_perspective(q, qr_index);
  return;

fail:
  /* We've been unable to complete setup for this grid. Undo what we've
     * recorded and pretend it never happened.
     */
  for (i = 0; i < 3; i++)
    q->capstones[qr->caps[i]].qr_grid = -1;
  q->num_grids--;
}

struct neighbour
{
  int index;
  float distance;
} __attribute__((aligned(8)));

struct neighbour_list
{
  struct neighbour n[QUIRC_MAX_CAPSTONES];
  int count;
} __attribute__((aligned(8)));

static void test_neighbours(struct quirc *q, int i,
                            const struct neighbour_list *hlist,
                            const struct neighbour_list *vlist)
{
  int j, k;
  float best_score = 0.0;
  int best_h = -1, best_v = -1;

  /* Test each possible grouping */
  for (j = 0; j < hlist->count; j++)
    for (k = 0; k < vlist->count; k++)
    {
      const struct neighbour *hn = &hlist->n[j];
      const struct neighbour *vn = &vlist->n[k];
      float score = fast_fabsf(1.0 - hn->distance / vn->distance);

      if (score > 2.5)
        continue;

      if (best_h < 0 || score < best_score)
      {
        best_h = hn->index;
        best_v = vn->index;
        best_score = score;
      }
    }

  if (best_h < 0 || best_v < 0)
    return;

  record_qr_grid(q, best_h, i, best_v);
}

static void test_grouping(struct quirc *q, int i)
{
  struct quirc_capstone *c1 = &q->capstones[i];
  int j;
  struct neighbour_list hlist;
  struct neighbour_list vlist;

  if (c1->qr_grid >= 0)
    return;

  hlist.count = 0;
  vlist.count = 0;

  /* Look for potential neighbours by examining the relative gradients
     * from this capstone to others.
     */
  for (j = 0; j < q->num_capstones; j++)
  {
    struct quirc_capstone *c2 = &q->capstones[j];
    float u, v;

    if (i == j || c2->qr_grid >= 0)
      continue;

    perspective_unmap(c1->c, &c2->center, &u, &v);

    u = fast_fabsf(u - 3.5);
    v = fast_fabsf(v - 3.5);

    if (u < 0.2 * v)
    {
      struct neighbour *n = &hlist.n[hlist.count++];

      n->index = j;
      n->distance = v;
    }

    if (v < 0.2 * u)
    {
      struct neighbour *n = &vlist.n[vlist.count++];

      n->index = j;
      n->distance = u;
    }
  }

  if (!(hlist.count && vlist.count))
    return;

  test_neighbours(q, i, &hlist, &vlist);
}

static void pixels_setup(struct quirc *q)
{
  if (sizeof(*q->image) == sizeof(*q->pixels))
  {
    q->pixels = (quirc_pixel_t *)q->image;
  }
  else
  {
    int x, y;
    for (y = 0; y < q->h; y++)
    {
      for (x = 0; x < q->w; x++)
      {
        q->pixels[y * q->w + x] = q->image[y * q->w + x];
      }
    }
  }
}

uint8_t *quirc_begin(struct quirc *q, int *w, int *h)
{
  q->num_regions = QUIRC_PIXEL_REGION;
  q->num_capstones = 0;
  q->num_grids = 0;

  if (w)
    *w = q->w;
  if (h)
    *h = q->h;

  return q->image;
}

void quirc_end(struct quirc *q)
{
  int i;
  pixels_setup(q);
  threshold(q);

  for (i = 0; i < q->h; i++)
  {
    finder_scan(q, i);
  }

  for (i = 0; i < q->num_capstones; i++)
  {
    test_grouping(q, i);
  }
}

void quirc_extract(const struct quirc *q, int index,
                   struct quirc_code *code)
{
  const struct quirc_grid *qr = &q->grids[index];
  int y;
  int i = 0;

  if (index < 0 || index > q->num_grids)
    return;

  memset(code, 0, sizeof(*code));

  perspective_map(qr->c, 0.0, 0.0, &code->corners[0]);
  perspective_map(qr->c, qr->grid_size, 0.0, &code->corners[1]);
  perspective_map(qr->c, qr->grid_size, qr->grid_size,
                  &code->corners[2]);
  perspective_map(qr->c, 0.0, qr->grid_size, &code->corners[3]);

  code->size = qr->grid_size;

  for (y = 0; y < qr->grid_size; y++)
  {
    int x;

    for (x = 0; x < qr->grid_size; x++)
    {
      if (read_cell(q, index, x, y) > 0)
        code->cell_bitmap[i >> 3] |= (1 << (i & 7));

      i++;
    }
  }
}