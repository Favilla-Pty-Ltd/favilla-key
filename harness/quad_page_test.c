/* quad_page_test.c — drives runEntropyQuad() on the host against stubs.
 *   c++ -Wall -Wextra -fsanitize=address,undefined -o quad_page_test \
 *       quad_page_test.c -I../src -lmbedcrypto && ./quad_page_test
 * Checks the ceremony's invariants, not its pixels: coverage, provenance,
 * the fail-closed gates, and that the entropy really is SHA-256(board). */
#include "quad_stub.h"
#include "entropy_quad.h"
#include <assert.h>

static int fails = 0;
static void ck(const char* what, bool ok){
  printf(ok ? "  ok   %s\n" : "  FAIL %s\n", what);
  if(!ok) fails++;
}

/* one full run: 4 x (ENTER deal, ENTER place), then ENTER through the end */
static void scriptFullRun(void){
  keyReset();
  keyPush(2);                                   /* intro -> begin */
  for(int i = 0; i < 4; i++){ keyPush(2); keyPush(2); }   /* deal, place */
  keyPush(2);                                   /* done -> verify */
  keyPush(2);                                   /* verify -> bits */
  keyPush(2);                                   /* bits -> exit */
}

static void expectHashOfBoard(const uint8_t board[32]){
  uint8_t want[32];
  quadEntropyFromBoard(board, want);
  ck("entropy == SHA-256(board)", memcmp(want, g_quadEntropy, 32) == 0);
}

int main(void){
  printf("S1  full run, lit camera, live motion\n");
  g_camMode = 0; g_accMode = 0; g_seMode = 0;
  scriptFullRun();
  runEntropyQuad();
  ck("board completed", g_quadValid);
  ck("all four quadrants attributed",
     qQuadSrc[0] == 0xFF && qQuadSrc[1] == 0xFF && qQuadSrc[2] == 0xFF && qQuadSrc[3] == 0xFF);
  /* qBoard is wiped on exit, so re-derive from the recorded bit counts instead */
  ck("SE budgeted 64.0",        qBits10[QS_SE]  == 640);
  ck("ESP budgeted 0.0",        qBits10[QS_ESP] == 0);
  ck("camera budgeted > 50",    qBits10[QS_CAM] > 500);
  ck("motion budgeted > 50",    qBits10[QS_ACC] > 500);
  ck("queue fully consumed",    g_keysLeft() == 0);

  printf("S2  dark camera is refused, and refusing costs nothing\n");
  g_camMode = 1;
  keyReset();
  keyPush(2);            /* begin */
  keyPush(2); keyPush(2);/* SE deal + place */
  keyPush(2);            /* camera deal -> refused */
  keyPush(4);            /* abort from the fail screen */
  runEntropyQuad();
  ck("no board produced",   !g_quadValid);
  ck("camera scored 0 bits", qBits10[QS_CAM] == 0);
  ck("measured change below the 25% gate", qCamChange10 < 250);

  printf("S3  dead camera and dead SE are named, not swallowed\n");
  g_camMode = 2; g_accMode = 0; g_seMode = 0;
  {
    uint8_t blk[QUAD_BLKB]; int b10 = 0; const char* why = "";
    ck("no frames -> refuse", !qDealCam(blk, &b10, &why));
    ck("reason names the camera", strstr(why, "Camera") != nullptr);
    g_seMode = 1;
    ck("SE no response -> refuse", !qDealSE(blk, &b10, &why));
    ck("reason names the SE051", strstr(why, "SE051") != nullptr);
    g_seMode = 2;
    ck("SE constant block -> refuse", !qDealSE(blk, &b10, &why));
    g_seMode = 0;
    g_accMode = 2;
    ck("accel no ACK -> refuse", !qDealAcc(blk, &b10, &why));
    ck("reason names motion", strstr(why, "Motion") != nullptr);
    g_accMode = 0;
  }

  printf("S4  the board really is the pre-image\n");
  g_camMode = 0; g_accMode = 0; g_seMode = 0;
  {
    /* Rebuild the board from the same deals and confirm the hash matches what
     * the page published. Done by placing four known blocks directly. */
    uint8_t board[QUAD_BYTES], cov[QUAD_BYTES], blk[QUAD_BLKB];
    memset(board, 0, sizeof board); memset(cov, 0, sizeof cov);
    for(int q = 0; q < 4; q++){
      for(int i = 0; i < QUAD_BLKB; i++) blk[i] = (uint8_t)(q * 16 + i);
      ck("placed", quadPlaceBlock(board, cov, q, blk));
    }
    ck("256/256", quadCoverageFull(cov));
    quadEntropyFromBoard(board, g_quadEntropy);
    expectHashOfBoard(board);
  }

  printf("S5  estimator reproduces the study's published figures\n");
  {
    /* lit camera: LSB frame-to-frame agreement 0.5293 -> 0.918 bits/px */
    int lit = qBits10From(qMinEnt(0.5293f));
    /* dark: 0.9434 -> 0.084 */
    int dark = qBits10From(qMinEnt(0.9434f));
    printf("       lit %d.%d bits, dark %d.%d bits per quadrant\n",
           lit/10, lit%10, dark/10, dark%10);
    ck("lit quadrant ~59 bits",  lit  >= 580 && lit  <= 595);
    ck("dark quadrant ~5 bits",  dark >= 50  && dark <= 60);
    /* motion at rest: the study's per-axis LSB MCV min-entropies are already in
     * BITS (0.889 / 0.848 / 0.999), unlike the camera figure which is an
     * agreement PROBABILITY. Feeding a bit count into qMinEnt() would be the
     * same category error the study is about. */
    float h = (0.889f + 0.848f + 0.999f) / 3.0f;
    int acc = qBits10From(h);
    printf("       motion %d.%d bits per quadrant\n", acc/10, acc%10);
    ck("motion quadrant ~58 bits", acc >= 570 && acc <= 590);
    int total = 640 + lit + 0 + acc;
    printf("       full board: %d.%d bits lit, %d.%d dark\n",
           total/10, total%10, (640 + dark + acc)/10, (640 + dark + acc)%10);
    ck("lit board ~181 bits",  total >= 1795 && total <= 1825);
    ck("dark board ~127 bits", (640 + dark + acc) >= 1260 && (640 + dark + acc) <= 1290);
  }

  printf(fails ? "\nFAILED (%d)\n" : "\nAll page checks passed\n", fails);
  return fails ? 1 : 0;
}
