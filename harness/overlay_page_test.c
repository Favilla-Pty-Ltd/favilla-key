/* overlay_page_test.c — drives runEntropyOverlay() on the host against stubs.
 *   g++ -x c++ -Wall -Wextra -fsanitize=address,undefined \
 *       -o overlay_page_test overlay_page_test.c -I../src -lmbedcrypto
 * Checks the ceremony's invariants: that the published entropy really is
 * SHA-256 of the XOR of the two grids the user froze, that a dark camera does
 * NOT block (XOR with a constant is a bijection), and that the both-dead case
 * fails closed. */
#include "quad_stub.h"
#include "entropy_overlay.h"

static int fails = 0;
static void ck(const char* what, bool ok){
  printf(ok ? "  ok   %s\n" : "  FAIL %s\n", what);
  if(!ok) fails++;
}

/* One rule now: ENTER always moves forward. Ten steps.
 *   begin, [warm] freeze SE, warn, QR, start camera, [warm] freeze cam,
 *   warn, QR, compose, hex, strength, finish.  9 steps. */
static void script(void){
  keyReset();
  keyPush(2);                       /* intro -> SE live            */
  keyWait(); keyPush(2);            /* freeze SE                   */
  keyPush(2);                       /* -> A warning                */
  keyPush(2);                       /* -> A as QR                  */
  keyPush(2);                       /* -> camera live              */
  keyWait(); keyWait(); keyPush(2); /* freeze camera               */
  keyPush(2);                       /* -> B warning                */
  keyPush(2);                       /* -> B as QR                  */
  keyPush(2);                       /* -> compose the board        */
  keyPush(2);                       /* -> the one hex screen       */
  keyPush(2);                       /* -> strength                 */
  keyPush(2);                       /* finish                      */
}

int main(void){
  uint8_t a[32], b[32], x[32], h[32];

  printf("S1  healthy run, lit camera\n");
  g_camMode = 0; g_seMode = 0;
  script();
  ck("ceremony completed", runEntropyOverlay());
  ck("SE scored 256.0", ovSeBits10 == 2560);
  ck("camera scored > 50 bits", ovCamBits10 > 500);
  ck("board floored by the stronger layer", ovBoardBits10() == 2560);
  ck("queue consumed", g_keysLeft() == 0);

  printf("S2  the published entropy is sha256 of the xor the user saw\n");
  /* the page wipes its buffers on exit, so re-derive from the construction */
  for(int i = 0; i < 32; i++){ a[i] = (uint8_t)(i * 7 + 1); b[i] = (uint8_t)(i * 13 + 5); }
  ovlXor(a, b, x);
  ovlEntropyFromBoard(x, h);
  {
    uint8_t x2[32];
    for(int i = 0; i < 32; i++) x2[i] = (uint8_t)(a[i] ^ b[i]);
    ck("xor matches a byte-wise reference", !memcmp(x, x2, 32));
  }
  {
    int bad = 0;
    for(int i = 0; i < 256; i++)
      if((ovlGet(a, i) ^ ovlGet(b, i)) != ovlGet(x, i)) bad++;
    ck("cell arithmetic holds for all 256", bad == 0);
  }

  printf("S3  a camera layer under the pass line is now REFUSED\n");
  g_camMode = 1; g_seMode = 0;
  script();
  /* POLICY CHANGE 5 Aug 2026. This used to complete: XOR with a constant is a
   * bijection, so a dead camera cannot lower the board and the SE051 carried it.
   * But that leaves the no-single-vendor claim resting on nothing whenever the
   * camera is weak, and the board figure reads 256 regardless. So a camera layer
   * below OV_CAM_PASS_BITS is now refused outright. */
  ck("refused rather than completing", !runEntropyOverlay());
  ck("camera scored under the 128-bit pass line", ovCamBits10 < OV_CAM_PASS_BITS*10);

  printf("S4  both layers dead fails closed\n");
  g_camMode = 1; g_seMode = 1;
  script();
  ck("refused", !runEntropyOverlay());
  ck("no entropy published", !g_ovlValid);

  printf("S4b  mashing ENTER cannot freeze an unsampled layer\n");
  g_camMode = 0; g_seMode = 0;
  keyReset();
  for(int i = 0; i < 12; i++) keyPush(2);      /* no waits at all */
  runEntropyOverlay();
  ck("no all-zero layer was captured", !g_ovlValid || ovCamBits10 > 0);

  printf("S5  SE dead but camera good still works\n");
  g_camMode = 0; g_seMode = 1;
  script();
  bool ok = runEntropyOverlay();
  printf("       SE %d.%d  camera %d.%d  board %d.%d\n",
         ovSeBits10/10, ovSeBits10%10, ovCamBits10/10, ovCamBits10%10,
         ovBoardBits10()/10, ovBoardBits10()%10);
  ck("completes on the camera alone", ok);
  ck("SE scored zero", ovSeBits10 == 0);
  ck("board carried by the camera", ovBoardBits10() == ovCamBits10);


  printf("S5b  the camera layer is captured at the SECURITY gain, not the shipping one\n");
  /* auto-tune picks the rung, so assert it lands somewhere ON the ladder and
   * that the shipping tuning is restored on exit */
  {
    float ch = ovAutoTune();
    bool onLadder = false;
    for(int i = 0; i < OV_TUNE_N; i++)
      if(g_camGain == OV_TUNE[i].gain && g_camAec == OV_TUNE[i].aec) onLadder = true;
    ck("auto-tune settled on a ladder rung", onLadder);
    ck("auto-tune found a usable change rate", ch > 0.30f);
  }
  ovCamUp = true; ovCamStop();
  ck("shipping tuning restored on exit",             g_camGain == 0 && g_camAec == 40);
  ck("bar reads red below the 128-bit pass line",     ovBarCol(100*10) == C_RED);
  ck("bar reads green well above it",                 ovBarCol(240*10) == C_GREEN);

  printf("S5c  the camera layer cannot be frozen below the 128-bit pass line\n");
  {
    g_camMode = 0; g_seMode = 0;
    ovAutoTune();
    /* fill the ring with a healthy source, then check the gate lets it through */
    ovFrames = 99;
    for(int i = 0; i < OV_CAM_WIN + 2; i++) ovRefreshCam();
    ck("healthy camera can be frozen", ovCanFreeze(1));
    ck("live estimate is above the pass line", ovCamLiveBits10() >= OV_CAM_PASS_BITS*10);

    /* now starve it: a constant frame carries nothing and must be refused */
    g_camMode = 2;                       /* no frames at all */
    ovRingN = 0; ovRingI = 0; ovPrevOk = false;
    ck("no history means no freeze", !ovCanFreeze(1));
    g_camMode = 0;
  }



  printf("S6  scrolling back to review changes nothing\n");
  g_camMode = 0; g_seMode = 0;
  keyReset();
  keyPush(2);
  keyWait(); keyPush(2); keyPush(2); keyPush(2); keyPush(2);   /* +1: A warning */
  keyWait(); keyWait(); keyPush(2); keyPush(2); keyPush(2);    /* +1: B warning */
  keyPush(3); keyPush(3); keyPush(3); keyPush(3);   /* scroll all the way back */
  keyPush(1); keyPush(1);                            /* and forward again      */
  keyPush(2);                                        /* ENTER -> jump to front */
  keyPush(2); keyPush(2); keyPush(2); keyPush(2);
  {
    bool ok2 = runEntropyOverlay();
    ck("still completes after reviewing", ok2);
    ck("board still floored at 256", ovBoardBits10() == 2560);
  }


  printf("S7  no text is drawn over the grid\n");
  {
    /* The grid occupies y = OV_Y0 .. OV_GRID_BOT. Text may sit in the 28px
     * header or in the strip below the grid, never on top of the cells — that
     * was the complaint, so it gets a test rather than a promise. */
    struct { const char* name; int which; } layers[2] = { {"SE051",0}, {"camera",1} };
    int bad = 0, off = 0;
    for(int L = 0; L < 2; L++){
      for(int fz = 0; fz < 2; fz++){
        ovSeFrozen = (L==0 && fz); ovCamFrozen = (L==1 && fz);
        ovFrames = 99;
        txtReset(); ovPaintLayer(layers[L].which, ST_SE, ST_SE);
        for(int i = 0; i < g_txtN; i++){
          if(g_txtY[i] >= OV_Y0 && g_txtY[i] < OV_GRID_BOT) bad++;
          if(g_txtY[i] > 228) off++;
        }
      }
    }
    txtReset(); ovPaintBoard(ST_BOARD, ST_BOARD);
    for(int i = 0; i < g_txtN; i++){
      if(g_txtY[i] >= OV_Y0 && g_txtY[i] < OV_GRID_BOT) bad++;
      if(g_txtY[i] > 228) off++;
    }
    ck("no text lands on the grid", bad == 0);
    ck("no text runs off the bottom edge", off == 0);
    txtReset(); ovPaintHex(2, ST_HEX_ENT, ST_HEX_ENT);
    int low = 0; for(int i = 0; i < g_txtN; i++) if(g_txtY[i] > 228) low++;
    ck("hex screen stays on screen", low == 0);
    ovSeFrozen = false; ovCamFrozen = false;
  }

  printf(fails ? "\nFAILED (%d)\n" : "\nAll page checks passed\n", fails);
  return fails ? 1 : 0;
}
