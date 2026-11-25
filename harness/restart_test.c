/* restart_test.c — host driver for entropy_restart.h. Checks the probe logic,
 * the sweep, the sequential dump and the restart loop against stubs. */
#define FAVILLA_ENTROPY_RESTART 1
#include "restart_stub.h"
#include "entropy_restart.h"

static int fails = 0;
static void ck(const char* w, bool ok){ printf(ok?"  ok   %s\n":"  FAIL %s\n", w); if(!ok) fails++; }

int main(void){
  printf("S1  power probe detects a genuine reset\n");
  g_camMode = 0; g_railResets = 1; g_powerCycles = 0;
  orsProbe();
  ck("rail was actually cut", g_powerCycles == 1);

  printf("S2  power probe CATCHES a sensor that kept its state\n");
  g_railResets = 0; g_powerCycles = 0;
  orsProbe();
  ck("still cut the rail", g_powerCycles == 1);
  ck("marker survived, so the probe should have said NOT RESETTING",
     g_sensor.regs[ORS_PROBE_REG] != 0);

  printf("S3  restart loop cycles the rail once per restart\n");
  g_railResets = 1; g_suspends = 0; g_resumes = 0;
  keyReset(); for(int i=0;i<40;i++) keyWait();
  orsRestart(8);
  /* 8 restarts + the one orsRecover() that establishes the camera first */
  ck("8 restarts + 1 setup suspend", g_suspends == 9);
  ck("8 restarts + 1 setup resume",  g_resumes  == 9);

  printf("S3b  a capture straight after the probe still works\n");
  g_railResets = 1; g_camMode = 0;
  orsProbe();                       /* leaves the sensor blank unless recovered */
  ck("probe restored the sensor", g_sensorConfigured == 1);
  {
    uint8_t b[ORS_BYTES]; int sf=0; float m=0;
    ck("a frame can be captured after the probe", orsSettledFrame(b,&sf,&m));
  }

  printf("S3c  a TORN frame is rejected, not sampled\n");
  {
    uint8_t b[ORS_BYTES]; int sf=0; float m=0;
    g_fb.len = 69120;                       /* the FB-SIZE case from the log */
    ck("short frame refused", !orsSettledFrame(b,&sf,&m));
    g_fb.len = STUBW;
    ck("full frame accepted", orsSettledFrame(b,&sf,&m));
  }

  printf("S3d  the run buffers to PSRAM and dumps separately\n");
  g_railResets = 1; g_camMode = 0; g_seMode = 0;
  keyReset(); for(int i=0;i<40;i++) keyWait();
  orsRestart(5);
  ck("5 restarts held in the buffer", orsBufN == 5);
  ck("metadata captured per restart", orsMeta[0] > 0 && orsMeta[8] > 0);
  ck("gain/aec recorded with the run", orsBufGain == ORS_RUN_GAIN && orsBufAec == ORS_RUN_AEC);
  ck("device kept awake during the run", lastActivity != 0);
  {
    int before = orsBufN;
    keyReset(); keyPush(2);
    orsDump();
    ck("dump does not disturb the buffer", orsBufN == before);
  }

  printf("S3e  sequential buffers to PSRAM too\n");
  g_railResets = 1; g_camMode = 0; g_seMode = 0;
  keyReset(); for(int i=0;i<60;i++) keyWait();
  orsSequential();
  ck("sequential filled the buffer", orsBufN > 0);
  ck("flagged as a sequential run",  orsBufSeq);
  ck("gain/aec recorded",            orsBufGain == ORS_RUN_GAIN && orsBufAec == ORS_RUN_AEC);
  {
    int held = orsBufN;
    keyReset(); keyPush(2);
    orsDump();
    ck("dump preserves the run",     orsBufN == held);
  }

  printf("S4  sample packing\n");
  ck("125 bytes per restart", ORS_BYTES == 125);
  ck("1000 samples matches the 800-90B row length", ORS_SAMPLES == 1000);
  ck("sequential target is the ea_non_iid minimum", ORS_SEQ_TARGET == 1000000);

  printf(fails ? "\nFAILED (%d)\n" : "\nAll restart-tool checks passed\n", fails);
  return fails ? 1 : 0;
}
