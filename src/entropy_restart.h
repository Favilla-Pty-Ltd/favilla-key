// ─────────────────────────────────────────────────────────────────────────────
// entropy_restart.h — camera datasets for NIST SP 800-90B   (Favilla KEY)  [TEST ONLY]
//
// Settings > Device > Restart cap.  Streams over USB serial for the laptop.
//
// Three datasets, in the order they should be run:
//
//   1. PROBE      — does cutting the rail actually reset the sensor?
//   2. SWEEP      — find the gain/exposure operating point worth measuring
//   3. SEQUENTIAL — 1,000,000 samples for ea_non_iid
//   4. RESTART    — 1,000 restarts x 1,000 samples for ea_restart
//
//   ┌─ WHY THE RAIL CYCLE IS A LEGITIMATE "RESTART" ────────────────────────┐
//   │ The noise source is the OV2640, so power-cycling the OV2640 is the     │
//   │ restart. TCA9554 P2 (CAM_EN) gates 3.3 V to all of the camera's        │
//   │ regulators, so cameraPowerDown() removes power at the outermost gate.  │
//   │                                                                        │
//   │ It is also the HARDER test, not a shortcut. Restart testing looks for  │
//   │ correlation BETWEEN restarts; resetting less state makes correlation   │
//   │ MORE likely, not less. So independence under a rail-only cycle implies │
//   │ independence under a full device power cycle. Say that in the writeup  │
//   │ rather than leaving a reviewer to wonder.                              │
//   │                                                                        │
//   │ What it does NOT reset is board temperature. This measures the         │
//   │ camera's power-up state, not a thermal cold start. State which one.    │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ THE TRAP THAT WOULD SILENTLY RUIN THE DATASET ───────────────────────┐
//   │ cameraResumeHW() calls camApplySensorTuning(), which re-applies the    │
//   │ shipping baseline (aec 40, gain 0) after EVERY rail cycle. So a sweep  │
//   │ or a run at a chosen operating point MUST re-apply its own settings    │
//   │ after each resume, or every restart silently reverts to the defaults   │
//   │ and you measure the wrong thing 1,000 times. orsApply() does that.     │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ NEVER THE SEED PATH ─────────────────────────────────────────────────┐
//   │ Raw, pre-hash, measurement only. Behind -D FAVILLA_ENTROPY_RESTART     │
//   │ with a #warning so this build cannot be mistaken for shippable.        │
//   └────────────────────────────────────────────────────────────────────────┘
//
// WIRE FORMAT — same line discipline as entropy_capture.h, so capture_serial.py
// needs only a new src= case:
//   <<<CAP BEGIN src=cam_restart restarts=N samples=1000 gain=G aec=A>>>
//   R:<idx>:<settleFrames>:<mean_x100>      per-restart metadata
//   D:<base64>                              the 1000 sampled LSBs, packed MSB-first
//   ...
//   <<<CAP END restarts=N bytes=NNN>>>
//
// Include ONCE after entropy_capture.h (needs cameraSuspendHW / cameraResumeHW /
// cameraPowerUp / cameraPowerDown, which are defined around L11190-11480).
// Enable with:  -D FAVILLA_ENTROPY_RESTART
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_ENTROPY_RESTART_H
#define FAVILLA_ENTROPY_RESTART_H
#ifdef FAVILLA_ENTROPY_RESTART
#warning "FAVILLA_ENTROPY_RESTART build — RAW entropy dump enabled. NOT SHIPPABLE."

#ifndef C_GREEN
#error "entropy_restart.h must be #included AFTER the colours, display, buttons and the camera power helpers."
#endif

// ── parameters ───────────────────────────────────────────────────────────────
// PARITY WHITENING. One pixel's LSB carries that pixel's permanent DC bias:
// the restart matrix found a pixel that came up the same value 678 times in 999
// independent power cycles. That is a per-die fingerprint (the same physics as
// PRNU), it is static, and static means an attacker does not have to guess it —
// which is why the column estimate bound the whole dataset at 0.899.
//
// Each sample is now the XOR of ORS_WHITEN_K pixels. Bias collapses as
// 2^(k-1)*eps^k, so the worst pixel (eps 0.178) goes 0.678 -> 0.563 at k=2 and
// 0.508 at k=4. With 76,800 pixels and 1000 samples, k=4 uses 4,000 of them.
// The k contributors to one sample are ORS_SAMPLES*stride apart (~19,000 px),
// so they are nowhere near each other — adjacent LSBs agree 0.545.
//
// This removes BIAS, not PREDICTABILITY: whitening a backdoored source makes it
// look perfect. It is also bounded by what goes in — 4 pixels at ~0.95 bits is
// 3.8 bits in for 1 bit out, so the sample genuinely carries its bit.
#define ORS_WHITEN_K     4
#define ORS_SAMPLES      1000   // samples per restart — SP 800-90B restart row length
#define ORS_BYTES        (ORS_SAMPLES / 8)          // 125
#define ORS_SEQ_TARGET   1000000                    // sequential dataset, ea_non_iid minimum
#define ORS_OFF_MS       1500   // rail-off dwell. Long enough for the regulator
                                // output caps to bleed with no load. PROBE tells
                                // you whether it actually is — do not guess.
#define ORS_DUD_RECOVER  16     // consecutive bad frames before a rail-cycle recover
#define ORS_DUD_LIMIT    48     // ...and before giving up on the capture
static uint32_t orsTorn = 0;    // torn/missing frames rejected this run
#define ORS_SETTLE_MIN   4
#define ORS_SETTLE_MAX   40
#define ORS_MAX_STALLS   20     // recovered stalls tolerated across one capture
#define ORS_EST_PIX      1024   // pixels sampled for the frame-mean settle test

// MEASURED OPERATING POINT (lens covered, dev unit, 5 Aug 2026).
// The shipping baseline of gain 0 / aec 40 leaves the dark frame mean at 0.07
// counts — below one LSB, so there is nothing to sample and the frame-to-frame
// change fraction is 0.159 (0.25 bits/bit). At gain 16 / aec 300 the mean is
// 3.20 counts and the change fraction is 0.493, i.e. 0.98 bits/bit — BETTER
// than the lit measurement of 0.918. Everything from gain 8/aec 1200 upward is
// statistically tied at n=1000; 16/300 is the middle of that plateau.
#define ORS_RUN_GAIN 16
#define ORS_RUN_AEC  300
static int  orsGain = ORS_RUN_GAIN;   // agc_gain 0..30
static int  orsAec  = ORS_RUN_AEC;    // aec_value 0..1200 (capped by frame time)
static bool orsAbort = false;

// ── output ───────────────────────────────────────────────────────────────────
static void orsB64(const uint8_t* d, int len){
  static const char* T =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char out[128]; int o=0;
  for(int i=0;i<len;i+=3){
    int n = d[i]<<16;
    if(i+1<len) n |= d[i+1]<<8;
    if(i+2<len) n |= d[i+2];
    out[o++]=T[(n>>18)&63];
    out[o++]=T[(n>>12)&63];
    out[o++]=(i+1<len)?T[(n>>6)&63]:'=';
    out[o++]=(i+2<len)?T[n&63]:'=';
  }
  out[o]=0;
  Serial.print("D:"); Serial.println(out);
}
static void orsStream(const uint8_t* b, int len){
  int i=0; while(i<len){ int c=(len-i)>48?48:(len-i); orsB64(b+i,c); i+=c; }
}

static void orsStatus(const char* l1, const char* l2, uint16_t col){
  spr.fillSprite(C_BG);
  uiHeader("Restart capture", C_AMBER);
  fSet(F_HEAD);  spr.setTextColor(col);   fDrawCentre(l1, 120, 92);  fEnd();
  if(l2){ fSet(F_SMALL); spr.setTextColor(C_DIM); fDrawCentre(l2, 120, 130); fEnd(); }
  fSet(F_SMALL); spr.setTextColor(C_VDIM); fDrawCentre("btn4 aborts", 120, 218); fEnd();
  dispPush();
}
static bool orsCheckAbort(){
  btn4.poll();
  if(btn4.isPressed()){ orsAbort = true; return true; }
  return false;
}

// ── sensor settings ──────────────────────────────────────────────────────────
// MUST be called after every cameraResumeHW(), which re-applies the shipping
// baseline over the top of whatever we set. See the header note.
static void orsApply(){
  sensor_t* s = esp_camera_sensor_get();
  if(!s) return;
  if(s->set_exposure_ctrl) s->set_exposure_ctrl(s, 0);   // manual
  if(s->set_gain_ctrl)     s->set_gain_ctrl(s, 0);       // manual
  if(s->set_aec2)          s->set_aec2(s, 0);
  if(s->set_aec_value)     s->set_aec_value(s, orsAec);
  if(s->set_agc_gain)      s->set_agc_gain(s, orsGain);
  if(s->set_gainceiling)   s->set_gainceiling(s, (gainceiling_t)6);  // let agc_gain reach
  // Leave bpc/wpc/raw_gma/lenc exactly as the shipping tuning left them: this
  // is a measurement of the source AS THE PRODUCT USES IT, not of a sensor
  // configured to flatter itself.
  delay(30);
}

// ── recover the camera into a known-good state ───────────────────────────────
// A rail cycle returns the OV2640 FACTORY-FRESH: frame size, format, PCLK/2 and
// every tuning register are gone. cameraPowerUp() restores power but leaves the
// driver's camSuspended flag false, so cameraStart() later sees "already
// running" and never calls camApplySensorTuning() — the sensor stays blank and
// esp_camera_fb_get() returns nothing for the rest of the session. Going
// through Suspend/Resume is what re-runs the tuning. Anything that cuts the
// rail behind the driver's back MUST end here.
static bool orsRecover(){
  cameraSuspendHW();
  delay(200);
  if(!cameraResumeHW()) return false;
  orsApply();
  return true;
}

// ── one settled frame ────────────────────────────────────────────────────────
// The warm-up transient does not reproduce — three captures gave three shapes,
// two anti-correlated at -0.71 — so a constant discard count is fitted to one
// case. Settle on the frame mean instead and report how many frames it took;
// that per-restart number is itself a result worth having.
static bool orsSettledFrame(uint8_t out[ORS_BYTES], int* settleFrames, float* meanOut){
  float prev = -1.0f; int stable = 0, frames = 0, duds = 0;
  camera_fb_t* fb = nullptr;
  while(frames < ORS_SETTLE_MAX){
    // esp_camera_fb_get() can block for a long time on a sensor that is not
    // producing. Feed the watchdog on BOTH sides of it, and give up after a
    // run of duds rather than spinning until the WDT fires.
    esp_task_wdt_reset();
    fb = esp_camera_fb_get();
    esp_task_wdt_reset();
    // A TORN frame is the dangerous case, not a missing one. The driver logs
    // "cam_hal: FB-SIZE: 69120 != 76800" when the DVP drops lines; that buffer
    // is still thousands of bytes long, so a size floor lets it through and the
    // stride then samples shifted pixels — which reads as change that is not
    // noise. Demand the exact frame size, as entropy_capture.h does.
    if(!fb || fb->len != (size_t)fb->width * (size_t)fb->height){
      if(fb) esp_camera_fb_return(fb);
      duds++;
      orsTorn++;                       // counted and reported, not silently dropped
      // The DVP tears intermittently ("cam_hal: FB-SIZE: 69120 != 76800"). A
      // short burst is normal; a sustained one means the sensor needs putting
      // back. Recover once mid-run before giving up, so an hour-long capture is
      // not lost to a few seconds of bad frames.
      if(duds == ORS_DUD_RECOVER) orsRecover();
      if(duds > ORS_DUD_LIMIT) return false;
      delay(20);
      continue;
    }
    duds = 0;
    size_t st = fb->len / ORS_EST_PIX;
    uint32_t sum = 0;
    for(int i=0;i<ORS_EST_PIX;i++) sum += fb->buf[i*st];
    float m = (float)sum / (float)ORS_EST_PIX;
    frames++;
    if(prev >= 0.0f && fabsf(m - prev) < 0.5f) stable++; else stable = 0;
    prev = m;
    if(frames >= ORS_SETTLE_MIN && stable >= 3){
      // This frame is settled — sample it and keep it.
      size_t stride = fb->len / ((size_t)ORS_SAMPLES * ORS_WHITEN_K);
      memset(out, 0, ORS_BYTES);
      for(int i=0;i<ORS_SAMPLES;i++){
        int bit = 0;
        for(int j=0;j<ORS_WHITEN_K;j++)
          bit ^= fb->buf[((size_t)i + (size_t)j*ORS_SAMPLES) * stride] & 1;
        if(bit) out[i>>3] |= (uint8_t)(1u << (7-(i&7)));
      }
      esp_camera_fb_return(fb);
      *settleFrames = frames; *meanOut = m;
      return true;
    }
    esp_camera_fb_return(fb);
    esp_task_wdt_reset();
    delay(5);
  }
  *settleFrames = frames; *meanOut = prev;
  return false;   // never settled
}

// ── 1. PROBE — did the rail cut actually reset the sensor? ───────────────────
// The decisive check. Write a non-default value to a sensor register, cut the
// rail, bring it back, and read it. If OUR value survives, the sensor never
// lost power: regulator output caps held it up, or the ESP32 back-powered it
// through the DVP/SCCB/XCLK pin ESD diodes. Every "restart" in the dataset
// would then be a continuation, and the whole run would be worthless.
//
// Uses cameraPowerDown/Up directly rather than Suspend/Resume, so that
// camApplySensorTuning() does NOT run and overwrite the probe value for us.
// REG04 in the sensor bank carries hmirror/vflip, which the shipping tuning
// sets to 1/1 — so after a real reset it must read back as the factory default,
// not as our value.
#define ORS_PROBE_BANK 0xFF
#define ORS_PROBE_SEL  0x01     // 0x01 = sensor bank
#define ORS_PROBE_REG  0x04     // REG04

static void orsProbe(){
  orsStatus("Power probe", "cutting the camera rail", C_AMBER);
  Serial.println("<<<PROBE BEGIN>>>");

  sensor_t* s = esp_camera_sensor_get();
  if(!s || !s->set_reg || !s->get_reg){
    Serial.println("PROBE: no sensor register access");
    orsStatus("Probe FAIL", "no register access", C_RED);
    delay(2500); return;
  }
  s->set_reg(s, ORS_PROBE_BANK, 0xFF, ORS_PROBE_SEL);
  int before = s->get_reg(s, ORS_PROBE_REG, 0xFF);
  int mark   = (before ^ 0xC0) & 0xFF;          // flip the mirror/flip bits
  s->set_reg(s, ORS_PROBE_REG, 0xFF, mark);
  int wrote  = s->get_reg(s, ORS_PROBE_REG, 0xFF);
  Serial.printf("PROBE: before=0x%02X wrote=0x%02X readback=0x%02X\n", before, mark, wrote);

  if(wrote != mark){
    // The write did not take, so the probe cannot conclude anything. Change
    // ORS_PROBE_REG rather than trusting a null result.
    Serial.println("PROBE: register not writable — INCONCLUSIVE");
    orsStatus("Inconclusive", "reg not writable", C_AMBER);
    delay(3000); return;
  }

  cameraPowerDown();
  delay(ORS_OFF_MS);
  cameraPowerUp();
  delay(50);

  s->set_reg(s, ORS_PROBE_BANK, 0xFF, ORS_PROBE_SEL);
  int after = s->get_reg(s, ORS_PROBE_REG, 0xFF);
  Serial.printf("PROBE: after=0x%02X (mark=0x%02X, orig=0x%02X) off_ms=%d\n",
                after, mark, before, ORS_OFF_MS);

  bool reset = (after != mark);
  // The rail cut went behind the driver's back, so the sensor is now factory
  // fresh and the driver does not know it. Put both back in step before
  // returning, or every capture after this probe fails with no_frame.
  bool rec = orsRecover();
  Serial.printf("<<<PROBE END reset=%d recovered=%d>>>\n", (int)reset, (int)rec);
  if(reset){
    orsStatus("Rail cycle OK", "sensor really resets", C_GREEN);
  } else {
    // Do not proceed to a dataset on this result.
    orsStatus("NOT RESETTING", "caps hold, or pin back-power", C_RED);
  }
  delay(3500);
}

// ── 2. SWEEP — find the operating point worth measuring ──────────────────────
// The shipping baseline is aec 40 / gain 0: minimum gain and a sub-millisecond
// integration time. At those settings dark current has no time to accumulate,
// so a covered-lens capture measures READ noise, not dark shot noise — which is
// why half the pixels never moved. Park et al. (IEEE Access 2019) used gain 8
// and 270 ms to get dark shot noise dominant. This sweeps toward that.
//
// Report per point: settled mean, the fraction of sampled bits that CHANGE
// between two settled frames, and the frozen fraction. Watch the CHANGE figure,
// not the frame variance — raising gain amplifies fixed-pattern noise too, and
// FPN is static, so a per-frame variance rise proves nothing.
static void orsSweep(){
  if(!orsRecover()){
    Serial.println("<<<CAP END error=camera_recover_failed>>>");
    orsStatus("Camera FAIL", "could not resume", C_RED); delay(2500); return;
  }
  static const int GAINS[] = { 0, 8, 16, 30 };
  static const int AECS[]  = { 40, 300, 800, 1200 };
  orsAbort = false;
  Serial.println("<<<SWEEP BEGIN>>>");
  Serial.println("gain,aec,mean,settleFrames,changeFrac,frozenFrac,note");
  uint8_t a[ORS_BYTES], b[ORS_BYTES];
  for(int gi=0; gi<4 && !orsAbort; gi++){
    for(int ai=0; ai<4 && !orsAbort; ai++){
      orsGain = GAINS[gi]; orsAec = AECS[ai];
      char l2[40]; snprintf(l2,sizeof l2,"gain %d  aec %d", orsGain, orsAec);
      orsStatus("Sweep", l2, C_AMBER);
      orsApply();
      int sf=0; float mean=0;
      if(!orsSettledFrame(a,&sf,&mean)){
        Serial.printf("%d,%d,,,,,no_frame_1\n",orsGain,orsAec);
        orsRecover(); continue;
      }
      int sf2=0; float m2=0;
      if(!orsSettledFrame(b,&sf2,&m2)){
        Serial.printf("%d,%d,,,,,no_frame_2\n",orsGain,orsAec);
        orsRecover(); continue;
      }
      int changed=0;
      for(int i=0;i<ORS_SAMPLES;i++){
        int x=(a[i>>3]>>(7-(i&7)))&1, y=(b[i>>3]>>(7-(i&7)))&1;
        if(x!=y) changed++;
      }
      // "frozen" here is the same-bit fraction, i.e. 1 - change. Reported
      // separately so the CSV reads the way the paper talks.
      Serial.printf("%d,%d,%.2f,%d,%.4f,%.4f\n", orsGain, orsAec, mean, sf,
                    (double)changed/ORS_SAMPLES, 1.0-(double)changed/ORS_SAMPLES);
      esp_task_wdt_reset();
      orsCheckAbort();
    }
  }
  Serial.println("<<<SWEEP END>>>");
  orsGain = ORS_RUN_GAIN; orsAec = ORS_RUN_AEC; orsApply();  // back to the run point
  orsStatus("Sweep done", "any button", C_GREEN);
  delay(300);
  while(true){
    btn1.poll(); btn2.poll(); btn4.poll();
    if(btn1.isPressed() || btn2.isPressed() || btn4.isPressed()) break;
    esp_task_wdt_reset(); delay(5);
  }
}

// ── buffered capture, so the run does not need USB attached ──────────────────
// The seed path runs on battery with the radios off. Streaming the dataset over
// USB measures the camera in a NOISIER electrical environment than the product
// actually uses: the charge path is switching and the CDC peripheral is active
// throughout. Buffering into PSRAM lets the whole run happen unplugged, then
// dump it once USB is back. 1000 restarts is 125 KB of data + 4 KB of metadata
// against ~7.8 MB free, so it costs nothing.
#define ORS_MAX_RESTARTS 1000
static uint8_t*  orsBuf     = nullptr;   // ORS_MAX_RESTARTS * ORS_BYTES
static int16_t*  orsMeta    = nullptr;   // 2 per restart: settleFrames, mean*100
static int       orsBufN    = 0;         // rows actually held
static int       orsBufGain = 0, orsBufAec = 0;
static bool      orsBufSeq  = false;     // true = sequential run, false = restart matrix
// A sequential 1M is 1000 frames x 125 bytes = exactly the same 125,000 bytes
// as a 1000-restart matrix, so both share one PSRAM allocation. Only one run is
// held at a time; starting either discards the previous one.

static bool orsBufAlloc(){
  if(orsBuf && orsMeta) return true;
  orsBuf  = (uint8_t*)ps_malloc((size_t)ORS_MAX_RESTARTS * ORS_BYTES);
  orsMeta = (int16_t*)ps_malloc((size_t)ORS_MAX_RESTARTS * 2 * sizeof(int16_t));
  if(!orsBuf || !orsMeta){
    if(orsBuf){ free(orsBuf); orsBuf=nullptr; }
    if(orsMeta){ free(orsMeta); orsMeta=nullptr; }
    return false;
  }
  return true;
}

// Dump whatever is held. Separate from the run so a failed serial capture can
// be repeated without redoing the hour.
static void orsDump(){
  if(!orsBuf || orsBufN<=0){
    orsStatus("Nothing held", "run a capture first", C_AMBER);
    delay(2000); return;
  }
  char s[40];
  snprintf(s, sizeof s, "%d restarts", orsBufN);
  orsStatus("Dumping", s, C_GREEN);
  if(orsBufSeq)
    Serial.printf("<<<CAP BEGIN src=cam_seq fmt=bits samples=%lu gain=%d aec=%d whiten=%d buffered=1 torn=%lu>>>\n",
                  (unsigned long)((uint32_t)orsBufN*ORS_SAMPLES), orsBufGain, orsBufAec, ORS_WHITEN_K,
                  (unsigned long)orsTorn);
  else
    Serial.printf("<<<CAP BEGIN src=cam_restart fmt=bits restarts=%d samples=%d off_ms=%d gain=%d aec=%d whiten=%d buffered=1 torn=%lu>>>\n",
                  orsBufN, ORS_SAMPLES, ORS_OFF_MS, orsBufGain, orsBufAec, ORS_WHITEN_K,
                  (unsigned long)orsTorn);
  for(int r=0; r<orsBufN; r++){
    Serial.printf("R:%d:%d:%d\n", r, (int)orsMeta[r*2], (int)orsMeta[r*2+1]);
    orsStream(orsBuf + (size_t)r*ORS_BYTES, ORS_BYTES);
    esp_task_wdt_reset();
  }
  if(orsBufSeq)
    Serial.printf("<<<CAP END samples=%lu bytes=%lu>>>\n",
                  (unsigned long)((uint32_t)orsBufN*ORS_SAMPLES),
                  (unsigned long)((uint32_t)orsBufN*ORS_BYTES));
  else
    Serial.printf("<<<CAP END restarts=%d bytes=%lu>>>\n",
                  orsBufN, (unsigned long)((uint32_t)orsBufN*ORS_BYTES));
  orsStatus("Dump done", "any button", C_GREEN);
  delay(300);
  while(true){
    btn1.poll(); btn2.poll(); btn4.poll();
    if(btn1.isPressed() || btn2.isPressed() || btn4.isPressed()) break;
    esp_task_wdt_reset(); delay(5);
  }
}

// ── 3. SEQUENTIAL — the ea_non_iid dataset ───────────────────────────────────
// One million samples, no restarts. ea_restart needs the sequential min-entropy
// (H_I) as an input, so this has to exist before the restart dataset means
// anything.
static void orsSequential(){
  if(!orsBufAlloc()){
    orsStatus("No PSRAM", "cannot buffer the run", C_RED); delay(2500); return;
  }
  if(!orsRecover()){
    orsStatus("Camera FAIL", "could not resume", C_RED); delay(2500); return;
  }
  orsAbort = false;
  uint8_t buf[ORS_BYTES];
  // BUFFERED, exactly like the restart matrix. The sequential dataset supplies
  // H_I for ea_restart, and SP 800-90B assumes both datasets come from the same
  // source under the SAME operating conditions — so if the restart matrix is
  // captured on battery with the radios down, this one has to be too. Streaming
  // it over USB was the reason those two datasets did not match.
  orsBufN = 0; orsBufGain = orsGain; orsBufAec = orsAec; orsBufSeq = true;
  orsTorn = 0;
  uint32_t lastUi = 0; int stalls = 0;
  const int NFRAMES = ORS_SEQ_TARGET / ORS_SAMPLES;   // 1000
  while(orsBufN < NFRAMES && orsBufN < ORS_MAX_RESTARTS && !orsAbort){
    int sf=0; float m=0;
    if(!orsSettledFrame(buf,&sf,&m)){
      if(++stalls > ORS_MAX_STALLS) break;
      orsRecover();
      continue;                    // try again rather than ending the run
    }
    memcpy(orsBuf + (size_t)orsBufN*ORS_BYTES, buf, ORS_BYTES);
    orsMeta[orsBufN*2]   = (int16_t)sf;
    orsMeta[orsBufN*2+1] = (int16_t)(m*100.0f+0.5f);
    orsBufN++;
    lastActivity = millis();       // no auto-sleep, no light sleep, unattended
    if(millis()-lastUi > 400){
      char s[40]; snprintf(s,sizeof s,"%lu / %d",
                           (unsigned long)((uint32_t)orsBufN*ORS_SAMPLES), ORS_SEQ_TARGET);
      orsStatus("Sequential", s, C_GREEN); lastUi=millis();
    }
    esp_task_wdt_reset();
    orsCheckAbort();
  }
  char s[48];
  snprintf(s, sizeof s, "%lu samples, %lu torn",
           (unsigned long)((uint32_t)orsBufN*ORS_SAMPLES), (unsigned long)orsTorn);
  orsStatus("Sequential done", s, (orsBufN < NFRAMES) ? C_AMBER : C_GREEN);
  delay(1500);
  orsStatus("Held in PSRAM", "plug USB, then Dump", C_GREEN);
  delay(300);
  while(true){
    btn1.poll(); btn2.poll(); btn4.poll();
    if(btn1.isPressed() || btn2.isPressed() || btn4.isPressed()) break;
    esp_task_wdt_reset(); delay(5);
  }
}

// ── 4. RESTART — the ea_restart dataset ──────────────────────────────────────
// N restarts x 1000 samples. Each restart is a real rail cycle, so the sensor
// comes back factory-fresh and has to walk its warm-up again. settleFrames and
// the settled mean are logged per restart: that series is also the answer to
// the ~15% per-boot effective-gain variation that §4.4 lists as unexplained.
// If the spread appears across rail cycles alone it is camera-side analog
// settling; if it does not, it is board thermal state.
static void orsRestart(int nRestarts){
  if(!orsRecover()){
    Serial.println("<<<CAP END error=camera_recover_failed>>>");
    orsStatus("Camera FAIL", "could not resume", C_RED); delay(2500); return;
  }
  orsAbort = false;
  if(nRestarts > ORS_MAX_RESTARTS) nRestarts = ORS_MAX_RESTARTS;
  if(!orsBufAlloc()){
    orsStatus("No PSRAM", "cannot buffer the run", C_RED); delay(2500); return;
  }
  uint8_t buf[ORS_BYTES];
  orsBufN = 0; orsBufGain = orsGain; orsBufAec = orsAec; orsBufSeq = false;
  int done = 0, failed = 0;
  orsTorn = 0;
  uint32_t t0 = millis();
  for(int r=0; r<nRestarts && !orsAbort; r++){
    cameraSuspendHW();            // quiesce DVP, park pins, rail OFF
    delay(ORS_OFF_MS);
    if(!cameraResumeHW()){ failed++; continue; }
    orsApply();                   // resume re-applied the shipping baseline — undo it
    int sf=0; float m=0;
    if(!orsSettledFrame(buf,&sf,&m)){ failed++; orsRecover(); continue; }
    memcpy(orsBuf + (size_t)orsBufN*ORS_BYTES, buf, ORS_BYTES);
    orsMeta[orsBufN*2]   = (int16_t)sf;
    orsMeta[orsBufN*2+1] = (int16_t)(m*100.0f+0.5f);
    orsBufN++;
    done++;
    // Keep the device awake for the whole run: the auto-sleep timer and the
    // dim-then-light-sleep path would both otherwise fire during an hour of
    // unattended capture, and light sleep mid-frame corrupts a DVP grab.
    lastActivity = millis();
    if((r & 7) == 0){
      uint32_t el = (millis()-t0)/1000;
      char s[48]; snprintf(s,sizeof s,"%d / %d   %lus", done, nRestarts, (unsigned long)el);
      orsStatus("Restarts", s, C_GREEN);
    }
    esp_task_wdt_reset();
    orsCheckAbort();
  }
  char s[48]; snprintf(s,sizeof s,"%d held, %d failed", done, failed);
  orsStatus("Restarts done", s, failed ? C_AMBER : C_GREEN);
  delay(1500);
  orsStatus("Held in PSRAM", "plug USB, then Dump", C_GREEN);
  delay(300);
  while(true){
    btn1.poll(); btn2.poll(); btn4.poll();
    if(btn1.isPressed() || btn2.isPressed() || btn4.isPressed()) break;
    esp_task_wdt_reset(); delay(5);
  }
}

// ── menu ─────────────────────────────────────────────────────────────────────
static void runEntropyRestart(){
  static const char* ITEMS[] = { "1  Power probe", "2  Gain/exposure sweep",
                                 "3  Sequential 1M", "4  Restart dataset",
                                 "5  Dump held run" };
  static const int NREST[] = { 100, 1000 };
  int sel = 0, ni = 0;

  pwrBoost();
  pmHoldWake();           // no light sleep during captures — now actually enforced
  cameraStart();          // resident driver up for the whole session
  orsApply();

  while(true){
    spr.fillSprite(C_BG);
    uiHeader("Restart capture", C_AMBER);
    fSet(F_SMALL); spr.setTextColor(C_DIM);
    fDrawCentre("RAW dump over USB serial", 120, 34); fEnd();
    for(int i=0;i<5;i++){
      fSet(F_BODY); spr.setTextColor(i==sel ? C_GREEN : C_MUTED);
      spr.drawString(ITEMS[i], 26, 56 + i*24); fEnd();
    }
    char s[48];
    snprintf(s,sizeof s,"restarts %d   gain %d   aec %d", NREST[ni], orsGain, orsAec);
    fSet(F_SMALL); spr.setTextColor(C_VDIM); fDrawCentre(s, 120, 186); fEnd();
    fSet(F_SMALL); spr.setTextColor(C_DIM);
    fDrawCentre("btn1 move  btn2 run  btn3 count  btn4 exit", 120, 220); fEnd();
    dispPush();

    while(true){
      btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
      bool k1=btn1.isPressed(), k2=btn2.isPressed(), k3=btn3.isPressed(), k4=btn4.isPressed();
      if(k1){ sel=(sel+1)%5; break; }
      if(k3){ ni=(ni+1)&1; break; }
      if(k2){
        switch(sel){
          case 0: orsProbe();       break;
          case 1: orsSweep();       break;
          case 2: orsSequential();  break;
          case 3: orsRestart(NREST[ni]); break;
          default: orsDump();       break;
        }
        break;
      }
      if(k4){ cameraStop(); pwrIdle(); pmReleaseWake(); return; }
      esp_task_wdt_reset(); delay(10);
    }
  }
}

#endif // FAVILLA_ENTROPY_RESTART
#endif // FAVILLA_ENTROPY_RESTART_H
