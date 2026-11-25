// ── LIS2DW12 accelerometer (KeyV4 board, replaces the BMA400) ────────────────
// Same public surface as bma400.h's BMA400 struct, so main.cpp, the Settings
// screen and cipher_steps.h compile unchanged against `accel` (see the
// AccelDrv alias in main.cpp). Differences that matter:
//   * no pedometer: readSteps() returns false, so proof-of-walk reports no
//     hardware (step counting was ruled a nice-to-have, 18 Sep 2026);
//   * INT1/INT2 are not routed (ruling: motion-lock is polled, no motion wake
//     from sleep), so this is a pure polled driver - the motion state machine
//     is the BMA400 one, byte for byte, with the output scaled to the same
//     counts (1 g = 512) so the 0-10 sensitivity dial keeps its meaning;
//   * SA0 -> GND = address 0x18 (0x19 if tied high), CS -> VDDIO = I2C.
// Registers per ST DS11648 (LIS2DW12). Included from main.cpp AFTER the
// I2C_LOCK macros exist, exactly like bma400.h.
#pragma once
#include <math.h>
#ifndef Wire_h
#include <Wire.h>
#endif

#define LIS2DW12_REG_WHO_AM_I  0x0F   // = 0x44
#define LIS2DW12_REG_CTRL1     0x20   // ODR[7:4] MODE[3:2] LP_MODE[1:0]
#define LIS2DW12_REG_CTRL2     0x21   // BOOT[7] SOFT_RESET[6] BDU[3] IF_ADD_INC[2]
#define LIS2DW12_REG_CTRL3     0x22
#define LIS2DW12_REG_CTRL4_INT1 0x23  // INT1_SINGLE_TAP[6] INT1_TAP(double)[3]: route so the event latches even with the pad unconnected
#define LIS2DW12_REG_CTRL6     0x25   // BW_FILT[7:6] FS[5:4] LOW_NOISE[2]
#define LIS2DW12_REG_STATUS    0x27   // DRDY[0]
#define LIS2DW12_REG_CTRL7     0x3F   // INTERRUPTS_ENABLE[5] - embedded functions need it even with no INT pin routed
#define LIS2DW12_REG_TAP_THS_X 0x30
#define LIS2DW12_REG_TAP_THS_Y 0x31
#define LIS2DW12_REG_TAP_THS_Z 0x32   // TAP_X_EN[7] TAP_Y_EN[6] TAP_Z_EN[5] THS[4:0]
#define LIS2DW12_REG_INT_DUR   0x33   // LATENCY[7:4] QUIET[3:2] SHOCK[1:0]
#define LIS2DW12_REG_WAKE_THS  0x34   // SINGLE_DOUBLE_TAP[7]
#define LIS2DW12_REG_FIFO_CTRL 0x2E   // FMode[7:5] (110 = continuous) FTH[4:0]
#define LIS2DW12_REG_FIFO_SMPL 0x2F   // FTH[7] OVR[6] DIFF[5:0] = samples waiting
#define LIS2DW12_REG_TAP_SRC   0x39   // TAP_IA[6] SINGLE[5] DOUBLE[4] SIGN[3] X[2] Y[1] Z[0]; reset on read (LIR)
#define LIS2DW12_CTRL1_TAP     0x74   // ODR 400 Hz in HIGH-PERFORMANCE mode: in low-power mode the same ODR code caps at 200 Hz and the tap engine needs >= 400 Hz (first cut used 0x71 and never fired)
#define LIS2DW12_CTRL3_LIR     0x10   // latch the tap source until TAP_SRC is read (we poll, no INT pin)
#define LIS2DW12_REG_OUT_X_L   0x28
#define LIS2DW12_WHO_AM_I      0x44
// CTRL1: ODR 25 Hz (0011), low-power mode (00), LP mode 2 = 14-bit (01)
#define LIS2DW12_CTRL1_RUN     0x31
#define LIS2DW12_CTRL1_OFF     0x00   // ODR 0000 = power-down (~<1 uA)
#define LIS2DW12_CTRL2_INIT    0x0C   // BDU + address auto-increment
#define LIS2DW12_CTRL6_INIT    0x04   // +-2 g, low-noise on, default filter

struct LIS2DW12 {
  bool    ok   = false;
  uint8_t addr = 0x18;

  bool _writeReg(uint8_t reg, uint8_t val) {
    I2C_LOCK();
    Wire.beginTransmission(addr);
    Wire.write(reg); Wire.write(val);
    bool r = (Wire.endTransmission() == 0);
    I2C_UNLOCK();
    return r;
  }
  bool _readRegs(uint8_t reg, uint8_t* buf, uint8_t n) {
    // Polled every main-loop tick (motion lock, steps, taps). Never wait on
    // the bus: a G0 op can hold it for most of a second and the UI would
    // stall with it. A skipped sample is harmless; the next tick retries.
    if (!I2C_TRYLOCK(20)) return false;
    Wire.beginTransmission(addr);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0) { I2C_UNLOCK(); return false; }
    uint8_t got = Wire.requestFrom(addr, n);
    if (got != n) { I2C_UNLOCK(); return false; }
    for (uint8_t i = 0; i < n; i++) buf[i] = Wire.read();
    I2C_UNLOCK();
    return true;
  }
  uint8_t _readReg(uint8_t reg) { uint8_t v = 0xFF; _readRegs(reg, &v, 1); return v; }
  bool _ackAt(uint8_t a) {
    I2C_LOCK(); Wire.beginTransmission(a); bool r = (Wire.endTransmission() == 0); I2C_UNLOCK(); return r;
  }

  // Find the part (0x18 then 0x19), check WHO_AM_I, soft-reset, configure.
  bool init() {
    ok = false;
    if      (_ackAt(0x18)) addr = 0x18;
    else if (_ackAt(0x19)) addr = 0x19;
    else { Serial.println("[LIS2DW12] no ACK at 0x18/0x19"); return false; }
    uint8_t who = _readReg(LIS2DW12_REG_WHO_AM_I);
    Serial.printf("[LIS2DW12] ACK at 0x%02X, WHO_AM_I = 0x%02X (expect 0x44)\n", addr, who);
    if (who != LIS2DW12_WHO_AM_I) return false;
    _writeReg(LIS2DW12_REG_CTRL2, 0x40);            // SOFT_RESET
    delay(5);
    if (!_writeReg(LIS2DW12_REG_CTRL2, LIS2DW12_CTRL2_INIT)) return false;
    if (!_writeReg(LIS2DW12_REG_CTRL6, LIS2DW12_CTRL6_INIT)) return false;
    if (!_writeReg(LIS2DW12_REG_CTRL1, LIS2DW12_CTRL1_RUN))  return false;
    delay(50);                                       // first samples at 25 Hz
    uint8_t c1 = _readReg(LIS2DW12_REG_CTRL1), c6 = _readReg(LIS2DW12_REG_CTRL6);
    Serial.printf("[LIS2DW12] CTRL1=0x%02X CTRL6=0x%02X (want 0x%02X / 0x%02X)\n", c1, c6, LIS2DW12_CTRL1_RUN, LIS2DW12_CTRL6_INIT);
    ok = (c1 == LIS2DW12_CTRL1_RUN);
    return ok;
  }

  // ── software pedometer ───────────────────────────────────────────────────
  // The LIS2DW12 has no step engine, but the BMA400 only ever counted while
  // the KEY was awake anyway (goSleep() put it in SLEEP), so an awake-only
  // software counter is the same feature. Peak detection on |a| at 25 Hz:
  // a step is a magnitude peak >= STEP_PEAK counts above the slow baseline
  // (1 g = 512 counts here, so ~0.16 g), no sooner than STEP_MIN_MS after the
  // last one (walking cadence <= ~3.3 Hz), and the first peak after a pause
  // needs a second within STEP_MAX_MS to confirm (kills single knocks).
  // stepTick() must be called from the main loop whenever the device is awake;
  // readSteps() returns the count since boot, which is exactly what
  // cipher_steps.h expects from the hardware counter (it keeps its own base).
  static const int32_t  STEP_PEAK   = 80;
  static const uint32_t STEP_MIN_MS = 400;   // 2.5 steps/s max; toe-off bumps at 250-350 ms are rejected
  static const uint32_t STEP_MAX_MS = 2000;
  uint32_t stepCount = 0;
  uint32_t stepLastMs = 0, stepLastPeakMs = 0, stepSampleMs = 0;
  int32_t  stepBase = 512;           // slow-tracked |a| (gravity)
  int32_t  stepPrev = 0;             // previous high-passed magnitude
  bool     stepRising = false, stepPending = false;
  bool     stepArmed  = true;        // re-arms only once |a| has fallen back below half the threshold (one count per impact)
  void stepTick() {
    if (!ok) return;
    if (batchOn) { batchDrain(false); return; }   // 11cf: dark: the FIFO holds the samples, drained once a second
    uint32_t now = millis();
    if (now - stepSampleMs < 40) return;   // 25 Hz
    stepSampleMs = now;
    int16_t x, y, z;
    if (!read(x, y, z)) return;
    stepFeed(x, y, z, now);
  }
  // One sample at time `now` (11cf: a FIFO sample carries its own time, 40 ms apart).
  void stepFeed(int16_t x, int16_t y, int16_t z, uint32_t now) {
    int32_t mag = (int32_t)sqrtf((float)x * x + (float)y * y + (float)z * z);
    stepBase += (mag - stepBase) >> 5;     // ~1.3 s time constant
    int32_t hp = mag - stepBase;
    hp = (hp + stepPrev) / 2;                                            // 2-tap smoothing: kills the secondary bump
    bool peak = stepRising && hp < stepPrev && stepPrev >= STEP_PEAK;   // just passed a local max
    stepRising = hp > stepPrev;
    stepPrev = hp;
    if (hp < STEP_PEAK / 2) stepArmed = true;                            // must come back down before the next count
    // 11cf: signed gaps: a FIFO sample's time can sit a few ms before a stamp taken just before the dark began
    if (!peak || !stepArmed || (int32_t)(now - stepLastPeakMs) < (int32_t)STEP_MIN_MS) return;
    stepArmed = false;
    uint32_t gap = (int32_t)(now - stepLastPeakMs) > 0 ? now - stepLastPeakMs : 0;
    stepLastPeakMs = now;
    if (gap > STEP_MAX_MS) { stepPending = true; return; }   // first peak after a pause: wait for a second
    if (stepPending) { stepPending = false; stepCount += 2; } else stepCount += 1;
    stepLastMs = now;
  }
  bool readSteps(uint32_t& out, uint8_t* activity = nullptr) {
    if (!ok) { if (activity) *activity = 0; return false; }
    out = stepCount;
    if (activity) *activity = (millis() - stepLastMs < STEP_MAX_MS) ? 1 : 0;   // 1 = walking
    return true;
  }

  // Acceleration in BMA400-equivalent counts (1 g = 512) so the motion-lock
  // thresholds below carry over unchanged. 14-bit left-justified data: raw16
  // >> 2 gives 0.244 mg/LSB (1 g = 4096); a further >> 3 lands on 512/g.
  bool read(int16_t& x, int16_t& y, int16_t& z) {
    uint8_t b[6];
    if (!_readRegs(LIS2DW12_REG_OUT_X_L, b, 6)) return false;
    int16_t rx = (int16_t)((b[1] << 8) | b[0]);
    int16_t ry = (int16_t)((b[3] << 8) | b[2]);
    int16_t rz = (int16_t)((b[5] << 8) | b[4]);
    x = (int16_t)(rx >> 5); y = (int16_t)(ry >> 5); z = (int16_t)(rz >> 5);
    return true;
  }

  // ── double tap (28 Sep 2026): "knock twice to bring the hotspot back" ────
  // The part's own tap engine, polled through TAP_SRC because INT1/INT2 are
  // not routed. Armed only while the hotspot is parked (apPark), since it
  // needs 400 Hz ODR (~+40 uA, irrelevant next to the AP it replaces).
  // Threshold: 5-bit, 1 LSB = FS/32 = 62.5 mg at +-2 g; 10 = ~0.6 g, a firm
  // knock on the aluminium case, not a bump in a pocket. INT_DUR at 400 Hz:
  // SHOCK 2 = 40 ms max tap width, QUIET 1 = 10 ms settle, LATENCY 7 = 560 ms
  // window for the second tap. read()/stepTick()/tickMotion() keep working
  // at the higher ODR - they just see a fresher sample.
  static const uint8_t TAP_THS = 2;    // hardware engine, 0.125 g: bench 28 Sep showed knocks reach the sensor at only 0.15-0.17 g through the case
  // Software double tap on the FIFO stream (the real detector at these levels;
  // the hardware engine's 62.5 mg steps are too coarse). A tap = |a|-1g rising
  // through SW_TAP_THS counts (bench: knocks 79-86, handling 27-52); it must
  // fall back under half that before the next one counts; two taps between
  // SW_GAP_MIN and SW_GAP_MAX apart = double.
  // Bench 28 Sep: amplitude alone cannot separate a knock (0.16-0.42 g) from
  // handling (0.05-0.25 g). SHAPE can: a knock is a spike SW_MAX_WIDTH samples
  // wide at most (6 = 15 ms at 400 Hz) that comes out of SW_QUIET_MIN samples
  // of stillness (24 = 60 ms) and drops straight back; handling is a hump
  // 100 ms+ wide. Bursts wider than SW_MAX_WIDTH are rejected and also cancel
  // a pending first tap, so a knock followed by a grab is not a double.
  // Second bench pass: every knock is a 2-6 sample spike followed ONE sample
  // later by the case ringing (as tall, 10-30 wide). Judging the ring as
  // movement cancelled every first tap, so bursts inside SW_DEAD_MS after a
  // tap are ignored outright. Hard knocks clip near the +-2 g full scale,
  // which flattens the spike to 17-27 wide; "eqwidth" = sum(dev)/peak is the
  // energy-equivalent width - small for a spike even when clipped, large for
  // a hump - and a burst passes on EITHER raw width or eqwidth.
  static const int32_t  SW_TAP_THS = 70;
  static const uint16_t SW_MAX_WIDTH = 8, SW_MAX_EQWIDTH = 7, SW_QUIET_MIN = 24;
  static const uint32_t SW_GAP_MIN = 100, SW_GAP_MAX = 700, SW_DEAD_MS = 60;
  bool     swPending = false, swDouble = false;
  uint32_t swLastTapMs = 0;
  uint16_t swBurst = 0, swQuiet = 0, swBurstQuietBefore = 0;
  int32_t  swBurstPeak = 0, swBurstSum = 0;
  bool tapArmed = false;
  bool tapArm() {
    if (!ok || tapArmed) return tapArmed;
    _writeReg(LIS2DW12_REG_CTRL1,     LIS2DW12_CTRL1_TAP);
    _writeReg(LIS2DW12_REG_TAP_THS_X, TAP_THS);
    _writeReg(LIS2DW12_REG_TAP_THS_Y, TAP_THS);
    _writeReg(LIS2DW12_REG_TAP_THS_Z, (uint8_t)(0xE0 | TAP_THS));   // all three axes
    _writeReg(LIS2DW12_REG_INT_DUR,   0x76);
    _writeReg(LIS2DW12_REG_WAKE_THS,  0x80);                         // double-tap mode
    _writeReg(LIS2DW12_REG_CTRL3,     LIS2DW12_CTRL3_LIR);
    _writeReg(LIS2DW12_REG_CTRL4_INT1, 0x48);                        // single + double tap -> INT1 (pad not routed; this is what makes LIR latch the source)
    _writeReg(LIS2DW12_REG_CTRL7,     0x20);                         // INTERRUPTS_ENABLE
    _writeReg(LIS2DW12_REG_FIFO_CTRL, 0xDF);                         // FIFO continuous, 32 deep = 80 ms of 400 Hz history for the peak log
    tapPeak = 0; tapPeakMs = millis(); tapFifoN = 0;
    swPending = false; swDouble = false; swLastTapMs = 0; swBurst = 0; swQuiet = 0;
    delay(10);
    (void)_readReg(LIS2DW12_REG_TAP_SRC);                            // clear anything latched
    tapArmed = true;
    uint8_t c1 = _readReg(LIS2DW12_REG_CTRL1), c4 = _readReg(LIS2DW12_REG_CTRL4_INT1), c7 = _readReg(LIS2DW12_REG_CTRL7), th = _readReg(LIS2DW12_REG_TAP_THS_Z), wk = _readReg(LIS2DW12_REG_WAKE_THS);
    Serial.printf("[LIS2DW12] double-tap ARMED: CTRL1=0x%02X (want 0x74) CTRL4=0x%02X CTRL7=0x%02X THS_Z=0x%02X WAKE_THS=0x%02X\n", c1, c4, c7, th, wk);
    return true;
  }
  void tapDisarm() {
    if (!ok || !tapArmed) return;
    _writeReg(LIS2DW12_REG_FIFO_CTRL, 0x00);                         // FIFO bypass
    _writeReg(LIS2DW12_REG_CTRL7,    0x00);
    _writeReg(LIS2DW12_REG_CTRL4_INT1, 0x00);
    _writeReg(LIS2DW12_REG_WAKE_THS, 0x00);
    _writeReg(LIS2DW12_REG_CTRL3,    0x00);
    _writeReg(LIS2DW12_REG_CTRL1,    LIS2DW12_CTRL1_RUN);            // back to 25 Hz
    tapArmed = false;
  }
  uint32_t tapPollMs = 0, tapLastMs = 0;
  uint8_t  tapLastSrc = 0;           // last non-zero TAP_SRC (for the on-screen test)
  // Knock calibration log: drain the FIFO every poll, track the largest
  // |a| - 1 g deviation, and print it once a second whenever something moved.
  // 1 g = 512 counts here; TAP_THS is in units of FS/32 = 62.5 mg = 32 counts.
  int32_t  tapPeak = 0; uint32_t tapPeakMs = 0; uint16_t tapFifoN = 0;
  void _tapDrainFifo() {
    uint8_t n = _readReg(LIS2DW12_REG_FIFO_SMPL) & 0x3F;
    if (n == 0xFF) return;
    for (uint8_t i = 0; i < n; i++) {
      int16_t x, y, z;
      if (!read(x, y, z)) break;
      int32_t mag = (int32_t)sqrtf((float)x * x + (float)y * y + (float)z * z);
      int32_t dev = mag - 512; if (dev < 0) dev = -dev;
      if (dev > tapPeak) tapPeak = dev;
      tapFifoN++;
      // software tap detector (sample time ~ poll time; 50 ms resolution is fine for 100-700 ms gaps)
      uint32_t now = millis();
      bool above = dev >= SW_TAP_THS / 2;
      if (above) {
        if (swBurst == 0) { swBurstQuietBefore = swQuiet; swBurstPeak = 0; swBurstSum = 0; }
        swBurst++; swBurstSum += dev;
        if (dev > swBurstPeak) swBurstPeak = dev;
        swQuiet = 0;
      } else {
        if (swBurst && swLastTapMs && now - swLastTapMs < SW_DEAD_MS) {
          swBurst = 0;                                                 // ringing of the tap just counted: ignore
        } else if (swBurst) {                                          // a burst just ended: judge its shape
          uint16_t eqw = (uint16_t)(swBurstSum / (swBurstPeak > 0 ? swBurstPeak : 1));
          bool sharp = swBurst <= SW_MAX_WIDTH || eqw <= SW_MAX_EQWIDTH;
          bool tap = swBurstPeak >= SW_TAP_THS && sharp && swBurstQuietBefore >= SW_QUIET_MIN;
          if (tap) {
            uint32_t gap = now - swLastTapMs;
            if (swPending && gap >= SW_GAP_MIN && gap <= SW_GAP_MAX) {
              swPending = false; swDouble = true;
              Serial.printf("[TAP] sw DOUBLE (gap %lu ms, peak %ld, width %u eq %u)\n", (unsigned long)gap, (long)swBurstPeak, swBurst, eqw);
            } else {
              swPending = true;
              Serial.printf("[TAP] sw tap (peak %ld, width %u eq %u, quiet %u)\n", (long)swBurstPeak, swBurst, eqw, swBurstQuietBefore);
            }
            swLastTapMs = now;
          } else if (swBurstPeak >= SW_TAP_THS) {
            Serial.printf("[TAP] sw reject (peak %ld, width %u eq %u, quiet %u) - %s\n", (long)swBurstPeak, swBurst, eqw, swBurstQuietBefore,
                          !sharp ? "too wide = movement" : "no stillness before it");
            swPending = false;                                         // movement cancels a pending first tap
          }
          swBurst = 0;
        }
        if (swQuiet < 1000) swQuiet++;
      }
      if (swPending && now - swLastTapMs > SW_GAP_MAX) swPending = false;
    }
  }
  // True once per double tap. Poll every 50 ms: LIR holds the flag until read.
  bool tapPollDouble() {
    if (!ok || !tapArmed) return false;
    uint32_t now = millis();
    if (now - tapPollMs < 50) return false;
    tapPollMs = now;
    _tapDrainFifo();
    if (now - tapPeakMs >= 1000) {
      if (tapPeak >= 24)                                               // ~0.05 g: skip the silent seconds
        Serial.printf("[TAP] peak %ld counts = %.2f g  (threshold %u = %ld counts, %.2f g)  samples=%u\n",
                      (long)tapPeak, tapPeak / 512.0f, TAP_THS, (long)TAP_THS * 32, TAP_THS * 32 / 512.0f, tapFifoN);
      tapPeak = 0; tapPeakMs = now; tapFifoN = 0;
    }
    uint8_t st  = _readReg(LIS2DW12_REG_STATUS);                     // DOUBLE_TAP[4] SINGLE_TAP[3] (live)
    uint8_t src = _readReg(LIS2DW12_REG_TAP_SRC);                    // TAP_IA[6] DOUBLE[4] (latched, cleared by this read)
    if (src == 0xFF) return false;
    if (swDouble) { swDouble = false; tapLastSrc = 0x50; tapLastMs = now; return true; }   // software detector fired
    bool any = (src & 0x40) || (st & 0x18);
    if (!any) return false;
    bool dbl = (src & 0x10) || (st & 0x10);
    Serial.printf("[LIS2DW12] hw engine says %s (TAP_SRC=0x%02X STATUS=0x%02X) - log only, the shape detector decides\n", dbl ? "DOUBLE" : "single", src, st);
    return false;
  }

  // ── power ────────────────────────────────────────────────────────────────
  bool sleepMode() { return ok && _writeReg(LIS2DW12_REG_CTRL1, LIS2DW12_CTRL1_OFF); }
  bool wakeMode()  { return ok && _writeReg(LIS2DW12_REG_CTRL1, LIS2DW12_CTRL1_RUN); }

  // ── motion auto-lock state machine: identical to bma400.h ────────────────
  enum MotionState { MS_DISABLED, MS_SETTLING, MS_ARMED };
  bool      featureEnabled = false;
  uint32_t  armDelayMs     = 120000;
  int32_t   motionThresh   = 40;
  uint8_t   sensitivity    = 5;
  void applySensitivity(){
    if (sensitivity > 10) sensitivity = 10;
    motionThresh = 90 - (int32_t)sensitivity * 75 / 10;
  }
  MotionState mState = MS_DISABLED;
  int16_t   baseX = 0, baseY = 0, baseZ = 0;
  bool      baseValid = false;
  uint32_t  stillSince = 0;
  uint32_t  lastSample = 0;
  static const uint32_t SAMPLE_MS = 100;

  void motionOnUnlock() {
    if (!ok || !featureEnabled) { mState = MS_DISABLED; return; }
    baseValid = false; stillSince = millis(); mState = MS_SETTLING;
    Serial.println("[LIS2DW12] motion-lock: SETTLING");
  }
  void motionOnLock() { mState = MS_DISABLED; }

  bool tickMotion() {
    if (!ok || mState == MS_DISABLED) { motionHit = false; return false; }
    if (batchOn) { batchDrain(false); bool h = motionHit; motionHit = false; return h; }   // 11cf: dark: judged on every FIFO sample
    if (motionHit) { motionHit = false; return true; }   // a hit found in the FIFO drained at the dark's end
    uint32_t now = millis();
    if (now - lastSample < SAMPLE_MS) return false;
    lastSample = now;
    int16_t x, y, z;
    if (!read(x, y, z)) return false;
    return motionFeed(x, y, z, now, false);
  }
  // 11cf: one sample. From the FIFO (fromFifo) every sample is judged once ARMED,
  // so a lift between two 100 ms reads is not missed; SETTLING keeps 100 ms steps
  // so the baseline drifts at the same rate as before.
  bool motionFeed(int16_t x, int16_t y, int16_t z, uint32_t now, bool fromFifo) {
    if (!ok || mState == MS_DISABLED) return false;
    if (fromFifo && mState == MS_SETTLING) { if ((int32_t)(now - lastSample) < (int32_t)SAMPLE_MS) return false; lastSample = now; }
    if (!baseValid) { baseX = x; baseY = y; baseZ = z; baseValid = true; return false; }
    int32_t dx = (int32_t)x - baseX, dy = (int32_t)y - baseY, dz = (int32_t)z - baseZ;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    if (dz < 0) dz = -dz;
    bool moving = (dx > motionThresh || dy > motionThresh || dz > motionThresh);
    if (mState == MS_SETTLING) {
      if (moving) { stillSince = now; baseX = x; baseY = y; baseZ = z; }
      else if ((int32_t)(now - stillSince) >= (int32_t)armDelayMs) {   // 11cf: signed, so a FIFO sample stamped before stillSince never reads as hours still
        mState = MS_ARMED; baseX = x; baseY = y; baseZ = z;
        Serial.println("[LIS2DW12] motion-lock: ARMED");
      } else { baseX += (x - baseX) >> 4; baseY += (y - baseY) >> 4; baseZ += (z - baseZ) >> 4; }
      return false;
    }
    if (moving) { Serial.println("[LIS2DW12] motion-lock: MOTION DETECTED -> locking"); mState = MS_DISABLED; return true; }
    return false;
  }
  // ── 11cf (power, 21 Nov 2026): FIFO batching while the screen is dark ──────
  // In the dark the main loop runs every 100 ms, and each pass read one sample
  // for the step counter: about 10 bus reads a second, each one waking the G0
  // out of Stop first (11k), so the G0 never stayed in Stop, and the step
  // counter saw 10 of the 25 samples a second. Dark, the part's 32-deep FIFO
  // (continuous mode, 25 Hz = 1.28 s) holds every sample and the loop drains
  // it once a second in one bus visit. The step counter and motion-lock see
  // every sample, each with its own time. On wake the FIFO is drained once
  // more (motion found in the last second still locks) and set back to bypass.
  // Not while the tap engine owns the FIFO (bench only, FAVILLA_TAP_WAKE).
  static const uint32_t BATCH_DRAIN_MS = 1000;
  bool     batchOn = false, motionHit = false;
  uint32_t batchDrainMs = 0, batchDrains = 0, batchSamples = 0, batchOverruns = 0;
  void batchBegin() {
    if (!ok || batchOn || tapArmed) return;
    if (!_writeReg(LIS2DW12_REG_FIFO_CTRL, 0xC0)) return;      // FMode 110 = continuous, FTH 0
    batchOn = true; batchDrainMs = millis();
  }
  void batchEnd() {
    if (!batchOn) return;
    batchDrain(true);
    batchOn = false;
    _writeReg(LIS2DW12_REG_FIFO_CTRL, 0x00);                    // bypass: direct reads again
    stepSampleMs = millis(); lastSample = millis();
  }
  void batchDrain(bool force) {
    if (!batchOn) return;
    uint32_t now = millis();
    if (!force && now - batchDrainMs < BATCH_DRAIN_MS) return;
    batchDrainMs = now;
    int16_t xs[32], ys[32], zs[32]; uint8_t n = 0;
    // One bus visit (one G0 wake) for the whole FIFO.
    if (!I2C_TRYLOCK(20)) return;
    uint8_t st = 0xFF;
    Wire.beginTransmission(addr); Wire.write(LIS2DW12_REG_FIFO_SMPL);
    if (Wire.endTransmission(false) == 0 && Wire.requestFrom(addr, (uint8_t)1) == 1) st = Wire.read();
    if (st != 0xFF) {
      if (st & 0x40) batchOverruns++;                            // OVR: more than 1.28 s since the last drain
      uint8_t want = st & 0x3F; if (want > 32) want = 32;
      for (; n < want; n++) {
        uint8_t b[6];
        Wire.beginTransmission(addr); Wire.write(LIS2DW12_REG_OUT_X_L);
        if (Wire.endTransmission(false) != 0 || Wire.requestFrom(addr, (uint8_t)6) != 6) break;
        for (int i = 0; i < 6; i++) b[i] = Wire.read();
        xs[n] = (int16_t)((int16_t)((b[1] << 8) | b[0]) >> 5);
        ys[n] = (int16_t)((int16_t)((b[3] << 8) | b[2]) >> 5);
        zs[n] = (int16_t)((int16_t)((b[5] << 8) | b[4]) >> 5);
      }
    }
    I2C_UNLOCK();
    batchDrains++; batchSamples += n;
    for (uint8_t i = 0; i < n; i++) {                            // oldest first, 40 ms apart, the newest at now
      const uint32_t t = now - (uint32_t)(n - 1 - i) * 40;
      stepFeed(xs[i], ys[i], zs[i], t);
      if (motionFeed(xs[i], ys[i], zs[i], t, true)) motionHit = true;
    }
    if (n) stepSampleMs = now;
  }
  const char* motionStateName() {
    switch (mState) { case MS_SETTLING: return "SETTLING"; case MS_ARMED: return "ARMED"; default: return "DISABLED"; }
  }
};

extern LIS2DW12 accel;
