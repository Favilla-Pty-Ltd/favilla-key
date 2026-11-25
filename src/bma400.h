// ======================================================================
// bma400.h — Bosch BMA400 accelerometer driver (Favilla KEY V1.1)
// Stage 1: bring-up — I2C probe, CHIP_ID, live accel readout.
// Stage 2 (motion auto-lock) lives in this same struct, added later.
//
// Bus: main I2C (Wire, SDA=6/SCL=5), shared with TCA9554/MAX17048/DRV2605L.
//      ALWAYS wrap transactions in I2C_LOCK()/I2C_UNLOCK().
//
// WIRING (shuttle board 3.0 headers, I2C mode):
//   P1.1 VDD   -> 3V3
//   P1.2 VDDIO -> 3V3
//   P1.3 GND   -> GND
//   P2.2 SCK/SCL -> SCL (GPIO5)
//   P2.4 SDI/SDA -> SDA (GPIO6)
//   P2.1 CS  -> HIGH (VDDIO)  *** required: selects I2C, else part is in SPI ***
//   P2.3 SDO -> GND for 0x14, VDDIO for 0x15  *** must NOT float ***
//   Pull-ups 4k7 on SCL/SDA to VDDIO if not already on the bus.
//
// Defensive init pattern (mirrors HapticDriver): if the chip doesn't ACK,
// .ok stays false and all calls become no-ops. A missing accelerometer
// must never brick the device.
// ======================================================================
#pragma once
#include <Arduino.h>
#include <Wire.h>

// I2C_LOCK / I2C_UNLOCK are defined in main.cpp before this header is included.

// ── Register map (BMA400 datasheet) ───────────────────────────────────────
#define BMA400_REG_CHIPID      0x00   // expect 0x90
#define BMA400_REG_STATUS      0x03
#define BMA400_REG_ACC_X_LSB   0x04   // X LSB, then X MSB, Y LSB/MSB, Z LSB/MSB
#define BMA400_REG_STEP_CNT_0  0x15   // 24-bit LE step count (0x15..0x17), 0x18=activity
#define BMA400_REG_ACC_CONFIG0 0x19   // power mode
#define BMA400_REG_ACC_CONFIG1 0x1A   // range + OSR + ODR
#define BMA400_REG_ACC_CONFIG2 0x1B
#define BMA400_REG_INT_CONFIG1 0x20   // bit0 = step-counter engine enable
#define BMA400_REG_CMD         0x7E

#define BMA400_STEP_INT_EN     0x01   // INT_CONFIG1 bit0

#define BMA400_CHIPID          0x90

// power_mode bits in ACC_CONFIG0 [1:0]: 00=sleep, 01=low-power, 10=normal
#define BMA400_MODE_SLEEP      0x00
#define BMA400_MODE_LOWPOWER   0x01
#define BMA400_MODE_NORMAL     0x02

struct BMA400 {
  bool    ok   = false;
  uint8_t addr = 0x14;   // resolved at init (0x14 if SDO->GND, 0x15 if SDO->VDDIO)

  // ── low-level I2C (caller need not hold the lock; we take it) ────────────
  bool _writeReg(uint8_t reg, uint8_t val) {
    I2C_LOCK();
    Wire.beginTransmission(addr);
    Wire.write(reg);
    Wire.write(val);
    bool r = (Wire.endTransmission() == 0);
    I2C_UNLOCK();
    return r;
  }

  // Multi-register write. IMPORTANT: the BMA400 does NOT support I2C burst
  // (auto-increment) writes — Bosch's own driver notes "Burst write is not
  // allowed" and writes each byte as a SEPARATE single-register transaction,
  // incrementing the address each time. Doing it as one multi-byte transaction
  // silently fails: the config never lands and the step counter stays at 0
  // (while activity detection, which needs no config, still works — the exact
  // symptom we saw). So loop single writes.
  bool _writeRegs(uint8_t reg, const uint8_t* buf, uint8_t n) {
    for (uint8_t i = 0; i < n; i++) {
      if (!_writeReg(reg + i, buf[i])) return false;
    }
    return true;
  }

  bool _readRegs(uint8_t reg, uint8_t* buf, uint8_t n) {
    I2C_LOCK();
    Wire.beginTransmission(addr);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0) { I2C_UNLOCK(); return false; }
    uint8_t got = Wire.requestFrom(addr, n);
    if (got != n) { I2C_UNLOCK(); return false; }
    for (uint8_t i = 0; i < n; i++) buf[i] = Wire.read();
    I2C_UNLOCK();
    return true;
  }

  uint8_t _readReg(uint8_t reg) {
    uint8_t v = 0xFF;
    _readRegs(reg, &v, 1);
    return v;
  }

  // ── probe: ACK test at a given address ───────────────────────────────────
  bool _ackAt(uint8_t a) {
    I2C_LOCK();
    Wire.beginTransmission(a);
    bool r = (Wire.endTransmission() == 0);
    I2C_UNLOCK();
    return r;
  }

  // ── init: find the device, verify CHIP_ID, put it in normal mode ─────────
  // Returns true on success. Tries 0x14 then 0x15 so the probe itself tells
  // you which way SDO floated/was tied.
  bool init() {
    ok = false;

    uint8_t found = 0;
    if      (_ackAt(0x14)) found = 0x14;
    else if (_ackAt(0x15)) found = 0x15;

    if (!found) {
      Serial.println("[BMA400] no ACK at 0x14 or 0x15 — check CS=HIGH, SDO tied, wiring");
      return false;
    }
    addr = found;
    Serial.printf("[BMA400] ACK at 0x%02X\n", addr);

    uint8_t id = _readReg(BMA400_REG_CHIPID);
    Serial.printf("[BMA400] CHIP_ID = 0x%02X (expect 0x90)\n", id);
    if (id != BMA400_CHIPID) {
      Serial.println("[BMA400] CHIP_ID mismatch — something else is at that address");
      return false;
    }

    // soft reset, then into normal mode @ default range (4g) / ODR
    _writeReg(BMA400_REG_CMD, 0xB6);   // soft reset
    delay(5);
    // re-resolve address survives reset (latched from SDO), but re-probe cheap:
    if (!_ackAt(addr)) { Serial.println("[BMA400] lost ACK after reset"); return false; }

    _writeReg(BMA400_REG_ACC_CONFIG1, 0x49); // range=4g, OSR, ODR=100Hz (datasheet default-ish)
    _writeReg(BMA400_REG_ACC_CONFIG0, BMA400_MODE_NORMAL);
    delay(5);

    // ── STEP COUNTER CONFIG (THE PART THAT MAKES IT ACTUALLY COUNT) ──────────
    // Registers 0x59..0x70 hold 24 algorithm coefficients. Out of reset they
    // are effectively zero and the step engine counts NOTHING no matter how
    // far you walk — enabling the interrupt bit alone does nothing. These MUST
    // be loaded. Values below are Bosch's "non-wrist" tuning (better than the
    // wrist default for a pocket/handheld device). One 24-byte burst write,
    // matching bma400_set_step_counter_param() -> bma400_set_regs(0x59,..,24).
    static const uint8_t SC_CONF[24] = {
      0x01, 0x32, 0x78, 0xE6, 0x87, 0x00, 0x84, 0x6C,   // 0x59..0x60
      0x9C, 0x75, 0x64, 0x7E, 0xAA, 0x0C, 0x0C, 0x4A,   // 0x61..0x68
      0xA0, 0x00, 0x00, 0x0C, 0x3C, 0xF0, 0x01, 0x00    // 0x69..0x70
    };
    bool scOk = _writeRegs(0x59, SC_CONF, 24);
    delay(2);

#ifdef STEPS_DEBUG
    // Read back the config so the log PROVES whether it landed. If these bytes
    // don't match SC_CONF, the write path is still wrong; if they match but
    // steps still don't count, the problem is elsewhere (ODR/mode/variant).
    {
      uint8_t rb[24]; bool rbOk = _readRegs(0x59, rb, 24);
      Serial.printf("[BMA400] stepcfg readback ok=%d: ", (int)rbOk);
      bool match = rbOk;
      for (uint8_t i = 0; i < 24; i++) {
        Serial.printf("%02X", rb[i]);
        if (rb[i] != SC_CONF[i]) match = false;
      }
      Serial.printf("  match=%d\n", (int)match);
    }
#endif

    // Now enable the step-counter engine (bit0 of INT_CONFIG1). The engine is
    // an "advanced interrupt" and only runs in normal mode (entered above). No
    // INT-pin mapping needed — we poll STEP_CNT. Coexists with motion auto-lock.
    _writeReg(BMA400_REG_INT_CONFIG1, BMA400_STEP_INT_EN);
    delay(2);

    ok = true;
    Serial.printf("[BMA400] init OK (normal mode, step cfg %s, engine on)\n",
                  scOk ? "loaded" : "FAILED");
    return true;
  }

  // ── lifetime hardware step count (24-bit, wraps at 2^24) ──────────────────
  // Lock-safe via _readRegs. Returns false (leaves out untouched) if the chip
  // isn't present or the read fails, so callers can distinguish "0 steps" from
  // "no read". byte[3] (reg 0x18) low 2 bits = activity: 0 still,1 walk,2 run.
  bool readSteps(uint32_t& out, uint8_t* activity = nullptr) {
    if (!ok) return false;
    uint8_t b[4];
    if (!_readRegs(BMA400_REG_STEP_CNT_0, b, 4)) return false;
    out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16);
    if (activity) *activity = b[3] & 0x03;
    return true;
  }

  // ── read raw 12-bit signed accel (sign-extended to int16) ────────────────
  bool read(int16_t& x, int16_t& y, int16_t& z) {
    if (!ok) return false;
    uint8_t b[6];
    if (!_readRegs(BMA400_REG_ACC_X_LSB, b, 6)) return false;
    // 12-bit, left-justified in LSB/MSB pair; sign-extend from bit 11
    auto conv = [](uint8_t lsb, uint8_t msb) -> int16_t {
      int16_t v = (int16_t)((msb << 8) | lsb);
      v &= 0x0FFF;
      if (v & 0x0800) v -= 4096;     // sign-extend 12-bit
      return v;
    };
    x = conv(b[0], b[1]);
    y = conv(b[2], b[3]);
    z = conv(b[4], b[5]);
    return true;
  }

  // ── magnitude of the raw vector (cheap, no float) — used by Stage 2 ──────
  uint32_t magSq() {
    int16_t x, y, z;
    if (!read(x, y, z)) return 0;
    return (uint32_t)((int32_t)x * x + (int32_t)y * y + (int32_t)z * z);
  }

  // ======================================================================
  // STAGE 2 — motion auto-lock state machine
  // ----------------------------------------------------------------------
  // Behaviour: when the device is unlocked AND this feature is enabled, the
  // SM watches for stillness. Once the board has been still for armDelayMs,
  // it ARMS. While armed, any motion above motionThresh fires the lock and
  // disarms (until the next unlock re-enters the cycle).
  //
  // Detection is SCALE-INDEPENDENT: we track a slow-moving baseline of the
  // rest vector and compare each sample's per-axis delta against it. This
  // is why the 8g-vs-4g range ambiguity from bring-up doesn't matter — we
  // watch CHANGE, not absolute g. From bench data: rest noise ~±8 counts,
  // real movement 100–200 counts, so a threshold of ~40 sits safely between.
  //
  // tick() is non-blocking and self-rate-limits internally; call it every
  // main-loop iteration. It only reads the sensor every SAMPLE_MS.
  // ======================================================================
  enum MotionState { MS_DISABLED, MS_SETTLING, MS_ARMED };

  bool      featureEnabled = false;     // master on/off (persisted)
  uint32_t  armDelayMs     = 120000;    // stillness before arming (persisted; default 2 min)
  int32_t   motionThresh   = 40;        // per-axis delta counts to call "motion" (derived from sensitivity)
  uint8_t   sensitivity    = 5;         // 0–10 UI dial (persisted); 10=touchiest, 0=least

  // Map the 0–10 UI dial to a raw per-axis count threshold. Higher
  // sensitivity = smaller threshold = easier to trigger. Bench data: rest
  // noise ~±8 counts, real movement 100–200, so 15..90 is the useful band.
  //   sens 10 -> 15 (touchiest)   sens 5 -> ~48 (default)   sens 0 -> 90
  void applySensitivity(){
    if (sensitivity > 10) sensitivity = 10;
    motionThresh = 90 - (int32_t)sensitivity * 75 / 10;  // 90..15 across 0..10
  }

  MotionState mState = MS_DISABLED;
  int16_t   baseX = 0, baseY = 0, baseZ = 0;  // rest baseline
  bool      baseValid = false;
  uint32_t  stillSince = 0;             // millis when stillness began
  uint32_t  lastSample = 0;
  static const uint32_t SAMPLE_MS = 100; // 10Hz polling — plenty for this

  // Called by main.cpp when the device unlocks. Begins the settling phase.
  void motionOnUnlock() {
    if (!ok || !featureEnabled) { mState = MS_DISABLED; return; }
    baseValid  = false;          // force fresh baseline capture
    stillSince = millis();
    mState     = MS_SETTLING;
    Serial.println("[BMA400] motion-lock: SETTLING");
  }

  // ── power mode control ───────────────────────────────────────────────────
  // ACC_CONFIG0 [1:0] selects sleep / low-power / normal. init() puts the part
  // in NORMAL and, until this was added, NOTHING ever moved it out again — the
  // chip ran at ODR 100Hz with the step-counter engine on straight through
  // deep sleep, because deep sleep only powers down the ESP32 core.
  //
  // NOTE: the step-counter engine is an "advanced interrupt" and only runs in
  // NORMAL mode. Dropping to SLEEP therefore stops step counting AND clears no
  // registers (config is retained), so wake must restore NORMAL to resume both
  // motion detection and proof-of-walk. See sleepMode()/wakeMode() below.
  bool setPowerMode(uint8_t mode) {
    if (!ok) return false;
    // Preserve the upper bits of ACC_CONFIG0 (filter/osr config lives there);
    // only the low 2 bits are the power mode.
    uint8_t cfg = _readReg(BMA400_REG_ACC_CONFIG0);
    if (cfg == 0xFF) return false;             // read failed
    cfg = (uint8_t)((cfg & ~0x03) | (mode & 0x03));
    bool r = _writeReg(BMA400_REG_ACC_CONFIG0, cfg);
    delay(2);                                   // mode change settle
    return r;
  }

  // Lowest-power state. Call before deep sleep. Retains configuration.
  bool sleepMode() { return setPowerMode(BMA400_MODE_SLEEP); }

  // Back to the mode init() established. Call on wake before relying on
  // motion detection or step counting.
  bool wakeMode()  { return setPowerMode(BMA400_MODE_NORMAL); }

  // Called by main.cpp when the device locks (by any path) so the SM resets.
  // NOTE: this is software state only — it does NOT change the chip's power
  // mode. Use sleepMode() for that.
  void motionOnLock() {
    mState = MS_DISABLED;
  }

  // The tick. Returns true exactly once, on the sample where it decides the
  // device should lock due to motion. main.cpp acts on that return value.
  bool tickMotion() {
    if (!ok || mState == MS_DISABLED) return false;
    uint32_t now = millis();
    if (now - lastSample < SAMPLE_MS) return false;
    lastSample = now;

    int16_t x, y, z;
    if (!read(x, y, z)) return false;

    // Establish baseline on first valid sample of a settling phase.
    if (!baseValid) {
      baseX = x; baseY = y; baseZ = z;
      baseValid = true;
      return false;
    }

    int32_t dx = (int32_t)x - baseX;
    int32_t dy = (int32_t)y - baseY;
    int32_t dz = (int32_t)z - baseZ;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    if (dz < 0) dz = -dz;
    bool moving = (dx > motionThresh || dy > motionThresh || dz > motionThresh);

    if (mState == MS_SETTLING) {
      if (moving) {
        // restart the stillness clock and re-baseline to the new position
        stillSince = now;
        baseX = x; baseY = y; baseZ = z;
      } else if (now - stillSince >= armDelayMs) {
        mState = MS_ARMED;
        // lock baseline to this confirmed-still position
        baseX = x; baseY = y; baseZ = z;
        Serial.println("[BMA400] motion-lock: ARMED");
      } else {
        // slow baseline drift-follow while settling (tracks slow thermal/g drift
        // without ever accumulating toward the motion threshold)
        baseX += (x - baseX) >> 4;
        baseY += (y - baseY) >> 4;
        baseZ += (z - baseZ) >> 4;
      }
      return false;
    }

    // MS_ARMED
    if (moving) {
      Serial.println("[BMA400] motion-lock: MOTION DETECTED → locking");
      mState = MS_DISABLED;   // disarm; unlock will re-enter SETTLING
      return true;
    }
    return false;
  }

  const char* motionStateName() {
    switch (mState) {
      case MS_SETTLING: return "SETTLING";
      case MS_ARMED:    return "ARMED";
      default:          return "DISABLED";
    }
  }
};

extern BMA400 accel;
