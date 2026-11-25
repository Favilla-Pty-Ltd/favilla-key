// ── INA232 current/voltage monitor (KeyV4 board, replaces the MAX17048) ──────
// Shunt: 0.1 ohm (R32) in the BATTERY+ lead, +BATT -> shunt -> +BATT_SNS,
// IN+ on the cell side, so a POSITIVE shunt voltage is DISCHARGE current and
// charging reads negative (flip INA232_DISCHARGE_POSITIVE if the bench says
// otherwise). VBUS is on the cell side, so bus voltage IS the cell voltage,
// on USB or off it. A0 -> GND = 0x40. ADCRANGE 0: +-81.92 mV shunt full scale
// = +-819 mA at 0.1 ohm, 2.5 uV/LSB = 25 uA/LSB. Bus: 1.6 mV/LSB.
// No calibration register is used: current is computed here from the raw
// shunt reading, so there is no scaling to get wrong on the chip.
// Per TI SBOSA79 (INA232). Included from main.cpp after the I2C_LOCK macros.
#pragma once
#ifndef Wire_h
#include <Wire.h>
#endif

#define INA232_ADDR            0x40
#define INA232_REG_CONFIG      0x00
#define INA232_REG_SHUNT       0x01
#define INA232_REG_BUS         0x02
#define INA232_REG_MFR_ID      0x3E   // 0x5449 "TI"
// CONFIG: bit14 reserved=1, ADCRANGE 0, AVG 16 (010), VBUSCT 1.1 ms (100),
// VSHCT 1.1 ms (100), MODE continuous shunt+bus (111). 16 x 2 x 1.1 ms =
// ~35 ms per fresh reading, which is plenty for a 3 s battery poll.
#define INA232_CONFIG_RUN      0x4527
#define INA232_CONFIG_SHUTDOWN 0x4520   // MODE 000: ~0.5 uA before deep sleep
// 11cf (power, 21 Nov 2026). TI lists 300 uA typical in continuous operation
// and 2.2 uA in standby. With the screen dark the gauge is read once every 30 s,
// so the part converts only when asked: MODE 011 (shunt + bus, triggered) with
// the RUN averaging, one ~35 ms conversion, then standby.
#define INA232_CONFIG_TRIGGER  0x4523
// 11cf: the Battery page with the screen dark measures the dark floor: AVG 256,
// bus 140 us, shunt 8.244 ms, continuous = one reading averages ~2.15 s with
// the shunt sampled ~98% of the time, so short radio bursts are not missed.
#define INA232_CONFIG_LONGAVG  0x4A3F
#define INA232_SHUNT_OHMS      0.1f
#define INA232_DISCHARGE_POSITIVE 1     // 1: +shunt = discharge (IN+ on the cell side)

struct INA232 {
  bool  ok = false;
  float volts = 0.0f;      // cell voltage, last read
  float amps  = 0.0f;      // signed: + discharge, - charge (after the sign rule above)
  bool _write16(uint8_t reg, uint16_t v) {
    I2C_LOCK();
    Wire.beginTransmission(INA232_ADDR);
    Wire.write(reg); Wire.write((uint8_t)(v >> 8)); Wire.write((uint8_t)v);
    bool r = (Wire.endTransmission() == 0);
    I2C_UNLOCK();
    return r;
  }
  bool _read16(uint8_t reg, uint16_t& v) {
    // 20 Oct 2026: polled from the main loop every 3 s; never wait behind a
    // G0 operation (see I2C_TRYLOCK). A skipped sample just delays the gauge.
    if (!I2C_TRYLOCK(20)) return false;
    Wire.beginTransmission(INA232_ADDR);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0) { I2C_UNLOCK(); return false; }
    if (Wire.requestFrom((uint8_t)INA232_ADDR, (uint8_t)2) != 2) { I2C_UNLOCK(); return false; }
    v = (uint16_t)((Wire.read() << 8) | Wire.read());
    I2C_UNLOCK();
    return true;
  }
  bool init() {
    ok = false;
    uint16_t id = 0;
    if (!_read16(INA232_REG_MFR_ID, id)) { Serial.println("[INA232] no ACK at 0x40"); return false; }
    Serial.printf("[INA232] manufacturer id 0x%04X (expect 0x5449)\n", id);
    if (id != 0x5449) return false;
    if (!_write16(INA232_REG_CONFIG, INA232_CONFIG_RUN)) return false;
    uint16_t cfg = 0; _read16(INA232_REG_CONFIG, cfg);
    Serial.printf("[INA232] config 0x%04X (want 0x%04X)\n", cfg, INA232_CONFIG_RUN);
    ok = (cfg == INA232_CONFIG_RUN);
    cfgNow = INA232_CONFIG_RUN;                  // 11cf
    delay(40);                                   // one full averaged conversion
    return ok;
  }
  // Fresh cell voltage + current. Returns false on a bus error.
  bool read() {
    if (!ok) return false;
    uint16_t rb = 0, rs = 0;
    if (!_read16(INA232_REG_BUS, rb) || !_read16(INA232_REG_SHUNT, rs)) return false;
    volts = (float)(rb & 0x7FFF) * 0.0016f;
    float a = (float)(int16_t)rs * 2.5e-6f / INA232_SHUNT_OHMS;
    amps = INA232_DISCHARGE_POSITIVE ? a : -a;
    return true;
  }
  bool shutdown() { return ok && _write16(INA232_REG_CONFIG, INA232_CONFIG_SHUTDOWN); }
  bool wake()     { cfgNow = INA232_CONFIG_RUN; return ok && _write16(INA232_REG_CONFIG, INA232_CONFIG_RUN); }
  // 11cf: the conversion mode in force (RUN, TRIGGER or LONGAVG).
  uint16_t cfgNow = INA232_CONFIG_RUN;
  bool setMode(uint16_t cfg) {
    if (!ok) return false;
    if (cfg == cfgNow) return true;
    if (cfg == INA232_CONFIG_TRIGGER) { cfgNow = cfg; return _write16(INA232_REG_CONFIG, INA232_CONFIG_SHUTDOWN); }   // standby until the next read triggers
    if (!_write16(INA232_REG_CONFIG, cfg)) return false;
    cfgNow = cfg; return true;
  }
  // A fresh reading in any mode. Triggered: start one conversion, wait it out
  // (the task naps meanwhile), read, and the part is back in standby.
  bool readFresh() {
    if (!ok) return false;
    if (cfgNow != INA232_CONFIG_TRIGGER) return read();
    if (!_write16(INA232_REG_CONFIG, INA232_CONFIG_TRIGGER)) return false;
    delay(40);                                   // 16 x (1.1 + 1.1) ms = 35 ms
    return read();
  }
};
