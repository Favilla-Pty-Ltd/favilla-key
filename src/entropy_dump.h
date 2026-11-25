#pragma once
// ─────────────────────────────────────────────────────────────────────────
//  entropy_dump.h — RAW ENTROPY DUMP. TEST BUILD ONLY.
//
//  ███ THIS FILE IS AN ENTROPY EXFILTRATION FEATURE. ███
//
//  It prints raw bytes from the device's entropy sources over USB CDC. On a
//  production device that is a direct path to reconstructing a seed. It is
//  guarded by FAVILLA_ENTROPY_DUMP and emits a #warning so it cannot be
//  built by accident, but the real protection is procedural:
//
//    - Build it on a BRANCH, never on main.
//    - Run it on a DEV UNIT with no wallet, then wipe.
//    - Never merge the -D flag into platformio.ini on a shippable branch.
//    - Delete the resulting .bin files when the analysis is done.
//
//  ── WHY MEASURE AT ALL ─────────────────────────────────────────────────
//
//  seed_entropy.h budgets 256 bits at the SE051 and nothing elsewhere. That
//  is a DESIGN claim. This produces the EVIDENCE:
//
//    1. Does se_random actually deliver full-entropy bytes, or is the
//       certificate the only thing saying so?
//    2. How bad is esp_fill_random with radios down? Onboarding is confirmed
//       to run in that state, so this is the number that decides whether the
//       ESP32 source is worth anything at all — and it belongs in the
//       published spec rather than a hand-wave.
//    3. Same source with radios up, as a control. The delta between 2 and 3
//       is the RF-conditioning effect, measured on this silicon rather than
//       quoted from the ESP-IDF docs.
//
//  Analyse with:  python3 extract_dump.py serial.log
//                 python3 entropy_check.py source se051.bin
//
//  Health tests and min-entropy estimates catch a DEAD source. They cannot
//  detect a SMALL entropy space — that needs the reboot-loop and fleet
//  collision tests. Do not read a good number here as proof of anything
//  more than "this source is alive and unbiased".
// ─────────────────────────────────────────────────────────────────────────

#ifdef FAVILLA_ENTROPY_DUMP
#warning "*** ENTROPY DUMP BUILD — prints raw entropy over USB. NEVER SHIP. ***"

#include <stdint.h>
#include <stddef.h>
#include <esp_wifi.h>   // esp_wifi_get_mode — verify the radio state, never assume it

// CHUNK SIZE — 32, NOT 256.
//
// se_random() ALLOWS up to 256, but this applet REFUSES it: a 256-byte
// GetRandom returns 6985 (conditions of use not satisfied) 100% of the time,
// while every 16/24/32-byte call in the firmware succeeds. Measured, not
// assumed. 32 matches what seed generation actually requests, so the dump
// samples the source the same way the device does.
//
// If you want to know the real ceiling, walk it: 32, 64, 128, 192, 256 and
// see where 6985 starts. Worth knowing, and worth tightening the guard in
// se_random() to match rather than leaving it at a limit the SE rejects.
#define ENT_DUMP_CHUNK 32

// 256 KB = 262,144 samples. Enough for the byte-level estimators in
// entropy_check.py. NIST's own SP 800-90B tool wants ~1e6 for a defensible
// published figure — raise this to 1048576 when producing that number.
#ifndef ENT_DUMP_BYTES
#define ENT_DUMP_BYTES (256UL * 1024UL)
#endif

// label: goes in the output header and becomes the .bin filename, so use
//        something that survives being read six months later, e.g.
//        "SE051", "ESP32-RF-OFF", "ESP32-RF-ON".
static void entropyDumpSource(const char* label, bool useSE) {
  Serial.printf("\n[DUMP-BEGIN] source=%s bytes=%lu chunk=%d\n",
                label, (unsigned long)ENT_DUMP_BYTES, ENT_DUMP_CHUNK);

  uint8_t buf[ENT_DUMP_CHUNK];
  char    hex[ENT_DUMP_CHUNK * 2 + 1];
  static const char HEXD[] = "0123456789abcdef";

  unsigned long done = 0;
  unsigned long failures = 0;
  unsigned long t0 = millis();

  // ABORT CAP. Without this, a source that fails every call loops thousands
  // of times inside setup(), saturates USB CDC, and blocks the boot — which
  // is exactly what happened on 31 Jul 2026 and left the device needing
  // manual BOOT+RESET recovery. A diagnostic that bricks the thing it is
  // diagnosing is worse than no diagnostic.
  const unsigned long MAX_FAILURES = 8;

  while (done < ENT_DUMP_BYTES) {
    size_t n = ENT_DUMP_CHUNK;
    if (ENT_DUMP_BYTES - done < n) n = (size_t)(ENT_DUMP_BYTES - done);

    if (useSE) {
      if (!favilla::se_random(buf, n)) {
        // Record rather than abort: a source that fails 1 call in 10,000 is
        // itself a finding, and silently retrying would hide it.
        failures++;
        memset(buf, 0, n);
        Serial.printf("[DUMP-FAIL] at offset %lu (SW in the line above)\n", done);
        if (failures >= MAX_FAILURES) {
          Serial.printf("[DUMP-ABORT] %lu consecutive failures — giving up on %s.\n",
                        failures, label);
          Serial.println("[DUMP-ABORT] The source is not answering at this request");
          Serial.println("[DUMP-ABORT] size. Try a smaller ENT_DUMP_CHUNK.");
          break;
        }
      }
    } else {
      esp_fill_random(buf, n);
    }

    for (size_t i = 0; i < n; i++) {
      hex[i * 2]     = HEXD[(buf[i] >> 4) & 0x0F];
      hex[i * 2 + 1] = HEXD[buf[i] & 0x0F];
    }
    hex[n * 2] = 0;
    Serial.printf("D:%s\n", hex);

    done += n;
    esp_task_wdt_reset();          // this loop runs for minutes
    if ((done % (32UL * 1024UL)) == 0)
      Serial.printf("[DUMP-PROGRESS] %lu/%lu\n", done, (unsigned long)ENT_DUMP_BYTES);
  }

  mbedtls_platform_zeroize(buf, sizeof(buf));
  mbedtls_platform_zeroize(hex, sizeof(hex));

  Serial.printf("[DUMP-END] source=%s bytes=%lu failures=%lu elapsed_ms=%lu\n",
                label, done, failures, (unsigned long)(millis() - t0));
}

// Report the ACTUAL radio state rather than assuming it from where this is
// called. On a NETWORK-mode boot, "[AUTO] boot scan started (pre-AP)" runs
// BEFORE this hook — a scan brings the RF subsystem up, so a sample taken
// here would be RF-ON while a hard-coded label claimed otherwise. Labelling
// a measurement with an unverified assumption is how you end up publishing a
// number that means something other than what it says.
static const char* entropyDumpRfState() {
  wifi_mode_t m = WIFI_MODE_NULL;
  if (esp_wifi_get_mode(&m) != ESP_OK) return "RF-OFF";   // driver not started
  return (m == WIFI_MODE_NULL) ? "RF-OFF" : "RF-ON";
}

// Called from setup() after SE init. Whether the radio is up depends on the
// device's saved mode — see entropyDumpRfState().
static void entropyDumpBoot() {
  Serial.println("\n########################################################");
  Serial.println("#  ENTROPY DUMP BUILD — raw entropy follows on this port");
  Serial.println("#  Capture with:  pio device monitor > serial.log");
  Serial.println("#  Then:          python3 extract_dump.py serial.log");
  Serial.println("########################################################");
  const char* rf = entropyDumpRfState();
  char espLabel[24];
  snprintf(espLabel, sizeof(espLabel), "ESP32-%s", rf);

  Serial.printf("#  radio state at this hook: %s\n", rf);
  if (strcmp(rf, "RF-ON") == 0) {
    Serial.println("#  NOTE: the radio is ALREADY UP on this boot (network mode");
    Serial.println("#  runs a scan before this point). For the RF-OFF sample —");
    Serial.println("#  the state seed generation actually runs in — put the");
    Serial.println("#  device in OFFLINE mode, or wipe it, and reboot.");
  }
  Serial.println("########################################################");

  entropyDumpSource("SE051",  true);
  entropyDumpSource(espLabel, false);
  Serial.printf("\n[DUMP] boot-stage dumps complete (radio was %s).\n", rf);
}

// Called once after WiFi association, to measure the same source with the RF
// subsystem live. The delta against ESP32-RF-OFF is the whole question.
static void entropyDumpRfOn() {
  static bool done = false;
  if (done) return;
  done = true;
  const char* rf = entropyDumpRfState();
  if (strcmp(rf, "RF-ON") != 0) {
    // Should be impossible here, but assert it rather than assume it: this
    // sample is the CONTROL, and a control taken in the wrong state is worse
    // than no control.
    Serial.printf("[DUMP] SKIPPED RF-ON dump: radio reports %s\n", rf);
    return;
  }
  entropyDumpSource("ESP32-RF-ON", false);
}

#endif  // FAVILLA_ENTROPY_DUMP
