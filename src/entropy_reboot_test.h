#pragma once
// ─────────────────────────────────────────────────────────────────────────
//  entropy_reboot_test.h — ONE DRAW PER BOOT, ACROSS N POWER CYCLES.
//                          TEST BUILD ONLY.
//
//  ── WHY THIS AND NOT THE STREAM DUMP ───────────────────────────────────
//
//  entropy_dump.h measured 256 KB drawn in a single session. Every source
//  passed: Shannon 7.999, no repeated blocks, no cross-correlation. That
//  tests the STREAM.
//
//  This tests the SEEDING, and the distinction is the whole point. A
//  generator can be perfect after warm-up and degenerate on the FIRST draw
//  after power-on — and first-draw-after-boot is exactly when a user
//  onboards. A stream dump cannot see it, because by the time you have
//  drawn a kilobyte the generator has recovered.
//
//  It is also the shape of the suspected COLDCARD mechanism: their PRNG was
//  seeded ONCE at boot from the MCU UID and timer registers and never
//  reseeded. Every subsequent output was a deterministic state transition
//  that looked statistically perfect. Only comparing many separate boots
//  reveals it.
//
//  ── WHAT IT CAN AND CANNOT PROVE ───────────────────────────────────────
//
//  A collision, a near-collision, or positional bias across boots is
//  CONCLUSIVE evidence of a broken generator. True 128-bit entropy needs
//  ~2^64 samples before a birthday collision, so any repeat in 500 is proof.
//
//  A clean result proves the generator is not broken IN THIS WAY. It does
//  not prove full entropy — nothing you can run on the device does. That
//  needs cross-DEVICE collision testing at provisioning, where hundreds of
//  units are compared against each other rather than one unit against
//  itself.
//
//  ── SAFETY ─────────────────────────────────────────────────────────────
//
//  This prints derived seed entropy over USB. It is a test build:
//    - Build on a BRANCH. Never merge the -D flag.
//    - Run on a DEV UNIT. Wipe it afterwards.
//    - Delete the log when the analysis is done.
//
//  It stops on its own after ENT_REBOOT_RUNS boots (counter in NVS) so it
//  cannot loop forever, and it prints a RESUME line every boot so a lost
//  capture can be restarted without losing the samples already taken.
//
//  ── USE ────────────────────────────────────────────────────────────────
//
//    build_flags += -DFAVILLA_ENTROPY_REBOOT_TEST
//    pio device monitor > reboot.log
//    (wait — ~500 boots, a few minutes, unattended)
//
//    python3 extract_reboot.py reboot.log -o entropy/
//    python3 entropy_check.py seeds entropy/reboot_seeds.txt
//
//  To clear the counter and start again, hold any button during boot, or
//  flash a build without the flag once (it wipes the namespace on exit).
// ─────────────────────────────────────────────────────────────────────────

#ifdef FAVILLA_ENTROPY_REBOOT_TEST
#warning "*** REBOOT-LOOP TEST BUILD — restarts continuously. NEVER SHIP. ***"

#include <Preferences.h>
#include <esp_system.h>

#ifndef ENT_REBOOT_RUNS
#define ENT_REBOOT_RUNS 500
#endif

// Runs from setup() AFTER SE init and BEFORE anything else touches the
// device. Draws once, prints, restarts. Never returns until the run is done.
static void entropyRebootTest() {
  Preferences p;
  p.begin("entreboot", false, NVSPART_SEC);
  uint32_t n = p.getUInt("n", 0);

  if (n == 0) {
    Serial.println("\n########################################################");
    Serial.println("#  REBOOT-LOOP ENTROPY TEST");
    Serial.printf ("#  %d boots, one 32-byte draw each.\n", ENT_REBOOT_RUNS);
    Serial.println("#  Tests SEEDING, not the stream. Leave it running.");
    Serial.println("#  Capture:  pio device monitor > reboot.log");
    Serial.println("########################################################\n");
  }

  if (n >= ENT_REBOOT_RUNS) {
    Serial.printf("\n[REBOOT-TEST] COMPLETE — %lu samples collected.\n",
                  (unsigned long)n);
    Serial.println("[REBOOT-TEST] Analyse:");
    Serial.println("[REBOOT-TEST]   python3 extract_reboot.py reboot.log -o entropy/");
    Serial.println("[REBOOT-TEST]   python3 entropy_check.py seeds entropy/reboot_seeds.txt");
    Serial.println("[REBOOT-TEST] Counter left set; reflash without the flag to reset.");
    p.end();
    return;                       // fall through to a normal boot
  }

  // The draw. Deliberately generateSeedEntropy() and not se_random() alone:
  // this must exercise the EXACT path onboarding uses, including the health
  // checks and the mix. Testing a different path proves nothing about the
  // one that makes wallets.
  uint8_t ent[32];
  uint8_t mask = 0;
  bool ok = generateSeedEntropy(ent, 32, &mask);

  if (!ok) {
    // A failure here is a finding in itself — record it and keep going, so
    // an intermittent fault shows up as a rate rather than a dead run.
    Serial.printf("R:%04lu:FAIL:mask=%02X\n", (unsigned long)n, mask);
  } else {
    char hex[65];
    static const char HEXD[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
      hex[i * 2]     = HEXD[(ent[i] >> 4) & 0x0F];
      hex[i * 2 + 1] = HEXD[ent[i] & 0x0F];
    }
    hex[64] = 0;
    Serial.printf("R:%04lu:%02X:%s\n", (unsigned long)n, mask, hex);
  }
  mbedtls_platform_zeroize(ent, sizeof(ent));

  p.putUInt("n", n + 1);
  p.end();

  Serial.printf("[REBOOT-TEST] %lu/%d — restarting\n",
                (unsigned long)(n + 1), ENT_REBOOT_RUNS);
  Serial.flush();
  delay(60);            // let USB CDC drain before the reset kills it
  esp_restart();
}

#endif  // FAVILLA_ENTROPY_REBOOT_TEST
