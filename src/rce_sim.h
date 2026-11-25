// ─────────────────────────────────────────────────────────────────────────────
// rce_sim.h — RCE SIM: play a compromised ESP32 in a live Nostr life  [BENCH]
//
// Settings > Device > RCE sim   (bench env only: pio run -e favilla_key_bench)
// Serial:  rce run             same steps, console only
//          rce dec <spendpin>  the last step: spend-PIN DEC of the seed key
//
// Review findings 3 and 4 (19 Oct 2026). Everything here is something code
// execution on this chip could do right now, in this life, with the daily PIN
// session the user opened. Each step reports what the G0 / SE answered:
//   BLOCKED  the fix held          OPEN  the attacker got that step
//
//   1 Door BTC      G0 DOORBTC in a NOSTR life        expect BLOCKED (first-wins)
//   2 MODEDEL       raw G0 cmd 0x0C                    expect BLOCKED (not accepted)
//   3 BTC sign      raw G0 BTCSIGN in a NOSTR life     expect BLOCKED (door memory)
//   4 Latch         read MODE_PCR in the daily session expect NOSTR (info)
//   5 Delete latch  daily-PIN DeleteSecureObject       expect BLOCKED (6986)
//   6 Re-create     anon WritePCR create at BTC value  expect BLOCKED (id live)
//   7 Spend DEC     serial "rce dec <pin>"             expect BLOCKED (6985/6986)
//
// On a wallet onboarded BEFORE the fix, 5 succeeds and DESTROYS the latch,
// 6 then plants one that reads BTC, and 7 returns 9000: that is the hole,
// confirmed on silicon. Wipe and re-onboard that unit afterwards.
// Nothing here reads or outputs key material: step 7 decrypts 32 zero bytes
// and keeps only the status word.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_RCE_SIM_H
#define FAVILLA_RCE_SIM_H
#ifdef FAVILLA_BENCH_PROBES
#warning "FAVILLA_BENCH_PROBES build - RCE sim page compiled in. NOT SHIPPABLE."

enum { RCE_PEND = 0, RCE_BLOCKED, RCE_OPEN, RCE_SKIP, RCE_INFO };
struct RceRow { const char* name; uint8_t v; char det[22]; };
static RceRow g_rce[7] = {
  {"Door BTC",     RCE_PEND, ""}, {"MODEDEL",   RCE_PEND, ""}, {"BTC sign", RCE_PEND, ""},
  {"Latch",        RCE_PEND, ""}, {"Delete latch", RCE_PEND, ""}, {"Re-create", RCE_PEND, ""},
  {"Spend DEC",    RCE_PEND, "rce dec <pin>"},
};
static const char* rceVerdict(uint8_t v){
  switch(v){ case RCE_BLOCKED: return "BLOCKED"; case RCE_OPEN: return "OPEN";
             case RCE_SKIP: return "SKIP"; case RCE_INFO: return "INFO"; default: return "-"; }
}
static void rceSet(int i, uint8_t v, const char* fmt, ...){
  g_rce[i].v = v;
  va_list ap; va_start(ap, fmt); vsnprintf(g_rce[i].det, sizeof(g_rce[i].det), fmt, ap); va_end(ap);
  Serial.printf("[RCE-SIM] %d %-12s %-7s %s\n", i + 1, g_rce[i].name, rceVerdict(v), g_rce[i].det);
}
static const char* rceLatchName(uint8_t c){
  switch(c){ case 1: return "NEUTRAL"; case 2: return "NOSTR"; case 3: return "BTC"; case 4: return "SPENT";
             case 5: return "other"; case 0xFE: return "ABSENT"; default: return "unreadable"; }
}

// Steps 1-6. Returns false (and runs nothing) if this is not a Nostr life.
static bool rceRunChain(){
  for(int i = 0; i < 6; i++){ g_rce[i].v = RCE_PEND; g_rce[i].det[0] = 0; }
  Serial.println("[RCE-SIM] ===== simulated RCE, NOSTR life, daily session as the user left it =====");
  if(g_ceremonyBoot){ Serial.println("[RCE-SIM] refused: this is a Bitcoin ceremony boot - run it in a Nostr life"); return false; }
  if(!g0_present()){ Serial.println("[RCE-SIM] refused: G0 not present"); return false; }

  // 1. Door memory: ask the G0 for the BTC door in this life.
  { uint8_t held = 0xFF;
    I2C_LOCK(); bool ok = g0_door_commit(2 /*BTC*/, &held); I2C_UNLOCK();
    if(ok) rceSet(0, RCE_OPEN, "G0 took BTC! restart");
    else if(held == 1) rceSet(0, RCE_BLOCKED, "G0 holds NOSTR");
    else rceSet(0, RCE_SKIP, "no answer (held=%u)", held); }

  // 2. MODEDEL: the retired G0 command. Relay never pumped, so even an old G0
  //    that accepts it deletes nothing; accepted = it went BUSY/NEED_RELAY.
  { I2C_LOCK(); g0_reset(); delay(20); uint8_t st = g0_bench_raw_cmd(0x0C, 1500); I2C_UNLOCK();
    if(st == G0_ST_IDLE || st == G0_ST_SIG_READY) rceSet(1, RCE_BLOCKED, "not accepted");
    else if(st == G0_ST_NEED_RELAY || st == G0_ST_BUSY) rceSet(1, RCE_OPEN, "G0 accepted it");
    else rceSet(1, RCE_SKIP, "status %02X", st); }

  // 3. BTC signing in a Nostr life: door memory must refuse before any relay.
  { I2C_LOCK(); g0_reset(); delay(20); uint8_t st = g0_bench_raw_cmd(G0_CMD_BTCSIGN, 1500); I2C_UNLOCK();
    if(st == G0_ST_ERROR) rceSet(2, RCE_BLOCKED, "door refused");
    else if(st == G0_ST_NEED_RELAY || st == G0_ST_BUSY) rceSet(2, RCE_OPEN, "G0 started fetch!");
    else rceSet(2, RCE_SKIP, "status %02X", st);
    I2C_LOCK(); g0_reset(); I2C_UNLOCK(); }

  // 4. Where the latch is now (the daily session can read it).
  { I2C_LOCK(); uint8_t c = favilla::se_bench_mode_class(); I2C_UNLOCK();
    rceSet(3, RCE_INFO, "%s", rceLatchName(c)); }

  // 5. Delete the latch from the daily session.
  { I2C_LOCK(); bool sess = favilla::se_bench_daily_session_open(); uint16_t sw = sess ? favilla::se_bench_mode_delete_daily() : 0; I2C_UNLOCK();
    if(!sess) rceSet(4, RCE_SKIP, "unlock first");
    else if(sw == 0x9000) rceSet(4, RCE_OPEN, "DELETED (9000)");
    else rceSet(4, RCE_BLOCKED, "SW %04X", sw); }

  // 6. Re-create the id at the public BTC value, anonymously.
  { I2C_LOCK(); bool live = favilla::se_bench_mode_exists(); uint16_t sw = live ? 0 : favilla::se_bench_mode_recreate_btc(); I2C_UNLOCK();
    if(live) rceSet(5, RCE_BLOCKED, "id live, can't");
    else if(sw == 0x9000){
      I2C_LOCK(); uint8_t c = favilla::se_bench_mode_class(); I2C_UNLOCK();
      rceSet(5, RCE_OPEN, "planted, reads %s", rceLatchName(c));
    } else rceSet(5, RCE_BLOCKED, "SW %04X", sw); }

  int open = 0; for(int i = 0; i < 6; i++) if(g_rce[i].v == RCE_OPEN) open++;
  Serial.printf("[RCE-SIM] steps 1-6: %d OPEN. Step 7 (needs the spend PIN): rce dec <pin>\n", open);
  if(g_rce[4].v == RCE_OPEN)
    Serial.println("[RCE-SIM] WARNING: the latch was deleted - this wallet's BTC side is now damaged. Wipe and re-onboard after the test.");
  return true;
}

// Step 7. Ends with NO SE session open: the device must be unlocked again.
static void rceRunDec(const char* pin){
  if(g_ceremonyBoot){ Serial.println("[RCE-SIM] refused: ceremony boot"); return; }
  if(!pin || strlen(pin) != (size_t)PIN_NEW_LEN){ Serial.printf("[RCE-SIM] usage: rce dec <%d-digit spend PIN>\n", PIN_NEW_LEN); return; }
  I2C_LOCK(); uint8_t c = favilla::se_bench_mode_class(); I2C_UNLOCK();
  Serial.printf("[RCE-SIM] latch before DEC: %s\n", rceLatchName(c));
  I2C_LOCK(); uint16_t sw = favilla::se_bench_seed_dec_spend(pin); I2C_UNLOCK();
  if(sw == 0x9000)      rceSet(6, RCE_OPEN, "SE DECRYPTED (9000)");
  else if(sw == 0xFFFE) rceSet(6, RCE_SKIP, "spend PIN refused");
  else                  rceSet(6, RCE_BLOCKED, "SW %04X", sw);
  if(sw == 0x9000) Serial.println("[RCE-SIM] HOLE CONFIRMED: the SE would unwrap the seed's outer layer in a Nostr life.");
  // The spend session is closed; no daily session either. Lock like a real lock.
  clearKeyCache();
  wallet.unlocked = false;
  Serial.println("[RCE-SIM] SE sessions closed, wallet locked - unlock again to keep using the device");
}

static void rceDraw(bool ran){
  fEnd();
  spr.fillSprite(C_BG);
  uiHeader("RCE SIM", C_RED);
  if(!ran){
    fSet(F_BODY); spr.setTextColor(C_TEXT2);
    fDrawCentre("Plays a hacked ESP32", 120, 70);
    fDrawCentre("in this Nostr life.", 120, 92);
    fSet(F_SMALL); spr.setTextColor(C_MUTED);
    fDrawCentre("Watch the serial console.", 120, 124);
    fDrawCentre("Pre-fix wallets: damages the", 120, 150);
    fDrawCentre("BTC latch. Re-onboard after.", 120, 168);
    spr.setTextColor(C_AMBER);
    fDrawCentre("OK = run   BACK = leave", 120, 204);
    fEnd(); dispPush(); return;
  }
  fSet(F_SMALL);
  int open = 0;
  for(int i = 0; i < 7; i++){
    int y = 46 + i * 24;
    const RceRow& r = g_rce[i];
    if(r.v == RCE_OPEN) open++;
    uint16_t vc = (r.v == RCE_BLOCKED) ? C_GREEN : (r.v == RCE_OPEN) ? C_RED : C_MUTED;
    spr.setTextColor(C_TEXT2);
    char lab[20]; snprintf(lab, sizeof lab, "%d %s", i + 1, r.name);
    spr.drawString(lab, 12, y);
    spr.setTextColor(vc);
    fDrawRight(r.v == RCE_PEND ? "-" : rceVerdict(r.v), 228, y);
    spr.setTextColor(C_VDIM);
    spr.drawString(r.det, 24, y + 11);
  }
  spr.setTextColor(open ? C_RED : C_GREEN);
  fDrawCentre(open ? "ATTACK STEP OPEN - see console" : "No step open (step 7: serial)", 120, 222);
  fEnd(); dispPush();
}

void handleSerialInput();   // main.cpp: this page owns the loop, so it must poll the console itself
static void runRceSim(){
  if(!wallet.exists || !wallet.unlocked){ dispError("Unlock first"); errorPause(); return; }
  bool ran = false;
  rceDraw(false);
  while(true){
    btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
    esp_task_wdt_reset();
    // 19 Oct 2026: serial commands are only read by loop(), which does not run
    // while this page is open. Poll here so "rce dec <pin>" works from the
    // results screen, and repaint when step 7 lands.
    { uint8_t before = g_rce[6].v; handleSerialInput();
      if(g_rce[6].v != before){ ran = true; rceDraw(true); } }
    if(btn4.isPressed()) return;
    if(btn2.isPressed()){
      spr.fillSprite(C_BG); uiHeader("RCE SIM", C_RED);
      fSet(F_BODY); spr.setTextColor(C_TEXT2); fDrawCentre("Running...", 120, 116); fEnd(); dispPush();
      ran = rceRunChain();
      if(!ran){ dispError("Nostr life only"); errorPause(); return; }
      rceDraw(true);
    }
    delay(10);
  }
}

static void rceRunChain_serial(){ rceRunChain(); }
static void rceRunDec_serial(const char* pin){ rceRunDec(pin); }

#endif  // FAVILLA_BENCH_PROBES
#endif  // FAVILLA_RCE_SIM_H
