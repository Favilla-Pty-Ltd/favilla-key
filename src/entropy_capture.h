// ─────────────────────────────────────────────────────────────────────────────
// entropy_capture.h — RAW entropy sample collectors  (Favilla KEY)   [TEST ONLY]
//
// Streams the RAW, PRE-HASH output of a source over USB serial so a laptop can
// run NIST SP 800-90B min-entropy estimation on it. This is measurement
// instrumentation for the entropy study (Part 2), NOT a seed source.
//
//   ┌─ WHY RAW ─────────────────────────────────────────────────────────────┐
//   │ Entropy MUST be measured before any hashing. SHA-256 makes a stuck     │
//   │ sensor look perfect, which is exactly how the Coldcard failure hid.    │
//   │ Nothing here hashes, whitens, or conditions. Bytes go out as captured. │
//   └────────────────────────────────────────────────────────────────────────┘
//
//   ┌─ NEVER THE SEED PATH ─────────────────────────────────────────────────┐
//   │ These functions must never feed generateSeedEntropy(). They exist only │
//   │ under -D FAVILLA_ENTROPY_CAPTURE, which emits a #warning so a capture   │
//   │ build can never be mistaken for a shippable one.                        │
//   └────────────────────────────────────────────────────────────────────────┘
//
// WIRE FORMAT (line-based, robust to interleaved log lines):
//   <<<CAP BEGIN src=accel fmt=s16le axes=3 n=NNN>>>     header
//   D:<base64>                                            data line (only these decode)
//   ...                                                   (F:i:len:w:h before each camera frame)
//   <<<CAP END bytes=NNN>>>                               footer
// The laptop parser (capture_serial.py) decodes ONLY lines starting "D:" between
// BEGIN/END, so stray firmware log lines are ignored.
//
// Include ONCE near dice_roll.h. Enable with:  -D FAVILLA_ENTROPY_CAPTURE
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_ENTROPY_CAPTURE_H
#define FAVILLA_ENTROPY_CAPTURE_H
#ifdef FAVILLA_ENTROPY_CAPTURE
#warning "FAVILLA_ENTROPY_CAPTURE build — RAW entropy dump enabled. NOT SHIPPABLE."

#ifndef C_GREEN
#error "entropy_capture.h must be #included AFTER the C_* colours, display, buttons, camera and the global BMA400 'accel'."
#endif

// ── minimal base64 (self-contained; no dependency) ───────────────────────────
static void ecapB64Line(const uint8_t* d, int len){
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

// stream an arbitrary byte buffer as D: lines, 48 raw bytes (64 b64 chars) per line
static void ecapStream(const uint8_t* buf, size_t len){
  size_t i=0;
  while(i<len){ int chunk = (int)((len-i)>48?48:(len-i)); ecapB64Line(buf+i, chunk); i+=chunk; }
}

// ── simple full-screen status ────────────────────────────────────────────────
static void ecapStatus(const char* line1, const char* line2){
  spr.fillSprite(C_BG);
  uiHeader("Entropy capture", C_AMBER);
  fSet(F_HEAD); spr.setTextColor(C_GREEN); fDrawCentre(line1, 120, 96);  fEnd();
  if(line2){ fSet(F_SMALL); spr.setTextColor(C_DIM); fDrawCentre(line2, 120, 128); fEnd(); }
  dispPush();
}

// ── ACCELEROMETER capture ────────────────────────────────────────────────────
// Streams raw 12-bit signed X,Y,Z (each as int16 little-endian) as fast as the
// I2C read + serial allow, for `target` samples. Run it TWICE for the study:
//   • device at REST  -> sensor electronic noise floor
//   • device SHAKEN   -> user-motion entropy (heavily correlated — the point)
// The laptop side extracts low bits per axis; we dump full readings for fidelity.
static void entropyCapAccel(uint32_t target){
  // The BMA400 is parked in sleep/low-power by the auto-lock system; in that
  // state its data registers don't update and read() fails as slow I2C timeouts,
  // which looks like a hang. Force NORMAL mode and let it settle before sampling.
  accel.wakeMode();
  delay(40);
  ecapStatus("Accel capture", "shake now (or rest)");
  delay(600);
  Serial.printf("<<<CAP BEGIN src=accel fmt=s16le axes=3 n=%lu>>>\n", (unsigned long)target);
  uint8_t buf[48]; int bi=0;
  uint32_t got=0, fails=0; uint32_t lastUi=millis();
  while(got < target){
    int16_t x,y,z;
    if(accel.read(x,y,z)){
      fails=0;
      buf[bi++]=(uint8_t)(x&0xFF); buf[bi++]=(uint8_t)((x>>8)&0xFF);
      buf[bi++]=(uint8_t)(y&0xFF); buf[bi++]=(uint8_t)((y>>8)&0xFF);
      buf[bi++]=(uint8_t)(z&0xFF); buf[bi++]=(uint8_t)((z>>8)&0xFF);
      if(bi>=48){ ecapStream(buf,bi); bi=0; }
      got++;
      if(millis()-lastUi > 250){
        char s[32]; snprintf(s,sizeof s,"%lu / %lu", (unsigned long)got,(unsigned long)target);
        ecapStatus("Accel capture", s); lastUi=millis();
      }
    } else {
      // read failing: bail out loudly rather than grind through I2C timeouts.
      if(++fails > 500){
        Serial.println("<<<CAP END samples=0 error=accel_read_fail>>>");
        ecapStatus("Accel FAIL", "sensor not reading");
        delay(1500);
        accel.wakeMode();   // leave it awake for the auto-lock system
        return;
      }
    }
    esp_task_wdt_reset();
    btn4.poll(); if(btn4.isPressed()) break;   // abort
  }
  if(bi>0) ecapStream(buf,bi);
  Serial.printf("<<<CAP END samples=%lu bytes=%lu>>>\n",(unsigned long)got,(unsigned long)(got*6));
  ecapStatus("Accel done", "any button");
  delay(300); while(true){ btn1.poll();btn2.poll();btn4.poll();
    if(btn1.isPressed()||btn2.isPressed()||btn4.isPressed()) break; esp_task_wdt_reset(); delay(5); }
}

// ── CAMERA capture ───────────────────────────────────────────────────────────
// Streams `nFrames` raw grayscale frames. Run it TWO ways for the study:
//   • LENS COVERED -> pure sensor noise (cleanest science; recommended)
//   • normal scene -> sensor noise + scene content (scene is NOT reliable entropy)
// Capturing many frames of a STATIC target lets the laptop do TEMPORAL analysis
// (per-pixel variation across frames), which isolates true noise from the fixed
// pattern. No hashing — raw pixels only.
static void entropyCapCamera(int nFrames){
  ecapStatus("Camera capture", "hold still / cover lens");
  pwrBoost();                 // 240MHz or frames tear on this DVP
  cameraStart();
  for(int f=0; f<4; f++){ camera_fb_t* s=esp_camera_fb_get(); if(s) esp_camera_fb_return(s); delay(10); } // warm/flush

  int w=0,h=0; size_t flen=0;
  Serial.printf("<<<CAP BEGIN src=camera fmt=gray8 frames=%d>>>\n", nFrames);
  int done=0;
  for(int f=0; f<nFrames; f++){
    camera_fb_t* fb = esp_camera_fb_get();
    if(!fb) continue;
    if(fb->len != (size_t)fb->width*fb->height){ esp_camera_fb_return(fb); continue; } // torn -> skip
    w=fb->width; h=fb->height; flen=fb->len;
    Serial.printf("F:%d:%u:%d:%d\n", f, (unsigned)fb->len, fb->width, fb->height);
    ecapStream(fb->buf, fb->len);
    esp_camera_fb_return(fb);
    done++;
    char s[40]; snprintf(s,sizeof s,"frame %d / %d", done, nFrames);
    ecapStatus("Camera capture", s);
    esp_task_wdt_reset();
    btn4.poll(); if(btn4.isPressed()) break;   // abort
  }
  Serial.printf("<<<CAP END frames=%d w=%d h=%d framelen=%u>>>\n", done, w, h, (unsigned)flen);
  cameraStop();
  pwrIdle();
  ecapStatus("Camera done", "any button");
  delay(300); while(true){ btn1.poll();btn2.poll();btn4.poll();
    if(btn1.isPressed()||btn2.isPressed()||btn4.isPressed()) break; esp_task_wdt_reset(); delay(5); }
}

// ── menu entry: choose a source ──────────────────────────────────────────────
// btn1 = accel, btn2 = camera, btn3 = cycle accel sample target, btn4 = back.
static void runEntropyCapture(){
  static const uint32_t TARGETS[] = { 100000, 250000, 1000000 };
  int ti = 1;
  while(true){
    spr.fillSprite(C_BG);
    uiHeader("Entropy capture", C_AMBER);
    fSet(F_SMALL); spr.setTextColor(C_DIM);
    fDrawCentre("RAW dump over USB serial", 120, 34); fEnd();
    fSet(F_BODY); spr.setTextColor(C_GREEN); fDrawCentre("1  Accelerometer", 120, 78); fEnd();
    char s[40]; snprintf(s,sizeof s,"target %lu samples", (unsigned long)TARGETS[ti]);
    fSet(F_SMALL); spr.setTextColor(C_VDIM); fDrawCentre(s, 120, 98); fEnd();
    fSet(F_BODY); spr.setTextColor(C_GREEN); fDrawCentre("2  Camera (64 frames)", 120, 134); fEnd();
    dispPush();
    while(true){
      btn1.poll(); btn2.poll(); btn3.poll(); btn4.poll();
      if(btn1.isPressed()){ entropyCapAccel(TARGETS[ti]); break; }
      if(btn2.isPressed()){ entropyCapCamera(64); break; }
      if(btn3.isPressed()){ ti=(ti+1)%3; break; }
      if(btn4.isPressed()){ return; }
      esp_task_wdt_reset(); delay(10);
    }
  }
}

#endif // FAVILLA_ENTROPY_CAPTURE
#endif // FAVILLA_ENTROPY_CAPTURE_H
