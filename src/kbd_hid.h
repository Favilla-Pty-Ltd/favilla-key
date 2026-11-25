// =============================================================================
// kbd_hid.h - the KEY as a USB keyboard (3 Nov 2026, Vault spec 7f, D4: the
// KEY types a password into the site's field; phase 4 stage 2a).
// =============================================================================
// WHY A SECOND INTERFACE, AND WHY OUR OWN CLASS DRIVER
// The FIDO interface (fido_hid.h) must keep reports with no report ID: CTAPHID
// is 64-byte reports with no ID, and browsers expect exactly that. Arduino's
// USBHID puts every HID device it is given into ONE interface, which would
// force report IDs on FIDO too. And the prebuilt TinyUSB has one HID instance
// only (CFG_TUD_HID 1). So the keyboard is its own interface (Arduino's
// USB_INTERFACE_CUSTOM slot) served by a small class driver of ours, handed to
// TinyUSB through usbd_app_driver_get_cb (a weak hook in the prebuilt lib).
// TinyUSB offers each interface to app drivers first; ours claims only its own
// interface number, so FIDO and the serial port are untouched.
//
// The interface exists in every life (USB descriptors are fixed at power-on,
// before the door is chosen). Nothing is typed except through kbd::type(),
// which the PASSWORDS screens call in the PASSKEY life after a press (the
// bench build also has a fixed test string, never a stored password).
//
// Boot keyboard report (8 bytes: modifiers, reserved, 6 keys), IN endpoint
// only, polled every 1 ms. Caps Lock is never read: every character is typed
// with an explicit shift state and the layout check runs first.
// =============================================================================
#pragma once
#ifdef FAVILLA_FIDO_PROBE
#include <Arduino.h>
#include "esp32-hal-tinyusb.h"
#include "tusb.h"
#include "device/usbd_pvt.h"
#include "kbd_layout.h"

namespace kbd {

static const uint8_t KBD_REPORT_DESC[] = { TUD_HID_REPORT_DESC_KEYBOARD() };
static uint8_t s_itf = 0xFF, s_epIn = 0, s_protocol = 1, s_idle = 0;
static volatile bool s_mounted = false, s_busy = false;
static volatile uint32_t s_mountedAt = 0;   // 4 Nov 2026 (phase 6): when a computer took the keyboard (typer picks the latest of USB and Bluetooth)
static uint32_t s_sent = 0, s_fail = 0;   // counters, task side only
static uint8_t s_report[8];

// Configuration descriptor piece (Arduino calls this while building the
// configuration). Returns its length; 0 would abort USB, so it never does.
static uint16_t descCb(uint8_t* dst, uint8_t* itf) {
  uint8_t str = tinyusb_add_string_descriptor("Favilla KEY keyboard");
  uint8_t ep = tinyusb_get_free_in_endpoint();
  s_itf = *itf; s_epIn = (uint8_t)(0x80 | ep);
  uint8_t d[TUD_HID_DESC_LEN] = { TUD_HID_DESCRIPTOR(*itf, str, HID_ITF_PROTOCOL_KEYBOARD, sizeof(KBD_REPORT_DESC), (uint8_t)(0x80 | ep), 8, 1) };
  *itf += 1;
  memcpy(dst, d, sizeof d);
  return sizeof d;
}

// ---- the class driver ----------------------------------------------------------
static void drvInit() {}
static bool drvDeinit() { return true; }
static void drvReset(uint8_t) { s_mounted = false; s_busy = false; s_protocol = 1; }
static uint16_t drvOpen(uint8_t rhport, tusb_desc_interface_t const* d, uint16_t maxLen) {
  if (d->bInterfaceNumber != s_itf || d->bInterfaceClass != TUSB_CLASS_HID) return 0;   // not ours: FIDO and CDC go to their own drivers
  uint16_t len = sizeof(tusb_desc_interface_t);
  const uint8_t* p = (const uint8_t*)d + len;
  if (len + 9 + 7 > maxLen) return 0;
  if (p[1] != HID_DESC_TYPE_HID) return 0;
  len += p[0]; p += p[0];
  const tusb_desc_endpoint_t* ep = (const tusb_desc_endpoint_t*)p;
  if (ep->bDescriptorType != TUSB_DESC_ENDPOINT || !usbd_edpt_open(rhport, ep)) return 0;
  len += ep->bLength;
  s_mounted = true; s_mountedAt = millis();
  return len;
}
static bool drvControl(uint8_t rhport, uint8_t stage, tusb_control_request_t const* r) {
  if (r->bmRequestType_bit.recipient != TUSB_REQ_RCPT_INTERFACE || (uint8_t)r->wIndex != s_itf) return false;
  if (stage != CONTROL_STAGE_SETUP) return true;
  static uint8_t buf[8];
  if (r->bmRequestType_bit.type == TUSB_REQ_TYPE_STANDARD) {
    if (r->bRequest == TUSB_REQ_GET_DESCRIPTOR && (r->wValue >> 8) == HID_DESC_TYPE_REPORT)
      return tud_control_xfer(rhport, r, (void*)KBD_REPORT_DESC, sizeof(KBD_REPORT_DESC));
    return false;
  }
  if (r->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS) return false;
  switch (r->bRequest) {
    case HID_REQ_CONTROL_SET_IDLE:     s_idle = (uint8_t)(r->wValue >> 8); return tud_control_status(rhport, r);
    case HID_REQ_CONTROL_GET_IDLE:     buf[0] = s_idle; return tud_control_xfer(rhport, r, buf, 1);
    case HID_REQ_CONTROL_SET_PROTOCOL: s_protocol = (uint8_t)r->wValue; return tud_control_status(rhport, r);
    case HID_REQ_CONTROL_GET_PROTOCOL: buf[0] = s_protocol; return tud_control_xfer(rhport, r, buf, 1);
    case HID_REQ_CONTROL_GET_REPORT:   memset(buf, 0, 8); return tud_control_xfer(rhport, r, buf, r->wLength < 8 ? r->wLength : 8);
    case HID_REQ_CONTROL_SET_REPORT:   return tud_control_xfer(rhport, r, buf, r->wLength < 8 ? r->wLength : 8);   // the host's LED report: read and ignored
    default: return false;
  }
}
static bool drvXfer(uint8_t, uint8_t ep, xfer_result_t, uint32_t) { if (ep == s_epIn) s_busy = false; return true; }

static const usbd_class_driver_t s_driver = {
  "FAVKBD",
  drvInit, drvDeinit, drvReset, drvOpen, drvControl, drvXfer, nullptr, nullptr
};

// Registers the interface while the USB stack is still being assembled (a
// static object: constructors run before Arduino starts USB).
struct Reg { Reg() { tinyusb_enable_interface(USB_INTERFACE_CUSTOM, TUD_HID_DESC_LEN, descCb); } };
static Reg s_reg;

// ---- sending -------------------------------------------------------------------
static bool sendReport(uint8_t mod, uint8_t usage) {
  if (!s_mounted || !tud_mounted()) return false;
  uint32_t t0 = millis();
  while (s_busy) { if (millis() - t0 > 100) { s_fail++; return false; } delay(1); }
  if (!usbd_edpt_claim(0, s_epIn)) { s_fail++; return false; }
  memset(s_report, 0, 8); s_report[0] = mod; s_report[2] = usage;
  s_busy = true;
  bool ok = usbd_edpt_xfer(0, s_epIn, s_report, 8);
  if (!ok) { s_busy = false; usbd_edpt_release(0, s_epIn); s_fail++; return false; }
  t0 = millis();
  while (s_busy) { if (millis() - t0 > 100) { s_fail++; return false; } delay(1); }
  s_sent++;
  return true;
}

// Type s (len bytes). Checks the whole string first (nothing is typed if any
// character cannot be). Returns 0 ok, n > 0 untypable characters (listed in
// bad), -1 the host is not listening, -2 a report failed part way.
inline int type(const char* s, size_t len, char* bad, size_t badCap) {
  int n = untypable(s, len, bad, badCap);
  if (n) return n;
  if (!s_mounted || !tud_mounted() || tud_suspended()) return -1;   // 8l: as ready() below
  for (size_t i = 0; i < len; i++) {
    Key k = keyFor(s[i]);
    if (!sendReport(k.shift ? 0x02 : 0x00, k.usage)) { sendReport(0, 0); return -2; }   // 0x02 = left shift
    if (!sendReport(0, 0)) return -2;                                                   // release: repeated letters need it
    delay(2);
  }
  return 0;
}
// 8l (bench, 5 Nov 2026): the S3 does not see the cable pulled (no VBUS sense),
// so TinyUSB stays "mounted" after unplugging and the KEY kept typing to a USB
// host that was gone instead of the phone. A pulled cable leaves the bus idle,
// which the device sees as suspend: a suspended bus is not a keyboard target.
inline bool ready() { return s_mounted && tud_mounted() && !tud_suspended(); }
inline void status() { Serial.printf("[KBD] interface %u, IN 0x%02X | mounted %d (host %d) | protocol %u | reports %lu, failed %lu\n",
                                     s_itf, s_epIn, (int)s_mounted, (int)tud_mounted(), s_protocol, (unsigned long)s_sent, (unsigned long)s_fail); }

}  // namespace kbd

// TinyUSB asks for extra class drivers at stack init (weak in the prebuilt lib).
#ifndef FAVILLA_VCHAN   // with the channel, vchan_hid.h hands TinyUSB both drivers
extern "C" usbd_class_driver_t const* usbd_app_driver_get_cb(uint8_t* driver_count) {
  *driver_count = 1;
  return &kbd::s_driver;
}
#endif
#endif  // FAVILLA_FIDO_PROBE
