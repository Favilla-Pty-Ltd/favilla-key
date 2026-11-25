#!/usr/bin/env python3
"""attest_read.py - read a Favilla KEY's device (attestation) public key over USB.

For the Forge (firmware 11eh and later). The KEY makes its device key on its own
first boot, inside its SE051 (no `attest provision` step any more), and signs
the fixed self-test vector with it. This reads the public key and that
signature back, whichever way the build offers them:

  - the extension's USB channel (vendor HID, usage page 0xFF46): builds with the
    channel (fido_release from 11en, fido_pmv, fido_vchan), in every mode, even
    at the door screen;
  - the USB serial port: release builds before 11en (fido_release had a serial
    port and no channel until issue #74), which take only the `attest` and
    `wdt last` commands. Leave the KEY booted, not in Flash mode
    (Flash mode is a different port with no firmware behind it). If it does not
    answer, choose NOSTR on the KEY.

The station checks the signature against the self-test vector (as it always
did), which shows the key really signs inside that KEY's SE.

    pip install hidapi pyserial
    python tools/attest_read.py                  the one KEY plugged in
    python tools/attest_read.py --list           every KEY seen, with its MAC
    python tools/attest_read.py --mac 3C8427...  one KEY when several are in
    python tools/attest_read.py --wdt            why the KEY last restarted
                                                 (`wdt last`, over the channel)

Prints one JSON line and exits 0:
    {"pk": "<66 hex>", "sig": "<128 hex>", "mac": "<12 hex>", "drop": "11eh", "via": "usb channel"}
Exit codes: 2 no KEY found, 3 the KEY has no device key (making it failed: see
its boot log), 4 no answer (firmware older than 11eh, or busy), 5 more than one
KEY (use --mac). From Python: read(mac=None, wait=20) returns (code, dict).

Nothing secret is read: the private key never leaves the SE051.
"""
import argparse
import json
import re
import sys
import time

VID = 0x303A                # Espressif (the KEY's USB vendor id)
USAGE_PAGE = 0xFF46         # the Favilla channel
USJ_PID = 0x1001            # the chip's own USB-JTAG port: Flash mode, no firmware to talk to
CMD_ATT, RSP_ATT = 0x04, 0x84
CMD_WDT, RSP_WDT = 0x05, 0x85
RESET_REASONS = {0: "unknown", 1: "power on", 2: "external pin", 3: "software restart", 4: "panic",
                 5: "interrupt watchdog", 6: "WATCHDOG: main loop stuck", 7: "other watchdog",
                 8: "wake from sleep", 9: "brownout", 10: "SDIO", 11: "USB", 12: "JTAG",
                 13: "eFuse error", 14: "power glitch", 15: "CPU lock-up"}


def _norm_mac(s):
    return (s or "").replace(":", "").upper()


# ---- the extension's USB channel (builds with it) ----
def _hid_keys(hid):
    return [d for d in hid.enumerate(VID, 0) if d.get("usage_page") == USAGE_PAGE]


def _hid_part(dev, part, deadline):
    """Ask for one part; returns (state, data) or None when nothing came back in time."""
    while time.time() < deadline:
        dev.write(bytes([0x00, CMD_ATT, part]) + bytes(62))   # report id 0, then the 64-byte report
        t_end = min(deadline, time.time() + 1.0)
        while time.time() < t_end:
            r = dev.read(64, 250)
            if not r or r[0] != RSP_ATT or r[2] != part:
                continue                                       # nothing yet, or something else on the channel
            return r[1], bytes(r[3:])
        time.sleep(0.2)
    return None


def _hid_read(hid, info, wait_s):
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        deadline = time.time() + wait_s
        while time.time() < deadline:
            a = _hid_part(dev, 0, deadline)
            if a is None:
                return None
            state, data = a
            if state == 2:
                return {"error": "no device key"}
            if state != 1:
                time.sleep(0.5)                                # 0: still booting, ask again
                continue
            pk, drop = data[:33].hex(), data[33:41].split(b"\0")[0].decode("ascii", "replace")
            b, c = _hid_part(dev, 1, deadline), _hid_part(dev, 2, deadline)
            if b is None or c is None:
                return None
            return {"pk": pk, "sig": b[1][:32].hex() + c[1][:32].hex(), "drop": drop}
        return None
    finally:
        dev.close()


def _hid_wdt(hid, info, wait_s):
    """The `wdt last` report (WDT request, 25 Nov 2026); None when nothing came back."""
    import struct
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        deadline = time.time() + wait_s
        while time.time() < deadline:
            dev.write(bytes([0x00, CMD_WDT]) + bytes(63))
            t_end = min(deadline, time.time() + 1.0)
            while time.time() < t_end:
                r = dev.read(64, 250)
                if not r or r[0] != RSP_WDT:
                    continue
                r = bytes(r) + bytes(64 - len(r))
                count, up_ms, state = struct.unpack_from("<IIi", r, 3)
                name = lambda o: r[o:o + 16].split(b"\0")[0].decode("ascii", "replace")
                out = {"reset_reason": r[1], "reset_text": RESET_REASONS.get(r[1], "other"),
                       "watchdog_crumb": bool(r[2])}
                if r[2]:
                    out.update(watchdog_restarts=count, last_stuck_uptime_s=up_ms // 1000, ui_state=state,
                               i2c_lock=name(15), display_lock=name(31), cpu1_task=name(47))
                return out
            time.sleep(0.2)
        return None
    finally:
        dev.close()


def read_wdt(mac=None, wait=10.0, hid=None):
    """-> (code, result dict): why the KEY last restarted. Channel builds only."""
    hid, _, _ = _load_libs(hid, None, None)
    keys = _hid_keys(hid) if hid else []
    if mac:
        keys = [k for k in keys if _norm_mac(k.get("serial_number")) == _norm_mac(mac)]
    if not keys:
        return 2, {"error": "no Favilla KEY found on the USB channel"}
    if len(keys) > 1:
        return 5, {"error": "more than one KEY plugged in: use --mac", "macs": [_norm_mac(k.get("serial_number")) for k in keys]}
    res = _hid_wdt(hid, keys[0], wait)
    if res is None:
        return 4, {"error": "no answer to WDT (firmware older than 11en?)"}
    res["mac"] = _norm_mac(keys[0].get("serial_number"))
    return 0, res


# ---- the USB serial port (release builds before 11en) ----
def _serial_ports(list_ports):
    return [p for p in list_ports.comports() if p.vid == VID and p.pid != USJ_PID]


def _serial_read(serial_mod, port, wait_s):
    deadline = time.time() + wait_s
    with serial_mod.Serial(port.device, 115200, timeout=0.3) as ser:
        buf = ""
        while time.time() < deadline:
            ser.write(b"attest selftest\n")
            t_end = time.time() + 1.5
            while time.time() < t_end:
                chunk = ser.read(512).decode("ascii", "replace")
                if not chunk:
                    continue
                buf = (buf + chunk)[-4096:]
                m = re.search(r"pubkey\(c33\)=([0-9a-f]{66})", buf)
                g = re.search(r"sig\(raw64\)=([0-9a-f]{128})", buf)
                if m and g:
                    return {"pk": m.group(1), "sig": g.group(1)}
                if "selftest: no pubkey" in buf or "[attest] no key" in buf:
                    return {"error": "no device key"}
            time.sleep(0.5)
    return None


def _load_libs(hid, serial_mod, list_ports):
    if hid is None:
        try:
            import hid as hid
        except ImportError:
            hid = None
    if list_ports is None:
        try:
            import serial as serial_mod
            from serial.tools import list_ports
        except ImportError:
            serial_mod = list_ports = None
    return hid, serial_mod, list_ports


def list_keys(hid=None, serial_mod=None, list_ports=None):
    hid, serial_mod, list_ports = _load_libs(hid, serial_mod, list_ports)
    out = [{"mac": _norm_mac(k.get("serial_number")), "via": "usb channel"} for k in (_hid_keys(hid) if hid else [])]
    out += [{"mac": _norm_mac(p.serial_number), "port": p.device, "via": "serial"} for p in (_serial_ports(list_ports) if list_ports else [])]
    return out


def read(mac=None, wait=20.0, hid=None, serial_mod=None, list_ports=None):
    """-> (code, result dict). code 0 = ok; see the module text for the others."""
    hid, serial_mod, list_ports = _load_libs(hid, serial_mod, list_ports)
    want = _norm_mac(mac) if mac else None
    keys = _hid_keys(hid) if hid else []
    if want:
        keys = [k for k in keys if _norm_mac(k.get("serial_number")) == want]
    if len(keys) > 1:
        return 5, {"error": "more than one KEY plugged in: use --mac", "macs": [_norm_mac(k.get("serial_number")) for k in keys]}
    if keys:
        res = _hid_read(hid, keys[0], wait)
        if res is None:
            return 4, {"error": "no answer on the USB channel (firmware older than 11eh?)"}
        res.update(via="usb channel", mac=_norm_mac(keys[0].get("serial_number")))
        return (3 if "error" in res else 0), res
    ports = _serial_ports(list_ports) if list_ports else []
    if want:
        ports = [p for p in ports if _norm_mac(p.serial_number) == want]
    if not ports:
        return 2, {"error": "no Favilla KEY found on USB (booted, not in Flash mode?)"}
    if len(ports) > 1:
        return 5, {"error": "more than one KEY plugged in: use --mac", "macs": [_norm_mac(p.serial_number) for p in ports]}
    res = _serial_read(serial_mod, ports[0], wait)
    if res is None:
        return 4, {"error": "no answer on " + ports[0].device + " (choose NOSTR on the KEY, close any serial monitor)"}
    res.update(via="serial", port=ports[0].device, mac=_norm_mac(ports[0].serial_number))
    return (3 if "error" in res else 0), res


def main(argv=None, hid=None, serial_mod=None, list_ports=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mac", help="the KEY's MAC (12 hex, as --list shows) when several are plugged in")
    ap.add_argument("--list", action="store_true", help="list the KEYs seen and exit")
    ap.add_argument("--wdt", action="store_true", help="print why the KEY last restarted (`wdt last`) and exit")
    ap.add_argument("--wait", type=float, default=20.0, help="seconds to wait for the KEY to finish booting (default 20)")
    a = ap.parse_args(argv)
    if a.list:
        for k in list_keys(hid, serial_mod, list_ports):
            print(json.dumps(k))
        return 0
    if a.wdt:
        code, res = read_wdt(a.mac, a.wait, hid)
        print(json.dumps(res))
        return code
    code, res = read(a.mac, a.wait, hid, serial_mod, list_ports)
    print(json.dumps(res))
    return code


if __name__ == "__main__":
    sys.exit(main())
