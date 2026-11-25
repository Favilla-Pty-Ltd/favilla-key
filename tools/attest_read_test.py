# Run: python3 tools/attest_read_test.py   (no KEY needed: a simulated USB channel and serial port)
# With --station "<Manufacturing Station folder>": also checks that a signature read
# this way passes the station's own self-test check (favilla_attest.ecdsa_verify_digest).
import importlib.util, json, os, sys, types
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ar", os.path.join(HERE, "attest_read.py")); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
ar.time.sleep = lambda s: None
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
TV = bytes.fromhex("967f3b1c35499df87b573e2671e03d29c535b6cec24e391d58ea437f9671ba11")
priv = ec.generate_private_key(ec.SECP256R1())
PK = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
r_, s_ = decode_dss_signature(priv.sign(TV, ec.ECDSA(Prehashed(hashes.SHA256()))))
SIG = r_.to_bytes(32, "big") + s_.to_bytes(32, "big")     # the SE's raw r||s
fails = 0
def ok(c, m):
    global fails; print(("ok:   " if c else "FAIL: ") + m); fails += 0 if c else 1

# ---- the USB channel ----
def rsp(state, part, data=b""):
    r = bytearray(64); r[0] = 0x84; r[1] = state; r[2] = part; r[3:3 + len(data)] = data; return list(r)
class Dev:
    def __init__(s, answer): s.answer = answer; s.out = []
    def open_path(s, p): pass
    def close(s): pass
    def write(s, b): assert b[0] == 0 and b[1] == 0x04 and len(b) == 65; s.out = s.answer(b[2])
    def read(s, n, t): return s.out.pop(0) if s.out else []
class Hid:
    def __init__(s, keys, answer): s.keys = keys; s.answer = answer
    def enumerate(s, vid, pid): assert vid == 0x303A; return s.keys
    def device(s): return Dev(s.answer)
KEY = {"path": b"p1", "usage_page": 0xFF46, "serial_number": "3C8427ABCDEF"}
OTHER = {"path": b"k", "usage_page": 0x01, "serial_number": "3C8427ABCDEF"}   # the keyboard interface: not ours
NOSER = types.SimpleNamespace(comports=lambda: [])
def good_after(n_booting):
    calls = {"n": 0}
    def answer(part):
        calls["n"] += 1
        if part == 0 and calls["n"] <= n_booting: return [rsp(0, 0)]
        if part == 0: return [list(b"\x82" + bytes(63)), rsp(1, 0, PK + b"11eh")]
        return [rsp(1, part, SIG[(part - 1) * 32: part * 32])]
    return answer
code, res = ar.read(wait=3, hid=Hid([OTHER, KEY], good_after(1)), list_ports=NOSER)
ok(code == 0 and res["pk"] == PK.hex() and res["sig"] == SIG.hex() and res["mac"] == "3C8427ABCDEF" and res["drop"] == "11eh" and res["via"] == "usb channel",
   "USB channel: booting, then pk + signature (two halves), MAC and drop; other reports ignored")
code, res = ar.read(wait=3, hid=Hid([KEY], lambda p: [rsp(2, p)]), list_ports=NOSER); ok(code == 3, "USB channel: no device key -> 3")
code, res = ar.read(wait=3, hid=Hid([KEY], lambda p: []), list_ports=NOSER); ok(code == 4, "USB channel: no answer (old firmware) -> 4")
K2 = dict(KEY, path=b"p2", serial_number="3C8427000001")
code, res = ar.read(wait=3, hid=Hid([KEY, K2], good_after(0)), list_ports=NOSER); ok(code == 5 and len(res["macs"]) == 2, "two KEYs -> 5 with both MACs")
code, res = ar.read(mac="3c:84:27:00:00:01", wait=3, hid=Hid([KEY, K2], good_after(0)), list_ports=NOSER); ok(code == 0 and res["mac"] == "3C8427000001", "--mac picks one")

# ---- the serial port (release builds) ----
class Port:
    def __init__(s, dev, pid, sn): s.device, s.vid, s.pid, s.serial_number = dev, 0x303A, pid, sn
class Ser:
    def __init__(s, lines): s.lines = list(lines)
    def __call__(s, dev, baud, timeout): return s
    def __enter__(s): return s
    def __exit__(s, *a): pass
    def write(s, b): assert b == b"attest selftest\n"
    def read(s, n): return s.lines.pop(0).encode() if s.lines else b""
NOHID = types.SimpleNamespace(enumerate=lambda v, p: [])
FLASH = Port("COM9", 0x1001, "3C:84:27:AB:CD:EF"); RUN = Port("COM7", 0x0002, "3C8427ABCDEF")
def ser(ports, lines): return ar.read(wait=3, hid=NOHID, serial_mod=types.SimpleNamespace(Serial=Ser(lines)), list_ports=types.SimpleNamespace(comports=lambda: ports))
code, res = ser([FLASH, RUN], ["boot noise\n[ATTEST] selftest pubkey(c", "33)=" + PK.hex() + "\n[ATTEST] selftest sig(raw64)=" + SIG.hex() + "\n"])
ok(code == 0 and res["pk"] == PK.hex() and res["sig"] == SIG.hex() and res["port"] == "COM7" and res["via"] == "serial", "serial: pk + sig from split reads; the Flash-mode port skipped")
code, res = ser([FLASH], []); ok(code == 2, "serial: only the Flash-mode port -> 2")
code, res = ser([RUN], ["[attest] no key — run `attest provision` first\n"]); ok(code == 3, "serial: no device key -> 3")
code, res = ser([RUN], []); ok(code == 4 and "COM7" in res["error"], "serial: no answer -> 4, names the port")
code, res = ser([], []); ok(code == 2, "nothing plugged in -> 2")

# ---- the station's own check ----
if "--station" in sys.argv:
    st = sys.argv[sys.argv.index("--station") + 1]
    sys.path.insert(0, os.path.join(st, "Attestation"))
    import favilla_attest as A
    code, res = ar.read(wait=3, hid=Hid([KEY], good_after(0)), list_ports=NOSER)
    ok(A.ecdsa_verify_digest(A.c33_to_pub(bytes.fromhex(res["pk"])), bytes.fromhex(res["sig"]), TV), "station: a signature read over USB passes favilla_attest.ecdsa_verify_digest")
    bad = bytearray(bytes.fromhex(res["sig"])); bad[5] ^= 1
    ok(not A.ecdsa_verify_digest(A.c33_to_pub(bytes.fromhex(res["pk"])), bytes(bad), TV), "station: a tampered signature fails it")
# ---- WDT, the `wdt last` report (11en) ----
import struct
class WDev(Dev):
    def write(s, b): assert b[0] == 0 and b[1] == 0x05 and len(b) == 65; s.out = s.answer(None)
class WHid(Hid):
    def device(s): return WDev(s.answer)
def wrsp(reason, valid, count=0, up=0, state=0, i2c=b"", disp=b"", cpu1=b""):
    r = bytearray(64); r[0] = 0x85; r[1] = reason; r[2] = valid
    struct.pack_into("<IIi", r, 3, count, up, state)
    r[15:15 + len(i2c)] = i2c; r[31:31 + len(disp)] = disp; r[47:47 + len(cpu1)] = cpu1
    return list(r)
code, res = ar.read_wdt(wait=3, hid=WHid([OTHER, KEY], lambda _: [rsp(1, 0), wrsp(6, 1, 2, 734000, 41, b"loopTask", b"uiTask", b"IDLE1")]))
ok(code == 0 and res["reset_text"] == "WATCHDOG: main loop stuck" and res["watchdog_restarts"] == 2 and res["last_stuck_uptime_s"] == 734
   and res["ui_state"] == 41 and res["i2c_lock"] == "loopTask" and res["display_lock"] == "uiTask" and res["cpu1_task"] == "IDLE1",
   "WDT: watchdog restart with its crumb; ATT answers on the channel ignored")
code, res = ar.read_wdt(wait=3, hid=WHid([KEY], lambda _: [wrsp(1, 0)]))
ok(code == 0 and res["reset_text"] == "power on" and res["watchdog_crumb"] is False and "i2c_lock" not in res, "WDT: power on, no crumb")
code, res = ar.read_wdt(wait=3, hid=WHid([KEY], lambda _: [])); ok(code == 4, "WDT: no answer (older firmware) -> 4")
code, res = ar.read_wdt(wait=3, hid=WHid([], lambda _: [])); ok(code == 2, "WDT: no KEY -> 2")
print("all passed" if not fails else f"{fails} FAILED"); sys.exit(1 if fails else 0)
