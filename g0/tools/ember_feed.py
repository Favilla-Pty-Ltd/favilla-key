#!/usr/bin/env python3
"""ember_feed.py - bench helper, 28 Oct 2026.

Feeds mainnet headers to the Emberwill G0 over the KEY's USB serial port,
with the PC doing the fetching. The KEY's WiFi stays out of it (the bench
build's WiFi driver crashed twice during a long `em sync`; the G0 held its
chain both times). The G0 still checks every header's proof of work itself;
this only moves bytes.

    close the serial monitor first (one program per COM port), then:
    C:\\Users\\<you>\\.platformio\\penv\\Scripts\\python.exe tools\\ember_feed.py COM5

Needs the ember-bench-6 (or later) KEY image: it drives `em hdr <hex>`.
Stops at the network tip, on any G0 refusal, or on Ctrl-C; re-running
carries on from wherever the G0 is.
"""
import sys, time, json, urllib.request
try:
    import serial
except ImportError:
    sys.exit("pyserial missing: run this with PlatformIO's python (see the docstring)")

if len(sys.argv) < 2: sys.exit("usage: ember_feed.py COMx [max_headers]")
PORT = sys.argv[1]; MAXN = int(sys.argv[2]) if len(sys.argv) > 2 else 10**6
UP = "https://mempool.space"

def get(path):
    with urllib.request.urlopen(UP + path, timeout=20) as r: return r.read()

def header_hex(o):
    le = lambda v: v.to_bytes(4, "little")
    rev = lambda h: bytes.fromhex(h)[::-1]
    return (le(o["version"]) + rev(o["previousblockhash"]) + rev(o["merkle_root"]) +
            le(o["timestamp"]) + le(o["bits"]) + le(o["nonce"])).hex()

ser = serial.Serial(PORT, 115200, timeout=0.2, write_timeout=2)
ser.dtr = True
time.sleep(0.3); ser.reset_input_buffer()

def send(cmd):
    # The KEY's USB port takes a long line in small pieces: 32 bytes at a time
    # with a short gap, and a stalled piece is retried rather than fatal.
    b = (cmd + "\n").encode()
    for i in range(0, len(b), 32):
        for attempt in range(5):
            try:
                ser.write(b[i:i + 32]); ser.flush(); break
            except serial.SerialTimeoutException:
                time.sleep(0.2)
        else:
            sys.exit("the KEY stopped taking serial input (is the serial monitor still open?)")
        time.sleep(0.01)

def ask(cmd, want, tmo=10):
    send(cmd)
    t0 = time.time(); buf = b""
    while time.time() - t0 < tmo:
        buf += ser.read(4096)
        for line in buf.decode("latin1").splitlines():
            if want in line: return line.strip()
    return None

st = ask("em status", "[EMB]   tip")
if not st: sys.exit("no [EMB] status from the KEY: is the bench image flashed and the monitor closed?")
tip = int(st.split("tip")[1].split()[0])
net = int(get("/api/blocks/tip/height"))
print("G0 tip %d, network tip %d: %d to feed" % (tip, net, net - tip))

fed = 0; t0 = time.time(); ms_sum = 0
h = tip + 1
while h <= net and fed < MAXN:
    top = min(h + 9, net)
    page = sorted(json.loads(get("/api/v1/blocks/%d" % top)), key=lambda o: o["height"])
    for o in page:
        if o["height"] < h: continue
        r = ask("em hdr " + header_hex(o), "[EMB] hdr", tmo=15)
        if not r: sys.exit("no answer for %d" % o["height"])
        if " rc 0 " not in r: sys.exit("G0 refused %d: %s" % (o["height"], r))
        ms_sum += int(r.split()[-2]); fed += 1; h = o["height"] + 1
        if fed % 100 == 0: print("  %d fed, at %d, %d s, G0 %d ms/header" % (fed, h - 1, time.time() - t0, ms_sum // fed))
    net = int(get("/api/blocks/tip/height"))
done = ask("em hdr-done", "[EMB]   tip", tmo=15)
print("fed %d headers in %d s (G0 %d ms per header incl. I2C)" % (fed, time.time() - t0, ms_sum // fed if fed else 0))
print(done)
