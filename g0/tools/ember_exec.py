#!/usr/bin/env python3
"""ember_exec.py - the executor, on a PC, for the mainnet lifecycle test. 28 Oct 2026.

Owns the KEY's serial port and does what an executor app will do one day:
  - keeps the G0's header clock current (mempool.space -> em hdr), every minute
  - asks the G0 what the rule allows (em status); when it allows a refresh or a
    coupon, pulls the signed transaction (em release) and broadcasts it
    (POST mempool.space/api/tx)
  - once a broadcast confirms deep enough (refresh 3, coupon 1), fetches the
    merkle proof and the block header and hands them to the G0 (em proof),
    which is what moves the walk to the next link / ends the plan
  - logs everything with timestamps; state in ember_exec_state.json so it can
    be stopped and restarted

Close the serial monitor first, then:
  C:\\Users\\<you>\\.platformio\\penv\\Scripts\\python.exe tools\\ember_exec.py COM3

The KEY stays on the lock screen (heir path). Unlocking it is a sign of life
and resets the fuse: do that only when you mean to.
"""
import sys, time, json, os, hashlib, urllib.request, urllib.error
try:
    import serial
except ImportError:
    sys.exit("pyserial missing: run this with PlatformIO's python (see the docstring)")

if len(sys.argv) < 2: sys.exit("usage: ember_exec.py COMx")
PORT = sys.argv[1]; UP = "https://mempool.space"; STATE = "ember_exec_state.json"
state = json.load(open(STATE)) if os.path.exists(STATE) else {"broadcast": {}}
def save(): json.dump(state, open(STATE, "w"), indent=1)
def log(*a): print(time.strftime("%H:%M:%S"), *a, flush=True)

def get(path):
    with urllib.request.urlopen(UP + path, timeout=20) as r: return r.read()
def post_tx(hexraw):
    req = urllib.request.Request(UP + "/api/tx", data=hexraw.encode(), method="POST", headers={"Content-Type": "text/plain"})
    with urllib.request.urlopen(req, timeout=20) as r: return r.read().decode().strip()

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def header_hex(o):
    le = lambda v: v.to_bytes(4, "little"); rev = lambda h: bytes.fromhex(h)[::-1]
    return (le(o["version"]) + rev(o["previousblockhash"]) + rev(o["merkle_root"]) + le(o["timestamp"]) + le(o["bits"]) + le(o["nonce"])).hex()

ser = serial.Serial(PORT, 115200, timeout=0.2, write_timeout=2); ser.dtr = True
time.sleep(0.3); ser.reset_input_buffer()
def send(cmd):
    b = (cmd + "\n").encode()
    for i in range(0, len(b), 32):
        for attempt in range(5):
            try: ser.write(b[i:i + 32]); ser.flush(); break
            except serial.SerialTimeoutException: time.sleep(0.2)
        else: sys.exit("the KEY stopped taking serial input (is the serial monitor still open?)")
        time.sleep(0.01)
def ask(cmd, want, tmo=60, echo=False):
    """Send cmd, return all lines until one contains `want` (as a list), or None."""
    send(cmd); t0 = time.time(); buf = b""; lines = []
    while time.time() - t0 < tmo:
        buf += ser.read(4096)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1); l = line.decode("latin1").strip(); lines.append(l)
            if echo and l: print("   ", l)
            if want in l: return lines
    return None

def status():
    ls = ask("em status", "next allowed", tmo=30)
    if not ls: ls = ask("em status", "plan no", tmo=10)
    if not ls: return None
    st = {"raw": ls}
    for l in ls:
        if "[EMB]   tip" in l: st["tip"] = int(l.split("tip")[1].split()[0])
        if "plan yes" in l: st["plan"] = True; st["flags"] = l
        if "plan no" in l: st["plan"] = False
        if "next allowed:" in l:
            w = l.split("next allowed:")[1].split(); st["next"] = (w[0], int(w[2]), int(w[4]))
        if "link " in l and " X " in l:
            w = l.split(); st["link"] = int(w[2]); st["nlinks"] = int(w[4]); st["X"] = int(w[6]); st["last_life"] = int(l.split("last_life")[1].split()[0])
    return st

def feed_headers(tip):
    net = int(get("/api/blocks/tip/height"))
    if net <= tip: return tip
    h = tip + 1; fed = 0
    while h <= net:
        top = min(h + 9, net)
        page = sorted(json.loads(get("/api/v1/blocks/%d" % top)), key=lambda o: o["height"])
        for o in page:
            if o["height"] < h: continue
            r = ask("em hdr " + header_hex(o), "[EMB] hdr", tmo=15)
            if not r or not (" rc 0 " in r[-1] or " rc 3 " in r[-1]):   # 3 = DUP: the KEY's own sync got there first
                log("header", o["height"], "refused:", r[-1] if r else "no answer"); return h - 1
            fed += 1; h = o["height"] + 1
    ask("em hdr-done", "[EMB]   tip", tmo=15)
    log("fed", fed, "headers, G0 tip", net)
    return net

def release():
    ls = ask("em release", "tampered blob", tmo=30)
    if not ls: return None
    import re
    for i, l in enumerate(ls):
        if "RELEASED" in l:
            for m in ls[i + 1:]:
                m = m.strip()
                if re.fullmatch(r"[0-9a-f]{100,}", m): return m
    for l in ls:
        if "refused" in l: log(l)
    return None

def send_proof(kind, link, var, txid):
    pr = json.loads(get("/api/tx/%s/merkle-proof" % txid))
    hdr = bytes.fromhex(get("/api/block/%s/header" % json.loads(get("/api/tx/%s/status" % txid))["block_hash"]).decode())
    root = hdr[36:68]; txb = bytes.fromhex(txid)[::-1]; pos = pr["pos"]; branch = [bytes.fromhex(x) for x in pr["merkle"]]
    # the API's byte order is checked here against the header's root, both ways
    def check(br):
        h = txb; i = pos
        for sib in br:
            h = dsha(sib + h if i & 1 else h + sib); i >>= 1
        return h == root
    if not check(branch):
        branch = [b[::-1] for b in branch]
        if not check(branch): log("merkle proof does not check either way; not sent"); return False
    depth = len(branch)
    if depth > 20: log("proof deeper than 20"); return False
    b = bytes([ord(kind), link, var, depth]) + pos.to_bytes(4, "little") + hdr + b"".join(branch) + b"\0" * (32 * (20 - depth))
    assert len(b) == 728
    ls = ask("em proof " + b.hex(), "EM_PROOF", tmo=30)
    ok = bool(ls) and " rc 0 " in ls[-1]
    log("proof", kind, link, var, "->", ls[-1] if ls else "no answer")
    return ok

st = status()
if not st or not st.get("plan"): sys.exit("the G0 reports no plan; run em plan + em ceremony first")
log("plan on the G0:", st["flags"]); [log("  ", l) for l in st["raw"] if l.startswith("[EMB]  ")]
tip = st["tip"]
while True:
    try:
        tip = feed_headers(tip)
        st = status()
        if not st: log("no status"); time.sleep(30); continue
        nxt = st.get("next", ("nothing", 0, 0))
        log("tip", st["tip"], "| link", st.get("link"), "of", st.get("nlinks"), "| X", st.get("X"), "| last_life", st.get("last_life"), "| next allowed:", *nxt)
        if nxt[0] != "nothing":
            key = "%s-%d-%d" % nxt
            if key not in state["broadcast"]:
                raw = release()
                if raw:
                    try:
                        txid = post_tx(raw)
                        state["broadcast"][key] = {"txid": txid, "raw": raw, "at": time.time(), "proved": False}; save()
                        log("BROADCAST", key, "txid", txid)
                    except urllib.error.HTTPError as e:
                        log("broadcast rejected:", e.read().decode()[:200]); state["broadcast"][key] = {"txid": None, "raw": raw, "err": True}; save()
        for key, b in list(state["broadcast"].items()):
            if not b.get("txid") or b.get("proved"): continue
            s = json.loads(get("/api/tx/%s/status" % b["txid"]))
            if not s.get("confirmed"): continue
            conf = st["tip"] - s["block_height"] + 1
            kind, link, var = key.split("-"); kind = "R" if kind == "REFRESH" else "C"
            need = 3 if kind == "R" else 1
            log(key, "confirmed at", s["block_height"], "depth", conf, "need", need)
            if conf >= need and send_proof(kind, int(link), int(var), b["txid"]): b["proved"] = True; save()
    except KeyboardInterrupt:
        break
    except Exception as e:
        log("error:", repr(e))
    time.sleep(60)
