# Passwordless passkeys over CTAP2 (2 Nov 2026, Vault spec phase 2): the REAL
# fido_hid.h and the REAL pk_records.cpp (sealed records, budget, cache) against
# models of the G0's PKSIGN and VAULT (harness_pkr.cpp, rk_host.cpp).
import cbor2, subprocess, hashlib, os, re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
def req(cmd, m): return bytes([cmd]) + cbor2.dumps(m, canonical=True)
def run(args):
    out = subprocess.run(["./harness_pkr"] + args, capture_output=True, text=True, errors="strict")
    msgs, pkts = [], []
    for line in out.stdout.splitlines():
        if line == "END": msgs.append(pkts); pkts = []
        elif line.startswith("PKT "): pkts.append(bytes.fromhex(line[4:]))
    return msgs, out.stderr
def reassemble(pkts):
    res, i = [], 0
    while i < len(pkts):
        p = pkts[i]; cmd = p[4] & 0x7f; n = (p[5] << 8) | p[6]; data = p[7:7+min(n,57)]; i += 1
        while len(data) < n: data += pkts[i][5:5+min(59, n-len(data))]; i += 1
        res.append((cmd, data))
    return res
def last(m): r = [x for x in reassemble(m) if x[0] == 0x10]; return r[-1][1] if r else None
ok = True
def check(c, m):
    global ok; print(("PASS " if c else "FAIL ") + m); ok &= c
def rkstats(err): return [tuple(map(int, x)) for x in re.findall(r"RKSTATS records=(\d+) openleft=(-?\d+) tags=(\d+) opens=(\d+) seals=(\d+)", err)]
def kinds(err): return re.findall(r"PROMPT kind=(\d)", err)
def picks(err): return re.findall(r"PICK n=(\d+)(.*)", err)
def pub_of(adr):
    cl = int.from_bytes(adr[53:55], "big"); cid = adr[55:55+cl]; cose = cbor2.loads(adr[55+cl:])
    return cid, ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2],"big"), int.from_bytes(cose[-3],"big"), ec.SECP256R1()).public_key()
def verifies(pub, sig, msg):
    try: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())); return True
    except InvalidSignature: return False

rp = "webauthn.io"; rph = hashlib.sha256(rp.encode()).digest(); cdh = os.urandom(32)
def mc(handle, name, disp, extra=None, site=rp):
    m = {1: os.urandom(32), 2: {"id": site, "name": "x"}, 3: {"id": handle, "name": name, "displayName": disp}, 4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}}
    if extra: m.update(extra)
    return req(1, m)
open("r_mc_a.bin","wb").write(mc(b"\xA1"*16, "josh@favilla.io", "Josh"))
open("r_mc_b.bin","wb").write(mc(b"\xB2"*16, "alicia@favilla.io", "Alicia"))
open("r_mc_a2.bin","wb").write(mc(b"\xA1"*16, "josh2@favilla.io", "Josh C"))
open("r_mc_other.bin","wb").write(mc(b"\xC3"*8, "z", "Z", site="other.example"))
open("r_mc_noid.bin","wb").write(req(1, {1: os.urandom(32), 2: {"id": rp}, 3: {"name": "n"}, 4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}}))
open("r_mc_bigid.bin","wb").write(mc(b"\x01"*65, "n", "n"))
open("r_mc_longrp.bin","wb").write(mc(b"\x01"*8, "n", "n", site="a"*200 + ".io"))
utf = ("é" * 40)   # 80 bytes of 2-byte characters
open("r_mc_utf.bin","wb").write(mc(b"\xD4"*8, utf, utf, site="utf.example"))
open("r_ga.bin","wb").write(req(2, {1: rp, 2: cdh}))
open("r_ga_uv.bin","wb").write(req(2, {1: rp, 2: cdh, 5: {"uv": True}}))
open("r_ga_silent.bin","wb").write(req(2, {1: rp, 2: cdh, 5: {"up": False}}))
open("r_ga_none.bin","wb").write(req(2, {1: "nobody.example", 2: cdh}))
open("r_ga_utf.bin","wb").write(req(2, {1: "utf.example", 2: cdh}))
open("r_mc_plain.bin","wb").write(req(1, {1: os.urandom(32), 2: {"id": rp}, 3: {"id": b"\xEE"*8, "name": "p"}, 4: [{"alg": -7, "type": "public-key"}]}))

# 1. register two accounts (rk), sign in with no username, pick each
msgs, err = run(["decide=aa", "r_mc_a.bin", "rkstats", "decide=a", "r_mc_b.bin", "rkstats",
                 "decide=0", "r_ga.bin", "rkstats", "decide=1", "r_ga.bin", "rkstats"])
st = rkstats(err); k = kinds(err); pk = picks(err)
s = last(msgs[0]); att = cbor2.loads(s[1:]); adA = att[2]; cidA, pubA = pub_of(adA)
check(s[0] == 0 and adA[32] == 0x5D and st[0][0] == 1 and st[0][4] == 1, f"rk register: one record sealed and saved, flags AT+UP+UV+BE+BS = 0x5D ({s[0]:#x}, {adA[32]:#x}, {st[0]})")
check(k[:2] == ["1", "0"], f"rk register: the one-time warning, then one press (UV from the window) ({k[:2]})")
s = last(msgs[1]); adB = cbor2.loads(s[1:])[2]; cidB, pubB = pub_of(adB)
check(s[0] == 0 and st[1][0] == 2, f"second account on the same site: two records ({st[1]})")
s = last(msgs[2]); a = cbor2.loads(s[1:])
check(s[0] == 0 and len(a) == 4 and a[1]["id"] == cidA and a[4] == {"id": b"\xA1"*16, "name": "josh@favilla.io", "displayName": "Josh"}, f"no-username sign-in, row 0: account A, its user handle, name and display name ({s[0]:#x}, {a.get(4)})")
check(a[2][:32] == rph and a[2][32] == 0x1D and verifies(pubA, a[3], a[2] + cdh), f"flags UP+UV+BE+BS = 0x1D and the signature verifies with A's registered key ({a[2][32]:#x})")
check(cbor2.dumps(a, canonical=True) == s[1:], "the assertion is canonical CBOR (keys and user map in order)")
check(pk[0][0] == "2" and "josh@favilla.io|Josh" in pk[0][1] and "alicia@favilla.io|Alicia" in pk[0][1], f"the KEY's picker lists both accounts ({pk[0]})")
s = last(msgs[3]); a = cbor2.loads(s[1:])
check(s[0] == 0 and a[1]["id"] == cidB and a[4]["id"] == b"\xB2"*16 and verifies(pubB, a[3], a[2] + cdh), "row 1: account B, signed with B's key")
check(st[2][3] == 0 and st[3][3] == 0 and st[2][2] == 1, f"records cached when sealed: sign-ins after registering cost no record opens, one tag ({st[2]}, {st[3]})")

# 2. same account again replaces; lock forgets the cache; power cycle keeps records
msgs, err = run(["decide=aa", "r_mc_a.bin", "r_mc_b.bin", "decide=a", "r_mc_a2.bin", "rkstats", "decide=0", "r_ga.bin", "rkstats",
                 "lock", "decide=0", "r_ga.bin", "rkstats", "powercycle", "decide=0", "r_ga.bin", "rkstats"])
st = rkstats(err); pk = picks(err)
check(st[0][0] == 2, f"the same user handle again replaces its record: still 2 ({st[0]})")
check("josh2@favilla.io|Josh C" in pk[0][1] and "josh@favilla.io|" not in pk[0][1], f"the picker shows the new name ({pk[0]})")
check(st[2][3] - st[1][3] == 2 and st[2][2] - st[1][2] == 1, f"after a lock the records are opened again (cache wiped): 2 opens, 1 tag ({st[1]} -> {st[2]})")
check(st[3][0] == 2 and st[3][1] == 30, f"a power cycle keeps the records (NVS), the budget is full again and two opens are used ({st[3]})")

# 3. refusals and edges
msgs, err = run(["decide=aa", "r_mc_a.bin", "decide=r", "r_ga.bin", "rkstats", "r_ga_silent.bin", "rkstats", "r_ga_none.bin", "rkstats",
                 "r_mc_noid.bin", "r_mc_bigid.bin", "r_mc_longrp.bin", "rkstats"])
st = rkstats(err); k = kinds(err)
s = last(msgs[1]); check(s[0] == 0x27 and len([x for x in reassemble(msgs[1]) if x[0] == 0x10]) == 1, f"picker refused: OPERATION_DENIED, nothing signed ({s[0]:#x})")
s = last(msgs[2]); a = cbor2.loads(s[1:]) if s[0] == 0 else {}; _, pubA3 = pub_of(cbor2.loads(last(msgs[0])[1:])[2])
check(s[0] == 0 and len(k) == 3 and a[2][32] == 0x18 and a[4] == {"id": b"\xA1"*16} and verifies(pubA3, a[3], a[2] + cdh), f"silent check with no username (Windows pre-flight): answered with UP and UV clear, user id only (no names), no picker, signature valid ({s[0]:#x}, prompts {k}, {a.get(4)})")
s = last(msgs[3]); check(s[0] == 0x2E and len(k) == 3, f"a site with no record: NO_CREDENTIALS, nothing shown ({s[0]:#x})")
s = last(msgs[4]); check(s[0] == 0x03, f"rk with no user handle: INVALID_LENGTH ({s[0]:#x})")
s = last(msgs[5]); check(s[0] == 0x03, f"rk with a 65-byte user handle: INVALID_LENGTH ({s[0]:#x})")
s = last(msgs[6]); check(s[0] == 0x2B and st[-1][0] == 1, f"rk for a site name over 199 bytes: UNSUPPORTED_OPTION, nothing saved ({s[0]:#x})")

# 2b. a PASSKEY life holds both kinds: a request offering only a device-bound ID goes to the device-bound path
open("r_ga_dev.bin","wb").write(req(2, {1: rp, 2: cdh, 3: [{"id": b"\x55"*16, "type": "public-key"}]}))
open("r_ga_pkr.bin","wb").write(req(2, {1: rp, 2: cdh, 3: [{"id": b"\x01\x01" + b"\x66"*32, "type": "public-key"}]}))
msgs, err = run(["dooropen", "pkropen", "r_ga_dev.bin", "r_ga_pkr.bin"])
s = last(msgs[0]); check(s[0] == 0x2E and "no credential here for that site" in err, f"2b: device-bound ID with both kinds open -> the device-bound path ({s[0]:#x})")
s = last(msgs[1]); check(s[0] == 0x2E and "none of the offered restorable IDs" in err, f"2b: restorable ID with both kinds open -> the restorable path ({s[0]:#x})")

# 4. UV: window stale -> picker, then the PIN; rk register always asks for UV
msgs, err = run(["decide=aa", "r_mc_a.bin", "uvstale", "decide=0a", "r_ga.bin", "decide=a", "r_mc_b.bin", "decide=0r", "r_ga.bin"])
k = kinds(err)
s = last(msgs[1]); a = cbor2.loads(s[1:]); check(s[0] == 0 and a[2][32] == 0x1D and k[2:4] == ["3", "2"], f"window expired: the picker, then the PIN on the KEY, UV set ({k[2:4]})")
s = last(msgs[2]); check(s[0] == 0 and cbor2.loads(s[1:])[2][32] == 0x5D and k[4] == "2", f"rk register with the window expired: the PIN even though the site did not ask for uv ({k[4]})")
s = last(msgs[3]); check(s[0] == 0x27, f"PIN refused after the pick: OPERATION_DENIED ({s[0]:#x})")

# 5. full, budget, failures
msgs, err = run(["fill=200", "rkstats", "decide=aa", "r_mc_a.bin", "rkstats"])   # P4-1: RK_MAX 200
st = rkstats(err); k = kinds(err); s = last(msgs[0])
check(st[0][0] == 200, f"200 records fit ({st[0]})")
check(s[0] == 0x28 and st[1][0] == 200 and "0" in k, f"the 201st: the KEY says no room (a prompt), KEY_STORE_FULL, nothing saved ({s[0]:#x}, {k})")
msgs, err = run(["decide=aa", "r_mc_a.bin", "lock", "budget=0", "decide=0", "r_ga.bin", "rkstats"])
st = rkstats(err); k = kinds(err); s = last(msgs[1])
check(s[0] == 0x27 and k.count("3") == 0, f"record opens used up (cache empty): OPERATION_DENIED, no picker ({s[0]:#x})")
msgs, err = run(["decide=aa", "putfail=1", "r_mc_a.bin", "rkstats"])
st = rkstats(err); s = last(msgs[0])
check(s[0] == 0x7F and st[0][0] == 0 and len([x for x in reassemble(msgs[0]) if x[0] == 0x10]) == 1, f"the record cannot be written: ST_OTHER, no credential given to the site ({s[0]:#x}, {st[0]})")
msgs, err = run(["decide=aa", "r_mc_a.bin", "lock", "vfail=2", "decide=0", "r_ga.bin", "rkstats"])
s = last(msgs[1]); check(s[0] == 0x2E, f"the G0 does not answer: NO_CREDENTIALS, no crash ({s[0]:#x})")

# 6. a record altered in flash is not opened; wipe; UTF-8 cut; non-rk registration saves nothing
msgs, err = run(["decide=aa", "r_mc_utf.bin", "decide=0", "r_ga_utf.bin", "r_mc_plain.bin", "rkstats", "wipe", "rkstats", "r_ga.bin"])
st = rkstats(err); s = last(msgs[1]); a = cbor2.loads(s[1:])
nm = a[4]["name"]
check(s[0] == 0 and len(nm.encode()) <= 64 and nm == "é" * 32, f"name over 64 bytes cut on a character boundary ({len(nm.encode())} bytes, valid UTF-8)")
check(st[0][0] == 1, f"a registration without rk saves no record ({st[0]})")
s = last(msgs[3]); check(st[1][0] == 0 and s[0] == 0x2E, f"wipe: no records, no-username sign-in finds nothing ({st[1]}, {s[0]:#x})")

msgs, err = run(["decide=aa", "r_mc_a.bin", "lock", "tamper", "reboot", "decide=0", "r_ga.bin", "rkstats"])
st = rkstats(err); s = last(msgs[1])
check(s[0] == 0x2E and st[0][0] == 1, f"a record altered in flash fails the G0's MAC: not opened, not offered ({s[0]:#x}, {st[0]})")
# review fixes (2 Nov 2026)
open("p_gi.bin","wb").write(bytes([4]))
msgs, err = run(["decide=aa", "r_mc_a.bin", "lock", "decide=r", "r_mc_b.bin", "rkstats"])
st = rkstats(err); s = last(msgs[1])
check(s[0] == 0x27 and st[0][3] == 0, f"rk register refused at the press: no record opened (a page cannot spend opens without a press) ({s[0]:#x}, {st[0]})")
msgs, err = run(["pkrclosed", "p_gi.bin", "r_mc_a.bin"])
r = [x for x in reassemble(msgs[0]) if x[0] == 0x10][0][1]; info = cbor2.loads(r[1:]); s = last(msgs[1])
check(info[4]["rk"] is True and s[0] == 0x27, f"KEY locked: getInfo still says rk (platforms cache it), and rk register gets OPERATION_DENIED ({info[4]}, {s[0]:#x})")
msgs, err = run(["decide=aa", "r_mc_a.bin", "lock", "vfail=1", "decide=a", "r_mc_a2.bin", "rkstats"])
st = rkstats(err); s = last(msgs[1])
check(s[0] == 0x7F and st[0][0] == 1, f"re-register when the site's records cannot be checked: refused, no duplicate record ({s[0]:#x}, {st[0]})")

# 9. One passkey window per request (2 Nov 2026, S2 follow-up). The harness
# models g0_window_batch_*: each G0-backed call is an op; inside a batch the ops
# share one window. No prompt may come while a batch is held.
def winstats(err): return [tuple(map(int, x)) for x in re.findall(r"WINSTATS windows=(\d+) depth=(\d+) badwait=(\d+) refused=(\d+)", err)]
open("r_ga_two.bin","wb").write(req(2, {1: rp, 2: cdh, 3: [{"id": b"\x01\x01" + b"\x77"*32, "type": "public-key"}, {"id": b"\x01\x01" + b"\x78"*32, "type": "public-key"}]}))
msgs, err = run(["winstats", "decide=aa", "r_mc_a.bin", "winstats", "batch", "decide=a", "r_mc_b.bin", "winstats", "lock", "r_ga_silent.bin", "winstats",
                 "lock", "decide=0", "r_ga.bin", "winstats", "r_ga_two.bin", "winstats"])
w = winstats(err)
check(last(msgs[0])[0] == 0 and w[1][0] == 4, f"without batching a register costs 4 windows (room, register, attestation, save) ({w[1]})")
check(last(msgs[1])[0] == 0 and w[2][0] == 1, f"batched: a register costs ONE window ({w[2]})")
check(last(msgs[2])[0] == 0 and w[3][0] == 1, f"batched: a silent check with no username (find + sign) costs one window ({w[3]})")
check(last(msgs[3])[0] == 0 and w[4][0] == 2, f"batched: a no-username sign-in costs two (find, then sign after the picker: never held across a wait) ({w[4]})")
check(last(msgs[4])[0] == 0x2E and w[5][0] == 1, f"batched: two offered IDs, neither ours, one window for both ({w[5]})")
check(all(x[1] == 0 and x[2] == 0 for x in w), f"no batch left open and no prompt shown inside one ({w})")
msgs, err = run(["batch", "fill=200", "decide=aa", "r_mc_a.bin", "winstats"])
w = winstats(err)
check(last(msgs[0])[0] == 0x28 and w[0][1] == 0 and w[0][2] == 0, f"store full: the 'No room' screen comes after the window closes ({last(msgs[0])[0]:#x}, {w[0]})")
msgs, err = run(["pkrclosed", "winstats", "r_mc_a.bin", "r_ga.bin", "winstats"])
w = winstats(err)
check(last(msgs[0])[0] == 0x27 and last(msgs[1])[0] == 0x27 and w[1][3] == 2, f"passkeys closed in this life: both requests refused and the KEY is told why each time ({w[1]})")
print("ALL PASS" if ok else "SOME FAILED")
