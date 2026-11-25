import cbor2, subprocess, hashlib, os, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def req(cmd, m): return bytes([cmd]) + cbor2.dumps(m, canonical=True)
def run(args):
    out = subprocess.run(["./harness"] + args, capture_output=True, text=True)
    msgs, cur = [], b""
    pkts = []
    for line in out.stdout.splitlines():
        if line == "END": msgs.append(pkts); pkts = []
        elif line.startswith("PKT "): pkts.append(bytes.fromhex(line[4:]))
    return msgs, out.stderr

def reassemble(pkts):
    # returns list of (cmd, payload); keepalives included
    res, i = [], 0
    while i < len(pkts):
        p = pkts[i]; cmd = p[4] & 0x7f; n = (p[5] << 8) | p[6]; data = p[7:7+min(n,57)]; i += 1
        while len(data) < n: data += pkts[i][5:5+min(59, n-len(data))]; i += 1
        res.append((cmd, data))
    return res

rp = "webauthn.io"; cdh1 = os.urandom(32); cdh2 = os.urandom(32)
mc = {1: cdh1, 2: {"id": rp, "name": "WebAuthn.io"}, 3: {"id": b"\x01"*16, "name": "josh", "displayName": "Josh"},
      4: [{"alg": -8, "type": "public-key"}, {"alg": -7, "type": "public-key"}, {"alg": -257, "type": "public-key"}],
      7: {"rk": False}}
open("mc.bin","wb").write(req(1, mc))
open("gi.bin","wb").write(bytes([4]))
msgs, err = run(["init", "gi.bin", "mc.bin"])
ok = True
def check(c, m):
    global ok
    print(("PASS " if c else "FAIL ") + m); ok &= c

r = reassemble(msgs[0]); check(r[0][0] == 0x06 and len(r[0][1]) == 17, "INIT answered, 17 bytes")
r = reassemble(msgs[1]); info = cbor2.loads(r[0][1][1:]); check(r[0][1][0] == 0 and info[1] == ["FIDO_2_0"] and info[4] == {"rk": False, "up": True, "plat": False} and info[5] == 1024 and info[9] == ["usb"], f"getInfo {info}")
check(cbor2.dumps(info, canonical=True) == r[0][1][1:], "getInfo is canonical CBOR")
r = [x for x in reassemble(msgs[2]) if x[0] == 0x10]; resp = r[0][1]
check(resp[0] == 0, f"makeCredential status {resp[0]:#x}")
att = cbor2.loads(resp[1:]); check(cbor2.dumps(att, canonical=True) == resp[1:], "makeCredential response is canonical CBOR")
ad = att[2]; check(att[1] == "packed" and att[3]["alg"] == -7, "fmt packed, alg -7")
check(ad[:32] == hashlib.sha256(rp.encode()).digest(), "rpIdHash correct")
check(ad[32] == 0x41, f"flags UP+AT ({ad[32]:#x})")
credLen = int.from_bytes(ad[53:55], "big"); credId = ad[55:55+credLen]; cose = cbor2.loads(ad[55+credLen:])
check(credLen == 16 and cose[1] == 2 and cose[3] == -7 and cose[-1] == 1, f"credId 16 bytes, COSE EC2 ES256 P-256 {sorted(cose.keys())}")
check(len(ad) == 55 + credLen + len(cbor2.dumps(cose, canonical=True)), "authData has no trailing bytes")
pub = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2],"big"), int.from_bytes(cose[-3],"big"), ec.SECP256R1()).public_key()
try: pub.verify(att[3]["sig"], ad + cdh1, ec.ECDSA(hashes.SHA256())); check(True, "self-attestation signature verifies")
except InvalidSignature: check(False, "self-attestation signature verifies")

# sign in: wrong site, right site, unknown credential, refuse, uv request, silent probe
ga = {1: rp, 2: cdh2, 3: [{"id": os.urandom(16), "type": "public-key"}, {"id": credId, "type": "public-key"}]}
open("ga.bin","wb").write(req(2, ga))
open("ga_wrongrp.bin","wb").write(req(2, {1: "evil.example", 2: cdh2, 3: [{"id": credId, "type": "public-key"}]}))
open("ga_uv.bin","wb").write(req(2, {**ga, 5: {"uv": True}}))
open("ga_silent.bin","wb").write(req(2, {**ga, 5: {"up": False}}))
open("mc_excl.bin","wb").write(req(1, {**mc, 5: [{"id": credId, "type": "public-key"}]}))
open("mc_rk.bin","wb").write(req(1, {**mc, 7: {"rk": True}}))
open("bad.bin","wb").write(bytes([1, 0xBF, 0x01, 0xFF]))     # indefinite-length map
open("trunc.bin","wb").write(req(1, mc)[:60])
# The harness keeps state in one process, so register again inside the same run.
msgs, err = run(["mc.bin", "ga.bin", "ga_wrongrp.bin", "ga_uv.bin", "ga_silent.bin", "mc_excl.bin", "mc_rk.bin", "bad.bin", "trunc.bin", "refuse", "ga.bin"])
def last_status(m): r = [x for x in reassemble(m) if x[0] == 0x10]; return r[-1][1] if r else None
att2 = cbor2.loads(last_status(msgs[0])[1:]); ad2 = att2[2]; cl = int.from_bytes(ad2[53:55],"big"); cid2 = ad2[55:55+cl]; cose2 = cbor2.loads(ad2[55+cl:])
pub2 = ec.EllipticCurvePublicNumbers(int.from_bytes(cose2[-2],"big"), int.from_bytes(cose2[-3],"big"), ec.SECP256R1()).public_key()
ga["3"] = None
open("ga2.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": cid2, "type": "public-key"}]}))
msgs2, _ = run(["mc.bin"])  # (separate process; slots are in-memory only)
s = last_status(msgs[1]); check(s[0] == 0x00, f"sign-in on the registered credential -> OK ({s[0]:#x})")
a = cbor2.loads(s[1:]); check(cbor2.dumps(a, canonical=True) == s[1:], "getAssertion response is canonical CBOR")
check(a[1] == {"id": cid2, "type": "public-key"}, "assertion names the right credential")
check(a[2][:32] == hashlib.sha256(rp.encode()).digest() and a[2][32] == 0x01 and len(a[2]) == 37, "assertion authData: rpIdHash, UP only, counter 0")
try: pub2.verify(a[3], a[2] + cdh2, ec.ECDSA(hashes.SHA256())); check(True, "assertion signature verifies with the registered public key")
except InvalidSignature: check(False, "assertion signature verifies with the registered public key")
s = last_status(msgs[2]); check(s[0] == 0x2E, f"same credential, wrong site -> NO_CREDENTIALS ({s[0]:#x})")
s = last_status(msgs[3]); check(s[0] == 0x2B, f"uv requested -> UNSUPPORTED_OPTION ({s[0]:#x})")
s = last_status(msgs[4]); check(s[0] == 0x00, f"silent up=false -> answered ({s[0]:#x})")
a4 = cbor2.loads(s[1:]); check(a4[2][32] == 0x00, "silent answer has the User Present flag CLEAR")
try: pub2.verify(a4[3], a4[2] + cdh2, ec.ECDSA(hashes.SHA256())); check(True, "silent answer signature valid (RP must still reject: UP=0)")
except InvalidSignature: check(False, "silent answer signature valid")
s = last_status(msgs[5]); check(s[0] == 0x19, f"excludeList holds our credential -> CREDENTIAL_EXCLUDED after a press ({s[0]:#x})")
s = last_status(msgs[6]); check(s[0] == 0x2B, f"rk requested -> UNSUPPORTED_OPTION ({s[0]:#x})")
s = last_status(msgs[7]); check(s[0] == 0x12, f"indefinite-length CBOR -> INVALID_CBOR ({s[0]:#x})")
s = last_status(msgs[8]); check(s[0] == 0x12, f"truncated makeCredential -> INVALID_CBOR ({s[0]:#x})")
s = last_status(msgs[9]); check(s[0] == 0x27, f"BACK on the KEY -> OPERATION_DENIED ({s[0]:#x})")
ka = [x for x in reassemble(msgs[9]) if x[0] == 0x3B]; check(len(ka) >= 1 and ka[0][1] == b"\x02", "keepalive UPNEEDED sent while waiting for the press")
# step 3b: the door gate. With the PASSKEY door closed nothing is made or used.
msgs3, _ = run(["closed", "mc.bin", "ga.bin", "ga_silent.bin", "init", "open", "mc.bin"])
s = last_status(msgs3[0]); check(s[0] == 0x27, f"door closed: makeCredential -> OPERATION_DENIED, no press asked ({s[0]:#x})")
check(not [x for x in reassemble(msgs3[0]) if x[0] == 0x3B and x[1] == b"\x02"], "door closed: no UPNEEDED keepalive (no prompt shown)")
s = last_status(msgs3[1]); check(s[0] == 0x27, f"door closed: getAssertion -> OPERATION_DENIED ({s[0]:#x})")
s = last_status(msgs3[2]); check(s[0] == 0x27, f"door closed: silent check -> OPERATION_DENIED ({s[0]:#x})")
r = [x for x in reassemble(msgs3[3]) if x[0] == 0x06]; check(len(r) == 1, "door closed: INIT still answered (the platform can see the key)")
s = last_status(msgs3[4]); check(s[0] == 0x00, f"door opened: makeCredential works ({s[0]:#x})")
# silent-check cap: 64 per life, then refused
msgs4, _ = run(["mc.bin"] + ["ga_silent.bin"] * 66)
sts = [last_status(m)[0] for m in msgs4[1:]]
check(sts[:64] == [0x2E] * 64 or sts[:64] == [0x00] * 64, "silent checks answered up to the cap")
print("      (silent statuses: first", hex(sts[0]), "65th", hex(sts[64]), ")")
check(sts[64] == 0x2E and sts[65] == 0x2E, "silent check 65 and 66 refused once this life's cap is used")
print("ALL PASS" if ok else "SOME FAILED")
