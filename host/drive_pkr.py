# Restorable passkeys over CTAP2 (30 Oct 2026): the real fido_hid.h in the
# NOSTR life against a model of the G0's PKSIGN (harness_pkr.cpp).
import cbor2, subprocess, hashlib, os, re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
def req(cmd, m): return bytes([cmd]) + cbor2.dumps(m, canonical=True)
def run(args):
    out = subprocess.run(["./harness_pkr"] + args, capture_output=True, text=True)
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
def stats(err): m = re.findall(r"STATS prompts=(\d+) warns=(\d+) regs=(\d+) signs=(\d+) acked=(\d+)", err); return [tuple(map(int, x)) for x in m]

rp = "webauthn.io"; rph = hashlib.sha256(rp.encode()).digest(); cdh1 = os.urandom(32); cdh2 = os.urandom(32)
mc = {1: cdh1, 2: {"id": rp, "name": "WebAuthn.io"}, 3: {"id": b"\x01"*16, "name": "josh"}, 4: [{"alg": -7, "type": "public-key"}]}
open("p_mc.bin","wb").write(req(1, mc))
# 1. refuse the warning: nothing registered, still unacked
msgs, err = run(["decide=r", "p_mc.bin", "stats"])
s = last(msgs[0]); st = stats(err)[0]
check(s[0] == 0x27 and st[1] == 1 and st[2] == 0 and st[4] == 0, f"warning refused -> OPERATION_DENIED, nothing registered, not acknowledged ({s[0]:#x}, {st})")
# 2. one process: accept warning, register; register again (no second warning); then sign-in paths
msgs, err = run(["decide=aa", "p_mc.bin", "stats", "decide=a", "p_mc.bin", "stats"])
st = stats(err)
check(st[0][1] == 1 and st[0][0] == 2 and st[0][4] == 1, f"first registration: the warning, then the Register prompt; acknowledged ({st[0]})")
check(st[1][1] == 1 and st[1][0] == 3, f"second registration: no second warning ({st[1]})")
s = last(msgs[0]); att = cbor2.loads(s[1:]); ad = att[2]
check(s[0] == 0 and att[1] == "packed" and cbor2.dumps(att, canonical=True) == s[1:], "makeCredential OK, packed, canonical CBOR")
check(ad[:32] == rph and ad[32] == 0x59, f"flags UP+BE+BS+AT = 0x59 ({ad[32]:#x})")
cl = int.from_bytes(ad[53:55], "big"); cid = ad[55:55+cl]; cose = cbor2.loads(ad[55+cl:])
check(cl == 34 and cid[0] == 1 and cid[1] == 1, f"credential ID is 34 bytes, ver 1, kind 1 ({cl})")
check(len(ad) == 55 + cl + len(cbor2.dumps(cose, canonical=True)), "authData has no trailing bytes")
pub = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2],"big"), int.from_bytes(cose[-3],"big"), ec.SECP256R1()).public_key()
try: pub.verify(att[3]["sig"], ad + cdh1, ec.ECDSA(hashes.SHA256())); check(True, "self-attestation verifies with the new public key")
except InvalidSignature: check(False, "self-attestation verifies with the new public key")
cid2 = None
s2 = last(msgs[1]); a2 = cbor2.loads(s2[1:]); ad2 = a2[2]; cl2 = int.from_bytes(ad2[53:55],"big"); cid2 = ad2[55:55+cl2]
check(cid2 != cid, "a second registration is a different credential")
# sign-in in a fresh process (no stored state: the tag is the index)
ga = {1: rp, 2: cdh2, 3: [{"id": os.urandom(16), "type": "public-key"}, {"id": cid, "type": "public-key"}]}
open("p_ga.bin","wb").write(req(2, ga))
open("p_ga_two.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": bytes([1,1]) + os.urandom(32), "type": "public-key"}, {"id": cid, "type": "public-key"}]}))
open("p_ga_wrongrp.bin","wb").write(req(2, {1: "evil.example", 2: cdh2, 3: [{"id": cid, "type": "public-key"}]}))
open("p_ga_forged.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": cid[:-1] + bytes([cid[-1]^1]), "type": "public-key"}]}))
open("p_ga_dev.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": os.urandom(16), "type": "public-key"}]}))
open("p_ga_silent.bin","wb").write(req(2, {**ga, 5: {"up": False}}))
open("p_mc_excl.bin","wb").write(req(1, {**mc, 5: [{"id": cid, "type": "public-key"}]}))
open("p_mc_excl_other.bin","wb").write(req(1, {**mc, 2: {"id": "other.example"}, 5: [{"id": cid, "type": "public-key"}]}))
msgs, err = run(["p_ga.bin", "stats", "p_ga_two.bin", "stats", "p_ga_wrongrp.bin", "stats", "p_ga_forged.bin", "p_ga_dev.bin", "p_ga_silent.bin", "stats", "p_mc_excl.bin", "stats", "p_mc_excl_other.bin", "stats", "pkrclosed", "p_ga.bin"])
st = stats(err)
s = last(msgs[0]); a = cbor2.loads(s[1:])
check(s[0] == 0 and a[1] == {"id": cid, "type": "public-key"} and st[0][0] == 1, f"sign-in names the restorable credential, one press ({s[0]:#x})")
check(a[2][:32] == rph and a[2][32] == 0x19 and len(a[2]) == 37, f"assertion flags UP+BE+BS = 0x19 ({a[2][32]:#x}), counter 0")
try: pub.verify(a[3], a[2] + cdh2, ec.ECDSA(hashes.SHA256())); check(True, "assertion verifies with the registered public key")
except InvalidSignature: check(False, "assertion verifies with the registered public key")
s = last(msgs[1]); check(s[0] == 0 and cbor2.loads(s[1:])[1]["id"] == cid and st[1][0] == 2, f"two KEY-shaped IDs offered: picks this KEY's one before the press, one press ({s[0]:#x}, {st[1]})")
s = last(msgs[2]); check(s[0] == 0x2E and st[2][0] == 2, f"same ID from another site -> NO_CREDENTIALS, no press asked ({s[0]:#x})")
s = last(msgs[3]); check(s[0] == 0x2E, f"forged ID -> NO_CREDENTIALS ({s[0]:#x})")
s = last(msgs[4]); check(s[0] == 0x2E, f"a 16-byte (device-bound) ID in the NOSTR life -> NO_CREDENTIALS ({s[0]:#x})")
s = last(msgs[5]); a5 = cbor2.loads(s[1:]); check(s[0] == 0 and a5[2][32] == 0x18 and st[3][0] == st[2][0], f"forged ID and silent check: no press; silent answered with UP clear (0x18) ({s[0]:#x})")
s = last(msgs[6]); check(s[0] == 0x19, f"excludeList holds this KEY's credential for the site -> CREDENTIAL_EXCLUDED ({s[0]:#x})")
s = last(msgs[7]); check(s[0] == 0 and st[5][2] == st[4][2] + 1, f"excludeList credential is for another site -> registers ({s[0]:#x})")
s = last(msgs[8]); check(s[0] == 0x27, f"NOSTR life not open (locked / no master) -> OPERATION_DENIED ({s[0]:#x})")
msgs, err = run(["decide=r", "p_ga.bin"])
s = last(msgs[0]); r = [x for x in reassemble(msgs[0]) if x[0] == 0x10]
check(s[0] == 0x27 and len(r) == 1, f"press refused after the signature was made: OPERATION_DENIED, the signature never leaves ({s[0]:#x})")
# pre-press budget: 64 refused sign-ins in one life, then the 65th is refused before any G0 call
msgs, err = run(["decide=" + "r"*64] + ["p_ga.bin"]*64 + ["stats", "p_ga.bin", "stats"])
st = stats(err); s = last(msgs[64])
check(st[1][3] == st[0][3] and s[0] == 0x27, f"a host that asks and cancels: 64 pre-press signs per life, then refused with no G0 call ({s[0]:#x}, signs {st[0][3]} -> {st[1][3]})")
msgs, err = run(["decide=" + "a"*70] + ["p_ga.bin"]*70)
s = last(msgs[69]); check(s[0] == 0, f"approved sign-ins give their pre-press sign back: the 70th still works ({s[0]:#x})")
# ---- user verification (31 Oct 2026) ----
open("p_gi.bin","wb").write(bytes([4]))
open("p_mc_uv.bin","wb").write(req(1, {**mc, 7: {"uv": True}}))
open("p_ga_uv.bin","wb").write(req(2, {**ga, 5: {"uv": True}}))
msgs, err = run(["p_gi.bin"])
r = [x for x in reassemble(msgs[0]) if x[0] == 0x10][0][1]; info = cbor2.loads(r[1:])
check(info[4] == {"rk": True, "up": True, "uv": True, "plat": False} and cbor2.dumps(info, canonical=True) == r[1:], f"getInfo advertises built-in UV and (2 Nov 2026) rk with the record store, canonical ({info[4]})")
msgs, err = run(["rkoff", "p_gi.bin"])
r = [x for x in reassemble(msgs[0]) if x[0] == 0x10][0][1]; info = cbor2.loads(r[1:])
check(info[4]["rk"] is False, f"no record store (partition or G0 VAULT missing): rk false ({info[4]})")
msgs, err = run(["decide=aa", "p_mc_uv.bin", "p_ga_uv.bin"])
kinds = re.findall(r"PROMPT kind=(\d)", err)
s = last(msgs[0]); a = cbor2.loads(s[1:]); adr = a[2]
check(s[0] == 0 and adr[32] == 0x5D and kinds[:2] == ["1", "0"], f"register with uv inside the window: the one-time warning, then a press (no PIN), flags UP+UV+BE+BS+AT = 0x5D ({adr[32]:#x}, prompts {kinds})")
cl = int.from_bytes(adr[53:55], "big"); cidu = adr[55:55+cl]
open("p_ga_uv2.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": cidu, "type": "public-key"}], 5: {"uv": True}}))
open("p_ga_nouv2.bin","wb").write(req(2, {1: rp, 2: cdh2, 3: [{"id": cidu, "type": "public-key"}]}))
msgs, err = run(["p_ga_uv2.bin", "uvstale", "decide=a", "p_ga_uv2.bin", "decide=r", "p_ga_uv2.bin", "decide=w", "p_ga_uv2.bin", "p_ga_nouv2.bin"])
kinds = re.findall(r"PROMPT kind=(\d)", err)
s = last(msgs[0]); check(s[0] == 0 and cbor2.loads(s[1:])[2][32] == 0x1D and kinds[0] == "0", f"sign-in with uv inside the window: one press, flags UP+UV+BE+BS = 0x1D")
s = last(msgs[1]); check(s[0] == 0 and cbor2.loads(s[1:])[2][32] == 0x1D and kinds[1] == "2", f"window expired: the KEY asks for the PIN (kind 2) instead of a press, UV set ({kinds[1]})")
s = last(msgs[2]); check(s[0] == 0x27, f"PIN prompt cancelled -> OPERATION_DENIED, signature never leaves ({s[0]:#x})")
s = last(msgs[3]); check(s[0] == 0x3C, f"too many wrong PINs -> UV_BLOCKED ({s[0]:#x})")
s = last(msgs[4]); check(s[0] == 0 and cbor2.loads(s[1:])[2][32] == 0x19 and kinds[-1] == "0", "no uv asked, window expired: a press, no UV flag (never UV on a press alone)")
print("ALL PASS" if ok else "SOME FAILED")
