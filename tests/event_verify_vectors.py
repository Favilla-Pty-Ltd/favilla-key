#!/usr/bin/env python3
# event_verify_vectors.py - signed Nostr events for tests/event_verify_test.cpp
# (11bl, issues #41 and #45). BIP-340 signing is the BIP's own reference code;
# the id is sha256 of the NIP-01 array written as JSON.stringify writes it
# (json.dumps with ensure_ascii=False and no spaces gives the same bytes for
# the strings used here: no lone surrogates, no U+2028/9). One JSON line per
# vector: {"event": {...}, "ok": true|false, "why": "..."}.
#   python3 tests/event_verify_vectors.py [count] > /tmp/evv.jsonl
import hashlib, json, random, sys

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    if P1[0] == P2[0] and P1[1] != P2[1]: return None
    lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p if P1 == P2 else ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % p)
def mul(P, k):
    R = None
    for i in range(256):
        if (k >> i) & 1: R = add(R, P)
        P = add(P, P)
    return R
def tagged(tag, m):
    t = hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t + t + m).digest()
def b32(x): return x.to_bytes(32, 'big')
def sign(sk, msg, aux):
    P = mul(G, sk); d = sk if P[1] % 2 == 0 else n - sk
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + b32(P[0]) + msg), 'big') % n
    R = mul(G, k0); k = k0 if R[1] % 2 == 0 else n - k0
    e = int.from_bytes(tagged("BIP0340/challenge", b32(R[0]) + b32(P[0]) + msg), 'big') % n
    return b32(R[0]) + b32((k + e * d) % n), b32(P[0])

def evid(pk, ca, kind, tags, content):
    s = json.dumps([0, pk, ca, kind, tags, content], ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

rnd = random.Random(1119)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
pieces = ['plain', 'nostr:npub1abc', '"', '\\', '\n', '\t', '/', 'é', '🔥', '漢字', 'مرحبا', '{}', 'x' * 300, '?iv=']
def text(): return ''.join(rnd.choice(pieces) for _ in range(rnd.randrange(0, 8)))
def emit(ev, ok, why): print(json.dumps({"event": ev, "ok": ok, "why": why}, ensure_ascii=False))

for i in range(N):
    sk = rnd.randrange(1, n)
    kind = rnd.choice([1, 13, 24133, 30078, 0])
    tags = [[rnd.choice(['p', 'e', 'alt', 'd']), text()] for _ in range(rnd.randrange(0, 4))]
    content, ca = text(), 1700000000 + rnd.randrange(0, 10**8)
    pkx = b32(mul(G, sk)[0]).hex()
    eid = evid(pkx, ca, kind, tags, content)
    sig, _ = sign(sk, bytes.fromhex(eid), bytes(rnd.randrange(256) for _ in range(32)))
    ev = {"id": eid, "pubkey": pkx, "created_at": ca, "kind": kind, "tags": tags, "content": content, "sig": sig.hex()}
    emit(ev, True, "signed")
    m = rnd.randrange(9)
    bad = json.loads(json.dumps(ev))
    if m == 0: bad["content"] = content + "!"; why = "content changed"
    elif m == 1: bad["sig"] = sig[:63].hex() + '%02x' % (sig[63] ^ 1); why = "sig changed"
    elif m == 2: bad["pubkey"] = b32(mul(G, sk + 1)[0]).hex(); why = "other pubkey"
    elif m == 3: bad["kind"] = kind + 1; why = "kind changed"
    elif m == 4: bad["created_at"] = ca + 1; why = "created_at changed"
    elif m == 5: bad["tags"] = tags + [["p", "x"]]; why = "tag added"
    elif m == 6: bad["id"] = evid(pkx, ca, kind, tags, content + "x"); why = "id of other content"
    elif m == 7: bad["id"] = eid.upper(); why = "upper-case id"
    else: del bad["sig"]; why = "no sig"
    emit(bad, False, why)
# shape refusals
ev = json.loads(json.dumps(ev))
f = dict(ev); f["kind"] = 1.5; emit(f, False, "float kind")
f = dict(ev); f["created_at"] = "1700000000"; emit(f, False, "string created_at")
f = dict(ev); f["tags"] = {"p": "x"}; emit(f, False, "tags not an array")
f = dict(ev); f["content"] = 5; emit(f, False, "content not a string")
