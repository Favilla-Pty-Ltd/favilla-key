# import_item_vector.py - 11bf: IMPORT_ITEM's encrypted body, computed from the
# protocol doc's construction alone (not from the KEY's code): keystream block
# i = HMAC(Ke, 0x4C || clientId || ctr LE u32 || i), Ke = HMAC(k, "FAVILLA-CHAN-ENC-1").
# k = 00..1f, clientId = a0..a7, ctr = 9 (password) and 10 (one-time code).
import hmac, hashlib, struct
H = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
k = bytes(range(32)); cid = bytes(range(0xA0, 0xA8))
Ke = H(k, b"FAVILLA-CHAN-ENC-1")
def enc(cmd, ctr, body):
    out = bytearray()
    for i in range((len(body) + 31) // 32):
        idx = bytes([i]) if i < 255 else b"\xff" + struct.pack("<H", i)
        out += H(Ke, bytes([cmd]) + cid + struct.pack("<I", ctr) + idx)
    return bytes(a ^ b for a, b in zip(body, out))
def f(s): b = s.encode(); return bytes([len(b)]) + b
pw = bytes([1]) + f("github.com") + f("favillakey") + f("hunter2") + f("from Bitwarden")
# JBSWY3DPEHPK3PXP (base32) = the 10 raw bytes below
otp = bytes([2]) + f("github.com") + f("favillakey") + bytes([6, 30, 10]) + bytes.fromhex("48656c6c6f21deadbeef")
for name, ctr, body in (("pw", 9, pw), ("otp", 10, otp)):
    print(name, "plain ", body.hex())
    print(name, "cipher", enc(0x4C, ctr, body).hex())
