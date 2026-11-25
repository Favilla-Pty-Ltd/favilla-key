#!/usr/bin/env python3
"""The app channel's pairing (docs/BLE_PASSKEY_PROTOCOL.md, "The app channel",
"Pairing"), worked through with fixed keys, for the iPhone app to check its
bytes against. host/app_pair_check.cpp runs the KEY's own chan::derive and
chan::commitment on the same inputs and must print the same K and code.
Prints C hex lines a C++ check can read: Z, extPub, keyPub, nonce, then the results."""
import hmac, hashlib, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
H = lambda k, d: hmac.new(k, d, hashlib.sha256).digest()
def key(d):
    k = ec.derive_private_key(d, ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
appPriv, extPub = key(0x1111111111111111111111111111111111111111111111111111111111111111)
keyPriv, keyPub = key(0x2222222222222222222222222222222222222222222222222222222222222222)
nonce = bytes(range(0x30, 0x40))
clientId = bytes.fromhex("a1a2a3a4a5a6a7a8")
C = H(b"FAVILLA-COMMIT-1", extPub + nonce)
Z = appPriv.exchange(ec.ECDH(), keyPriv.public_key())
assert Z == keyPriv.exchange(ec.ECDH(), appPriv.public_key())
PRK = H(b"FAVILLA-CHAN-1", Z)
K = H(PRK, b"key" + extPub + keyPub + b"\x01")
code = struct.unpack(">I", H(PRK, b"code" + extPub + keyPub + b"\x01")[:4])[0] % 1000000
def req(cmd, ctr, body=b""):
    m = bytes([cmd]) + clientId + struct.pack("<I", ctr) + body
    return m + H(K, b"REQ" + m)[:16]
def rsp(r, ctr, body):
    m = bytes([r]) + clientId + struct.pack("<I", ctr) + body
    return m + H(K, b"RSP" + m)[:16]
print("app private key   1111...11 (32 bytes of 0x11)")
print("KEY private key   2222...22 (32 bytes of 0x22)")
print("extPub   ", extPub.hex())
print("keyPub   ", keyPub.hex())
print("nonce    ", nonce.hex())
print("1. PAIR_COMMIT  ", (b"\x20" + C).hex())
print("2. R_PAIR_KEY   ", (b"\xa0" + keyPub + clientId).hex())
print("3. PAIR_REVEAL  ", (b"\x22" + extPub + nonce).hex())
print("Z        ", Z.hex())
print("K        ", K.hex())
print("code      %03d %03d" % (code // 1000, code % 1000))
print("4. R_PAIR_DONE (paired)", rsp(0xA1, 0, b"\x00").hex())
print("5. HELLO ctr 1  ", req(0x30, 1).hex())
print("CHECK", Z.hex(), extPub.hex(), keyPub.hex(), nonce.hex(), K.hex(), code, C.hex())
