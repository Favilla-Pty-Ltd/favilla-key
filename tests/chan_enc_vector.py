#!/usr/bin/env python3
"""Independent implementation of the 9f app-channel body encryption (chan::encBody)
for the cross-check in host/chan_enc_test.cpp. Prints the 70-byte test vector."""
import hmac, hashlib, struct
H = lambda k, d: hmac.new(k, d, hashlib.sha256).digest()
k = bytes(range(32)); cid = bytes(0xA0 + i for i in range(8)); ctr = 7; rsp = 0xB3
body = bytes((i * 3) & 0xFF for i in range(70))
ke = H(k, b"FAVILLA-CHAN-ENC-1")
ks = b"".join(H(ke, bytes([rsp]) + cid + struct.pack("<I", ctr) + bytes([i])) for i in range(3))
print(bytes(a ^ b for a, b in zip(body, ks)).hex())
