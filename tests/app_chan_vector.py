#!/usr/bin/env python3
"""9g: a worked example of the app channel over Bluetooth (docs/BLE_PASSKEY_PROTOCOL.md,
"The app channel"), for the iPhone app to check its bytes against. Fixed key and
client id; prints a FILL request as 64-byte reports and decrypts a login answer."""
import hmac, hashlib, struct
H = lambda k, d: hmac.new(k, d, hashlib.sha256).digest()
K = bytes(range(32)); CID = bytes.fromhex("0102030405060708")

def reports(msg):
    out = [bytes([0x10, len(msg) & 0xFF, len(msg) >> 8]) + msg[:61]]
    off, i = 61, 1
    while off < len(msg):
        out.append(bytes([0x11, i]) + msg[off:off + 62]); off += 62; i += 1
    return [r.ljust(64, b"\0") for r in out]

def req(cmd, ctr, body):
    m = bytes([cmd]) + CID + struct.pack("<I", ctr) + body
    return m + H(K, b"REQ" + m)[:16]

def keystream_xor(rsp, ctr, body):
    ke = H(K, b"FAVILLA-CHAN-ENC-1"); out = bytearray(body)
    for i in range(0, len(body), 32):
        ks = H(ke, bytes([rsp]) + CID + struct.pack("<I", ctr) + bytes([i // 32]))
        for j in range(min(32, len(body) - i)): out[i + j] ^= ks[j]
    return bytes(out)

def rsp(r, ctr, body, enc):
    b = keystream_xor(r, ctr, body) if enc else body
    m = bytes([r]) + CID + struct.pack("<I", ctr) + b
    return m + H(K, b"RSP" + m)[:16]

site, user = b"github.com", b""
fill = req(0x34, 1, bytes([len(site)]) + site + bytes([len(user)]) + user)
print("FILL request (ctr 1):", fill.hex())
for r in reports(fill): print("  report", r.hex())
login = bytes([0, 4]) + b"josh" + bytes([6]) + b"secret"
ans = rsp(0xB3, 1, login, True)
print("R_LOGIN answer:", ans.hex())
body = ans[13:-16]
assert H(K, b"RSP" + ans[:-16])[:16] == ans[-16:]
assert keystream_xor(0xB3, 1, body) == login
print("decrypts to:", keystream_xor(0xB3, 1, body))

# 10p (issue #11): the Bluetooth bunker. Framing only: the event and the reply
# below are placeholders (their ids, signatures and NIP-44 content are not
# real), so this checks the bytes around them, not NIP-46 itself.
print()
ev = (b'{"id":"' + b"11" * 32 + b'","pubkey":"' + b"22" * 32 + b'","created_at":1762650000,"kind":24133,'
      b'"tags":[["p","' + b"33" * 32 + b'"]],"content":"AgAA","sig":"' + b"44" * 64 + b'"}')
nreq = req(0x3B, 2, ev)
print("NIP46 request (ctr 2):", nreq.hex())
print("  reports:", len(reports(nreq)))
relay_msg = (b'["EVENT",{"id":"' + b"55" * 32 + b'","pubkey":"' + b"33" * 32 + b'","created_at":1762650001,"kind":24133,'
             b'"tags":[["p","' + b"22" * 32 + b'"]],"content":"AgBB","sig":"' + b"66" * 64 + b'"}]')
body = bytes([0x00, 1]) + struct.pack("<H", len(relay_msg)) + relay_msg
nans = rsp(0xB9, 2, body, False)
print("R_NIP46 answer with one reply (not encrypted; from 11m this shape only comes to a POLL):", nans.hex())
assert H(K, b"RSP" + nans[:-16])[:16] == nans[-16:]
b = nans[13:-16]; more, count = b[0] & 1, b[1]; off = 2; got = []
for _ in range(count):
    L = struct.unpack("<H", b[off:off + 2])[0]; got.append(b[off + 2:off + 2 + L]); off += 2 + L
assert got == [relay_msg] and more == 0
print("  more to come:", more, "| replies:", count, "| first:", got[0][:40], "...")
poll = req(0x3C, 3, b"")
print("NIP46_POLL request (ctr 3):", poll.hex())
empty = rsp(0xB9, 3, bytes([0x01, 0]), False)
print("R_NIP46 answer, nothing yet, more to come:", empty.hex())
info = req(0x3D, 4, b"")
print("BUNKER_INFO request (ctr 4):", info.hex())
relays = [b"relay.favillakey.io", b"relay.damus.io"]
ib = bytes.fromhex("33" * 32) + bytes([len(relays)]) + b"".join(bytes([len(h)]) + h for h in relays)
print("R_BUNKER_INFO answer (not encrypted):", rsp(0xBA, 4, ib, False).hex())
locked = rsp(0xBF, 5, bytes([0x05]), False)
print("ERROR S_LOCKED to a NIP46 request (ctr 5):", locked.hex())

# 11i (issue #11, path B): NUDGE_SET and an unsolicited R_NUDGE (counter 0).
print()
ns = req(0x3E, 6, bytes([5]))
print("NUDGE_SET request, every 5 s (ctr 6):", ns.hex())
print("  answer:", rsp(0xB1, 6, bytes([0x00]), False).hex())
nudge = rsp(0xBB, 0, struct.pack("<I", 1) + bytes([0, 0]), False)
print("R_NUDGE (seq 1, 0 replies waiting, no vault ask), counter 0:", nudge.hex())
assert H(K, b"RSP" + nudge[:-16])[:16] == nudge[-16:]

# 11q: the vault through the phone. VAULT_INFO, a two-chunk VAULT_GET, VAULT_DONE,
# and a VAULT_PUT of a small (placeholder) event.
print()
vi = req(0x3F, 7, b"")
print("VAULT_INFO request (ctr 7):", vi.hex())
host = b"vault.favillakey.io"
vib = bytes([0]) + bytes.fromhex("44" * 32) + struct.pack("<I", 1762732800) + struct.pack("<H", 108) + bytes([1, 0]) + host
print("  answer (ok, 108 records backed up, dirty):", rsp(0xBC, 7, vib, False).hex())
frame = b'["EVENT",{"kind":30078,"content":"' + b"A" * 50 + b'"}]'
g0 = req(0x40, 8, struct.pack("<I", 0))
print("VAULT_GET offset 0 (ctr 8):", g0.hex())
c0 = bytes([0]) + struct.pack("<II", len(frame), 0) + frame[:40]
print("  answer, first 40 of", len(frame), "bytes:", rsp(0xBD, 8, c0, False).hex())
g1 = req(0x40, 9, struct.pack("<I", 40))
c1 = bytes([0]) + struct.pack("<II", len(frame), 40) + frame[40:]
print("VAULT_GET offset 40 (ctr 9):", g1.hex(), "answer:", rsp(0xBD, 9, c1, False).hex())
done = req(0x41, 10, bytes([1]))
print("VAULT_DONE accepted (ctr 10):", done.hex(), "answer:", rsp(0xB1, 10, bytes([0]), False).hex())
ev = b'{"kind":30078,"content":"' + b"B" * 20 + b'"}'
put = req(0x42, 11, struct.pack("<II", len(ev), 0) + ev)
print("VAULT_PUT whole event (ctr 11):", put.hex())
print("  answer, merged, 3 added 0 removed:", rsp(0xBE, 11, bytes([1, 0]) + struct.pack("<HH", 3, 0), False).hex())
none = req(0x42, 12, struct.pack("<II", 0, 0))
print("VAULT_PUT, the relay has none (ctr 12):", none.hex(), "answer (result 11):", rsp(0xBE, 12, bytes([1, 11, 0, 0, 0, 0]), False).hex())

# 11s: SHOW, LIST with health, HEALTH.
print()
sid = bytes.fromhex("0102030405060708")
show = req(0x43, 13, sid)
print("SHOW request (ctr 13):", show.hex(), "answer:", rsp(0xB1, 13, bytes([0]), False).hex())
l2 = req(0x37, 14, bytes([0, 0, 1]))
print("LIST with health (ctr 14):", l2.hex())
ent = bytes([0x02, 10]) + b"github.com" + bytes([4]) + b"josh" + bytes([0x47]) + sid   # strong, made on KEY, breach checked
lb = bytes([0, 0, 1, 1]) + ent + bytes([0])
print("  answer (encrypted; one entry, health 0x47):", rsp(0xB6, 14, lb, True).hex())
hq = req(0x44, 15, b"")
print("HEALTH, prefixes wanted (ctr 15):", hq.hex())
hb = bytes([0]) + struct.pack("<H", 2) + bytes([1]) + bytes.fromhex("5BAA60")
print("  answer (encrypted; 2 pending, prefix 5BAA6):", rsp(0xC0, 15, hb, True).hex())
suf = bytes.fromhex("1E4C9B93F3F0682250B6CF8331B7EE68FD80") # "password": 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8, packed
hp = req(0x44, 16, bytes.fromhex("5BAA60") + struct.pack("<H", 1) + suf)
print("HEALTH bucket with one suffix (ctr 16):", hp.hex())
import hashlib as _h
assert _h.sha1(b"password").hexdigest().upper() == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
