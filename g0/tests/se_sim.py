#!/usr/bin/env python3
"""Minimal SE05x applet-session simulator for host testing of lib/scp03.
Independent implementation (pycryptodome) of GP SCP03 as the SE051 IoT applet
runs it inside an AESKey session (AN12543 3.6.3.2). Speaks hex APDUs on
stdin/stdout, one per line. NOT a general SE emulator: only the objects and
commands the G0 uses are modelled."""
import sys, os
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def cmac(k, m): c = CMAC.new(k, ciphermod=AES); c.update(m); return c.digest()
def dd(const, L, ctx): return bytes(11) + bytes([const, 0]) + L.to_bytes(2, 'big') + b'\x01' + ctx

KSE      = bytes.fromhex(os.environ.get("KSE", "000102030405060708090a0b0c0d0e0f"))
AUTH_OBJ = int(os.environ.get("AUTH_OBJ", "20000030"), 16)
SCALAR_OBJ = int(os.environ.get("SCALAR_OBJ", "20000002"), 16)
WRAP_OBJ = int(os.environ.get("WRAP_OBJ", "20000022"), 16)
KDAILY   = bytes.fromhex(os.environ.get("KDAILY", "11"*32))
BLOB     = bytes.fromhex(os.environ.get("BLOB", ""))   # 48 bytes IV||CT stored in SCALAR_OBJ
PCR_UNLOCKED = os.environ.get("PCR", "1") == "1"
LOG = open(os.environ.get("SIMLOG", "/dev/null"), "w")

sessions = {}   # sid -> state
sid_counter = 1

def sw(code, body=b''): return body + code.to_bytes(2, 'big')

def parse_tlvs(b):
    out = []; i = 0
    while i < len(b):
        t = b[i]; l = b[i+1]; i += 2
        if l == 0x81: l = b[i]; i += 1
        elif l == 0x82: l = int.from_bytes(b[i:i+2], 'big'); i += 2
        out.append((t, b[i:i+l])); i += l
    return out

def parse_apdu(a):
    cla, ins, p1, p2 = a[0], a[1], a[2], a[3]
    rest = a[4:]
    if not rest: return cla, ins, p1, p2, b'', False
    if rest[0] == 0 and len(rest) >= 3:
        lc = int.from_bytes(rest[1:3], 'big'); data = rest[3:3+lc]; le = rest[3+lc:]
    else:
        lc = rest[0]; data = rest[1:1+lc]; le = rest[1+lc:]
    return cla, ins, p1, p2, data, len(le) > 0

def plain_cmd(cla, ins, p1, p2, data):
    if ins == 0x04 and p2 == 0x1B:          # CreateSession
        global sid_counter
        (t, v), = parse_tlvs(data)
        if int.from_bytes(v, 'big') != AUTH_OBJ: return sw(0x6A88)
        sid = os.urandom(8)
        sessions[sid] = {'authed': False}
        return sw(0x9000, b'\x41\x82\x00\x08' + sid)   # SE051 7.2.0 uses BER extended-length here
    if ins == 0x05:                          # ProcessSessionCmd
        tl = parse_tlvs(data); sid = tl[0][1]; inner = tl[1][1]
        if sid not in sessions: return sw(0x6A88)
        return session_cmd(sessions[sid], sid, inner)
    return sw(0x6D00)

def session_cmd(st, sid, inner):
    cla, ins, p1, p2, data, _ = parse_apdu(inner)
    if not st['authed']:
        if ins == 0x50:                      # INITIALIZE UPDATE
            hc = data; cc = os.urandom(8); st['hc'] = hc; st['cc'] = cc
            ctx = hc + cc
            st['senc'] = cmac(KSE, dd(0x04, 0x80, ctx)); st['smac'] = cmac(KSE, dd(0x06, 0x80, ctx)); st['srmac'] = cmac(KSE, dd(0x07, 0x80, ctx))
            cardcrypto = cmac(st['smac'], dd(0x00, 0x40, ctx))[:8]
            return sw(0x9000, bytes(10) + b'\x03\x03\x70' + cc + cardcrypto)
        if ins == 0x82 and cla == 0x84:      # EXTERNAL AUTHENTICATE
            hostcrypto, mac = data[:8], data[8:16]
            exp = cmac(st['smac'], bytes(16) + inner[:13])
            if exp[:8] != mac: return sw(0x6982)
            if hostcrypto != cmac(st['smac'], dd(0x01, 0x40, st['hc'] + st['cc']))[:8]: return sw(0x6300)
            st['mcv'] = exp; st['ctr'] = 1; st['authed'] = True
            return sw(0x9000)
        return sw(0x6985)
    # ---- authenticated: verify C-MAC, decrypt, dispatch, encrypt + R-MAC ----
    if cla & 0x04 == 0: return sw(0x6E00)
    hdr_len = len(inner) - len(data)
    ct, mac = data[:-8], data[-8:]
    macd = inner[:hdr_len] + ct
    exp = cmac(st['smac'], st['mcv'] + macd)
    if exp[:8] != mac: return sw(0x6982)
    st['mcv'] = exp
    ctr = st['ctr'].to_bytes(16, 'big')
    pt = b''
    if ct:
        icv = AES.new(st['senc'], AES.MODE_ECB).encrypt(ctr)
        pt = AES.new(st['senc'], AES.MODE_CBC, icv).decrypt(ct)
        pt = pt[:pt.rindex(b'\x80')]
    print("SIM inner", hex(ins), hex(p1), hex(p2), pt.hex(), file=LOG)
    r = inner_cmd(st, sid, ins, p1, p2, pt)
    body, code = r[:-2], r[-2:]
    rctr = ctr.to_bytes if False else None
    if body:
        ricv = AES.new(st['senc'], AES.MODE_ECB).encrypt(b'\x80' + ctr[1:])
        pb = body + b'\x80'; pb += bytes((16 - len(pb) % 16) % 16)
        body = AES.new(st['senc'], AES.MODE_CBC, ricv).encrypt(pb)
    rmac = cmac(st['srmac'], st['mcv'] + body + code)[:8]
    st['ctr'] += 1
    if os.environ.get('TAMPER') == '1' and body:   # a relay that flips one ciphertext byte
        body = bytes([body[0] ^ 0x01]) + body[1:]
    return body + rmac + code

def inner_cmd(st, sid, ins, p1, p2, pt):
    tl = dict(parse_tlvs(pt)) if pt else {}
    if ins == 0x04 and p2 == 0x1C:          # CloseSession
        del sessions[sid]; return sw(0x9000)
    if ins == 0x02:                          # ReadObject
        obj = int.from_bytes(tl[0x41], 'big')
        if obj != SCALAR_OBJ: return sw(0x6A88)
        if not PCR_UNLOCKED: return sw(0x6986)
        return sw(0x9000, b'\x41' + bytes([len(BLOB)]) + BLOB)
    if ins == 0x03 and p1 == 0x0E:          # CipherOneShot
        obj = int.from_bytes(tl[0x41], 'big')
        if obj != WRAP_OBJ: return sw(0x6A88)
        if not PCR_UNLOCKED: return sw(0x6986)
        if tl[0x42] != b'\x0D': return sw(0x6A80)
        c = AES.new(KDAILY, AES.MODE_CBC, tl[0x44])
        out = c.decrypt(tl[0x43]) if p2 == 0x38 else c.encrypt(tl[0x43])
        return sw(0x9000, b'\x41\x20' + out)
    return sw(0x6D00)

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    a = bytes.fromhex(line)
    print("SIM  C:", a.hex(), file=LOG)
    cla, ins, p1, p2, data, le = parse_apdu(a)
    r = plain_cmd(cla, ins, p1, p2, data)
    print("SIM  R:", r.hex(), file=LOG); LOG.flush()
    print(r.hex()); sys.stdout.flush()
