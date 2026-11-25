# 23 Nov 2026 (#57): builds PSBT test vectors for psbt_prevtx_test.c.
# Writes vectors.h. Run: python3 gen.py
import hashlib, struct
def vi(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def spk_wpkh(t): return bytes([0, 20]) + bytes([t]) * 20
def prev_tx(outs, segwit, tag):
    ins = bytes([tag]) * 32 + struct.pack('<I', 0) + vi(0) + struct.pack('<I', 0xffffffff)
    body = vi(1) + ins + vi(len(outs)) + b''.join(struct.pack('<Q', v) + vi(len(s)) + s for v, s in outs)
    ver = struct.pack('<I', 2); lock = struct.pack('<I', 0)
    txid = dsha(ver + body + lock)
    if segwit:
        wit = vi(2) + vi(71) + b'\x30' * 71 + vi(33) + b'\x02' * 33
        raw = ver + b'\x00\x01' + body + wit + lock
    else:
        raw = ver + body + lock
    return raw, txid
def kv(k, v): return vi(len(k)) + k + vi(len(v)) + v
def psbt(inputs, nwu_mode, wu_value_override=None):
    # inputs: list of (prev_raw, txid, vout, value, spk)
    txins = b''.join(t + struct.pack('<I', vo) + vi(0) + struct.pack('<I', 0xfffffffd) for _, t, vo, _, _ in inputs)
    outs = [(1000, spk_wpkh(9))]
    utx = struct.pack('<I', 2) + vi(len(inputs)) + txins + vi(len(outs)) + b''.join(struct.pack('<Q', v) + vi(len(s)) + s for v, s in outs) + struct.pack('<I', 0)
    out = b'psbt\xff' + kv(b'\x00', utx) + b'\x00'
    for i, (raw, txid, vo, val, spk) in enumerate(inputs):
        m = b''
        if nwu_mode in ('both', 'nwu_only'): m += kv(b'\x00', raw)
        if nwu_mode in ('both', 'wu_only'):
            v = wu_value_override if (wu_value_override is not None and i == 1) else val
            m += kv(b'\x01', struct.pack('<Q', v) + vi(len(spk)) + spk)
        out += m + b'\x00'
    out += b'\x00'
    return out
A_raw, A_id = prev_tx([(50000, spk_wpkh(1)), (77777, spk_wpkh(2))], True, 0xAA)
B_raw, B_id = prev_tx([(123456, spk_wpkh(3))], False, 0xBB)
ins = [(A_raw, A_id, 1, 77777, spk_wpkh(2)), (B_raw, B_id, 0, 123456, spk_wpkh(3))]
V = {}
V['ok_both']      = psbt(ins, 'both')
V['ok_nwu_only']  = psbt(ins, 'nwu_only')
V['wu_only_2in']  = psbt(ins, 'wu_only')
V['wu_only_1in']  = psbt(ins[:1], 'wu_only')
V['lie_amount']   = psbt(ins, 'both', wu_value_override=999999)
bad = list(ins); bad[1] = (A_raw, B_id, 0, 123456, spk_wpkh(3))   # previous tx that is not the prevout
V['wrong_prev']   = psbt(bad, 'both')
bad2 = list(ins); bad2[0] = (A_raw, A_id, 5, 77777, spk_wpkh(2))  # vout past the outputs
V['vout_range']   = psbt(bad2, 'both')
with open('vectors.h', 'w') as f:
    for k, v in V.items():
        f.write('static const unsigned char v_%s[] = {%s};\n' % (k, ','.join(str(b) for b in v)))
print('wrote', len(V), 'vectors')
