#!/usr/bin/env python3
# Independent check of the harness's pass-through output: embit verifies BOTH
# partial sigs on every input, then finalises the PSBT and extracts a tx.
# This is the "would Sparrow accept it" test.
import sys
from embit import psbt, bip32, bip39
from embit.psbt import PSBT
hexs = open(sys.argv[1]).read().strip()
p = PSBT.parse(bytes.fromhex(hexs))
ok = True
for i, inp in enumerate(p.inputs):
    sigs = inp.partial_sigs
    if len(sigs) != 2:
        print("input %d: expected 2 partial sigs, got %d" % (i, len(sigs))); ok = False
    sh = p.sighash(i)
    for pub, sig in sigs.items():
        from embit.ec import Signature
        if not pub.verify(Signature.parse(sig[:-1]), sh):
            print("input %d: signature by %s does NOT verify" % (i, pub.sec().hex())); ok = False
    if not inp.witness_script or not inp.witness_utxo or len(inp.bip32_derivations) != 3:
        print("input %d: pass-through lost metadata" % i); ok = False
if len(p.outputs[1].bip32_derivations) != 3 or not p.outputs[1].witness_script:
    print("output 1: pass-through lost change metadata"); ok = False
if len(p.xpubs) != 3:
    print("global xpubs lost"); ok = False
if ok:
    try:
        # both sigs present -> embit can finalise a 2-of-3
        from embit import finalizer
        tx = finalizer.finalize_psbt(p)
        print(" embit: all partial sigs verify, metadata intact, PSBT finalises -> txid %s" % tx.txid().hex())
    except Exception as e:
        print(" embit: sigs verify but finalise failed: %s" % e); ok = False

# crypto-account: decode the CBOR the device shows for "Export key" and check
# that the wsh hdkey rebuilds cosigner A's account xpub exactly.
try:
    import cbor2
    acct = cbor2.loads(bytes.fromhex(open("out_account.hex").read().strip()))
    assert acct[1] == int.from_bytes(bytes.fromhex("73c5da0a"), "big"), "master fp"
    descs = acct[2]
    tags = [d.tag for d in descs]
    assert tags == [404, 401], tags
    for d in descs:
        hd = d.value
        assert hd.tag == 303
        m = hd.value
        kp = m[6]; assert kp.tag == 304
        comps = kp.value[1]; path = [comps[i] | (0x80000000 if comps[i+1] else 0) for i in range(0, len(comps), 2)]
        depth = kp.value[3]
        assert depth == len(path)
        r = bip32.HDKey.from_seed(bip39.mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
        exp = r.derive(path).to_public()
        assert m[3] == exp.key.sec(), "key-data"
        assert m[4] == exp.chain_code, "chain-code"
        assert m[8] == int.from_bytes(exp.fingerprint, "big"), "parent fp"
        assert kp.value[2] == int.from_bytes(r.my_fingerprint, "big")
    print(" embit/cbor2: crypto-account carries the correct m/84 (wpkh) and m/48/2 (wsh) keys, paths and fingerprints")
except Exception as e:
    print(" crypto-account check FAILED: %r" % (e,)); ok = False
sys.exit(0 if ok else 1)
