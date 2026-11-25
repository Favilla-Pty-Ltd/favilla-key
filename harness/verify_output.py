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
sys.exit(0 if ok else 1)
