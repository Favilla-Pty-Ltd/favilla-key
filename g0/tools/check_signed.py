# Re-verifies every input signature of the signed plan transactions with embit,
# and that each refresh/coupon spends the txid of the refresh before it.
import sys
from embit.transaction import Transaction
from embit import script, ec
txs = {}; n = 0; bad = 0
for line in open(sys.argv[1]):
    k, kind, link, var, amts, raw = line.split()
    tx = Transaction.parse(bytes.fromhex(raw)); amts = [int(a) for a in amts.split(',')]
    for i, inp in enumerate(tx.vin):
        sig, pub = inp.witness.items
        pk = ec.PublicKey.parse(pub)
        sh = tx.sighash_segwit(i, script.p2pkh(pk), amts[i])
        ok = sig[-1] == 1 and pk.verify(ec.Signature.parse(sig[:-1]), sh); n += 1; bad += not ok
    if kind == 'R': txs[(k, int(link))] = tx
    if int(link) >= 1:
        r = txs[(k, int(link))]
        if kind == 'C': bad += not (tx.vin[0].txid == r.txid() and tx.vin[0].vout == 0)
        if kind == 'R' and int(link) >= 2: bad += not (tx.vin[0].txid == txs[(k, int(link) - 1)].txid())
print('  embit: %d signatures verified, chain links checked, %d bad' % (n, bad)); sys.exit(1 if bad else 0)
