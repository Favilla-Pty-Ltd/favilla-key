# Re-verifies every transaction the G0 released in host_ember_e2e with embit:
# each input signature against the amount it spends, chain links, and
# nLockTime below the height it was mined at.
import sys
from embit.transaction import Transaction
from embit import script, ec
coins = {}
for c in range(2):
    txid = bytes(0x40 + c * 7 + i for i in range(32))[::-1]   # display order
    coins[(txid, c)] = 50000000 + 1000 * c
txs = {}; n = bad = 0
for line in open(sys.argv[1]):
    h, raw = line.split(); h = int(h)
    tx = Transaction.parse(bytes.fromhex(raw))
    if not tx.locktime < h: bad += 1; print('locktime', tx.locktime, '>= mined at', h)
    for i, inp in enumerate(tx.vin):
        key = (inp.txid, inp.vout)
        amt = coins.get(key)
        if amt is None:
            prev = txs.get(inp.txid)
            if prev is None: bad += 1; print('unknown prevout'); continue
            amt = prev.vout[inp.vout].value
        sig, pub = inp.witness.items; pk = ec.PublicKey.parse(pub)
        ok = sig[-1] == 1 and pk.verify(ec.Signature.parse(sig[:-1]), tx.sighash_segwit(i, script.p2pkh(pk), amt))
        n += 1; bad += not ok
    txs[tx.txid()] = tx
print('  embit: %d released transactions, %d signatures verified, links and locktimes checked, %d bad' % (len(txs), n, bad))
sys.exit(1 if bad else 0)
