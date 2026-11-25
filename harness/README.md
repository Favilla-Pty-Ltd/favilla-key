# multisig harness

Compiles the REAL `src/` multisig headers on the desktop under UBSan and ASan and
checks them against vectors produced by embit (an independent Python
implementation), then hands our pass-through output back to embit to verify
every partial signature and finalise the transaction.

    apt install libmbedtls-dev      # 2.28 or 3.x
    pip install embit
    make                            # 82 checks, both sanitizers, embit cross-check
    make vectors                    # regenerate ms_vectors.h (only if you change gen_vectors.py)

`hostshim/` stands in for Arduino.h (Serial, String) and the one symbol
main.cpp normally defines (g_nostr_ecdh_hook). Nothing in it is used on device.

Vector set (gen_vectors.py): three BIP-39 test mnemonics -> 2-of-3 P2WSH
sortedmulti at m/48'/0'/0'/2'. Cosigner A is the KEY. The PSBT spends 0/0 and
0/5, pays one recipient and change to 1/3, and ALREADY carries cosigner B's
partial signatures, so the pass-through writer is tested against real
pre-existing sigs, not an empty map.
