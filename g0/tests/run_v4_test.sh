#!/bin/bash
# v4 host KATs: packed word list + mnemonic builder + PBKDF2 vs Python's
# hashlib and the BIP-39 reference vectors. Run from the project root.
set -e
gcc -O2 -Ilib/g0crypto -Isrc tests/host_v4_seed.c src/bip39_words.c lib/g0crypto/sha256.c lib/g0crypto/sha512.c lib/g0crypto/pbkdf2.c -o /tmp/g0_v4_seed
OUT=$(/tmp/g0_v4_seed)
EXP1=c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
EXP2=$(python3 -c "import hashlib;print(hashlib.pbkdf2_hmac('sha512',('zoo '*23+'vote').encode(),b'mnemonicTREZOR',2048).hex())")
echo "$OUT" | sed -n 1p | grep -q "$EXP1" && echo "PASS 12-word BIP-39 vector (00*16, TREZOR)" || { echo FAIL1; exit 1; }
echo "$OUT" | sed -n 2p | grep -q "$EXP2" && echo "PASS 24-word ff*32 vs hashlib" || { echo FAIL2; exit 1; }
echo "v4 KATs done"
