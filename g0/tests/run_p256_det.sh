#!/bin/bash
# G0 P-256 deterministic ECDSA: RFC 6979 vectors in C, then 200 random cases
# checked against python-ecdsa (RFC 6979) and verified with the public key.
# Run from g0/. Needs: pip install ecdsa
set -e
gcc -O2 -Wall -Wextra -fsanitize=address,undefined -Isrc -Ilib/p256m -Ilib/g0crypto \
  tests/host_p256_det.c src/p256_det.c lib/p256m/p256-m.c lib/g0crypto/sha256.c -o /tmp/g0_p256
/tmp/g0_p256 > /tmp/g0_p256.txt
tail -1 /tmp/g0_p256.txt
python3 -c "import ecdsa" 2>/dev/null || { echo "run_p256_det.sh needs the Python ecdsa package: pip install ecdsa"; exit 1; }   # 23 Nov 2026 (#56-8)
python3 - <<'PY'
import ecdsa, hashlib
from ecdsa.util import sigencode_string, sigdecode_der
n=0
for line in open('/tmp/g0_p256.txt'):
    if not line.startswith('K '): continue
    _,k,_,h,_,s,_,d = line.split()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(k), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
    want = sk.sign_digest_deterministic(bytes.fromhex(h), hashfunc=hashlib.sha256, sigencode=sigencode_string)
    assert want.hex() == s, ("mismatch", k, h, s, want.hex())
    vk = sk.get_verifying_key()
    assert vk.verify_digest(bytes.fromhex(s), bytes.fromhex(h))
    assert vk.verify_digest(bytes.fromhex(d), bytes.fromhex(h), sigdecode=sigdecode_der)
    n+=1
print(f"python-ecdsa: {n} random signatures identical to RFC 6979 and verified (raw and DER)")
m=0
for line in open('/tmp/g0_p256.txt'):
    if not line.startswith('X '): continue
    _,k,_,h,_,e,_,s = line.split()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(k), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
    want = sk.sign_digest_deterministic(bytes.fromhex(h), hashfunc=hashlib.sha256, sigencode=sigencode_string, extra_entropy=bytes.fromhex(e))
    assert want.hex() == s, ("hedged mismatch", k, h, e, s, want.hex())
    assert sk.get_verifying_key().verify_digest(bytes.fromhex(s), bytes.fromhex(h))
    m+=1
print(f"python-ecdsa: {m} hedged signatures identical to RFC 6979 section 3.6 with that extra data, and verified")
PY
T=$(ls -d ~/.platformio/packages/toolchain-gccarmnoneeabi*/bin 2>/dev/null | head -1)
if [ -n "$T" ]; then
  for f in lib/p256m/p256-m.c src/p256_det.c; do
    $T/arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -Os -ffunction-sections -fdata-sections -Isrc -Ilib/p256m -Ilib/g0crypto -c $f -o /tmp/p.o
    echo "$f: $($T/arm-none-eabi-size /tmp/p.o | tail -1 | awk '{print $1+$2" bytes flash"}')"
  done
fi
