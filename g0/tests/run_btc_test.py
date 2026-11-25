#!/usr/bin/env python3
"""Host KATs for src/btc.c against embit: BIP-32 account derivation (84/48),
master + parent fingerprints, the sealed-state key, BIP-143 sighash and the
RFC-6979 low-S ECDSA signature for random P2WPKH / P2WSH requests."""
import os, sys, subprocess, hashlib, hmac, struct, random
from embit import bip32, ec, script, hashes
from embit.networks import NETWORKS
HERE=os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
L='../lib'
cmd=('gcc -Wall -Wextra -O1 -I../src -I%s/g0crypto -I%s/secp256k1/include -I%s/secp256k1/src '
     '-DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 '
     '-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -Wno-unused-function -Wno-unused-parameter '
     '-DBTC_HOST_REFERENCE host_btc.c ../src/btc.c %s/g0crypto/sha256.c %s/g0crypto/sha512.c %s/g0crypto/ripemd160.c '
     '%s/secp256k1/src/secp256k1.c %s/secp256k1/src/precomputed_ecmult.c %s/secp256k1/src/precomputed_ecmult_gen.c '
     '-o /tmp/host_btc')%tuple([L]*9)
subprocess.check_call(cmd,shell=True)
def run(*a): return subprocess.check_output(['/tmp/host_btc']+list(a)).decode().split()
random.seed(1234)
fails=0; total=0
def check(name,got,exp):
    global fails,total; total+=1
    if got!=exp: fails+=1; print("FAIL",name,"\n got",got,"\n exp",exp)
check("libsecp256k1 RFC6979 canonical vector",run("rfc6979")[0],"934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")
seeds=[bytes(range(64)), bytes.fromhex('000102030405060708090a0b0c0d0e0f'*4)]+[os.urandom(64) for _ in range(6)]
for s in seeds:
    root=bip32.HDKey.from_seed(s)
    mfp=root.my_fingerprint.hex()
    for purpose,path in ((84,"m/84h/0h/0h"),(48,"m/48h/0h/0h/2h")):
        acct=root.derive(path); parent=root.derive(path.rsplit('/',1)[0])
        got=run('acct',s.hex(),str(purpose))
        exp=[mfp,parent.my_fingerprint.hex(),acct.key.sec().hex(),acct.chain_code.hex(),
             hmac.new(s,b"FAVILLA-BTC-STATE-v1",hashlib.sha256).hexdigest()]
        check(f"acct {purpose}",got,exp)
# signing requests
def mkreq(kind,ws,ver,lock,hp,hs,ho,outpoint,seq,amt,change,index):
    r=bytearray(416)
    r[0]=kind; r[1]=1; r[2:4]=struct.pack('<H',len(ws)); r[4:8]=struct.pack('<I',ver); r[8:12]=struct.pack('<I',lock)
    r[12:44]=hp; r[44:76]=hs; r[76:108]=ho; r[108:144]=outpoint; r[144:148]=struct.pack('<I',seq)
    r[148:156]=struct.pack('<Q',amt); r[156:160]=struct.pack('<I',change); r[160:164]=struct.pack('<I',index)
    r[164:164+len(ws)]=ws; return bytes(r)
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def varint(n): return bytes([n]) if n<0xfd else b'\xfd'+struct.pack('<H',n)
def sighash(req,scriptcode):
    pre=req[4:8]+req[12:44]+req[44:76]+req[108:144]+scriptcode+req[148:156]+req[144:148]+req[76:108]+req[8:12]+struct.pack('<I',req[1])
    return dsha(pre)
for s in seeds[:4]:
    root=bip32.HDKey.from_seed(s)
    for kind in (1,2):
        for _ in range(3):
            change=random.randint(0,1); index=random.randint(0,5000)
            if kind==1:
                leaf=root.derive(f"m/84h/0h/0h/{change}/{index}")
                pub=leaf.key.sec(); ws=b''
                sc=b'\x19\x76\xa9\x14'+hashes.hash160(pub)+b'\x88\xac'
            else:
                leaf=root.derive(f"m/48h/0h/0h/2h/{change}/{index}")
                pub=leaf.key.sec()
                n=random.randint(2,7); m=random.randint(1,n)
                keys=sorted([pub]+[ec.PrivateKey(os.urandom(32)).sec() for _ in range(n-1)])
                ws=script.multisig(m,[ec.PublicKey.parse(k) for k in keys]).data
                sc=varint(len(ws))+ws
            req=mkreq(kind,ws,2,random.randint(0,800000),os.urandom(32),os.urandom(32),os.urandom(32),os.urandom(36),0xfffffffd,random.randint(1000,10**9),change,index)
            sh=sighash(req,sc)
            got=run('sign',s.hex(),req.hex())
            # embit's pure-Python signer does NOT use standard RFC 6979 (its nonce
            # is its own deterministic scheme), so byte-compare is meaningless;
            # verify the signature, check low-S, and check the DER encoding.
            check(f"sign kind{kind} n={len(ws)} rc/pub/sighash",[got[0],got[1],got[3]],['0',pub.hex(),sh.hex()])
            sig=ec.Signature.parse(bytes.fromhex(got[2]))
            r,sv=sig.serialize()[0:0],None
            check(f"sign kind{kind} verify",leaf.key.get_public_key().verify(sig,sh),True)
            der=bytes.fromhex(got[2]); slen=der[5+der[3]]; sint=int.from_bytes(der[6+der[3]:6+der[3]+slen],'big')
            check(f"sign kind{kind} low-S",sint<0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141//2,True)
            check(f"sign kind{kind} DER",sig.serialize().hex(),got[2])
# refusals
bad=bytearray(mkreq(1,b'',2,0,b'\0'*32,b'\0'*32,b'\0'*32,b'\0'*36,0,1,0,0)); bad[1]=3
check("refuse sighash!=ALL",run('sign',seeds[0].hex(),bytes(bad).hex())[0],'-1')
bad=bytearray(mkreq(1,b'',2,0,b'\0'*32,b'\0'*32,b'\0'*32,b'\0'*36,0,1,2,0))
check("refuse change=2",run('sign',seeds[0].hex(),bytes(bad).hex())[0],'-1')
bad=bytearray(mkreq(2,b'',2,0,b'\0'*32,b'\0'*32,b'\0'*32,b'\0'*36,0,1,0,0))
check("refuse p2wsh empty ws",run('sign',seeds[0].hex(),bytes(bad).hex())[0],'-1')
bad=bytearray(mkreq(1,b'',2,0,b'\0'*32,b'\0'*32,b'\0'*32,b'\0'*36,0,1,0,0x80000000))
check("refuse hardened index",run('sign',seeds[0].hex(),bytes(bad).hex())[0],'-1')
# ── BIP-137 message signing (15 Oct 2026) ─────────────────────────────────
import base64, ecdsa
from ecdsa.util import sigencode_string, sigdecode_string
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def mkmsg(change,index,msg):
    r=bytearray(416); r[0:4]=b'FMSG'; r[4]=1; r[5]=change; r[6:10]=struct.pack('<I',index); r[10]=len(msg); r[11:11+len(msg)]=msg
    return bytes(r)
def msg_digest(m): return dsha(b'\x18Bitcoin Signed Message:\n'+bytes([len(m)])+m)
msgs=[b'hello', b'Favilla KEY proof of ownership 2026-10-15', bytes(range(0x20,0x7f)), b'x'*240, b' ']
for s in seeds[:4]:
    root=bip32.HDKey.from_seed(s)
    for m in msgs:
        change=random.randint(0,1); index=random.choice([0,1,random.randint(2,100000)])
        leaf=root.derive(f"m/84h/0h/0h/{change}/{index}")
        pub=leaf.key.sec(); dg=msg_digest(m)
        got=run('msg',s.hex(),mkmsg(change,index,m).hex())
        check(f"msg len{len(m)} rc/pub/digest",[got[0],got[1],got[3]],['0',pub.hex(),dg.hex()])
        sig=bytes.fromhex(got[2]); hdr=sig[0]
        check(f"msg len{len(m)} header P2WPKH 39..42",39<=hdr<=42,True)
        # RFC 6979 byte-for-byte against python-ecdsa's deterministic signer, low-S normalised
        sk=ecdsa.SigningKey.from_string(leaf.key.secret,curve=ecdsa.SECP256k1)
        r_,s_=sigdecode_string(sk.sign_digest_deterministic(dg,hashfunc=hashlib.sha256,sigencode=sigencode_string),N)
        if s_>N//2: s_=N-s_
        check(f"msg len{len(m)} RFC6979 r||s",sig[1:].hex(),(r_.to_bytes(32,'big')+s_.to_bytes(32,'big')).hex())
        # recovery with the advertised recid gives this key
        vks=ecdsa.VerifyingKey.from_public_key_recovery_with_digest(sig[1:],dg,ecdsa.SECP256k1,hashfunc=hashlib.sha256,sigdecode=sigdecode_string)
        rec=[vk.to_string('compressed') for vk in vks]
        check(f"msg len{len(m)} recid recovers the key",rec[hdr-39]==pub if hdr-39<len(rec) else False,True)
# refusals
base=bytearray(mkmsg(0,0,b'ok'))
for name,mut in (("bad magic",lambda b:b.__setitem__(0,ord('X'))),("bad version",lambda b:b.__setitem__(4,2)),
                 ("change=2",lambda b:b.__setitem__(5,2)),("hardened index",lambda b:b.__setitem__(9,0x80)),
                 ("len 0",lambda b:b.__setitem__(10,0)),("len 241",lambda b:b.__setitem__(10,241)),
                 ("non-ASCII byte",lambda b:b.__setitem__(11,0x0a)),("hidden tail byte",lambda b:b.__setitem__(300,1))):
    b=bytearray(base); mut(b)
    check("msg refuse "+name,run('msg',seeds[0].hex(),bytes(b).hex())[0],'-1')
# a transaction sign request is never accepted as a message
check("msg refuses a tx request",run('msg',seeds[0].hex(),mkreq(1,b'',2,0,b'\0'*32,b'\0'*32,b'\0'*32,b'\0'*36,0,1,0,0).hex())[0],'-1')
print(f"{total-fails}/{total} passed"); sys.exit(1 if fails else 0)
