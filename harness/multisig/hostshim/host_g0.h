// Host stand-in for the G0's BTCSIGN command (v3). The harness plays the G0:
// it parses the fixed request, derives the leaf from a HOST seed with the
// ESP32's own bip32/bip84/multisig helpers, recomputes the BIP-143 sighash and
// signs with the ESP32's secp256k1_ecdsa.h. The caller (psbt_sign_all /
// ms_sign_all) must then agree with this sighash and pubkey — so the harness
// exercises the exact contract the firmware relies on, on both sides.
#pragma once
#include <stdint.h>
#include <string.h>
#include "psbt_sign.h"
#include "multisig.h"

static const uint8_t* g_host_g0_seed = nullptr;   // what the "G0" holds

// Same definition as g0_signer.cpp (kept byte-identical).
bool g0_btc_build_request(uint8_t req[416], uint8_t kind,
                          uint32_t version, uint32_t locktime,
                          const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                          const uint8_t hashOutputs[32], const uint8_t outpoint[36],
                          uint32_t nSequence, uint64_t amount,
                          uint32_t change, uint32_t index,
                          const uint8_t* witness_script, size_t witness_script_len) {
  memset(req, 0, 416);
  if (kind == 1) { if (witness_script_len != 0) return false; }
  else if (kind == 2) { if (!witness_script || witness_script_len == 0 || witness_script_len > 252) return false; }
  else return false;
  if (change > 1 || (index & 0x80000000UL)) return false;
  req[0] = kind; req[1] = 0x01;
  req[2] = (uint8_t)witness_script_len; req[3] = (uint8_t)(witness_script_len >> 8);
  auto p32 = [](uint8_t* p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); };
  p32(req + 4, version); p32(req + 8, locktime);
  memcpy(req + 12, hashPrevouts, 32); memcpy(req + 44, hashSequence, 32); memcpy(req + 76, hashOutputs, 32);
  memcpy(req + 108, outpoint, 36);
  p32(req + 144, nSequence);
  for (int i = 0; i < 8; i++) req[148 + i] = (uint8_t)(amount >> (8 * i));
  p32(req + 156, change); p32(req + 160, index);
  if (witness_script_len) memcpy(req + 164, witness_script, witness_script_len);
  return true;
}

static uint32_t hg_rd32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

static bool host_g0_sign(const uint8_t req[416], uint8_t pub33_out[33], uint8_t der_out[72],
                         uint8_t* der_len_out, uint8_t sighash_out[32]) {
  if (!g_host_g0_seed) return false;
  uint8_t kind = req[0]; if (req[1] != 0x01) return false;
  uint32_t wslen = req[2] | (req[3] << 8), ver = hg_rd32(req + 4), lock = hg_rd32(req + 8);
  uint32_t seq = hg_rd32(req + 144), change = hg_rd32(req + 156), index = hg_rd32(req + 160);
  uint64_t amount = 0; for (int i = 7; i >= 0; i--) amount = (amount << 8) | req[148 + i];
  uint8_t priv[32];
  if (kind == 1) { if (wslen || !bip84_derive_address_privkey(g_host_g0_seed, BIP84_NETWORK_MAINNET, change, index, priv)) return false; }
  else if (kind == 2) { if (!wslen || !ms_derive_leaf_privkey(g_host_g0_seed, change, index, priv)) return false; }
  else return false;
  if (!bip32_priv_to_pub_compressed(priv, pub33_out)) return false;
  static uint8_t sc[BIP143_MAX_SCRIPTCODE]; size_t scl;
  if (kind == 1) { uint8_t pkh[20]; hash160(pub33_out, 33, pkh); scl = bip143_p2wpkh_scriptcode(pkh, sc); }
  else scl = bip143_p2wsh_scriptcode(req + 164, wslen, sc);
  if (!scl) return false;
  if (!bip143_input_sighash_sc(ver, lock, req + 108, seq, amount, sc, scl, req + 12, req + 44, req + 76, BIP143_SIGHASH_ALL, sighash_out)) return false;
  uint8_t r[32], s[32];
  if (!ecdsa_sign(priv, sighash_out, r, s)) return false;
  memset(priv, 0, 32);
  int dl = ecdsa_der_encode(r, s, der_out); if (dl <= 0 || dl > 72) return false;
  *der_len_out = (uint8_t)dl;
  return true;
}
