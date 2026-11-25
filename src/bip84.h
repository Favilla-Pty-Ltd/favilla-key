#ifndef FAVILLA_BIP84_H
#define FAVILLA_BIP84_H

// BIP-84 native SegWit (P2WPKH) derivation for Favilla Key
//
// Public-facing API for Bitcoin operations on the device.
//
// Path: m / 84' / coin' / account' / change / index
//   coin'    = 0' (mainnet) or 1' (testnet)
//   account' = 0' (single account in V1)
//   change   = 0 (receive) or 1 (change)
//   index    = 0, 1, 2, ...
//
// Address format: bc1q... (mainnet) / tb1q... (testnet)
// Witness program = HASH160(compressed_pubkey)
//
// Account zpub serialisation uses BIP-84 version bytes (not xpub):
//   Mainnet: 0x04B24746 → "zpub..." prefix
//   Testnet: 0x045F1CF6 → "vpub..." prefix

#include <stdint.h>
#include <string.h>
#include "bip32.h"
#include "bech32.h"
#include "hash160.h"
#include "base58.h"

static const uint8_t BIP84_ZPUB_VERSION[4] = { 0x04, 0xB2, 0x47, 0x46 };  // mainnet
static const uint8_t BIP84_VPUB_VERSION[4] = { 0x04, 0x5F, 0x1C, 0xF6 };  // testnet

typedef enum {
  BIP84_NETWORK_MAINNET = 0,
  BIP84_NETWORK_TESTNET = 1,
} bip84_network_t;

// ── Derive the account-level extended private key ─────────────────────────
// Walks m/84'/coin'/0' from the BIP-39 seed.
// Outputs the account xprv + master fingerprint (for serialisation).
static bool bip84_derive_account_xprv(const uint8_t seed[64],
                                       bip84_network_t network,
                                       bip32_xprv* account_out,
                                       uint8_t master_fingerprint_out[4]) {
  bip32_xprv master;
  if (!bip32_master_from_seed(seed, 64, &master)) return false;

  // Master fingerprint = HASH160(master_pubkey)[0..4]
  uint8_t master_pub[33];
  if (!bip32_priv_to_pub_compressed(master.key, master_pub)) return false;
  uint8_t master_h160[20];
  hash160(master_pub, 33, master_h160);
  memcpy(master_fingerprint_out, master_h160, 4);

  // m/84'
  bip32_xprv lvl1;
  if (!bip32_derive_child(&master, 0x80000000UL + 84, &lvl1)) return false;
  memcpy(lvl1.parent_fingerprint, master_fingerprint_out, 4);

  // m/84'/coin'
  uint32_t coin = (network == BIP84_NETWORK_MAINNET) ? 0 : 1;
  bip32_xprv lvl2;
  if (!bip32_derive_child(&lvl1, 0x80000000UL + coin, &lvl2)) return false;
  uint8_t lvl1_pub[33];
  if (!bip32_priv_to_pub_compressed(lvl1.key, lvl1_pub)) return false;
  uint8_t lvl1_h160[20];
  hash160(lvl1_pub, 33, lvl1_h160);
  memcpy(lvl2.parent_fingerprint, lvl1_h160, 4);

  // m/84'/coin'/0'
  bip32_xprv lvl3;
  if (!bip32_derive_child(&lvl2, 0x80000000UL + 0, &lvl3)) return false;
  uint8_t lvl2_pub[33];
  if (!bip32_priv_to_pub_compressed(lvl2.key, lvl2_pub)) return false;
  uint8_t lvl2_h160[20];
  hash160(lvl2_pub, 33, lvl2_h160);
  memcpy(lvl3.parent_fingerprint, lvl2_h160, 4);

  *account_out = lvl3;
  return true;
}

// ── Derive a single address private key ───────────────────────────────────
// change: 0 receive, 1 change. Caller zeroises privkey_out after use.
static bool bip84_derive_address_privkey(const uint8_t seed[64],
                                          bip84_network_t network,
                                          uint32_t change, uint32_t index,
                                          uint8_t privkey_out[32]) {
  if (change > 1) return false;

  bip32_xprv account;
  uint8_t fp[4];
  if (!bip84_derive_account_xprv(seed, network, &account, fp)) return false;

  bip32_xprv lvl_change;
  if (!bip32_derive_child(&account, change, &lvl_change)) return false;

  bip32_xprv lvl_idx;
  if (!bip32_derive_child(&lvl_change, index, &lvl_idx)) return false;

  memcpy(privkey_out, lvl_idx.key, 32);

  memset(&account, 0, sizeof(account));
  memset(&lvl_change, 0, sizeof(lvl_change));
  memset(&lvl_idx, 0, sizeof(lvl_idx));
  return true;
}

// ── Derive a bech32 address ───────────────────────────────────────────────
static bool bip84_derive_address(const uint8_t seed[64],
                                  bip84_network_t network,
                                  uint32_t change, uint32_t index,
                                  char* addr_out, size_t addr_out_cap) {
  if (addr_out_cap < 64) return false;

  uint8_t priv[32];
  if (!bip84_derive_address_privkey(seed, network, change, index, priv)) return false;

  uint8_t pub[33];
  bool ok = bip32_priv_to_pub_compressed(priv, pub);
  memset(priv, 0, sizeof(priv));
  if (!ok) return false;

  uint8_t witness_program[20];
  hash160(pub, 33, witness_program);

  const char* hrp = (network == BIP84_NETWORK_MAINNET) ? "bc" : "tb";
  return segwit_addr_encode(hrp, 0, witness_program, 20, addr_out);
}

// ── Serialise the account zpub (mainnet) or vpub (testnet) ────────────────
// Output: 111-character base58check string. Caller buffer must be ≥ 128 bytes.
static bool bip84_serialise_account_xpub(const uint8_t seed[64],
                                          bip84_network_t network,
                                          char* out, size_t out_cap) {
  if (out_cap < 128) return false;

  bip32_xprv account;
  uint8_t master_fp[4];
  if (!bip84_derive_account_xprv(seed, network, &account, master_fp)) return false;

  uint8_t account_pub[33];
  bool ok = bip32_priv_to_pub_compressed(account.key, account_pub);
  if (!ok) {
    memset(&account, 0, sizeof(account));
    return false;
  }

  // 78-byte serialised form
  uint8_t ser[78];
  const uint8_t* version = (network == BIP84_NETWORK_MAINNET)
                            ? BIP84_ZPUB_VERSION : BIP84_VPUB_VERSION;
  memcpy(ser + 0, version, 4);
  ser[4] = account.depth;  // 3
  memcpy(ser + 5, account.parent_fingerprint, 4);
  uint32_t cn = account.child_number;
  ser[9]  = (cn >> 24) & 0xFF;
  ser[10] = (cn >> 16) & 0xFF;
  ser[11] = (cn >>  8) & 0xFF;
  ser[12] =  cn        & 0xFF;
  memcpy(ser + 13, account.chain_code, 32);
  memcpy(ser + 45, account_pub, 33);

  size_t n = base58check_encode(ser, 78, out, out_cap);

  memset(&account, 0, sizeof(account));
  return n > 0;
}

// Seed-free zpub serialisation: build the zpub string directly from an already-
// derived account xpub struct (the persisted watch-only key). No seed required,
// so this works on a daily-door unlock — it's what /btc/info and the Wallet Info
// screen should use to serve the zpub seed-free. Mirrors the byte layout of
// bip84_serialise_account_xpub exactly; only the data source differs.
static bool bip84_serialise_xpub_struct(const bip32_xpub* xpub,
                                         bip84_network_t network,
                                         char* out, size_t out_cap) {
  if (out_cap < 128 || !xpub) return false;
  uint8_t ser[78];
  const uint8_t* version = (network == BIP84_NETWORK_MAINNET)
                            ? BIP84_ZPUB_VERSION : BIP84_VPUB_VERSION;
  memcpy(ser + 0, version, 4);
  ser[4] = xpub->depth;
  memcpy(ser + 5, xpub->parent_fingerprint, 4);
  uint32_t cn = xpub->child_number;
  ser[9]  = (cn >> 24) & 0xFF;
  ser[10] = (cn >> 16) & 0xFF;
  ser[11] = (cn >>  8) & 0xFF;
  ser[12] =  cn        & 0xFF;
  memcpy(ser + 13, xpub->chain_code, 32);
  memcpy(ser + 45, xpub->pubkey, 33);
  size_t n = base58check_encode(ser, 78, out, out_cap);
  return n > 0;
}

#endif // FAVILLA_BIP84_H
