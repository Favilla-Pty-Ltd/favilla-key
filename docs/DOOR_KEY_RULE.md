# One door, one PIN (spec, 13 Nov 2026; built in drop 11bd with G0 v19)

**Rule.** Every major key opens only with its own door's PIN, checked by the
secure element, never only by firmware. A full read of the G0's flash on a
locked KEY gives no major key.

| Door | PIN | Keys it alone opens |
|---|---|---|
| NOSTR | daily | the Nostr key; the vault backup publishing key |
| VAULT (passkey) | passkey | the passkey master, and through it every vault record, code, recovery code and the site index |
| BTC | spend | the seed |

Exception by design: Emberwill release. It needs no PIN because the owner may
be dead. What it releases is transactions already signed at the ceremony (BTC
door, spend PIN), never a key.

## 1. What a G0 flash read gives today

The G0's flash holds K_SE (its identity to the secure element), K_G0 (the inner
layer of every key), S (the door secret) and the Emberwill plan. On a locked
KEY:

| Secret | Path from a G0 flash read | Today |
|---|---|---|
| Nostr key | needs Door 1, unlocked only by a secret the daily PIN alone reads | safe |
| Seed | the seed key decrypts only in a spend-PIN session at BTC | safe |
| Passkey master | K_SE resets the mode latch, S mints V_3, K_PK decrypts for the G0 identity at V_3, PK_MASTER_P is readable by the G0 identity, K_G0 strips the inner layer | **exposed, no PIN** |
| Passkey master (NOSTR copy) | opens with Door 1 unlocked, which is the daily PIN | wrong door's PIN |
| Site index key (NOSTR copy, K_IXN) | daily PIN | wrong door's PIN |
| Vault backup publishing key | under K_PKN, Door 1 | daily PIN (allowed, see 4) |

The "a PIN armed the latch" check on the passkey path is in the G0's firmware
only. The secure element does not require it, so anyone posing as the G0 skips
it. The seed had the same hole until 19 Oct 2026 and was fixed by giving the
decrypt right to the spend PIN alone; this spec does the same for passkeys.

## 2. Passkey master: the passkey PIN decrypts, the G0 strips

- **PKMASTER (G0)** returns 64 bytes: `inner || tag`, where `inner` =
  AES-256-CBC(K_G0, master IV, S_pk) as now and `tag` = HMAC-SHA256(K_G0,
  "favilla-g0-pk-master-tag" || inner). The ESP32 cannot make a tag, so it
  cannot plant a master or swap in another one.
- **PK_MASTER_P (SE)** = IV16 || AES(K_PK, inner || tag), 80 bytes. Policy:
  passkey PIN READ|WRITE|DELETE, RECOVER DELETE. No G0 entry.
- **K_PK (SE)**: passkey PIN ENC|DEC|WRITE|DELETE at MODE_PCR == V_3, RECOVER
  DELETE. **No G0 entry.**
- **The window** (each PKSIGN or VAULT batch): the passkey PIN session ARMs, the
  G0 mints V_3, the ESP32 reopens the passkey session at V_3, READs
  PK_MASTER_P, DECs it with K_PK and writes the 64 bytes to the G0's new
  register PKM_IN (0x25). The window's close burns V_3, as now.
- **The G0 uses PKM_IN only:** in a PASSKEY life; when the tag checks
  (constant time); and when its own session reads MODE_PCR == V_3. The last
  check keeps every use inside a window the passkey PIN opened: a copy of the
  64 bytes kept from an earlier window is useless once V_3 is burned.
- **The G0 no longer opens any master in its own session.** A flash read gives
  K_SE, K_G0 and S, but K_PK needs the passkey PIN's session.

## 3. No NOSTR copies

Removed: K_PKN, PK_MASTER (the NOSTR copy), K_IXN, the "In NOSTR mode" gate
question and its menu item. The G0 refuses PKSIGN and VAULT outside a PASSKEY
life. In NOSTR mode:

- passkeys and password sign-ins answer "restart in VAULT mode";
- the PWA's Accounts page shows that line instead of the list;
- the app's Accounts page works in VAULT mode over Bluetooth (issue #30).

## 4. Vault backup and restore stay in NOSTR mode

The backup is the records exactly as stored (sealed); building, publishing,
fetching and merging open nothing. Only the publishing key k_pub is needed, to
sign the relay event. k_pub is derived one way from the master and signs only
backup events.

- **PUBSEAL** (PASSKEY life) gives k_pub sealed under K_G0 (32 bytes, the
  vpub IV). The ESP32 keeps it in nvs_sec until the next NOSTR life.
- **VPUB (SE, re-made)** = IV || AES(K_DAILY, sealed k_pub), written in the
  first NOSTR life after the daily PIN, inside the daily session. Policy: G0
  READ only while Door 1 is unlocked, daily PIN DELETE, RECOVER DELETE.
- **VSIGN** (NOSTR life) reads VPUB, strips the daily layer and the K_G0 layer,
  as the Nostr key is fetched.
- Rollback guard: the KEY remembers the created_at and record count of the
  last backup it published and refuses to merge an older relay copy.

## 5. Lock state on the KEY

SELFTEST v19 byte 26 = the G0's RDP level (0xAA none, 0xBB level 1, 0xCC level
2). Anything but 0xCC shows "DEV UNIT: G0 UNLOCKED" in red on the boot screen
and in Settings > Device.

## 6. Units and order

- A new secure element generation: every unit is set up again (restore from
  the words). Policies are fixed at creation.
- Flash order: the G0 (v19) first, then the ESP32.
- WIPEALL list: K_PK, PK_MASTER_P, VPUB, then the latch; K_PKN, PK_MASTER and
  K_IXN are gone from new generations and are still deleted if found.

## 7. Tests

- G0 host: PKM_IN refused outside PASSKEY, with a bad tag, or with the latch
  not at V_3; accepted at V_3; the master equals the PKMASTER input; PKSIGN and
  VAULT never touch K_PK or PK_MASTER_P in their own session; VSIGN reads VPUB
  under the daily layer.
- On the bench: a passkey sign-in and a password typing in VAULT mode; both
  refused in NOSTR mode; a backup published and restored in NOSTR mode.

## 8. As built (drop 11bd, G0 v19)

- **G0:** `pk_glue.inc` (PKM_IN, the tag, the V_3 check), `main.c` (register
  0x25, PKSIGN and VAULT in a PASSKEY life only, SELFTEST v19 of 27 bytes),
  `vault_glue.inc` (IMPORT in a PASSKEY life only), `vpub_glue.inc` (VPUB under
  the daily wrap). Host tests: pk 63/63, vault 125/125, doors, both fuzzers.
- **ESP32, `g0_signer.cpp`:** PKMASTER read as 64 bytes; `g0_pkm_set` and
  `g0_pkm_clear`; PKM_IN written after the reset and before every PKSIGN and
  VAULT (only to a v19 G0); `g0_doorpin_present` and `g0_rdp_level`.
- **ESP32, `passkey_door.inc`:** K_PK made with no G0 entry; the 80-byte
  PASSKEY copy (two chained one-shots, which is CBC over 64 bytes);
  `se_pk_master_read`; `se_vpub_write` through the daily session. K_PKN,
  K_IXN and the NOSTR copy are no longer made; `se_pk_old_generation` finds a
  KEY set up before v19.
- **ESP32, `passkey_life.inc`:** the window's open hook reads the copy and
  hands it to the G0, the close hook clears it first; first login writes the
  PASSKEY copy only, with no question; `vpubEnsure` keeps the sealed k_pub
  ("vseal" in nvs_sec); the "In NOSTR mode" row is gone; a KEY set up before
  v19 shows "Set up again" in red.
- **ESP32, `main.cpp`:** onboarding keeps 64 bytes and makes K_PK only, with a
  v19 G0; the NOSTR life writes VPUB from "vseal" once per unlock (or on the
  first backup); NOSTR Settings > Device > Passkeys offers the backup and says
  where the passkeys are; the rollback guard (status 19); the readout lock in
  the boot log, "DEV UNIT: G0 UNLOCKED" in red on the boot screen and as the
  header of Settings > Device.
- **PWA:** the refusal line reads "Passwords and passkeys open only in VAULT
  mode. Restart the KEY, choose VAULT and enter the passkey PIN."
- **Not done here:** the app's door-aware screens and its Accounts page in a
  NOSTR life (an app issue); the Emberwill outputs check.
- A G0 older than v19 reports no lock (byte 26 absent): no banner, and the
  boot log says "not reported".
