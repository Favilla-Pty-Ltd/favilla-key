# Known issues and accepted gaps

For developers and auditors. Each entry says what the gap is, why it is there,
how it is bounded, and what would close it. Drop names (11an etc.) are the
`[BUILD]` line the KEY prints at boot. Started 12 Nov 2026.

## Signing

### Hash-only signing trusts the client's description of the event
`/api/sign-hash` (PWA; the code comments call it /api/sig) and `sign_event_hash` (NIP-46) hand the KEY a 32-byte id and
the kind, tag count and a preview as the client states them. The KEY signs
the hash; it cannot check the claims. Since 11an the approval screen says so
("Hash only", "The phone sent only the hash of this event, so the KEY cannot
read what it says") instead of presenting the claims as the event, and the
screen no longer shows the previous event's body. The remaining gap: the
auto-approve decision uses the claimed kind, so a client allowed to auto-sign
kind 1 can present a kind 3 hash as kind 1. Bounded by: only a paired,
authenticated client can reach either path; the user chose the auto-approve
kinds. Would close it: parse large events on the KEY (needs more than the
16 KB `/api/sign` staging; kind 3 lists run to 170 KB) or refuse auto-approve
on hash-only requests. Full-event signing (`/api/sign`, `sign_event`) is not
affected: since 11an the KEY computes the id itself and refuses a `pre_id`
that does not match (`src/nostr_canon.h`, `tests/event_id_test.cpp`).

### Events the KEY will not sign
`/api/sign` answers 400 for an event whose id cannot be computed the way
clients compute it: a non-integer `created_at` or `kind`, a float or object
inside `tags`, nesting deeper than 8, a NUL (`\u0000`) in a string, a lone
UTF-16 surrogate. No client is known to produce any of these.

## Signer (G0)
- Signing takes about 1.4 s: two round trips to the isolated signer (init and
  finish, about 550 ms each) plus the host's check and verify. libsecp256k1 is
  pinned at ECMULT_WINDOW_SIZE 2, COMB_BLOCKS 2, COMB_TEETH 5 to fit the 120 KB
  image (118 KB used). Faster tables are parked until after the audit.
- Conversation keys (ECDH) are cached per session (11al, up to 16 peers plus
  the bunker allow list) and cleared on PIN forget, sleep, wipe and bunker
  stop. The first message to a peer still pays the signer round trip.

## Messaging
- NIP-17 messages have no forward secrecy by design of the NIP; the KEY adds
  none.

## Wi-Fi route
- Internal RAM headroom is tight when the web server and TLS are both up
  (about 42 KB free after the camera reserve is released; a DM burst dipped to
  2.8 KB once and an allocation failed, 11am bench). The Bluetooth route has
  more room. Watch `[ALLOC] FAILED` in the log.

## Backup and restore
- A backup made with a passkey-protected record set (VBR_PASS) cannot be
  restored without the original passkey; the restore screen stops without a
  prompt to supply it.

## Build
- `favilla_key_fido_release` (the ship environment, everything on, bench
  console off) is in CI but has not yet been built on a bench.
