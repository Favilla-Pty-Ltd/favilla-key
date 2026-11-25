# The Favilla app over Bluetooth: the KEY side (firmware drops 9a to 9j)

This is the interface the iPhone app's AutoFill extension uses to sign in with
passkeys and passwords held by the Favilla KEY. Passkeys use the FIDO framing
below; passwords use the sign-in request and answer (section "Passwords").
For passkeys: It is the FIDO Bluetooth transport from
CTAP 2.1 (section 11.4), served on the Favilla service so iOS apps can reach it.
The request and response bodies are plain CTAP2 CBOR.

## When the KEY answers

Naming (KEY 11n, 9 Nov 2026): the PASSKEY door, life and mode are now called
**VAULT** on the KEY's screen (SELECT MODE card, VAULT PIN, VAULT menu), since the
door holds passkeys, passwords and one-time codes. Nothing on the wire changed:
the door number, lives, UUIDs and bytes below are the same, and this document
keeps "PASSKEY life" as the technical name. The app should say Vault where it
names the mode to the user.

- Only in a PASSKEY life with the Bluetooth setting on, after the PIN.
- Only to a phone the owner confirmed in PAIR A PHONE (numeric comparison,
  LE Secure Connections, bonded). Any other link is refused at the write
  (ATT error 0x05, insufficient authentication).
- The KEY's Bluetooth setting has three states (from 9c): Off, **App only**,
  and **App and keyboard**.
  - **App only** (the setting for the iPhone app): the KEY offers no keyboard
    service, so iOS never takes over the phone's keyboard. The KEY advertises
    the whole PASSKEY life, with the Favilla service UUID `8F1A0001-...` in
    the advertisement, and never drops a link itself. Scan for that service
    UUID, or reconnect by the saved peripheral identifier. Because there is
    no keyboard service, the KEY does not appear in iOS Settings > Bluetooth:
    pairing is started by the app (see "Pairing").
  - **App and keyboard** (as before 9c): the KEY is also a Bluetooth keyboard.
    It does not advertise at rest; it advertises for 15 s after a press of
    Home (and while PAIR A PHONE is open). Subscribing to the FIDO status or
    the sign-in answer, and every control point write, hold the link for
    35 s; a FILL request holds it 120 s; 10 s after a reply it is let go.
    Otherwise it drops an idle link after about 3 s, to give the phone its
    keyboard back.

## GATT

Favilla service `8F1A0001-6B2E-4C8D-9A3E-5F7C2D1E0B4A`:

| Characteristic | UUID | Properties |
|---|---|---|
| Probe (8y) | `8F1A0002-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | read, encrypted |
| Sign-in request (8z7) | `8F1A0003-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | write, encrypted |
| **Sign-in answer (9c)** | `8F1A0004-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | notify |
| **App channel in (9g)** | `8F1A0005-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | write with or without response (11ad), encrypted; whole 64-byte reports, up to 8 per write |
| **App channel out (9g)** | `8F1A0006-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | notify |
| **FIDO control point** | `8F1A0010-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | write with response, encrypted |
| **FIDO status** | `8F1A0011-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | notify |
| **FIDO control point length** | `8F1A0012-6B2E-4C8D-9A3E-5F7C2D1E0B4A` | read, encrypted; 2 bytes big-endian |

The same three are also on the standard FIDO service `0xFFFD`
(`F1D0FFF1/2/3-DEB4-4A6A-9D4D-D97DA6E2A6E9`, plus the service revision
bitfield `F1D0FFF4`, which reads `0x20`, FIDO2 only). iOS may hide `0xFFFD`
from apps; the app should use the Favilla UUIDs above.

The attribute table changes with the setting (9g: layout 7 with the keyboard,
8 without; 9c was 5 and 6, 9a was 4, 8z7 was 3). The KEY sends Service Changed when it changes.
If the app still sees an old table, forget the KEY in iOS and pair again.

## Notes from the app (6 Nov 2026)

- Passkey registrations are handed to iOS with a "none" attestation and an
  empty attStmt, not the KEY's "packed": on the bench iOS refused "packed"
  although every field checked out.
- The app scans for both the Favilla service `8F1A0001` and the keyboard
  service `1812`, so it finds the KEY in either Bluetooth mode.
- Pairing from the app: read `8F1A0002` with PAIR A PHONE open; while iOS shows
  the 6-digit prompt the read is refused (insufficient authentication), so the
  app keeps the link and retries every 2 s for up to 60 s.

## Pairing

The KEY serves only a phone confirmed in PAIR A PHONE. With the keyboard on,
the phone can pair from iOS Settings > Bluetooth. With **App only**, it does
not show there, so the app pairs it: open PAIR A PHONE on the KEY, then
connect from the app and read the probe `8F1A0002` (encrypted). iOS shows its
pairing prompt with 6 digits; the owner checks they match the KEY's screen and
presses ENTER on the KEY.

## Passwords (9c)

1. Subscribe to notifications on the sign-in answer `8F1A0004`.
2. Write the request to `8F1A0003`: `[0x34 FILL][site length][site][user length][user]` (11aw: a trailing `fields` byte 0, 1 or 2 is accepted after `user`, as the browser extension sends for two-page sign-ins; the app need not send it, and the KEY ignores it on FILL)
   (the site iOS gave the extension, up to 100 bytes of printable text: a
   domain, or an app's name such as "My Bank"). The username is optional
   (length 0); from 9d, when it is given and exactly one saved login for the
   site has that username, the KEY opens that entry straight away. The write
   succeeds when the ask is on the KEY, or fails with ATT error `0x80 + status`
   (`0x85` locked, `0x86` busy, `0x87` bad request, `0x84` not in a PASSKEY
   life, `0x88` not a confirmed phone). `0x31` (8z7) still asks the KEY to type
   the login instead, which needs the keyboard.
3. The KEY shows the matching logins; the owner picks one and presses ENTER.
   - **No match (9d):** the KEY shows "No saved login, Pick one of your
     logins?". ENTER shows every login; the one picked is sent as usual, and
     the KEY then offers to save the asked name on that entry so it matches
     next time. BACK answers `[0x03]`. 11bi: DOWN makes a new login instead
     (see "New passwords from iPhone AutoFill").
   - **New login or new password (11bi):** the last row of the matches is
     NEW LOGIN FOR <site>, and UP on a login opens NEW PASSWORD (or NEW LOGIN).
     The KEY makes the password, saves it, and answers with it as below.
   - **Page two within 60 s (9d):** if this same phone (its bond, not the
     link, so a reconnect between pages still counts) was sent a login in the
     last 60 s and asks again for the same site, the KEY shows "Send again?"
     with the site and username: ENTER sends it, BACK shows the normal list.
     Never without a press; forgotten on lock, restart, once used, after 60 s.
4. The answer arrives on `8F1A0004` in the same framing as the FIDO replies,
   command byte `0x84`: first notification `[0x84][len hi][len lo][body...]`,
   then `[seq][body...]` if it does not fit. Body:
   - `[0x00][user length][username][password length][password]`: the login.
     Hand it to iOS as `ASPasswordCredential(user:password:)` and wipe it.
   - `[0x03]` no saved login for the site, `[0x02]` cancelled on the KEY or
     timed out, `[0x05]` the KEY is locked.
5. The answer goes only to the link the request came on. An ask not taken on
   the KEY within 30 s is dropped and answered `[0x02]`.

## The app channel (9g)

Ruled 7 Nov 2026: the Bluetooth link is locked to the Favilla app. On an
iPhone the bond belongs to the phone, so without this any app on the phone
could send a FILL or CTAP request and read the answer.

**Once one app install is paired, the KEY refuses the raw paths**: writes to
`8F1A0003` and `8F1A0010` (and the `0xFFFD` control point) fail with ATT error
`0x8F` ("an app is paired, use the app channel"). Until an app is paired the raw
paths work as before, so app 1.2.0 keeps working until the owner pairs.
**Settings > Bluetooth > Forget phones** forgets the paired apps as well.

### Bytes on the air

The messages are those of the USB channel (`src/chan_proto.h`), in 64-byte reports:

- start report: `[0x10][len lo][len hi][first 61 bytes]`
- next reports: `[0x11][index 1, 2, ..][next 62 bytes]`
- zero padding to 64 bytes. A message is at most 1088 bytes.

A write to `8F1A0005` carries one or more whole reports (64, 128, ... up to 512
bytes; the link MTU must be at least 67). A notification on `8F1A0006` carries
one or more whole reports too: split its value every 64 bytes. Subscribe to
`8F1A0006` before the first write. A message left half-sent for 3 s is
dropped. One request at a time; a second one before the first is taken fails
the write with ATT `0x86` (busy).

Little-endian throughout this section (the counter, the report length).
`H(k, x)` is HMAC-SHA256.

### Pairing

Only while **PAIR A PHONE** is open on the KEY, one attempt per window. If the
phone is not paired yet, the Bluetooth pairing (the iOS prompt) comes first, as
in "Pairing" above; the KEY then waits a further 60 s for the app.

1. App: make a P-256 key pair (`extPub`, 65 bytes uncompressed) and 16 random
   bytes `nonce`. Send `[0x20][C]`, `C = H("FAVILLA-COMMIT-1", extPub || nonce)`.
2. KEY: `[0xA0][keyPub 65][clientId 8]`.
3. App: `[0x22][extPub 65][nonce 16]`.
4. Both: `Z` = ECDH x coordinate (32 bytes), `PRK = H("FAVILLA-CHAN-1", Z)`,
   `K = H(PRK, "key" || extPub || keyPub || 0x01)`,
   `code = BE32(H(PRK, "code" || extPub || keyPub || 0x01)[0..3]) mod 1000000`.
   The app shows `code` as `123 456`. The KEY shows the same number under
   "PAIR THE APP"; the owner presses ENTER if they match.
5. KEY: `[0xA1][clientId 8][ctr 0, 4 bytes][status][mac16]`, status `0x00`
   paired, `0x0B` refused on the KEY, `0x0C` full (4 apps), `0x0E` could not
   store. The mac is as for every answer below.

Errors before a key exists come as `[0xBF][cmd][status]` with no mac:
`0x0A` no window open, `0x06` busy (an attempt is already used in this
window), `0x07` bad request.

Keep `K` and `clientId` in the iOS Keychain (this device only). Start the
counter at 1.

11ah (issue #22): the KEY accepts a REVEAL without the code screen when its
camera has read `favilla:pair?v=1&p=<extPub 65 bytes hex>&n=<nonce 16 bytes
hex>` with the same values (the KEY got the phone's key through its own
camera). The channel side is built and host-tested (`chan_key.h`,
`app_pair_qr.h`); the scan is not wired into PAIR A PHONE yet, because a
camera start in a Bluetooth life stops Bluetooth for the scan (RAM), which
drops the link mid-pairing. Until that is decided the code screen is the
way. Also 11ah: a WIPE forgets the Bluetooth bonds and the paired app
installs (as Forget phones does), so after a wipe every request is refused
`0xBF [cmd][0x0A]` until PAIR A PHONE is run again; the app shows that one
instruction. When the `pair id` in HELLO changes, the app clears the Nostr
client's `kv_device_pub`, `kv_session`, `kv_phone_id` and `kv_pair_eph`
before the client's first session.

### Requests and answers

Request: `[cmd][clientId 8][ctr 4][body][mac16]`,
`mac16 = H(K, "REQ" || everything before it)[0..15]`. `ctr` must be greater
than the last one the KEY accepted from this app.

Answer: `[rsp][clientId 8][ctr 4][body][mac16]`, `ctr` echoes the request,
`mac16 = H(K, "RSP" || everything before it)[0..15]`. Check the mac before
using any answer.

Encrypted bodies (marked **enc**) are XORed with a keystream before the mac:
`Ke = H(K, "FAVILLA-CHAN-ENC-1")`, block `i` = `H(Ke, rsp || clientId || ctr || i)`
(one byte `i`, from 0), 32 bytes each, as many as the body needs. The same
XOR decrypts. 11ad (11 Nov 2026, issue #9): from block 255 the index is
`0xFF || i u16 LE` (three bytes) instead of one byte, so an encrypted body
can be as long as its length field allows; blocks 0 to 254 are unchanged,
so every answer up to 8160 bytes is byte for byte what it was. Before 11ad
an R_API answer over 8160 bytes was not sent at all and the app timed out;
the KEY now answers `0xBF [0x3A][0x06 busy]` whenever an answer cannot go.

| Request | Body | Answers |
|---|---|---|
| `0x30` HELLO | none | `0xB0` `[status][life][drop name 8][pair id 8]` (11ah: `pair id` = the first 8 bytes of `dev_pair_pub`, the key the PWA pins; an app reading 10 bytes is unaffected) |
| `0x34` FILL | `[sLen][site][uLen][user]` (as on `8F1A0003`) | `0xB1` `[status]` at once, then `0xB3` **enc** `[status][uLen][user][pLen][password]` |
| `0x35` CTAP | a CTAP2 request: `[command][CBOR]`, up to 1024 bytes | `0xB5` `[0x01 or 0x02]` keepalives, then `0xB4` **enc** `[CTAP status][CBOR]` |
| `0x36` CANCEL | none | none (the CTAP request answers `0x2D`) |
| `0x3A` API (9k) | one HTTP call, see "NOSTR over Bluetooth" below | `0xB8` **enc** |
| `0x39` TIME (9j) | `[unix time 8, big endian]` | `0xB1` `[0x00]` set (or already right), `[0x07]` not a time between 2023 and 2100 |
| `0x38` OTP (9i) | `[sLen][site][unix time 8, big endian]` | `0xB7` **enc**, see "One-time codes" below |
| `0x37` LIST (9h) | `[start hi][start lo]`, the first entry wanted (0 first) | `0xB6` **enc**, see "LIST" below |
| `0x3B` NIP46 (10p) | one kind-24133 event, see "The Bluetooth bunker" below | `0xB9`, macced, not encrypted |
| `0x3C` NIP46_POLL (10p) | none | `0xB9`, macced, not encrypted |
| `0x3D` BUNKER_INFO (10p) | none | `0xBA`, macced, not encrypted |
| `0x3E` NUDGE_SET (11i) | `[seconds 1]`, 0 = off, at most 60 | `0xB1` `[0x00]`; then `0xBB` nudges, see below |
| `0x50` CIPHER_DAY (11bt) | the text `favillakey.io/api/cipher/day` answered, 1 to 199 bytes | `0xB1` `[status][height u32 LE]`, see "CIPHER's daily block" below |

- `0xB1 [status]`: `0x00` on the KEY's screen; `0x05` locked, `0x06` busy,
  `0x07` bad request.
- `0xB3` body as the raw FILL answer: `[0x00][uLen][user][pLen][password]`
  the login; `[0x03]` no saved login; `[0x02]` cancelled or timed out;
  `[0x05]` locked. The 9d behaviour (username, "Send again?", "Pick one?")
  is the same.
- `0xB4`: exactly the bytes the raw path sends in its `0x83` MSG.
- `0xB5`: `0x01` processing, `0x02` waiting for a press on the KEY.
- `0xBF` with a mac: `[0x09][floor 4]` replay (set your counter above the
  floor and resend), `[0x0E]` could not store the counter, `[0x06]` busy,
  `[0x07]` bad request.
- `0xBF` without a mac, `[0xBF][cmd][status]`: `0x08` not paired (unknown
  client or a wrong mac). Forget the stored key and pair again.

### LIST (9h)

For the iPhone's opt-in account list (`ASCredentialIdentityStore`).

- 11cg (22 Nov 2026, ruled by the owner): no question on the KEY. With the
  VAULT PIN entered, every page is answered at once; the KEY shows "Sharing
  list" with the count rising and returns to its home screen by itself. It
  answers from its home screen (an ask made while the owner is in a menu
  waits there, as before). The app should not tell the user to press ENTER.
- An ask not answered in 30 s (the owner was in a menu throughout) gets `[0x02]`.

`0xB6` body, decrypted:

- `[0x02]` timed out, `[0x05]` locked (no VAULT PIN).
- Otherwise `[0x00][total hi][total lo][count]`, then `count` entries, then
  `[more]` (1: ask again from `start + count`). The body is at most 1024 bytes.
- Password entry: `[0x00][sLen][site][uLen][username]`.
- 11s: a request with a third byte, `[start hi][start lo][flags]`, flags bit0,
  gets password entries as `[0x02][sLen][site][uLen][username][health][id 8]`
  instead. `health` is the KEY's health byte (bits 0-1 strength 0 unknown / 1
  weak / 2 fair / 3 strong; bits 2-3 origin 0 unknown / 1 made on this KEY /
  2 the owner's own / 3 imported; bit 4 reused; bit 5 seen in a breach; bit 6
  breach check done; bit 7 a one-time code is linked to this entry, 11v).
  `id` is what `SHOW` takes.
- Passkey entry: `[0x01][sLen][site][uLen][account name][0x22][credential id 34][hLen][user handle]`.
  Only passkeys with a record on the KEY are listed: the ones made as
  "sign in without a username" (discoverable). A passkey made with a username
  (the site sends its credential id at sign-in, as dash.cloudflare.com does)
  has no record on the KEY, so the KEY cannot list it.

Order: passwords newest first, then passkeys. A password whose name the KEY has
not read yet (in the first seconds after the PIN, while it reads the labels)
is left out and not counted; ask again a little later for the full list.
The first LIST after the PIN opens each passkey record once (one of the
sitting's record opens each); they stay cached until the KEY locks.

### One-time codes (9i, G0 v17)

Ruled 6 Nov 2026 (B): the shared secret never leaves the G0. The KEY holds
codes added on the KEY (PASSKEY > Codes > ADD BY QR, the site's setup QR). The
G0 computes each code and gives the ESP32 only the digits.

- Request `0x38`: `[sLen][site][time]`. `site` is the domain or app name iOS
  gave the extension (as for FILL); `time` is the phone's Unix time in seconds.
- The KEY shows the codes whose name matches the site ("GitHub" matches
  `github.com` and `www.github.com`; case and spaces are ignored). If none
  match it shows all of them: "None saved for <site>. Pick one?". The owner
  picks and presses ENTER, even when only one matches.
- `0xB7` body, decrypted: `[0x00][n][n ASCII digits]`, the code; or `[0x02]`
  refused or timed out (30 s), `[0x03]` no code saved, `[0x05]` locked.
- Hand it to iOS as `ASOneTimeCodeCredential` (iOS 18 and later).
- **Send TIME (`0x39`) after every connect, before anything else.** The KEY has
  no clock of its own in a PASSKEY life (it starts there only after a battery
  pull), so the app is its clock: the codes on the KEY's own screen need it.
  The KEY sets its clock when it does not know the time or is more than 2 s out.
  An OTP request's time also sets it when the KEY does not know the time.
- The KEY also reads the iPhone's standard Current Time Service (`0x1805`:
  `0x2A0F` then `0x2A2B`) on every secure connect, at most every 10 minutes,
  so it knows the time before the app is paired. iOS serves it to bonded
  accessories; the app does nothing for it.
- Each code uses one of the sitting's 32 record opens (refilled by the PIN on
  the KEY). Within one power-on the G0 refuses a time more than 60 s before or
  1200 s after the last code it gave.
- Only TOTP with SHA1, 6 to 8 digits; the QR reader refuses HOTP and SHA256.

11v (11 Nov 2026): a code is linked to a password entry. When a code is added
on the KEY it picks the entry from the setup QR's issuer and account label
(username match, site match) and asks "This account?"; the code is then saved
under the entry's own site and username, and the link is kept on the KEY
(Codes > a code > UP links or unlinks it later). What the app sees:
- LIST v2 health bit 7 set on an entry that has a code (show a 2FA badge, and
  a "Get code" action that sends `0x38` with that entry's site).
- An OTP request within 60 s of a FILL the KEY answered, for an entry that
  has a linked code, shows that one code alone: a two-step sign-in is one
  press for the password and one for the code. Otherwise codes whose linked
  entry is on the asked site come first, then the label match, then all.
- Nothing new on the air; the G0 is unchanged.

11aa (11 Nov 2026): a site's recovery codes (the one-time backup strings handed
out when two-step is turned on) live on the KEY as a kind-4 record found by the
entry's site tag, shown one at a time on the KEY (PASSWORD, UP, UP). They get
onto the KEY by a QR the phone draws, `favilla:recovery?v=1&s=<site>&u=<user>
&c=<code>,<code>,...` (percent-encoded; 1 to 16 codes of 1 to 24 printable
characters), scanned from that page (ENTER TO ADD BY QR), or over Wi-Fi from
the PWA (`POST /api/vault/recovery {slot, id, codes[]}`, one hold on the KEY).
Nothing on the app channel yet; the app can draw the QR as #18 does for setup keys.

11ac (issue #16): one-time code secrets from another manager's export go in
over Wi-Fi inside the import window the PIN opened, one per call, no press
(11bf: from G0 v19 this route is refused; codes go in with IMPORT_ITEM kind
`0x02` in VAULT mode, see "Import in VAULT mode"):
`POST /api/vault/otp/save {site, acct, secret, digits, period, algo}` (secret
base32; SHA1 only; digits 6 to 8; period 1 to 255; `409 window` outside the
window, `409 g0` without G0 v17, `400 secret|algo|digits|period|size`). Saved
under `site`, so the password entry with that exact site links to it.

### Checking it

`tests/app_pair_vector.py` works the pairing through with fixed keys (every
message, `Z`, `K`, the code `465 988`, the first HELLO); `host/app_pair_check.cpp`
checks the KEY's own derivation gives the same.
`tests/app_chan_vector.py` prints a FILL request as reports and an encrypted
login answer for a fixed key, to check the app's bytes against.
`host/chan_enc_test.cpp` and `tests/chan_enc_vector.py` hold a known answer for
the keystream; the pairing and mac rules are tested in the USB channel's tests
(the same code).

## NOSTR over Bluetooth (9k, issue #7)

The iPhone app runs the KEY's own PWA (`src/pwa.html`, unchanged) in a web view
and sends each of its `fetch("/api/...")` calls to the KEY as one API request
on the app channel. Relays, media, NIP-05 and zaps use the phone's internet.

### The life

- One NOSTR door (9p, 8 Nov 2026; until 9o Select Mode had a separate
  NOSTR BT door). **Settings > Network > Change mode** offers **Bluetooth**
  after Auto, Network, Hotspot and Offline, when the KEY's Bluetooth setting
  is not Off. Choosing it restarts the KEY into the NOSTR Bluetooth life; any
  Wi-Fi mode chosen there restarts it back. The choice lasts (NVS `sys/nbt`)
  until it is changed, and the NOSTR card on Select Mode reads "Over
  Bluetooth" while it is on. It is a NOSTR life: the NOSTR PIN, and the G0
  holds the NOSTR door. Wi-Fi never starts in that boot (the driver is
  refused, as in the air-gap life). The footer shows the Bluetooth glyph,
  brass while a confirmed phone is connected.
- Bluetooth: the Favilla service `8F1A0001` is advertised for the whole life,
  with no keyboard service. The same bond and the same app pairing (NVS
  `vapp`) as the PASSKEY life: a phone and app paired once work in both.
  Pair from **Settings > Network > Pair a phone** in this life, or from
  PAIR A PHONE in the PASSKEY life.
- HELLO `0x30` answers life `0x03` (`L_NOSTR`), before and after the PIN.
- In this life only pairing, HELLO, TIME, API, NIP46, NIP46_POLL,
  BUNKER_INFO, NUDGE_SET, the vault requests and CIPHER_DAY (11bt) are served. FILL, CTAP,
  CANCEL, LIST and OTP answer `0xBF [0x04]` (not here), and the raw
  `8F1A0003` and `8F1A0010` writes fail with ATT `0x84`. In the PASSKEY life
  API answers `0xBF [0x04]`. There is no Bluetooth in a BITCOIN life.

### API `0x3A`

Request body (inside `[0x3A][clientId 8][ctr 4][body][mac16]`), u16 values
little-endian:

```
[method 1]                 0x01 GET, 0x02 POST
[path len u16][path]       printable ASCII, starts "/api/", with its query, at most 2048
[header count 1]
  per header [id 1][len u16][value]   at most 1024 each
     0x01 X-Favilla-Session   0x02 X-Favilla-Auth   0x03 X-Favilla-Ctr
[body len u16][body]       the exact body the PWA would POST, at most 32768
```

Answer `0xB8` R_API, **enc** (encBody, as `0xB4`), echoing the counter:

```
[status u16]               the HTTP status the handler sent
[content type 1]           0x00 none, 0x01 application/json, 0x02 text/plain
[body len u16][body]       the exact response body, at most 32768
```

Example (the app's test vector): `POST /api/sign`, X-Favilla-Session "ab",
X-Favilla-Ctr "7", body `{}`:
`02 0900 2f6170692f7369676e 02 01 0200 6162 03 0100 37 0200 7b7d`.
Answer 200, JSON, `{}`: `c800 01 0200 7b7d`.

- The request runs through the same `/api` handlers as over Wi-Fi (the same
  route table, the same FSEC checks inside). Headers the handlers add (CORS,
  caching) are not sent.
- `/api/balance` and `POST /api/relays` answer **409**
  `{"error":"no_network"}`. 10p: `/api/bunker-url`, `/api/bunker/mint`,
  `/api/bunker/pairings` and `/api/bunker/revoke` answer as over Wi-Fi, with
  `"active":true` after the NOSTR PIN (the bunker runs through the phone), and
  the links carry the relays BUNKER_INFO lists. A path with no handler answers 404 as over HTTP.
- Before the NOSTR PIN, or after the KEY locks, the request answers
  `0xBF [0x05]` (locked, with a mac), except `GET /api/link` (11by, issue
  #25): it answers as over Wi-Fi, `{"ok":true,"unlocked":false,...}`, so the
  page's lock probe sees the lock and drops its DMs at once.
- One request at a time: the app waits for the answer before the next. A
  second request sent before the first is taken fails its write with ATT
  `0x86` (busy). The handlers answer at once; anything waiting on a press is
  polled by the PWA as over Wi-Fi.
- **The PWA's own pairing (9l, issue #8).** In this life a tunnelled
  `POST /api/session` for a `phone_pub` the KEY does not know is answered as a
  trusted reconnect (no `need_pair`, no FK1 QR, no `sas`): the app client it
  came through was confirmed on the KEY with its 6-digit code. The phone is
  enrolled when its first sealed request opens (proving it holds
  `phone_pub`'s key), recorded against that app client; Forget phones (which
  forgets the app clients) and WIPE forget it too. Confirm-on-reconnect, if
  the owner turned it on, still asks for the press. Over Wi-Fi nothing
  changes: an unknown `phone_pub` still gets 403 `need_pair`.
- Messages this long cross many reports: the `0x11` report index counts up
  from 1 and wraps from 255 to 0. A write carries up to 8 reports
  (512 bytes); at an iOS link's usual speed 32 KB takes about a second.

### The Bluetooth bunker (10p, issue #11)

The KEY's own NIP-46 bunker, with the phone as its internet. Everything
NIP-46 stays on the KEY: decrypt, per-app pairing, rate limits, signing
modes, the approval screen and press, and the reply event. Only the transport
changes: the phone brings each request in and publishes each reply.

Served in the NOSTR Bluetooth life only, after the NOSTR PIN:
- Before the PIN (or after the KEY locks): `0xBF [0x05]` S_LOCKED, with a mac.
- In any other life: `0xBF [0x04]` S_NOT_HERE, with a mac.

**`0x3B` NIP46**, app to KEY. Body: one kind-24133 event, the event object
only (UTF-8 JSON, starts `{`), at most 32768 bytes.
- The KEY runs it exactly as a `["EVENT",<sub>,<event>]` from a relay socket,
  event-id dedup included.
- The answer comes at once (KEY 11m and later): `0xB9 [0x01][0x00]`, taken,
  more to come, no replies. Replies travel only in the answer to a `0x3C` poll.
  Poll about 1 s after the request and again while bit0 stays set; one
  request takes the KEY about 3 s at 240 MHz, up to 9 s when it was idle.
  (Up to 11l the request answer waited up to 4 s and carried the reply when
  signing finished in time; the app must still parse `0xB9` the same way for
  both commands, since the format is one format.)
- `0xBF [0x06]` S_BUSY, request not taken: an approval is already on the KEY's
  screen, or 8 requests are queued. Keep it and send it again later.
- `0xBF [0x07]` S_BAD_REQUEST: empty, over 32768 bytes, or not an object.
- A request the KEY drops on purpose gets no reply event, as on a relay:
  a client it never paired, a throttled health check, a duplicate, a stale
  event (over 10 minutes old). The poll then simply never carries a reply for it.

**`0x3C` NIP46_POLL**, app to KEY. Empty body. The replies ready since.

**`0xB9` R_NIP46**, the answer to both, echoing the counter. Macced, **not
encrypted**: each reply is already NIP-44 to its client and is about to go to
a public relay.

```
[flags 1]   bit0 = more to come: a request not yet run, an encrypt/decrypt
            job running, an approval on the KEY's screen, or replies that did
            not fit this answer
[count 1]   replies in this answer (0 allowed)
per reply:  [len u16 LE][the relay message: ["EVENT",{...}], ready to publish]
```

- Oldest first, as many as fit one message (40,960 bytes in all).
- 11o (10 Nov 2026): the outbox is not only NIP-46 replies. A CIPHER score
  shared in the NOSTR Bluetooth life puts two signed events in it, a kind-1888
  run record and a kind-1 note, and the KEY sends one `0xBB` nudge at once
  (and again every 5 s for 20 s). The app publishes every relay message a poll
  returns, whatever its kind, to the `BUNKER_INFO` relays, and should poll on
  any `0xBB` even with bunker mode off. The KEY shows ON PHONE once the poll
  has taken both; it never sees the relay OK on this path.
- While bit0 is set, poll every 500 ms. A press comes back on the next poll.
- The KEY keeps up to 8 replies, each until an answer has carried it, or for
  60 s. On overflow the oldest goes (logged on the KEY). An answer whose
  write fails keeps its replies for the next one.
- A reply over 32768 bytes is not sent; the client gets a NIP-46 error
  `too large for Bluetooth` instead.

**`0x3D` BUNKER_INFO**, app to KEY. Empty body. Answer **`0xBA`**, macced,
not encrypted:

```
[pubkey 32]                the KEY's Nostr key: listen for kind 24133 #p this
[relay count 1]
per relay: [len 1][host]   no scheme ("relay.damus.io"), as in the bunker:// link
```

The relays are the enabled ones, at most 4, the same `relayQueryParams()`
puts in every `bunker://` link (relay.favillakey.io if none is enabled).

**The KEY wakes the app (11i, path B).** iOS keeps an app that holds a
Bluetooth link registered in the background and wakes it for a few seconds
whenever the connected device sends it something. So instead of a push:

- The app keeps the link up (its `bluetooth-central` background mode and
  state restoration) and sends **`0x3E` NUDGE_SET** `[seconds]` after each
  connect. 0 turns nudges off; at most 60. Answer `0xB1 [0x00]`. The setting
  is per connection: it is forgotten when the link drops.
- Every `seconds`, while the NOSTR PIN is in and the app channel is
  subscribed, the KEY sends **`0xBB` R_NUDGE**, unsolicited, macced, counter
  0, to the client that last spoke on this connection:
  `[seq u32 LE][replies waiting in the KEY's outbox 1][vault asks 1]` (the
  third byte since 11q: bit0 "back up the vault now", bit1 "restore the
  vault now"; see "The vault through the phone"; 11bt: bit2 "send me
  today's CIPHER block", see "CIPHER's daily block"). 11bx (issue #25): a
  seventh byte, the lock state: bit0 the NOSTR PIN is in now, bit1 the lock
  state changed since the last nudge sent. A 5- or 6-byte nudge (older KEYs)
  carries no lock byte.
- **Lock changes (11bx).** When the NOSTR PIN goes in, or the KEY locks
  (lock, sleep, timeout), and NUDGE_SET is on, the KEY sends one nudge at
  once with bit1 set, whatever the interval, and also while locked. The app
  runs the page's `GET /api/link` probe at once, which drops the page's DMs
  on a lock. `/api/link` stays the source of truth; the nudge only says
  "look now".
- On a nudge the app (woken by iOS if it was in the background) asks the
  bridge for waiting requests and hands them over with `0x3B` on the link it
  already holds; if the second byte is non-zero it polls `0x3C` first to
  collect replies already built. The push path stays as the fallback for an
  app that is not connected.
- Periodic nudges are not sent before the NOSTR PIN, nor while the channel is
  unsubscribed, nor to a client that has not yet sent a request on this
  connection. The lock-change nudge (11bx) is the one sent while locked. NUDGE_SET itself is accepted before the PIN.

Worked example: `tests/app_chan_vector.py` (key `00 01 .. 1f`, client
`0102030405060708`) prints a NIP46 request, its `0xB9` answer with one reply,
a poll, an empty answer with bit0 set, BUNKER_INFO and its `0xBA`, and an
S_LOCKED refusal. The event and reply in it are placeholders: the vector
checks the framing, not NIP-46.

### CIPHER's daily block (11bt, 19 Nov 2026, issue #39)

CIPHER's DAILY board is seeded by the first block of each 144-block Bitcoin
day. Over Wi-Fi the KEY fetches it itself. In the NOSTR Bluetooth life the
app fetches it and hands it over. The app is only a courier: the KEY checks
the block itself, exactly as a Wi-Fi fetch or a scanned `FCD1:` QR.

**The source.** `GET https://favillakey.io/api/cipher/day`, answer 200 with
`text/plain`: `<height>,<160 hex>` (the decimal height, a comma, the 80-byte
block header as hex). The app sends that body unchanged, with no trailing
newline needed (whitespace around it is accepted). Any other status: send
nothing.

**When the app sends it.**
- Once after each connect, after TIME (`0x39`), and
- whenever a `0xBB` nudge has **bit2 (`0x04`)** set in its third byte. The
  KEY raises that bit when DAILY is opened for the first time after
  power-on, and after that at most every 10 minutes (11bu), unless the app
  sent a block in the last 10 minutes. It sends one nudge at once (whatever
  the NUDGE_SET interval) and waits 8 s; with no answer it plays the block
  it already holds if that is still recent, otherwise the date board,
  unranked. The bit drops when a block arrives, or after 30 s.
- The KEY takes a block the app sends at once (11bu), as the newest: it is
  today's board for the next 26 h, or until a newer one arrives, whatever
  the block's own age (a 144-block day can run past 26 h).

**`0x50` CIPHER_DAY**, app to KEY. Body: the text, 1 to 199 bytes, not
encrypted (the block is public). NOSTR Bluetooth life only (the PASSKEY life
answers `0xBF [0x04]`); before or after the NOSTR PIN.

Answer **`0xB1`** R_ACK, macced, echoing the counter: `[status][height u32 LE]`.
- `0x00` S_OK: the block passed and the KEY keeps it for the next DAILY.
  `height` is its height. A block older than the one the KEY already holds
  is still S_OK but is not used (the KEY never steps back a day).
- `0x07` S_BAD_REQUEST, `height` 0: it did not pass: not `<height>,<hex>`,
  the height not a multiple of 144, the proof of work or the difficulty
  floor (at least 76 leading zero bits) failed, or, with the clock set, the
  block is from the future or more than 2 days old. Do not retry the same
  text; fetch again on the next ask.

The KEY logs `[CIPHER] day block from the phone: height N, checked` (or
`REFUSED`), and on DAILY `asked the phone (nudge bit2)` then `the phone sent
it in N ms` or `no answer from the phone in 8 s`.

### The vault through the phone (11q, 10 Nov 2026)

The passkey and password records back up to `vault.favillakey.io` as one
replaceable kind-30078 event signed by the vault publishing key (the G0 holds
it). Over Wi-Fi the KEY opens the socket itself. In the NOSTR Bluetooth life
the app is the courier: it talks to the relay, the KEY does everything else.
The app sees ciphertext only (the body is the sealed records plus a check
value), cannot alter a record, and a restore is verified on the KEY (author,
id, signature, check value) before anything is merged, so this is exactly as
safe as the Wi-Fi path. All four commands need the NOSTR PIN (`S_LOCKED`
otherwise) and only answer in the NOSTR Bluetooth life.

| Request | Body | Answer |
|---|---|---|
| `0x3F VAULT_INFO` | none | `0xBC [status][vault pub 32][last backup unix u32][records in it u16][dirty 1][asked bits 1][relay host]` |
| `0x40 VAULT_GET` | `[offset u32]` | `0xBD [status][total u32][offset u32][bytes]` |
| `0x41 VAULT_DONE` | `[ok][relay message]` | `0xB1 [status]` |
| `0x42 VAULT_PUT` | `[total u32][offset u32][bytes]` | `0xBE [state][result][added u16][removed u16]` |

Status and result bytes are the KEY's `VBR_*` codes: 0 ok, 1 no backup keys
(onboarded before this firmware), 2 the vault publishing copy is missing
(open VAULT mode once), 3 the signer chip is too old, 4 locked, 5 no link,
6 no clock, 7 export failed, 8 the signer refused to sign, 9 relay, 10
relay refused, 11 no backup found, 12 the event failed its checks, 13 the
backup belongs to other words, 14 needs a vault passphrase, 15 merge
failed, 16 out of memory, 17 busy (a restore from the words is pending; the
app should restore first), 18 the relay copy holds entries this KEY cannot
keep, 19 (KEY 11bd) the relay copy is older than the last backup a relay
accepted from this KEY: it was not merged. On 19 during a backup the app
carries on with VAULT_GET; the KEY's newer copy replaces the stale one.
20 (KEY 11dr) the backup is too big for one event: the KEY reads a relay
frame of at most 160 KB, so it does not stage or publish a backup it could not
read back. Nothing was sent; the entries are all on the KEY. Show it as "Too
much for one backup", not as a relay or link failure.

From KEY 11bd (G0 v19, "one door, one PIN", `docs/DOOR_KEY_RULE.md`), status 2
means: open VAULT mode once (it seals the publishing key), then unlock in
NOSTR mode (it stores the copy under the daily PIN). Backup and restore stay in
the NOSTR life; the vault routes of the PWA there answer `{"error":"gate"}`
always, since that door opens no record.

**A backup** (nudge bit0, or the app's own button):

1. Fetch the newest event from the relay in `VAULT_INFO`'s host:
   `["REQ","v",{"kinds":[30078],"authors":["<pub hex>"],"#d":["favilla-vault"],"limit":1}]`.
2. `VAULT_PUT` the event object (the JSON between the outer braces, not the
   `["EVENT",...]` frame) in chunks of up to 32 KB; `total 0` with no bytes
   when the relay has none. The KEY checks and merges it on its main loop,
   so the last chunk's answer may be `state 2`: ask again with an empty
   chunk at `offset = total` every second until `state 1`. A result other
   than 0 or 11 means the KEY will not publish over that copy; stop and show
   it.
3. `VAULT_GET` at offset 0. The KEY exports, signs (about 2 s) and stages
   the frame; the answer carries the first chunk, or `S_BUSY` (`0xBF 0x06`)
   if staging is still running, in which case ask again in a second. Then
   `VAULT_GET` at each next offset until `offset + bytes == total`. Chunks
   are up to 40,000 bytes. The frame is the whole `["EVENT",{...}]` text.
4. Publish the frame to the relay as is and wait for its `OK`.
5. `VAULT_DONE [1]` on `OK ... true`, `[0][message]` on `OK ... false`,
   `[2]` if the relay could not be reached. Only a 1 makes the KEY record
   "last backup" and clear "changes since". The staged frame is dropped
   either way, and after 2 minutes unasked.

**A restore** (nudge bit1) is steps 1 and 2 alone. The KEY's Backup page
waits up to 90 s for the phone and then says the app did not finish it;
the automatic backup (a quiet screen, 1 to 30 minutes after a change)
asks over Bluetooth too, with no screen, and tries again in 10 minutes if
the app never answers. `VAULT_INFO` can be sent at any time, for a settings
screen: it changes nothing.

### Password health, SHOW and the breach check (11s, 10 Nov 2026)

The KEY scores every password when it holds it anyway (at each seal, at each
OPEN, and by a slow backfill of a few entries per sitting) and keeps one health
byte per entry in the clear beside the record (bits above). The SHA-1s of the
passwords it has seen since the PIN stay in RAM until the KEY locks, for the
reuse check and the breach check; neither the password nor its hash is ever
written to flash or sent anywhere.

| Request | Body | Answer | Life |
|---|---|---|---|
| `0x43 SHOW` | `[id 8]` from LIST | `0xB1 [status]`: ok, `S_NO_MATCH` 0x03, `S_LOCKED` | VAULT |
| `0x44 HEALTH` | none, or `[prefix 3][n u16][suffix 18 x n]` | `0xC0` (encrypted) `[status][pending u16][count][prefix 3 x count]` | both |
| `0x46 ASSESS` (11ab) | `[max 1]` | `0xB1 [status][opening][unseen u16 LE]` | both |

- `SHOW` puts that entry's PASSWORD screen on the KEY (as PASSWORDS > the
  entry does), so the next sign-in on the phone is one press. 30 s to be
  drawn, then forgotten.
- `HEALTH` with no body: the distinct 20-bit SHA-1 prefixes (5 hex digits,
  packed high nibble first, the last nibble 0) of the passwords in RAM that
  have no breach verdict yet, with no entry attached, and how many entries
  wait. For each prefix the app fetches
  `https://api.pwnedpasswords.com/range/<PREFIX>` (send `Add-Padding: true`),
  drops lines ending `:0`, packs each 35-hex-digit suffix into 18 bytes (high
  nibble first, trailing nibble 0), and sends `HEALTH [prefix][n][suffixes]`;
  the KEY marks every matching entry breached, every other entry with that
  prefix checked, and answers with what is still pending. 11bc (13 Nov
  2026): busy buckets hold about 2,000 lines, so the old cap of 1,200 refused
  them. Now `n` is up to what one message carries (about 2,200), and bit 15
  of `n` (`0x8000`) marks a part of the bucket with more to follow: send a
  big bucket as parts of up to 1,000, the bit set on all but the last. The
  KEY remembers a hit in a part and records the verdict when the last part
  (bit clear) arrives. The Wi-Fi PWA has the same at
  `GET/POST /api/vault/health` (`{"p", "s", "more": true}` on a part; parts
  of 500, as the Bluetooth API body is 32 KB) and a "Check all" button.
- 11eb (24 Nov 2026): **a bucket must look real.** A whole bucket (all its
  parts together) with fewer than 100 suffixes is refused: the KEY records no
  verdict, the entries stay pending, and it answers `0xBF [0x07]` instead of
  `0xC0`. Real ranges hold hundreds of lines, so this only catches a failed or
  empty fetch, which used to mark every entry with that prefix "checked, not
  breached". The app must never send a bucket it could not fetch: on a failed
  or empty fetch, say so and send nothing. The PWA's `POST /api/vault/health`
  answers 422 `{"error":"bucket too small","pending":n}` the same way. The
  bench command `vault recheck` (PASSKEY life, bench builds) sends every
  "checked, not breached" entry back to pending; breached verdicts are kept.
- `pending` can be non-zero with no prefixes left only when the KEY has not
  seen those passwords this sitting (no hash in RAM): the backfill opens a few
  per sitting on a quiet screen, and any sign-in adds that entry.
- `ASSESS [max]` (11ab, issue #15): the app's one-tap "Check breaches". The KEY
  opens up to `max` (capped at 24, the PWA's Check all) never-assessed entries
  on its own loop, one every 200 ms or so, scoring each and keeping its hash
  for the bucket check; the answer says how many it will open now and how many
  were never assessed. Send `HEALTH` with no body about `opening x 0.3 s`
  later (or poll it: `pending` drops as entries are opened) and run the
  buckets as usual. Same budget rule as everything else: the G0's 32 record
  opens per unlock are the hard limit, so a vault with many unscored entries
  takes a few unlocks. 0x45 is taken on the browser channel, hence 0x46.

### VAULT mode edits from the Accounts page (11ax, 12 Nov 2026, issue #30)

The PWA's `/api/vault/pw/save`, `/pw/delete-many` and `/pw/result` over the app
channel, so the Accounts page adds, edits and deletes in VAULT mode. The KEY
runs the PWA's own job code: the same screen (NEW ENTRY / CHANGE ENTRY /
DELETE ENTRY / DELETE ENTRIES, hold ENTER 1 s, 2 s for several, BACK cancels,
60 s timeout) and the same record rules.

| Request | Body | Answer | Life |
|---|---|---|---|
| `0x47 PW_SAVE` | **encrypted** `[id 8][sLen][site][uLen][user][pLen][pass][nLen][note]`, 11bi: then an optional `[flags]` | `0xB1 [status]` | VAULT |
| `0x48 PW_DELETE` | `[n][id 8 x n]`, n 1 to 20 | `0xB1 [status]` | VAULT |
| `0x49 PW_RESULT` | none | `0xB1 [state][id 8][reason]` | VAULT |
| `0x4A ASSESS_ONE` | `[id 8]` | `0xB1` (encrypted) `[status][state][prefix 3]` | both |

**Request body encryption.** PW_SAVE is the one request whose body is
encrypted: the app encrypts the body with `encBody` exactly as answers are,
with the command byte `0x47` in the place of the answer byte (keystream block
i = `HMAC(Ke, 0x47 || clientId || ctr || index)`, `Ke = HMAC(k,
"FAVILLA-CHAN-ENC-1")`, the 11ad index rule), then macs the whole message as
usual ("REQ" over header and ciphertext). Commands are below 0x80 and answers
0xA0 and up, and the counter is never reused, so no request block can equal
an answer block. No other request body is encrypted; the app should not
encrypt anything else unless a later row says so. (11bf: IMPORT_ITEM `0x4C`
is the second, the same way with `0x4C` in that place; see "Import in VAULT
mode".)

Test vector (k = 00 01 02 .. 1f, clientId = a0 a1 .. a7, ctr = 7, a new entry
for proton.me, user favillakey, password hunter2, no note):

```
plain  00000000000000000970726f746f6e2e6d650a666176696c6c616b65790768756e7465723200
cipher 2ecc7f5386084dacbafe031c7f0a0a26a881f92d9ac2ea98b02fc77c89b62f713c3a64d57f01
```

**PW_SAVE.**
- `id` all zero: a new entry, `pass` required. `id` from LIST: an edit; an
  empty `pass` keeps the stored password, an empty `note` keeps the note;
  `site` and `user` are replaced as sent (as the PWA's save).
- Text is UTF-8 with no control characters (U+0000..U+001F, DEL, U+0080..
  U+009F refused; no overlong forms, no surrogates). `site` 1..199 bytes,
  the others 0..128 each, and the sealed record's total limit (the KEY checks
  it before showing anything).
- Statuses at once: `0x00` asked (now on the KEY or about to be), `0x03`
  `S_NO_MATCH` (no entry with that id: LIST again), `0x04` not in this life,
  `0x05` locked, `0x06` busy (another save or delete is still asking),
  `0x07` bad request, `0x10` `S_VAULT_FULL` (400 records from KEY 11dr, 200 before), `0x12`
  `S_TOO_LONG`. From KEY 11eo PW_SAVE no longer answers `0x11` `S_BUDGET` at
  once: the save runs on the KEY, which asks for the PIN on its screen if the
  vault limit stops it and carries on; only a save that still cannot go
  through ends as PW_RESULT failed, reason `0x11`. The issue's 0x0B to 0x0E were taken already (0x0B pair
  refused, 0x0C browsers full, 0x0D saved, 0x0E storage), hence 0x10 to 0x12.
  There is no PIN-needed status here: in VAULT mode the PIN is always the
  KEY's.

**PW_DELETE.** Ids not found are skipped (never another record); `0x03` if
none are found. One question on the KEY for the lot: DELETE ENTRY for one
(it shows the site and username), DELETE ENTRIES with a 2 s hold for several.

**PW_RESULT.** Poll every second while the KEY asks. `state`:
`0x00` asking, `0x01` done (`id` = the saved entry's id, new or unchanged;
zero for a delete), `0x02` declined (BACK), `0x03` timed out (60 s),
`0x04` the entry changed or went meanwhile (LIST again), `0x05` failed
(`reason` = `0x10` full, `0x11` budget, `0x12` too long, `0x05` locked during
the question, `0x06` a website's prompt or a browser ask took the screen,
`0x0E` the KEY could not write it), `0x06` no job from this app install since
the KEY started. Only the install that asked sees its result.

**ASSESS_ONE** (11ay: the prefix is in the answer, so over Bluetooth the app
fetches and sends one bucket instead of a full HEALTH round). The answer is
encrypted, like HEALTH's. `state`:
- `0` refused, see `status`: `0x03` no such entry, `0x05` locked, `0x06`
  another ASSESS_ONE is still opening a different entry, `0x11` no opens left.
- `1` the KEY is opening the entry now (one record open, ahead of the slow
  backfill). Send ASSESS_ONE again in about half a second.
- `2` ready: `prefix` is this entry's 20-bit SHA-1 prefix, packed as HEALTH
  packs it. Fetch that one range, send `HEALTH [prefix][n][suffixes]`; the
  answer's pending count drops by one (or more, for entries sharing it).
- `3` the verdict is already known: nothing to fetch, LIST shows it.

### Import in VAULT mode (11bf, 16 Nov 2026)

Entries from another manager's export (passwords, and one-time code secrets)
go onto the KEY over the app channel in **VAULT mode**. From G0 v19 the G0
seals an import only in a VAULT (PASSKEY) life, and VAULT mode has no Wi-Fi,
so the PWA's import (`/api/vault/import/begin`, the saves with
`"import": true`, `/api/vault/otp/save`) no longer works; in NOSTR mode it
answers `{"error":"gate"}`. This is the same import window, driven from the
app.

| Request | Body | Answer | Life |
|---|---|---|---|
| `0x4B IMPORT_BEGIN` | none | `0xB1 [status]` | VAULT |
| `0x4C IMPORT_ITEM` | **encrypted** `[kind][...]`, below | `0xB1 [status]` | VAULT |
| `0x4D IMPORT_STATUS` | none | `0xB1 [state][reason][saved u16 LE][failed u16 LE][last]`, from 11bh followed by `[queued][kept u16 LE][done u16 LE][n][n results]` | VAULT |
| `0x4E IMPORT_END` | none | `0xB1 [status][saved u16 LE][failed u16 LE]` | VAULT |

In NOSTR mode all four get `0xBF [0x04]` (not in this life).

**The flow.**

1. Read and check the export on the phone first. Show what will be imported
   and what will be skipped, and only then send IMPORT_BEGIN.
2. `IMPORT_BEGIN`. The KEY shows IMPORT PIN and the owner types the passkey
   PIN again on the KEY (90 s, BACK cancels, three wrong ends it). Statuses:
   `0x00` asked; `0x05` locked; `0x06` busy (a save, a delete or another
   import is on the KEY); `0x04` this KEY or its G0 cannot import (G0 v19
   and a vault are needed); `0x13` the window was already opened this power
   on (the G0 allows one per power-on life: restart the KEY and try again).
3. Poll `IMPORT_STATUS` every second until `state` is no longer `1`:
   - `2` open: send the items;
   - `5` refused: the window did not open. `reason` `0x02` BACK or 90 s on
     the PIN screen, `0x15` three wrong PINs, `0x0E` the signer refused to
     open it, `0x13` already used this power-on, `0x06` a website's prompt or
     a browser's ask took the screen, `0x05` the KEY locked.
4. Send the items with `IMPORT_ITEM`, **without waiting for each to be
   sealed** (11bh). `0x00` means queued. The KEY keeps up to 8 waiting and
   seals everything waiting under one passkey window. (One item at a time,
   each opening its own window, took 2 to 3 s an item on the bench.)
   `0x06` means 8 are waiting: wait 300 ms and send the same item again (a
   new counter, so encrypt it again). Poll `IMPORT_STATUS` about once a
   second for progress. Its `done` counts the items finished, in the order
   they were sent, and the `n` results after it are those of items
   `done-n .. done-1` (n at most 16), so poll at least every 2 s to see each
   one. Other statuses at once:
   `0x07` bad request (the body did not parse); `0x12` too long; `0x10`
   the vault is full (400 records from KEY 11dr, 200 before, counting those waiting); `0x04` a
   one-time code needs G0 v17; `0x14` no window is open for this app install.
5. `IMPORT_END` when done. `0x00` closes it; `0x06` items are still
   waiting or being sealed (ask again in a second); `0x14` no window. The answer carries the
   counts. IMPORT_END while the PIN is still being asked withdraws the ask.

`state` in IMPORT_STATUS: `0` no import from this app install since the KEY
started, `1` asking for the PIN, `2` open and idle, `3` sealing the last item,
`4` closed, `5` refused. `queued` (11bh) is the number waiting or being
sealed; `kept` is how many were already on the KEY (they are also counted
in `failed`, for an app built on 11bf). For `4`, `reason` is `0x00` the app ended it, `0x02`
BACK on the KEY, `0x05` the KEY locked, `0x06` a website's prompt took the
screen, `0x16` 10 minutes without an item. `last` (the last item's result):
`0x00` saved, `0x17` already on the KEY (kept, see below), `0x10` full,
`0x12` too long, `0x0E` the KEY could not seal or store it. Only the app install that sent IMPORT_BEGIN sees its import; others
get state `0`.

While the window is open the KEY shows IMPORT with the running count and
BACK TO CLOSE, and seals each item with no press. At the end it shows
IMPORTED and the number saved.

**Item bodies** (before encryption). Text as for PW_SAVE: UTF-8, no control
characters, `site` 1..199 bytes, the other text fields 0..128.

- Password, kind `0x01`: `[0x01][sLen][site][uLen][user][pLen][pass][nLen][note]`,
  `pass` 1..128. Saved as a new entry marked "imported" (LIST health bits 2-3
  = 3). **An entry already on the KEY with the same site and username is
  kept as it is** (11bh): the import never replaces it, since the KEY's
  password may be the newer one, and the item's result is `0x17`. (11bf
  replaced it, and opened the old record first, which spent the sitting's
  32 record opens after about 32 duplicates: bench 17 Nov.) Skipping
  duplicates on the phone first, using LIST v2, saves the time. To replace
  a password, use PW_SAVE.
- One-time code, kind `0x02`: `[0x02][sLen][site][aLen][account][digits][period][kLen][secret]`.
  TOTP with SHA1 only; `digits` 6..8, `period` 1..255 seconds, `secret` the
  **raw** bytes 1..64 (decode the export's base32 on the phone). Saved under
  `site`, so the password entry with that exact site links to it (11v rule).
  An HOTP or SHA256 code cannot go in: skip it and say so.

**Encryption.** As PW_SAVE, with `0x4C` in place of the answer byte:
keystream block i = `HMAC(Ke, 0x4C || clientId || ctr || index)`. Test vectors
(`tests/import_item_vector.py`, checked by `tests/import_item_test.cpp`;
k = 00 01 .. 1f, clientId = a0 a1 .. a7):

```
password, ctr 9: github.com / favillakey / hunter2 / note "from Bitwarden"
plain  010a6769746875622e636f6d0a666176696c6c616b65790768756e746572320e66726f6d2042697477617264656e
cipher 40eecc09628efbdf463d6975b48102cbd1c7754fff37d52cb738766404b6319f6a18b995bf244df0129fc8e0258c

one-time code, ctr 10: github.com / favillakey, 6 digits, 30 s, secret 48656c6c6f21deadbeef
plain  020a6769746875622e636f6d0a666176696c6c616b6579061e0a48656c6c6f21deadbeef
cipher 22e22922fd54b25add3423b08cd0d9f747adfcc007fc08df82b00f19b05278715a50a708
```

**Limits.** One window per power-on life, at most 300 items in it (the G0's
import budget). The window closes after 10 minutes with no item. A lock ends
it.

### Old copies from CHANGE PASSWORD (11az, 13 Nov 2026)

No bytes changed on the app channel. What the app sees:

- CHANGE PASSWORD on the KEY keeps the old password until the owner confirms
  the site took the new one. The old one is copied to an ordinary password
  entry named `<site> (old)` (the suffix is exactly space, `(old)`), with the
  same username and the note "Kept by CHANGE PASSWORD until the site takes
  the new one.". The new password goes into the login itself, which keeps its
  id (so its code link, note and recovery codes stay).
- LIST, VAULT_GET and the backup carry the copy like any entry. The Accounts
  page may show it with an OLD tag under its login.
- The KEY finishes it from the copy's MORE: NEW ONE WORKS deletes the copy;
  PUT THIS ONE BACK writes the old password back into the login and deletes
  the copy. The app can do the first with `PW_DELETE` on the copy's id. Put
  back needs the old password, which the app does not hold, so it is done on
  the KEY.
- The full screen rules are in `docs/PASSWORD_SCREENS.md`.

### New passwords from iPhone AutoFill (11bi, 17 Nov 2026, issue #38)

Three parts: GEN_PW for iOS's strong-password suggestion, a flags byte on
PW_SAVE to keep the old password on a change, and NEW LOGIN / NEW PASSWORD on
the KEY's FILL picker.

**GEN_PW `0x4F`** (VAULT life; no screen, no press, nothing stored).

| Request | Body | Answer |
|---|---|---|
| `0x4F GEN_PW` | `[kind][minLen][maxLen][required][allowed][sLen][specials]` (not encrypted) | `0xC1 R_GEN_PW` **enc** `[status][pLen][password]` |

- `kind`: `0x01` strong; `0x02` letters and digits only (the special bit is
  dropped from both class sets).
- `minLen`, `maxLen`: 8 to 64, min not above max. The KEY makes 20
  characters, or the nearest length the rules allow.
- `required`, `allowed`: `0x01` lower, `0x02` upper, `0x04` digit, `0x08`
  special. `required` must be inside `allowed`, and `allowed` must hold a
  letter or digit class. Every required class appears at least once; nothing
  outside `allowed` appears.
- `sLen`, `specials`: up to 32 printable ASCII characters that are not
  letters, digits or a space; duplicates are dropped. `sLen` 0 means the
  default set `-!@#$%^&*_+=?`. Ignored unless `allowed` has `0x08`.
- No character appears more than twice in a row (Apple's `max-consecutive: 2`
  is always met).
- The password comes from the KEY's generator: SHA-256 of the secure element's
  random bytes and the ESP32's, rejection-sampled so every allowed password is
  equally likely.
- Statuses in the answer: `0x00` made (`pLen` and the password follow);
  `0x05` locked, `0x07` bad rules, `0x06` more than 10 in a minute, `0x0E` the
  secure element's random generator did not answer, `0x11` `S_BUDGET` (KEY
  11eo: the vault limit would stop the save that follows, so no password is
  made; the KEY shows its PIN pad at the same moment. Tell the owner to enter
  the PIN on the KEY and try again). A refusal is
  `[status][0x00]`. Not in a VAULT life: `0xBF [0x04]`, as every request.
- Nothing is saved. iOS fills the password, then sends a save, which the app
  makes with PW_SAVE (the owner holds ENTER on the KEY).

Example: no rules from the site, `01 14 14 0F 0F 00` (strong, 20 to 20,
every class required and allowed, the default specials).

**PW_SAVE flags.** An optional byte after the note:

- bit0 `0x01` keep the old password: when this PW_SAVE changes an entry's
  password, the old one is first saved as `<site> (old)` with the same
  username and the note "Kept by CHANGE PASSWORD until the site takes the new
  one.", exactly as CHANGE PASSWORD does (11az). The KEY's question shows
  "Keeps the old one as OLD" under CHANGE ENTRY.
- Ignored on a new entry, and when the password sent is empty or the same as
  the stored one.
- Other bits are refused with `0x07`, so an app can tell an older KEY (which
  also answers `0x07` to the extra byte) and retry without it.
- When an old copy for that login is already waiting (or the entry is itself
  an old copy), nothing is changed: PW_RESULT `0x05` failed, reason `0x17`
  (`S_EXISTS`). The owner finishes the waiting one on the KEY first (NEW ONE
  WORKS or PUT THIS ONE BACK).
- The copy needs a free record: with bit0 set on an edit that sends a
  password, `0x10` full comes at once when there is none.

**NEW LOGIN and NEW PASSWORD on the FILL picker** (no byte changes):

- NEW LOGIN FOR <site> is the last row of the matching logins, and DOWN on
  the "No saved login" screen. The KEY makes a strong 20-character password
  (letters, digits and the KEY's symbols), shows NEW LOGIN with the FILL's
  username (a tap picks another from the usernames book), and a held ENTER
  saves it. If that site and username are already on the KEY it says so and
  saves nothing.
- UP on a login during the ask opens NEW PASSWORD and NEW LOGIN FOR THIS
  SITE. NEW PASSWORD is CHANGE PASSWORD on that login without the typing: the
  old password is kept as `<site> (old)`, the new one (24 characters by
  default, a tap picks another preset) goes into the login, which keeps its
  id.
- Either way the login is saved before anything leaves the KEY, then the FILL
  is answered as usual: `0xB3` **enc** `[0x00][uLen][user][pLen][password]`.
- When iOS then sends its save for the same site, username and password, the
  KEY already holds it: LIST finds the entry, and a PW_SAVE with that same
  password makes no old copy (it only rewrites the same login after the
  owner's hold). The app may skip it.

## Framing

1. Subscribe to notifications on the status characteristic first. Replies to
   an unsubscribed app are dropped.
2. Read the control point length (`L`, the most bytes per write; it is the
   link MTU minus 3).
3. Send a request as one or more writes:
   - first write: `[cmd][len hi][len lo][data...]`, at most `L` bytes
   - each following write: `[seq][data...]`, `seq` from `0x00`, at most `L` bytes
4. Replies arrive as notifications in the same framing.

| Byte | Meaning | Direction |
|---|---|---|
| `0x81` | PING (echoed back) | both |
| `0x82` | KEEPALIVE, 1 byte: `0x01` processing, `0x02` waiting for the user on the KEY | KEY to app |
| `0x83` | MSG: a CTAP2 request or response | both |
| `0xBE` | CANCEL (length 0): stops a request waiting on the KEY | app to KEY |
| `0xBF` | ERROR, 1 byte: `0x01` bad command, `0x03` bad length, `0x04` bad sequence, `0x05` timeout, `0x06` busy (a USB request is in progress), `0x7F` other | KEY to app |

The largest request or response body is 1024 bytes. A request left half-sent
for more than 3 s is dropped.

## CTAP2 bodies (inside MSG)

The first byte of a request is the CTAP2 command; the first byte of a response
is the status (`0x00` OK), followed by the CBOR map.

- `0x04` getInfo: `83 00 01 04`. Lists transports `["ble","usb"]` when
  Bluetooth is up.
- `0x02` getAssertion: `{1: rpId, 2: clientDataHash, 3: allowList (optional),
  5: {"up": true, "uv": true|false}}`. Use iOS's `clientDataHash` from the
  request parameters. The response is `{1: credential, 2: authData,
  3: signature, 4: user (discoverable credentials)}`, which maps onto
  `ASPasskeyAssertionCredential(userHandle:, relyingParty:, signature:,
  clientDataHash:, authenticatorData:, credentialID:)`.
- `0x01` makeCredential: `{1: clientDataHash, 2: rp, 3: user, 4: pubKeyCredParams,
  5: excludeList (optional), 7: {"rk": true}}`. The response is
  `{1: fmt, 2: authData, 3: attStmt}`; for
  `ASPasskeyRegistrationCredential` the app re-encodes it as an attestation
  object `{"fmt", "attStmt", "authData"}`.

From 9g the KEY shows the prompt as soon as the request arrives and signs while
the owner reads it (the G0 takes about 1.7 s per signature); the answer still
leaves only after the press. The KEY waits up to 30 s for a press (and the
PIN when `uv` is asked and the last PIN is more than 10 minutes old). While it
waits it sends KEEPALIVE `0x02` every 100 ms. Status `0x27` means the user said
no, `0x2F` that nobody pressed in time, `0x2E` no credential for this site.

## Quick check without the app

In nRF Connect on the paired iPhone (press Home on the KEY first, then connect
to "Favilla KEY"):

1. Service `8F1A0001...`: turn on notifications for `8F1A0011`.
2. Write `81 00 03 01 02 03` to `8F1A0010`. Expect the notification
   `81 00 03 01 02 03` (ping).
3. Write `83 00 01 04` to `8F1A0010`. Expect a notification starting
   `83 00 ..  00 A5`, the getInfo response.
