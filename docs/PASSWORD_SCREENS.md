# Password screens on the KEY (drops 11az and 11ba, 13 Nov 2026)

This drop builds the eleven approved screens of the "KEY password screens" mock:
new account, password presets, change password with the old one kept, reveal on
the KEY, fast scroll in PASSWORDS, the new account screen and its MORE menu. It
also teaches the browser extension (0.5.16) to tell sign-up and change-password
pages apart from sign-in pages.

Buttons, as everywhere on the KEY: UP, DOWN, ENTER, BACK. "Hold" means keep the
button down until the line under the label fills.

## 1. Password presets

| Preset | Length | Characters | Strength |
|---|---|---|---|
| 24 CHARACTERS (default) | 24 | letters, digits, symbols | 154 bits |
| 32 CHARACTERS | 32 | letters, digits, symbols | 206 bits |
| 22, NO SYMBOLS | 22 | letters, digits | 131 bits |
| 16 CHARACTERS | 16 | letters, digits, symbols | 103 bits (for sites with a 16 limit) |
| TYPE IT | yours | typed on the letter reel | |
| SCAN QR | yours | read from a QR | |

- The alphabet is 26 + 26 + 10 + 24 symbols (`kbd::kGenSymbols`). Every password
  holds at least one character of each kind in use, so the strength is
  log2 of the number of passwords that qualify, worked out by inclusion and
  exclusion, not length times 6.43.
- The seed is SHA-256 over "FAVILLA-PWGEN-V1", 32 bytes from the secure
  element's random number generator and 32 bytes of ESP32 randomness. If the
  secure element does not answer, nothing is made.

## 2. New account (screens 1 to 3)

Opened from PASSWORDS > NEW ACCOUNT, from the extension's button on a sign-up
page, or from a phone's new-login ask.

- **The form.** Three cards: SITE, USERNAME, PASSWORD.
  - SITE is read-only when the browser sent it. From the KEY's own menu it can
    be typed, scanned from a login QR, or left as "New entry N" to name later.
  - USERNAME starts on the username the page already holds, else the newest
    one in the usernames book. ENTER opens the picker: NONE, every username on
    the KEY, ADD A NEW ONE.
  - PASSWORD starts on 24 CHARACTERS. ENTER opens the presets.
  - UP and DOWN move between the cards. A tap of ENTER changes the card
    selected.
- **Hold ENTER: SAVE, TYPE.** The KEY saves the entry on the signer first, then
  types. A site never gets a password the KEY did not keep.
- **What is typed.** Username, Tab, password, and Tab and the password again
  when the extension saw a confirm box that Tab reaches. Where Tab does not
  reach the next box (an eye button in between, other fields in between), the
  KEY stops and asks: "Click the confirm box on the site. DOWN TO TYPE IT".
- **Already saved.** If the KEY already holds a login with this site name and
  username, it offers CHANGE PASSWORD instead of making a second one.
- **Saved (screen 3).**
  - "Typed, and the confirm box filled." when it was.
  - "Confirm box? DOWN types it again." when the KEY could not tell (no
    extension).
  - UP: the site refused the password. Pick another preset; the KEY replaces
    the password in the same entry, then the hold types it again.
  - ENTER or BACK: done. The entry stays.

## 3. Change password (screens 4 to 6)

Opened from an entry's MORE > CHANGE PASSWORD, or from the extension's button
on a change-password page. The KEY finds the saved logins for the site; when
the page names a username that one of them has, only that one; several give a
pick list. (11bb: a username the page names but no login has no longer hides
the site's logins.)

- **The rule (ruled 13 Nov 2026):** keep both until the owner confirms.
- **Hold ENTER: CHANGE IT.**
  1. The current password is copied to a new entry named `<site> (old)`, with
     the note "Kept by CHANGE PASSWORD until the site takes the new one." If
     that copy cannot be saved, nothing changes.
  2. The new password goes into the login itself. The login keeps its record
     id, so its linked one-time code, note and recovery codes stay with it.
  3. The KEY types the old one, Tab, the new one (and Tab and the new one
     again when the extension saw a confirm box Tab reaches). Splits ask for a
     click, as on a new account.
  4. If the new password never reached the site (BACK at a split, or typing
     stopped), the change is undone: the old password goes back and the copy
     is deleted.
- **Accepted? (screen 5).**
  - ENTER, yes: the old copy is deleted.
  - BACK, not yet: both stay. The copy shows in PASSWORDS with a brass OLD tag
    (screen 6).
  - DOWN, when the KEY could not tell about a confirm box: types the new one
    again.
- **Finishing later.** MORE on an OLD copy has:
  - NEW ONE WORKS: deletes the copy.
  - PUT THIS ONE BACK: the login gets the old password again (two record
    opens), then the copy is deleted.
  - NOTE and DELETE.
- One change at a time: while an OLD copy waits, CHANGE PASSWORD on that login
  says so and points to the copy.
- Sign-in matching scores "proton.me (old)" as a close name for proton.me, so
  a browser ask types the new password, and the old one is only listed.

## 4. The account screen (screens 7 and 10)

- Header PASSWORD, then "116 OF 137" (with "+ 2FA" when a one-time code is
  linked), the site, the username, "Select the username field first."
- ENTER types username, Tab, password. Hold ENTER types and submits.
- **UP**: a tap shows the linked one-time code. A 1 s hold shows the password
  (Reveal). Without a linked code the line reads "Hold UP to show it, DOWN for
  more".
- **DOWN**: MORE.
- DOWN no longer steps to the next account: fast scroll in the list does that
  job. While a phone's FILL ask runs, DOWN still steps to the next match and
  UP does nothing.
- On a two-page sign-in the line "This page: the username only" now takes the
  place of "Select the username field first." (in 11aw the two lines were
  drawn over each other).

## 5. Reveal (screen 8, ruled 13 Nov 2026)

- On the KEY's screen only, never sent anywhere.
- Hold UP for 1 s on the account screen. One record open from the sitting's
  budget.
- Groups of four in JetBrains Mono, digits in brass, a space drawn as a grey
  dot. Up to 48 characters in Bold 24, longer ones in Regular 12.
- Hidden after 30 s or by any button. The panel is blanked at once.
- Logged as "[PW] slot N shown on the KEY: shown", without the value.

## 6. MORE (screen 11)

| Row | What it does |
|---|---|
| CHANGE PASSWORD | Section 3 |
| ONE-TIME CODE | The linked code, or how to link one (CODES > ADD A CODE) |
| NOTE | The note, one record open |
| EDIT NAME OR USER | NAME on the letter reel, or USERNAME from the picker; the record keeps its id |
| RECOVERY CODES | As before (11aa) |
| DELETE | Last row. Hold ENTER 2 s |

The footer reads ENTER TO CHOOSE and BACK TO LEAVE, the pattern of every other
list on the KEY.

## 7. Fast scroll in PASSWORDS (screen 9)

- A tap of UP or DOWN moves one row and wraps round, as before.
- Held: after 0.4 s it repeats, about 8 rows a second; after 1.5 s, about 25 a
  second. (The mock's letter step after 2 s was dropped on 13 Nov 2026: the
  speed-up is enough.)
- While held, the other rows dim, and the footer reads LET GO TO STOP over
  "40 OF 137".
- The repeat stops at the ends. Letting go stops on that row.
- The list is not rebuilt during a hold, and the background name reader waits
  until the buttons are quiet, so a hold never stalls on a signer read.

## 8. The extension (0.5.16)

- **Sign-up page:** two password boxes (new and confirm), or one box marked
  `autocomplete="new-password"`, and no current-password box.
- **Change-password page:** a current-password box (by `autocomplete` or a
  name like current, old, existing) and a new one; three password boxes count
  as current, new, confirm.
- A page with one plain password box is still a sign-in page.
- On those pages there is no automatic sign-in ask. The Favilla button in the
  box sends NEW_LOGIN with a form byte, and puts the cursor in the first box.
- The form byte rides at the end of the NEW_LOGIN body
  (`[sLen][site][uLen][user][form]`), bit 7 set:

| Bit | Name | Meaning |
|---|---|---|
| 0x80 | FORM_KNOWN | The extension looked at the page |
| 0x01 | FORM_CONFIRM | A confirm box is there |
| 0x02 | FORM_CURRENT | The first box is the current password (a change) |
| 0x04 | FORM_USER | The first box is a username box (a sign-up) |
| 0x08 | FORM_SPLIT1 | Tab from the first box does not reach the new one |
| 0x10 | FORM_SPLIT2 | Tab from the new box does not reach the confirm box |

- Bits 5 and 6 are zero. The KEY refuses a form byte on a sign-in, and a
  fields byte other than 0 on a new login.
- A KEY older than 11az answers status 7 to the byte. The extension then asks
  again without it, and the KEY treats the page as unknown.
- The extension still never reads a password box. It reads only the boxes'
  attributes and their place in the Tab order.
- Example, account.proton.me, user favillakey, a sign-up page with a confirm
  box straight after the password box:
  `116163636f756e742e70726f746f6e2e6d650a666176696c6c616b657985` (form 0x85).

## 9. What the phone and the PWA see

- An OLD copy is an ordinary password entry named `<site> (old)`. LIST, the
  Accounts page and the vault backup carry it like any other.
- The Accounts page may show it with an OLD tag and offer the same two
  answers. Nothing in the app channel changed.
- A change made on the KEY keeps the login's id, so the app's cached row
  stays valid; LIST shows the new `updated` time.

## 10. Limits

- Tab order is read from the page as it stands. A site that moves focus by
  script, or builds its boxes after the button is pressed, can still send a
  Tab somewhere else. The split prompt is the fallback.
- A sign-in form that marks its password box `new-password` by mistake looks
  like a sign-up page: the button then offers NEW ACCOUNT, and there is no
  automatic sign-in on that page.
- Reveal puts the password on the KEY's screen for up to 30 s. That was ruled
  acceptable: the KEY types it anyway, and the screen is small and held in
  the hand.
