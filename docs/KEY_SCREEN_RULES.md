# KEY screen rules

How every screen on the KEY is laid out, from drop 11er (25 Nov 2026). New and
changed screens follow these. Screens built before 11er are being moved over
(see "Status" at the end).

The KEY has four buttons, one at each corner of the screen: UP top-left, DOWN
top-right, BACK bottom-left, ENTER bottom-right.

## 1. Each button labels itself

- A button that does something on this screen has one word in its corner,
  right over the button. No other place says what the buttons do.
- One word only: SEND, BACK, MORE, SHOW, TYPE, STOP, CHANGE, SAVE, YES, LATER.
  Never "ENTER TO ...", "PRESS UP", "DOWN TO TYPE IT" or a footer sentence.
- Bottom words sit 12 px from the bottom and sides; top words 12 px from the
  top and sides (uiCornerAnswers, uiCornerTop). Archivo Bold 12, tracked 3.
- A button with no word does nothing on that screen, with one exception:
  - Plain lists and menus have no corner words at all. When UP and DOWN only
    scroll, ENTER opens what is selected and BACK leaves, everyone knows that
    from the first list, so the words would only be noise. The same goes for a
    message page that BACK or ENTER closes. Corner words appear as soon as a
    button does something else (MORE, SHOW, a hold).

## 2. Colour

- Brass: the main answer, always ENTER's word (SEND, CHANGE, SAVE, YES).
- Grey: every other corner word, tags and secondary text.
- White (ink): the thing the screen is about (the site name) and the one
  instruction line when a screen needs one.
- Red: danger only (DELETE and other actions that cannot be undone).

## 3. What a screen shows

- Action screens (sign in, change, save, delete) have no header. The site is
  the hero (Archivo Bold 28, Bold 20 if it does not fit), the username in brass
  under it, the block centred between the top and bottom corner rows
  (pwSignInHero).
- A tag is a grey word above the site, shown only when the same screen means
  something different: OLD COPY, USERNAME, PASSWORD, SEND AGAIN, CHANGE
  PASSWORD, NEW ACCOUNT, DELETE.
- No counts ("94 OF 130") on an action screen. Lists show their place with the
  scroll bar.
- At most one instruction line, white, saying what to do on the computer or
  phone ("Click the current password box"). Only when the screen is confusing
  without it.
- Lists and menus keep a brass header, because the header names the list, and
  no corner words (section 1).

## 4. Taps and holds

- A tap for something that is easy to undo or only types (SEND, TYPE, MORE).
- A hold for something that changes what is saved (CHANGE, SAVE, DELETE). The
  bar fills above ENTER's word, the word's own width. A tap on a hold button
  does nothing.
- Never ask for a press that is not a decision. Waiting screens move on by
  themselves.

## 5. The same button, the same job

- DOWN (top-right) is MORE wherever there is more to choose: a login's menu,
  the kind of password, the phone's new password or new login.
- UP (top-left) is SHOW on a login (a tap the code, a hold the password), NEXT
  when the phone asks and more than one login matches.
- BACK always leaves or says no. ENTER always says yes.

## Status

Moved to these rules: Sign in (11er), Next box (11er), MORE on a login (11es),
Accepted? (11es), CHANGE PASSWORD (11et).

Still to move (mocked, waiting for approval): NEW ACCOUNT, its Saved screen,
the password kinds list, NEW LOGIN and NEW PASSWORD from the phone, DELETE,
message pages, "Check the site".
