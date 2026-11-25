# Favilla KEY: RF and EMC test sheet for the lab

Build `favilla_key_fido_rftest` (drop 11be, 15 Nov 2026). Flash it on both
lab units: the "continuous transmission" unit and the "normal operation" unit.
It is the release firmware (vault, passkeys, Bluetooth) plus the two lab pages
below. Not for shipping.

## Radio facts

| | Wi-Fi | Bluetooth LE |
|---|---|---|
| Module | ESP32-S3-WROOM-1 (one 2.4 GHz radio, shared) | same |
| Standard | 802.11 b/g/n, 20 MHz channels only | BLE 5, 1M PHY in these tests |
| Channels | 1 to 13 (country AU) | 0 to 39 (2402 to 2480 MHz), advertising on 37 / 38 / 39 |
| Power | capped at **8.5 dBm** on every radio start | set to **+9 dBm** on every Bluetooth start and read back (serial line `[RFDIAG] BLE TX`) |

- With both radios on, they share the antenna by time (Espressif's
  coexistence scheduler). They never transmit at the same instant.

## Getting to the pages

1. **The KEY:** power on, choose NOSTR, enter the daily PIN.
2. **The KEY:** go to Settings > Device. **RF test** and **EMC tests** are near
   the end of the list.
3. **The KEY, first Bluetooth use after each power-on or restart:** picking a
   BLE row or mode F or G shows **BLUETOOTH: Restart**. Choose Restart.
4. **The KEY:** unlock again with the daily PIN and go back to the page.
   Bluetooth now starts on its own. Any later restart needs step 3 again.

Buttons: the two top buttons scroll, ENTER (bottom right) chooses, BACK
(bottom left) stops or leaves.

## RF test page (continuous transmission unit)

| Row | What it does |
|---|---|
| CHANNEL | Wi-Fi channel 1 / 6 / 11 / 13 |
| MODE | 11b 1 Mbps, 11g 6 Mbps, 11g 54 Mbps, 11n MCS0, 11n MCS7 |
| TRANSMIT | Wi-Fi: 1086-byte frames, pseudo-random payload, back to back, 8.5 dBm. Duty about 100 % at 1 and 6 Mbps, about 50 % at 54 Mbps and MCS7 |
| RECEIVE | Wi-Fi receive only on the channel; shows packets heard |
| BLE LOW | BLE transmit, channel 0, **2402 MHz** |
| BLE MID | BLE transmit, channel 19, **2440 MHz** |
| BLE HIGH | BLE transmit, channel 39, **2480 MHz** |
| STOP | Radio off |

- **BLE rows:**
  - The controller's LE transmitter test: 1M PHY, 255-byte PRBS9 payload, one
    packet every 2.5 ms (2.12 ms on air, about 85 % duty), at +9 dBm.
  - The screen shows the channel, the frequency and the power read back from
    the controller.
  - Wi-Fi is stopped while a BLE row runs.
- **Leaving:** BACK stops the radio and offers **Restart KEY**. The page is left
  by restarting only.

## EMC tests page (normal operation unit)

| Mode | What it does | Leave |
|---|---|---|
| A Hold screen | Idle dim, auto-sleep and hotspot idle-off off until restart. Turn on first | ENTER again |
| B Display stress | Every pixel redrawn every frame, full backlight | BACK |
| C Camera live | Camera on with the live preview | BACK |
| D Radio traffic | 1200-byte UDP broadcasts on the network, or on the KEY's hotspot if none, 8.5 dBm | BACK |
| E Charging | Battery page with live current; plug USB in | BACK |
| F BLE advertising | The KEY's own advertising ("Favilla KEY", connectable) held at **20 to 30 ms** on 37 / 38 / 39 at +9 dBm, with no slowdown | BACK |
| G BLE + Wi-Fi | F and D together | BACK |

- **Suggested sweep:** A on, then idle home screen; B; C; D; F; G; E with USB in.
- **Immunity:** the counters on C, D and G, and the timer on F, show an upset.

## Serial log (115200)

- `[RFDIAG] BLE TX req=+9 dBm ... got default=+9 adv=+9 scan=+9 dBm`
- `[RFTEST] BLE TX 2440 MHz (channel 19) PRBS9 255 B 1M PHY, +9 dBm: rc 0`
- `[RFTEST] TX ch N <mode>`, `[RFTEST] RX ch N`, `[RFTEST] stop`
- `[EMC] F BLE advertising`, `[EMC] G radio traffic via ...`

## Not in this build

- Unmodulated carrier (CW), and a 100 % duty Wi-Fi transmitter at the 11n
  rates. Both need Espressif's certification test firmware. Ask if needed.
- BLE 2M and Coded PHY transmit rows. Ask if needed.
- The Wi-Fi-only lab build `favilla_key_rftest` still exists, for a unit
  without Bluetooth.
