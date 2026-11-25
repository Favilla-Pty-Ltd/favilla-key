# Third-party notices

## Lucide icons

The PASSKEY door card icon (`PASSKEY_ICON_A4` in `src/main.cpp`) is the
"key-round" icon from Lucide (https://lucide.dev), rendered at stroke width 1.5
and converted to a 44x44 4-bit bitmap.

ISC License

Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as part
of Feather (MIT). All other copyright (c) for Lucide are held by Lucide
Contributors 2022.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## Vendored ESP-IDF components (components/espressif__*, components/joltwallet__littlefs)

Copied unchanged from the Espressif component registry, at the versions the
release build used on 23 Nov 2026, so the release build fetches nothing at
build time (see PINNING.md). Each folder keeps its own licence file and its
registry checksums.

| Folder | Version | Licence |
|---|---|---|
| espressif__esp32-camera | 2.1.4 | Apache-2.0 (LICENSE in the folder) |
| espressif__esp_jpeg | 1.3.2 | Apache-2.0 (LICENSE in the folder) |
| espressif__esp_modem | 1.4.3 | Apache-2.0 (LICENSE in the folder) |
| espressif__mdns | 1.15.1 | Apache-2.0 (LICENSE in the folder) |
| espressif__fb_gfx | esp32-arduino-lib-builder, git | Apache-2.0 (header in fb_gfx.c) |
| joltwallet__littlefs | 1.23.1 | MIT (LICENSE in the folder) |
