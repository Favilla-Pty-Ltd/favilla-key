#!/usr/bin/env python3
# Regenerate pwa_data.h from pwa.html (stand-in for Josh's gen_pwa_data.py, same output format).
# Build id = first 12 hex of sha256(html with the data-pwa-build value blanked); the same id is
# stamped on <html data-pwa-build> and emitted as PWA_BUILD_ID, so /api/info and the running
# shell always agree. Gzip level 9, mtime 0.
import sys, re, gzip, hashlib
src, dst = sys.argv[1], sys.argv[2]
html = open(src, 'rb').read()
blank = re.sub(rb'data-pwa-build="[0-9a-f]*"', b'data-pwa-build=""', html, count=1)
bid = hashlib.sha256(blank).hexdigest()[:12]
stamped = re.sub(rb'data-pwa-build="[0-9a-f]*"', b'data-pwa-build="%s"' % bid.encode(), html, count=1)
if stamped != html: open(src, 'wb').write(stamped)
gz = gzip.compress(stamped, 9, mtime=0)
out = ["#pragma once", "#include <pgmspace.h>", "",
       "// Auto-generated -- %s bytes raw, %s gzip" % (format(len(stamped), ','), format(len(gz), ',')),
       "// Source:  pwa.html", "// Build:   %s" % bid, "",
       'const char PWA_BUILD_ID[] = "%s";' % bid,
       "const uint32_t PWA_HTML_GZ_LEN = %d;" % len(gz),
       "const uint8_t PWA_HTML_GZ[] PROGMEM = {"]
for i in range(0, len(gz), 16):
    out.append("  " + ",".join("0x%02x" % b for b in gz[i:i+16]) + ",")
out += ["};", ""]
open(dst, 'w', newline='\n').write("\n".join(out))
print("build", bid, "raw", len(stamped), "gz", len(gz))
