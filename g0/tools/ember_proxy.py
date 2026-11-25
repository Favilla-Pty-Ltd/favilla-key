#!/usr/bin/env python3
"""ember_proxy.py - bench helper, 28 Oct 2026.

Serves mempool.space's block API to the KEY over plain HTTP on your LAN, so
the bench build does not need a TLS session on the ESP32 to fetch headers.
The G0 checks every header's proof of work itself; this only moves bytes.

    python tools\\ember_proxy.py            (listens on port 8088)

Then on the KEY's serial console:  em src http://<this PC's IP>:8088
Only /api/blocks/tip/height, /api/v1/blocks/<h> and /api/block/... are passed.
"""
import http.server, urllib.request, re, socket, sys

UPSTREAM = "https://mempool.space"
ALLOWED = re.compile(r"^/api/(blocks/tip/height|v1/blocks/\d+|block-height/\d+|block/[0-9a-f]{64}/header)$")

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not ALLOWED.match(self.path):
            self.send_response(404); self.end_headers(); return
        try:
            with urllib.request.urlopen(UPSTREAM + self.path, timeout=20) as r:
                body = r.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        except Exception as e:
            msg = str(e).encode()
            self.send_response(502); self.send_header("Content-Length", str(len(msg))); self.end_headers(); self.wfile.write(msg)
    def log_message(self, fmt, *a):
        sys.stdout.write("%s  %s\n" % (self.address_string(), fmt % a))

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
    except Exception: return "127.0.0.1"
    finally: s.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
    print("ember proxy on port %d. On the KEY:  em src http://%s:%d" % (port, lan_ip(), port))
    http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
