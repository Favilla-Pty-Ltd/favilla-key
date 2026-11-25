#!/usr/bin/env bash
# favilla-vault.sh  (2 Nov 2026; 3 Nov 2026: 160 KB content, 192 KB events, for 200 records)
# Sets up wss://vault.favillakey.io: a second strfry on this box that only
# holds Favilla KEY vault backups (kind 30078, d-tag "favilla-vault").
#
# What it touches (nothing of relay.favillakey.io is changed):
#   /etc/strfry-vault.conf                 own config, port 7778, own database
#   /var/lib/strfry-vault/                 own LMDB database
#   /usr/local/bin/favilla-vault-policy.py write policy (vault backups only)
#   /etc/systemd/system/strfry-vault.service
#   /etc/nginx/conf.d/favilla-vault-limits.conf   per-IP limits
#   /etc/nginx/sites-available|enabled/vault.favillakey.io
#   Let's Encrypt cert for vault.favillakey.io (webroot, like relay.)
#   /usr/local/bin/favilla-vault-backup + nightly timer
# No router: vault backups are never forwarded to public relays.
#
# Safe to run again: every step checks what is already there.
# Run as root:  bash favilla-vault.sh
set -euo pipefail

DOMAIN=vault.favillakey.io
PORT=7778
DB=/var/lib/strfry-vault
CONF=/etc/strfry-vault.conf
POLICY=/usr/local/bin/favilla-vault-policy.py
UNIT=/etc/systemd/system/strfry-vault.service
SITE=/etc/nginx/sites-available/$DOMAIN
LIMITS=/etc/nginx/conf.d/favilla-vault-limits.conf
WEBROOT=/var/www/html
STRFRY=/opt/strfry/strfry

say()  { echo; echo "==> $*"; }
fail() { echo; echo "STOPPED: $*"; exit 1; }

[[ $EUID -eq 0 ]] || fail "run as root"
[[ -x $STRFRY ]] || fail "$STRFRY not found"
id strfry >/dev/null 2>&1 || fail "user 'strfry' not found"
[[ -f /etc/letsencrypt/options-ssl-nginx.conf ]] || fail "certbot nginx options file missing"

say "1/8 DNS"
IP=$(dig +short "$DOMAIN" | tail -n1)
MYIP=$(hostname -I | awk '{print $1}')
[[ -n "$IP" ]] || fail "$DOMAIN does not resolve yet"
echo "$DOMAIN -> $IP (this box: $MYIP)"
[[ "$IP" == "$MYIP" ]] || fail "$DOMAIN does not point at this box"

say "2/8 database folder"
mkdir -p "$DB"
chown strfry:strfry "$DB"
chmod 750 "$DB"
echo "$DB ready"

say "3/8 write policy"
cat > "$POLICY" <<'PYEOF'
#!/usr/bin/env python3
# Write policy for vault.favillakey.io (strfry plugin).
# Accepts ONLY Favilla KEY vault backups:
#   kind 30078, exactly one d tag "favilla-vault", optional "alt" tag,
#   content base64 up to 160 KB (3 Nov 2026, Vault spec P4-1: 200 records is
#   about 136 KB; the WebSocket frame limits, ESP32 160 KB and strfry 192 KB,
#   are the real ceiling, so not higher).
# Disk guards: refuses new events when the database passes 2 GB or the disk
# has under 3 GB free, so this relay can never fill the box.
# RULE (learned on relay.favillakey.io, Jul 2026): stdout carries ONLY the
# one JSON response per event. Every log line goes to stderr.
import json, os, re, sys, time

DB = "/var/lib/strfry-vault"
DB_MAX = 2 * 1024**3
FREE_MIN = 3 * 1024**3
CONTENT_MAX = 160 * 1024
B64 = re.compile(r"^[A-Za-z0-9+/=]*$")
_cache = {"t": 0.0, "used": 0, "free": 1 << 62}

def disk():
    now = time.time()
    if now - _cache["t"] > 30:
        used = 0
        for name in os.listdir(DB):
            try:
                used += os.stat(os.path.join(DB, name)).st_blocks * 512   # real blocks, not the sparse map size
            except OSError:
                pass
        st = os.statvfs(DB)
        _cache.update(t=now, used=used, free=st.f_bavail * st.f_frsize)
    return _cache["used"], _cache["free"]

def decide(ev):
    if ev.get("kind") != 30078:
        return "only Favilla vault backups are accepted here"
    tags = ev.get("tags") or []
    d = [t for t in tags if isinstance(t, list) and t and t[0] == "d"]
    if len(d) != 1 or len(d[0]) < 2 or d[0][1] != "favilla-vault":
        return "only Favilla vault backups are accepted here"
    for t in tags:
        if not isinstance(t, list) or not t or t[0] not in ("d", "alt"):
            return "unexpected tag"
        if t[0] == "alt" and (len(t) != 2 or len(t[1]) > 128):
            return "bad alt tag"
    c = ev.get("content") or ""
    if len(c) > CONTENT_MAX or not B64.match(c):
        return "content must be base64, at most 160 KB"
    used, free = disk()
    if used > DB_MAX or free < FREE_MIN:
        print(f"vault policy: storage guard (db {used} B, free {free} B)", file=sys.stderr, flush=True)
        return "relay storage full"
    return None

for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    ev = req.get("event") or {}
    why = "error"
    try:
        why = decide(ev)
    except Exception as e:
        print(f"vault policy: error {e!r}", file=sys.stderr, flush=True)
    out = {"id": ev.get("id", ""), "action": "accept" if why is None else "reject"}
    if why:
        out["msg"] = "blocked: " + why
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
PYEOF
chmod 755 "$POLICY"
# Self-test the policy before strfry ever uses it.
T=$(printf '%s\n%s\n%s\n' \
  '{"type":"new","event":{"id":"aa","kind":30078,"tags":[["d","favilla-vault"]],"content":"QUJD"}}' \
  '{"type":"new","event":{"id":"bb","kind":1,"tags":[],"content":"hi"}}' \
  '{"type":"new","event":{"id":"cc","kind":30078,"tags":[["d","other-app"]],"content":"QUJD"}}' \
  | sudo -u strfry python3 "$POLICY")
echo "$T"
echo "$T" | grep -q '"id": "aa", "action": "accept"' || fail "policy self-test: vault event not accepted"
echo "$T" | grep -q '"id": "bb", "action": "reject"'  || fail "policy self-test: kind 1 not rejected"
echo "$T" | grep -q '"id": "cc", "action": "reject"'  || fail "policy self-test: other d-tag not rejected"
echo "policy self-test passed (accept vault, reject kind 1, reject other d-tag)"

say "4/8 strfry config"
cat > "$CONF" <<EOF
# strfry config for vault.favillakey.io (written by favilla-vault.sh, 2 Nov 2026).
# Holds ONLY Favilla KEY vault backups. Separate database, port and policy
# from relay.favillakey.io, and no router: nothing here is forwarded anywhere.
db = "$DB/"

dbParams {
    maxreaders = 64
    mapsize = 10995116277760
}

events {
    # P4-1 (3 Nov 2026): a full vault (200 records) is about 136 KB of base64 in
    # one event. 192 KB, the same as the frame limit below (was 128 KB).
    maxEventSize = 196608
    rejectEventsNewerThanSeconds = 900
    rejectEventsOlderThanSeconds = 94608000
    rejectEphemeralEventsOlderThanSeconds = 60
    ephemeralEventsLifetimeSeconds = 300
    maxNumTags = 8
    maxTagValSize = 256
}

relay {
    bind = "127.0.0.1"
    port = $PORT
    nofiles = 4096

    # No NIP-42 here: a KEY never authenticates to its vault relay, so the
    # relay never learns more than the anonymous publishing key.
    auth {
        enabled = false
    }

    info {
        name = "Favilla vault"
        description = "Encrypted backups of Favilla KEY vaults. Accepts kind 30078 with d-tag favilla-vault only."
        pubkey = "dcd363dc444d95f77a8290c0ea27cfdd9fe384625cc95e89ac6cef092fcc79cd"
        self = ""
        contact = ""
        icon = ""
        privacy = ""
        terms = ""
    }

    maxWebsocketPayloadSize = 196608
    autoPingSeconds = 55
    maxFilterLimit = 50

    writePolicy {
        plugin = "$POLICY"
        timeoutSeconds = 10
    }

    filterValidation {
        enabled = false
    }

    compression {
        enabled = true
        slidingWindow = true
    }

    # One core, shared with coturn and the main relay: one thread each.
    numThreads {
        ingester = 1
        reqWorker = 1
        reqMonitor = 1
        negentropy = 1
    }
}
EOF
chmod 644 "$CONF"
echo "$CONF written"

say "5/8 systemd service"
cat > "$UNIT" <<EOF
[Unit]
Description=strfry nostr relay (Favilla vault backups)
After=network.target

[Service]
User=strfry
ExecStart=$STRFRY --config=$CONF relay
Restart=on-failure
RestartSec=3
LimitNOFILE=4096
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DB

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now strfry-vault.service
systemctl restart strfry-vault.service
sleep 2
systemctl is-active --quiet strfry-vault.service || { journalctl -u strfry-vault -n 30 --no-pager; fail "strfry-vault did not start"; }
INFO=$(curl -s -H 'Accept: application/nostr+json' "http://127.0.0.1:$PORT/")
echo "$INFO" | grep -q '"Favilla vault"' || { echo "$INFO"; fail "relay info (NIP-11) not served on port $PORT"; }
echo "strfry-vault running on 127.0.0.1:$PORT"

say "6/8 nginx and certificate"
cat > "$LIMITS" <<'EOF'
# vault.favillakey.io: per-IP limits (a KEY makes one connection now and then).
limit_conn_zone $binary_remote_addr zone=vaultconn:1m;
limit_req_zone  $binary_remote_addr zone=vaultreq:1m rate=30r/m;
EOF
if [[ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then
  # Port 80 only first, so Let's Encrypt can check the webroot.
  cat > "$SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root $WEBROOT;
    location /.well-known/acme-challenge/ { allow all; }
    location / { return 404; }
}
EOF
  ln -sf "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
  nginx -t
  systemctl reload nginx
  certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --non-interactive --agree-tos \
    --register-unsafely-without-email --deploy-hook "systemctl reload nginx" \
    || fail "certbot could not get a certificate for $DOMAIN"
fi
cat > "$SITE" <<EOF
server {
    server_name $DOMAIN;
    listen 443 ssl;
    listen [::]:443 ssl;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    root $WEBROOT;
    location /.well-known/acme-challenge/ { allow all; }

    # strfry serves Prometheus metrics on the websocket port: never publish them.
    location = /metrics { deny all; }

    # No access log for this site: the relay should not keep a record of
    # which IP fetched or wrote which backup.
    access_log off;

    location / {
        limit_conn vaultconn 4;
        limit_req zone=vaultreq burst=10 nodelay;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root $WEBROOT;
    location /.well-known/acme-challenge/ { allow all; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
ln -sf "$SITE" "/etc/nginx/sites-enabled/$DOMAIN"
nginx -t || fail "nginx config test failed (nothing reloaded)"
systemctl reload nginx
sleep 1
PUB=$(curl -s -H 'Accept: application/nostr+json' "https://$DOMAIN/")
echo "$PUB" | grep -q '"Favilla vault"' || { echo "$PUB"; fail "https://$DOMAIN does not serve the relay info"; }
echo "https://$DOMAIN serves the vault relay"

say "7/8 nightly backup of the vault database"
cat > /usr/local/bin/favilla-vault-backup <<'EOF'
#!/usr/bin/env bash
# Nightly export of the vault relay database. Restore with:
#   zcat <file> | sudo -u strfry /opt/strfry/strfry --config=/etc/strfry-vault.conf import
set -euo pipefail
DIR=/var/backups/favilla-vault
KEEP=14
mkdir -p "$DIR"; chmod 700 "$DIR"
OUT="$DIR/vault-$(date +%Y%m%d).jsonl.gz"
TMP="$OUT.partial"
trap 'rm -f "$TMP"' EXIT
sudo -u strfry /opt/strfry/strfry --config=/etc/strfry-vault.conf export | gzip -6 > "$TMP"
mv "$TMP" "$OUT"
trap - EXIT
ls -1t "$DIR"/vault-*.jsonl.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "vault backup written: $OUT ($(du -h "$OUT" | cut -f1))"
EOF
chmod 755 /usr/local/bin/favilla-vault-backup
cat > /etc/systemd/system/favilla-vault-backup.service <<'EOF'
[Unit]
Description=Export the Favilla vault relay database
[Service]
Type=oneshot
ExecStart=/usr/local/bin/favilla-vault-backup
EOF
cat > /etc/systemd/system/favilla-vault-backup.timer <<'EOF'
[Unit]
Description=Nightly Favilla vault relay export
[Timer]
OnCalendar=*-*-* 04:37:00
Persistent=true
RandomizedDelaySec=600
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now favilla-vault-backup.timer
/usr/local/bin/favilla-vault-backup
echo "nightly vault backup enabled"

say "8/8 summary"
systemctl --no-pager --lines=0 status strfry-vault.service | head -n 3
echo "relay:   wss://$DOMAIN"
echo "info:    curl -s -H 'Accept: application/nostr+json' https://$DOMAIN/"
echo "logs:    journalctl -u strfry-vault -f"
echo "size:    du -sh $DB"
echo
echo "DONE. relay.favillakey.io was not touched."
