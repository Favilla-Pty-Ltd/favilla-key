#!/bin/bash
# Builds the public copy of this repo: the tree at HEAD (or the commit given)
# minus tools/public_exclude.txt, scanned for secrets and personal details,
# committed as one fresh commit with no history.
#   tools/export_public.sh <out-dir> [commit]
# The commit's date is the private commit's date, so the same input gives the
# same public commit id.
set -euo pipefail
OUT=${1:?usage: tools/export_public.sh <out-dir> [commit]}
REV=${2:-HEAD}
ROOT=$(git rev-parse --show-toplevel)
[ -e "$OUT" ] && { echo "$OUT exists: give a new directory"; exit 1; }
mkdir -p "$OUT"
git -C "$ROOT" archive "$REV" | tar -x -C "$OUT"
while IFS= read -r p; do
  case "$p" in ''|\#*) continue;; esac
  rm -rf "${OUT:?}/$p"
done < <(git -C "$ROOT" show "$REV:tools/public_exclude.txt")

# Scan: anything here stops the export. Patterns, not values: no secret is
# written in this script.
fail=0
# A line naming a third-party author (Copyright, Author) is not a hit.
scan(){ local what=$1; shift; local hits; hits=$(grep -rIn -E "$@" "$OUT" --exclude-dir=components --exclude-dir=lib --exclude-dir=seeds 2>/dev/null | grep -v -i -E 'copyright|\(c\)|author' | cut -d: -f1 | sort -u || true)
  if [ -n "$hits" ]; then echo "STOP: $what"; echo "$hits" | sed "s#^$OUT/#  #"; fail=1; fi; }
scan "a Nostr private key" 'nsec1[02-9ac-hj-np-z]{20,}'
scan "a PEM private key" -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----'
scan "a GitHub token" 'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}'
scan "a TURN or API secret assigned in code" -i '(turn_secret|turn_password|static_auth_secret|api_key)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}'
# Personal details are not written here (this script is public): give a file
# of extended regexes, one per line, kept outside the repo.
if [ -n "${FAVILLA_PRIVATE_SCAN:-}" ]; then
  while IFS= read -r pat; do [ -n "$pat" ] && scan "a personal detail (private pattern list)" -i "$pat"; done < "$FAVILLA_PRIVATE_SCAN"
else echo "note: FAVILLA_PRIVATE_SCAN not set, personal details not scanned"; fi
scan "a personal mail address" -i '[a-z0-9._-]+@(icloud|gmail|proton(mail)?|pm)\.(com|me)' --exclude=imp_test.js
scan "a workers.dev or github.io service address" -i 'https?://[a-z0-9.-]+\.(workers\.dev|github\.io)'
for p in $(git -C "$ROOT" show "$REV:tools/public_exclude.txt" | grep -v -E '^(#|$)'); do
  b=$(basename "$p"); case "$b" in public_exclude.txt|*[!.]) [[ "$b" == *.* ]] || continue;; esac; [ "$b" = public_exclude.txt ] && continue
  hits=$(grep -rIl --exclude-dir=components --exclude-dir=lib -F "$b" "$OUT" 2>/dev/null || true)
  [ -n "$hits" ] && echo "note: $b is left out but named in: $(echo $hits | sed "s#$OUT/##g")"
done
[ $fail = 0 ] || { echo "export stopped; fix the private repo and run again"; exit 1; }

DATE=$(git -C "$ROOT" log -1 --format=%cI "$REV")
SRC=$(git -C "$ROOT" rev-parse --short "$REV")
DROP=$(grep -o 'FAVILLA_BENCH_DROP "[^"]*"' "$OUT/src/main.cpp" | cut -d'"' -f2)
cd "$OUT"
git init -q -b main
git add -A
GIT_AUTHOR_NAME="Favilla Pty Ltd" GIT_AUTHOR_EMAIL="noreply@favillakey.io" GIT_AUTHOR_DATE="$DATE" \
GIT_COMMITTER_NAME="Favilla Pty Ltd" GIT_COMMITTER_EMAIL="noreply@favillakey.io" GIT_COMMITTER_DATE="$DATE" \
  git commit -q -m "Favilla KEY firmware, drop $DROP" -m "ESP32-S3 firmware, the STM32G0B1 isolated signer, the browser extension, host tests, fuzz targets and the protocols. GPL-3.0."
echo "public copy of $SRC (drop $DROP): $(git rev-parse --short HEAD), $(git ls-files | wc -l) files"
