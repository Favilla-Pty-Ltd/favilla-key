#!/bin/bash
# 28 Oct 2026: chain-walk scenarios (life, refresh, Afterglow, Kindling) under ASan + UBSan.
set -e
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Isrc tests/host_ember_walk.c src/ember_walk.c -o /tmp/g0_ember_walk
/tmp/g0_ember_walk "$@"
