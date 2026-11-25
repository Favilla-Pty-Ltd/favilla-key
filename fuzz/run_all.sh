#!/bin/sh
# Run every ESP32-side parser fuzzer for SECS seconds each, JOBS at a time (9u).
#   sh fuzz/run_all.sh 600 2
# corpus/<name> (ignored by git) grows each run; seeds/<name> is the committed,
# minimised set (refresh: out/fuzz_<name> -merge=1 seeds/<name> corpus/<name>).
# Findings land in fuzz/findings/<name>/ (crash-*, timeout-*, oom-*); logs in fuzz/logs/.
cd "$(dirname "$0")"
SECS=${1:-600}; JOBS=${2:-2}
mkdir -p logs findings
run(){ n=$1; shift; mkdir -p corpus/$n seeds/$n findings/$n
  out/fuzz_$n corpus/$n seeds/$n -max_total_time=$SECS -close_fd_mask=3 -artifact_prefix=findings/$n/ -print_final_stats=1 "$@" > logs/$n.log 2>&1
  echo "$n: exit $? $(grep -E '^#[0-9]+.*DONE' logs/$n.log | tail -1 | sed 's/ *lim.*//')"; }
set -- api_decode app_channel chan_key otpauth login_qr app_pair_qr "event_id -max_len=4096" psbt "quirc -max_len=3918" ur "ctap -max_len=2048" "ctap_pkr -max_len=2048" "vault_restore -max_len=8192" "rk_health -max_len=2048"
i=0
for t in "$@"; do run $t & i=$((i+1)); [ $((i % JOBS)) -eq 0 ] && wait; done
wait
