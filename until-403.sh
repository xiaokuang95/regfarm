#!/bin/sh
# 每口并发拉满，一轮一个 IP；signup 403 的口本轮不再试。一直跑到整轮 sukses=0。
set -e
cd "$(dirname "$0")"
LOG="${LOG:-$HOME/projects/alysis_farm/out/farm.log}"
POOL=proxies.txt
N=$(grep -c . "$POOL")
round=0
echo "[$(date)] until-403 start n=$N log=$LOG" >>"$LOG"
while :; do
  round=$((round + 1))
  echo "[$(date)] ===== ROUND $round conc=$N =====" >>"$LOG"
  node cli.js --target alysis-code --count "$N" --conc "$N" --delay-min 0 --delay-max 0 --proxy-file "$POOL" >>"$LOG" 2>&1 || true
  line=$(grep 'SELESAI' "$LOG" | tail -1)
  echo "[$(date)] $line" >>"$LOG"
  case "$line" in
    *sukses=0/*) echo "[$(date)] all IPs 403, stop" >>"$LOG"; exit 0 ;;
  esac
done
