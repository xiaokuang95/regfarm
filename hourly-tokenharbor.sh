#!/bin/sh
# 每 90 分钟一轮。每轮一口一号并发，直到本轮 sukses=0
# （网络 1h 限流 / IP 已废）。邮箱未验证不算成功，不进 CPA。
set -e
export PATH="/usr/local/bin:/usr/bin:/bin"
cd "$(dirname "$0")"
LOG="${LOG:-$HOME/projects/tokenharbor_farm/out/farm.log}"
LOCKDIR="${LOCKDIR:-$HOME/projects/tokenharbor_farm/out/hourly.lock}"
POOL="${POOL:-proxies-tokenharbor.txt}"
INTERVAL="${INTERVAL:-5400}"
NODE="${NODE:-/usr/local/bin/node}"
mkdir -p "$(dirname "$LOG")"

grind() {
  N=$(grep -c . "$POOL")
  round=0
  echo "[$(date)] grind start n=$N pool=$POOL" >>"$LOG"
  while :; do
    round=$((round + 1))
    echo "[$(date)] ===== ROUND $round conc=$N =====" >>"$LOG"
    "$NODE" cli.js --target tokenharbor --count "$N" --conc "$N" --delay-min 0 --delay-max 0 --proxy-file "$POOL" >>"$LOG" 2>&1 || true
    line=$(grep 'SELESAI' "$LOG" | tail -1)
    echo "[$(date)] $line" >>"$LOG"
    case "$line" in
      *sukses=0/*) echo "[$(date)] 限流/全废, grind stop" >>"$LOG"; return 0 ;;
    esac
  done
}

if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "[$(date)] hourly skip, previous still running" >>"$LOG"
  exit 0
fi
trap 'rmdir "$LOCKDIR"' EXIT

if [ "${1:-}" = "once" ]; then
  grind
  exit 0
fi

while true; do
  grind
  echo "[$(date)] sleep ${INTERVAL}s" >>"$LOG"
  sleep "$INTERVAL"
done
