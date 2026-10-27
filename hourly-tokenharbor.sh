#!/bin/sh
# 每小时一轮：一口一号。出号/限流后 runner 把该 IP 冷却 1h。
set -e
export PATH="/usr/local/bin:/usr/bin:/bin"
cd "$(dirname "$0")"
LOG="${LOG:-$HOME/projects/tokenharbor_farm/out/farm.log}"
LOCKDIR="${LOCKDIR:-$HOME/projects/tokenharbor_farm/out/hourly.lock}"
POOL="${POOL:-proxies.txt}"
NODE="${NODE:-/usr/local/bin/node}"
mkdir -p "$(dirname "$LOG")"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "[$(date)] hourly skip, previous still running" >>"$LOG"
  exit 0
fi
trap 'rmdir "$LOCKDIR"' EXIT
N=$(grep -c . "$POOL")
echo "[$(date)] hourly start n=$N pool=$POOL" >>"$LOG"
"$NODE" cli.js --target tokenharbor --count "$N" --conc 2 --delay-min 0 --delay-max 0 --proxy-file "$POOL" >>"$LOG" 2>&1 || true
echo "[$(date)] hourly done $(grep 'SELESAI' "$LOG" | tail -1)" >>"$LOG"
