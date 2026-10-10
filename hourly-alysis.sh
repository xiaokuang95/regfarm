#!/bin/sh
# 每小时一轮：一口一号。403 短 ban 约 1h，下轮再试。
set -e
export PATH="/usr/local/bin:/usr/bin:/bin"
cd "$(dirname "$0")"
LOG="${LOG:-$HOME/projects/alysis_farm/out/farm.log}"
LOCKDIR="${LOCKDIR:-$HOME/projects/alysis_farm/out/hourly.lock}"
POOL=proxies.txt
mkdir -p "$(dirname "$LOG")"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "[$(date)] hourly skip, previous still running" >>"$LOG"
  exit 0
fi
trap 'rmdir "$LOCKDIR"' EXIT
N=$(grep -c . "$POOL")
echo "[$(date)] hourly start n=$N" >>"$LOG"
/usr/local/bin/node cli.js --target alysis-code --count "$N" --conc "$N" --delay-min 0 --delay-max 0 --proxy-file "$POOL" >>"$LOG" 2>&1 || true
echo "[$(date)] hourly done $(grep 'SELESAI' "$LOG" | tail -1)" >>"$LOG"
