#!/bin/sh
set -u

TARGETS_FILE="/app/targets.txt"
OUT_DIR="/app/scans"
OUT_FILE="$OUT_DIR/smap-output.json"

mkdir -p "$OUT_DIR"

if [ -f "$TARGETS_FILE" ] && [ -s "$TARGETS_FILE" ]; then
  echo "[entrypoint] Running smap with $TARGETS_FILE..."
  if /usr/local/bin/smap -iL "$TARGETS_FILE" -oJ - > "$OUT_FILE" 2> /tmp/smap-stderr.log; then
    echo "[entrypoint] smap finished successfully -> $OUT_FILE"
  else
    rc=$?
    echo "[entrypoint] smap failed (exit code $rc). Check /tmp/smap-stderr.log"
    cat /tmp/smap-stderr.log 1>&2 || true
  fi
else
  echo "[entrypoint] No targets file found."
fi

exec "$@"
