#!/bin/sh
set -u

TARGETS_FILE="/app/targets.txt"
OUT_DIR="/app/scans"
JSON_FILE="$OUT_DIR/smap-output.json"
XML_FILE="$OUT_DIR/smap-output.xml"
STDERR_LOG="/tmp/smap-stderr.log"
DB_PATH="/app/data/smap.db"

mkdir -p "$OUT_DIR" "$(dirname "$DB_PATH")"

# ── Pre-flight checks ────────────────────────────────────────
echo "[entrypoint] === PRE-FLIGHT ==="

# Test HTTPS to Shodan InternetDB
printf "[entrypoint] Testing internetdb.shodan.io ... "
if curl -sf --max-time 10 "https://internetdb.shodan.io/1.1.1.1" > /tmp/shodan-test.json 2>/dev/null; then
  TESTSIZE=$(wc -c < /tmp/shodan-test.json | tr -d ' ')
  echo "OK ($TESTSIZE bytes)"
  head -c 200 /tmp/shodan-test.json
  echo ""
else
  echo "FAILED"
  echo "[entrypoint] WARNING: Cannot reach internetdb.shodan.io"
  echo "[entrypoint] smap needs HTTPS access to https://internetdb.shodan.io"
  echo "[entrypoint] Checking TLS..."
  curl -vI --max-time 10 "https://internetdb.shodan.io/1.1.1.1" 2>&1 \
    | grep -i -E "(ssl|tls|cert|error|failed)" | head -10 | sed 's/^/  /'
  echo ""
  echo "[entrypoint] Checking DNS..."
  nslookup internetdb.shodan.io 2>&1 | head -5 | sed 's/^/  /'
  echo ""
fi

# ── Targets ───────────────────────────────────────────────────
if [ ! -f "$TARGETS_FILE" ] || [ ! -s "$TARGETS_FILE" ]; then
  echo "[entrypoint] No targets file or empty."
  exec "$@"
fi

NTARGETS=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
echo "[entrypoint] $NTARGETS targets in $TARGETS_FILE"

# ── Scan: try JSON ────────────────────────────────────────────
echo "[entrypoint] Running: smap -iL $TARGETS_FILE -oJ $JSON_FILE"
smap -iL "$TARGETS_FILE" -oJ "$JSON_FILE" 2>"$STDERR_LOG"
SCAN_RC=$?
echo "[entrypoint] smap exit: $SCAN_RC"

SCAN_FILE=""

if [ -f "$JSON_FILE" ]; then
  SIZE=$(wc -c < "$JSON_FILE" | tr -d ' ')
  echo "[entrypoint] JSON: $SIZE bytes"
  if [ "$SIZE" -gt 5 ]; then
    SCAN_FILE="$JSON_FILE"
    echo "[entrypoint] JSON output looks good"
    head -c 300 "$JSON_FILE" | sed 's/^/  /'
    echo ""
  else
    echo "[entrypoint] JSON empty: $(cat "$JSON_FILE")"
    rm -f "$JSON_FILE"
  fi
fi

# ── Fallback: XML ─────────────────────────────────────────────
if [ -z "$SCAN_FILE" ]; then
  echo "[entrypoint] Falling back to XML..."
  smap -iL "$TARGETS_FILE" -oX "$XML_FILE" 2>>"$STDERR_LOG"
  if [ -f "$XML_FILE" ]; then
    SIZE=$(wc -c < "$XML_FILE" | tr -d ' ')
    echo "[entrypoint] XML: $SIZE bytes"
    if [ "$SIZE" -gt 100 ]; then
      SCAN_FILE="$XML_FILE"
    fi
  fi
fi

# ── Stderr summary ────────────────────────────────────────────
if [ -s "$STDERR_LOG" ]; then
  ERRS=$(grep -c "InternetDB request failed" "$STDERR_LOG" 2>/dev/null || true)
  ERRS="${ERRS:-0}"
  # Garantir que ERRS est bien un entier
  case "$ERRS" in
    ''|*[!0-9]*) ERRS=0 ;;
  esac
  if [ "$ERRS" -gt 0 ]; then
    echo ""
    echo "[entrypoint] WARNING: $ERRS InternetDB HTTPS failures"
    echo "[entrypoint] smap cannot reach https://internetdb.shodan.io"
    echo "[entrypoint] Scan data will be minimal (no Shodan enrichment)"
    echo "[entrypoint] First 3 errors:"
    grep "InternetDB request failed" "$STDERR_LOG" | head -3 | sed 's/^/  /'
  fi
fi

# ── Import ────────────────────────────────────────────────────
echo ""
if [ -n "$SCAN_FILE" ]; then
  echo "[entrypoint] Importing $SCAN_FILE → $DB_PATH"
  python3 /app/import_smap.py "$SCAN_FILE" "$DB_PATH"
else
  echo "[entrypoint] No scan data produced."
  echo "[entrypoint] Creating empty DB with schema..."
  python3 -c "
import sqlite3, sys
sys.path.insert(0, '/app')
from import_smap import ensure_schema
conn = sqlite3.connect('$DB_PATH')
ensure_schema(conn)
conn.close()
print('[entrypoint] Empty DB created with schema')
"
fi

echo "[entrypoint] === DONE ==="
exec "$@"