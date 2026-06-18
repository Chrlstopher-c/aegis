#!/usr/bin/env bash
# Arrête le daemon Aegis via son PID file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT/logs/aegis.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Pas de PID file, Aegis ne tourne pas."
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Aegis arrêté (PID $PID)."
else
  echo "Process $PID introuvable, nettoyage du PID file."
fi
rm -f "$PID_FILE"
