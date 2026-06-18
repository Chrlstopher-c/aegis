#!/usr/bin/env bash
# Démarre le daemon Aegis en arrière-plan. PID dans logs/aegis.pid, logs reset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT/logs"
PID_FILE="$LOG_DIR/aegis.pid"
LOG_FILE="$LOG_DIR/daemon.log"
BIN="$ROOT/target/debug/aegis-daemon"

mkdir -p "$LOG_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Aegis tourne déjà (PID $(cat "$PID_FILE"))."
  exit 0
fi

if [[ ! -x "$BIN" ]]; then
  echo "Binaire absent. Compile d'abord : cargo build"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "⚠ Lancé sans root : les capteurs fanotify échoueront (mode dégradé)."
  echo "  Pour la protection réelle : sudo ./scripts/start.sh — ou le service systemd"
  echo "  (packaging/install.sh). Mode démo UI : ajoute --demo via AEGIS_ARGS."
fi

: > "$LOG_FILE"  # reset, pas d'append
RUST_LOG="${RUST_LOG:-info}" AEGIS_RULES_DIR="${AEGIS_RULES_DIR:-$ROOT/rules}" \
  "$BIN" ${AEGIS_ARGS:-} >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "Aegis démarré (PID $(cat "$PID_FILE")). Logs : $LOG_FILE"
