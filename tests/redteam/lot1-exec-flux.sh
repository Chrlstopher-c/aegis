#!/usr/bin/env bash
# Validation Lot 1 — flux exec temps réel via fanotify.
# À lancer EN ROOT (fanotify FAN_OPEN_EXEC_PERM exige CAP_SYS_ADMIN) :
#   sudo ./tests/redteam/lot1-exec-flux.sh
#
# Démarre le daemon, exécute un binaire trivial copié dans /tmp, et vérifie que
# l'exécution apparaît dans le flux. Nettoie tout en sortie.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/aegis-daemon"
LOG="$ROOT/logs/lot1-test.log"
DECOY="/tmp/aegis_decoy_$$"

[[ $EUID -eq 0 ]] || { echo "Doit être lancé en root (sudo)."; exit 1; }
[[ -x "$BIN" ]] || { echo "Binaire absent — cargo build d'abord."; exit 1; }

mkdir -p "$ROOT/logs"
: > "$LOG"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  rm -f "$DECOY"
}
trap cleanup EXIT

echo "▶ Démarrage du daemon…"
RUST_LOG=info "$BIN" >> "$LOG" 2>&1 &
DAEMON_PID=$!
sleep 1.5

if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "✗ Le daemon n'a pas démarré :"; cat "$LOG"; exit 1
fi

echo "▶ Création + exécution d'un binaire depuis /tmp…"
printf '#!/bin/sh\necho aegis-decoy\n' > "$DECOY"
chmod +x "$DECOY"
"$DECOY" >/dev/null 2>&1 || true
sleep 1

echo "▶ Flux capté (extrait) :"
grep -F "$DECOY" "$LOG" && echo "✓ Exécution depuis /tmp détectée dans le flux." \
  || { echo "✗ Exécution non détectée. Log complet :"; cat "$LOG"; exit 1; }
