#!/usr/bin/env bash
# Validation Lot 5 — FIM credential access (lecture de fichier sensible détectée).
# À lancer EN ROOT :  sudo ./tests/redteam/lot5-credential-fim.sh
#
# Le daemon surveille un fichier sensible de test en lecture. Un process non
# allowlisté (cat) le lit → détection CredentialAccess (T1003).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/aegis-daemon"
LOG="$ROOT/logs/lot5-test.log"
SECRET="/tmp/aegis_secret_$$"

[[ $EUID -eq 0 ]] || { echo "Doit être lancé en root (sudo)."; exit 1; }
[[ -x "$BIN" ]] || { echo "Binaire absent — cargo build d'abord."; exit 1; }

mkdir -p "$ROOT/logs"
: > "$LOG"
printf 'root:$6$secret-hash\n' > "$SECRET"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  rm -f "$SECRET"
}
trap cleanup EXIT

echo "▶ Démarrage du daemon (fichier sensible surveillé : $SECRET)…"
AEGIS_SENSITIVE_FILES="$SECRET" AEGIS_RULES_DIR="$ROOT/rules" RUST_LOG=info \
  "$BIN" >> "$LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "✗ daemon non démarré :"; cat "$LOG"; exit 1; }

echo "▶ Lecture du fichier sensible par 'cat' (non allowlisté)…"
cat "$SECRET" >/dev/null 2>&1 || true
sleep 1

echo "▶ Verdict Aegis :"
if grep -q "Lecture de credentials" "$LOG"; then
  grep -E "VERDICT|credentials" "$LOG"
  echo "✓ Accès credential détecté (CredentialAccess / T1003)."
else
  echo "✗ Détection absente. Log :"; cat "$LOG"; exit 1
fi
