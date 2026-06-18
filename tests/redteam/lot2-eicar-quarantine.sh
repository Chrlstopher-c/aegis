#!/usr/bin/env bash
# Validation Lot 2 — détection signature + quarantaine en temps réel.
# À lancer EN ROOT :  sudo ./tests/redteam/lot2-eicar-quarantine.sh
#
# Dépose EICAR dans /tmp, tente de l'exécuter (déclenche fanotify FAN_OPEN_EXEC),
# et vérifie que le daemon le détecte (VERDICT) et le met en quarantaine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/aegis-daemon"
LOG="$ROOT/logs/lot2-test.log"
QDIR="/var/lib/aegis/quarantine"
EICAR_FILE="/tmp/aegis_eicar_$$"

[[ $EUID -eq 0 ]] || { echo "Doit être lancé en root (sudo)."; exit 1; }
[[ -x "$BIN" ]] || { echo "Binaire absent — cargo build d'abord."; exit 1; }

mkdir -p "$ROOT/logs"
: > "$LOG"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  rm -f "$EICAR_FILE"
}
trap cleanup EXIT

echo "▶ Démarrage du daemon (règles : $ROOT/rules)…"
AEGIS_RULES_DIR="$ROOT/rules" RUST_LOG=info "$BIN" >> "$LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "✗ daemon non démarré :"; cat "$LOG"; exit 1; }

echo "▶ Dépôt d'EICAR dans /tmp et tentative d'exécution…"
# Chaîne EICAR assemblée à la volée (pas de fichier de test AV dans le dépôt).
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_FILE"
chmod +x "$EICAR_FILE"
"$EICAR_FILE" >/dev/null 2>&1 || true   # exec échoue (pas un vrai binaire), mais open-exec est capté
sleep 1.5

echo "▶ Recherche du verdict dans le flux :"
if grep -q "VERDICT" "$LOG" && grep -q "quarantaine" "$LOG"; then
  grep -E "VERDICT|quarantaine" "$LOG"
  echo "▶ Contenu du store de quarantaine :"
  ls -l "$QDIR" 2>/dev/null
  echo "✓ EICAR détecté et mis en quarantaine en temps réel."
else
  echo "✗ Détection/quarantaine absente. Log :"; cat "$LOG"; exit 1
fi
