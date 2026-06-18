#!/usr/bin/env bash
# Validation Lot 3 — ransomware simulé tué avant propagation (canari + kill).
# À lancer EN ROOT :  sudo ./tests/redteam/lot3-ransomware-kill.sh
#
# Le daemon déploie des canaris dans un dossier de test, puis un faux ransomware
# réécrit en masse les fichiers du dossier. Le canari (préfixe 0000) est touché
# tôt → Aegis tue le process avant qu'il ait pu chiffrer toutes les victimes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/aegis-daemon"
LOG="$ROOT/logs/lot3-test.log"
ZONE="/tmp/aegis_ransotest_$$"
VICTIMS=2000

[[ $EUID -eq 0 ]] || { echo "Doit être lancé en root (sudo)."; exit 1; }
[[ -x "$BIN" ]] || { echo "Binaire absent — cargo build d'abord."; exit 1; }

mkdir -p "$ROOT/logs" "$ZONE"
: > "$LOG"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$ZONE"
}
trap cleanup EXIT

echo "▶ Création de $VICTIMS fichiers victimes dans $ZONE…"
for i in $(seq 1 $VICTIMS); do printf 'donnees precieuses %d\n' "$i" > "$ZONE/victim_$i.txt"; done

echo "▶ Démarrage du daemon (canaris dans la zone de test)…"
AEGIS_CANARY_DIRS="$ZONE" AEGIS_RULES_DIR="$ROOT/rules" RUST_LOG=info "$BIN" >> "$LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "✗ daemon non démarré :"; cat "$LOG"; exit 1; }

echo "▶ Lancement du faux ransomware (réécriture en masse, ordre trié)…"
cat > "$ZONE/.encrypt.sh" <<'RANSOM'
#!/bin/sh
DIR="$1"
for f in $(ls -a "$DIR" | sort); do
  case "$f" in .|..|.encrypt.sh) continue ;; esac
  printf 'ENCRYPTED_BY_RANSOM\n' > "$DIR/$f"
done
RANSOM
chmod +x "$ZONE/.encrypt.sh"
"$ZONE/.encrypt.sh" "$ZONE" >/dev/null 2>&1 || true
sleep 1

echo "▶ Verdict Aegis :"
grep -E "VERDICT|neutralisé|ransomware" "$LOG" || true

encrypted=$(grep -l "ENCRYPTED_BY_RANSOM" "$ZONE"/victim_*.txt 2>/dev/null | wc -l)
echo "▶ Victimes chiffrées : $encrypted / $VICTIMS"

if grep -q "neutralisé" "$LOG" && [ "$encrypted" -lt $((VICTIMS / 2)) ]; then
  echo "✓ Ransomware neutralisé avant propagation (majorité des victimes intactes)."
else
  echo "✗ Échec : neutralisation absente ou propagation trop large."; cat "$LOG"; exit 1
fi
