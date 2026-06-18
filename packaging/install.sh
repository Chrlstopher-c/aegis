#!/usr/bin/env bash
# Installe Aegis comme service systemd avec capabilities minimales.
# À lancer EN ROOT :  sudo ./packaging/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="$ROOT/target/release/aegis-daemon"
BIN_DST="/usr/local/bin/aegis-daemon"
RULES_DST="/usr/share/aegis/rules"
UNIT_DST="/etc/systemd/system/aegis.service"

[[ $EUID -eq 0 ]] || { echo "Doit être lancé en root (sudo)."; exit 1; }

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Binaire release absent. Compile d'abord : cargo build --release"
  exit 1
fi

echo "▶ Installation du binaire → $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"

echo "▶ Installation des règles → $RULES_DST"
mkdir -p "$RULES_DST"
cp -r "$ROOT/rules/." "$RULES_DST/"

echo "▶ Installation de l'unit systemd → $UNIT_DST"
install -m 0644 "$ROOT/packaging/aegis.service" "$UNIT_DST"
mkdir -p /var/lib/aegis

systemctl daemon-reload
echo "✓ Installé. Activer : systemctl enable --now aegis"
echo "  Logs : journalctl -u aegis -f"
