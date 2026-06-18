#!/usr/bin/env bash
# Supprime les fichiers canari déposés par Aegis dans les zones de données.
# Utile après un run de test/dev lancé en root sans AEGIS_CANARY_DIRS.
# Lancer en root si les canaris appartiennent à root :  sudo ./scripts/clean-canaries.sh
set -euo pipefail

# Home ciblé : celui de SUDO_USER si présent, sinon HOME courant.
if [[ -n "${SUDO_USER:-}" ]]; then
  HOME_DIR="/home/$SUDO_USER"
else
  HOME_DIR="$HOME"
fi

removed=0
for sub in Documents Pictures Desktop; do
  for name in 0000_aegis_canary.docx zzzz_aegis_canary.xlsx; do
    f="$HOME_DIR/$sub/$name"
    if [[ -e "$f" ]]; then
      rm -f "$f" && removed=$((removed + 1))
    fi
  done
done
echo "✓ $removed canari(s) supprimé(s) sous $HOME_DIR."
