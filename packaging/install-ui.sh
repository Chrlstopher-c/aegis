#!/usr/bin/env bash
# Intègre le client de contrôle Aegis (AppImage) à l'environnement de bureau,
# sans root : copie l'AppImage, pose l'entrée .desktop, l'icône, et l'autostart
# (tray au login). Le daemon (protection réelle) reste géré par install.sh/systemd.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ID="agency.echo.aegis"
BUNDLE_DIR="$REPO_ROOT/ui/src-tauri/target/release/bundle/appimage"
ICON_SRC="$REPO_ROOT/ui/src-tauri/icons/icon.png"

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
AUTOSTART_DIR="$HOME/.config/autostart"
TARGET_APPIMAGE="$BIN_DIR/Aegis.AppImage"

appimage="$(find "$BUNDLE_DIR" -maxdepth 1 -name '*.AppImage' 2>/dev/null | head -1 || true)"
if [[ -z "$appimage" ]]; then
  echo "✗ Aucune AppImage trouvée dans $BUNDLE_DIR — lance d'abord: bun run tauri build" >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$AUTOSTART_DIR"

install -m 755 "$appimage" "$TARGET_APPIMAGE"
install -m 644 "$ICON_SRC" "$ICON_DIR/$APP_ID.png"

# WEBKIT_DISABLE_DMABUF_RENDERER=1 : sans ça, webkit2gtk rend un écran blanc sous
# Wayland (bug connu dmabuf). Indispensable dans le .desktop (le lanceur ne porte
# pas l'env du shell).
WEBKIT_ENV="env WEBKIT_DISABLE_DMABUF_RENDERER=1 WEBKIT_DISABLE_COMPOSITING_MODE=1"

cat > "$APP_DIR/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Aegis
Comment=EDR local souverain — protection desktop
Exec=$WEBKIT_ENV $TARGET_APPIMAGE
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;System;
StartupNotify=true
EOF

cat > "$AUTOSTART_DIR/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Aegis (tray)
Comment=Client de contrôle Aegis dans le SysTray
Exec=$WEBKIT_ENV $TARGET_APPIMAGE --hidden
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;System;
X-GNOME-Autostart-enabled=true
EOF

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

echo "✓ Aegis intégré :"
echo "  AppImage   → $TARGET_APPIMAGE"
echo "  Lanceur    → $APP_DIR/$APP_ID.desktop"
echo "  Autostart  → $AUTOSTART_DIR/$APP_ID.desktop (tray au login, --hidden)"
echo "  Le bouclier apparaît dans le SysTray dès le lancement."
