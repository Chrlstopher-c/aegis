//! Client de contrôle Aegis (Tauri). Vit dans le SysTray : icône bouclier,
//! statut live (vert = protégé, rouge = menace), clic → ouvre le dashboard.
//! La fenêtre se masque (close-to-tray) au lieu de quitter ; `--hidden` la
//! garde repliée au démarrage (autostart au login).

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};

const TRAY_ID: &str = "aegis";
const ICON_OK: &[u8] = include_bytes!("../icons/tray-64.png");
const ICON_ALERT: &[u8] = include_bytes!("../icons/tray-alert-64.png");

/// Met à jour l'icône et l'infobulle du tray selon l'état de protection.
/// Appelée par le front à chaque changement de statut / nombre de menaces.
#[tauri::command]
fn set_protection_status(app: AppHandle, online: bool, threats: u32) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let bytes = if online && threats == 0 { ICON_OK } else { ICON_ALERT };
    if let Ok(icon) = Image::from_bytes(bytes) {
        let _ = tray.set_icon(Some(icon));
    }
    let tip = match (online, threats) {
        (false, _) => "Aegis — daemon hors ligne".to_string(),
        (true, 0) => "Aegis — protection active".to_string(),
        (true, n) => format!("Aegis — {n} détection(s)"),
    };
    let _ = tray.set_tooltip(Some(&tip));
}

/// Révèle et met au premier plan la fenêtre principale.
fn reveal_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Ouvrir Aegis", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quitter", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let icon = Image::from_bytes(ICON_OK).map_err(|e| tauri::Error::Anyhow(e.into()))?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("Aegis — protection active")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => reveal_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button, button_state, .. } = event {
                if button == MouseButton::Left && button_state == MouseButtonState::Up {
                    reveal_window(tray.app_handle());
                }
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let start_hidden = std::env::args().any(|a| a == "--hidden");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![set_protection_status])
        .setup(move |app| {
            build_tray(app.handle())?;
            if !start_hidden {
                reveal_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Croix = repli dans le tray, pas un arrêt (l'AV reste accessible).
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
