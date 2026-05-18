//! AMPass - System Tray
//! Provides tray icon with lock/unlock status and quick actions.

use tauri::{
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    menu::{Menu, MenuItem},
    Manager, AppHandle,
};

pub fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open_item = MenuItem::with_id(app, "open", "Open AMPass", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open_item, &lock_item, &quit_item])?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("AMPass - Vault Locked")
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "open" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "lock" => {
                    // Send lock command to frontend
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.emit("tray-lock", ());
                    }
                }
                "quit" => {
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Update tray tooltip based on lock state
pub fn update_tray_status(app: &AppHandle, locked: bool) {
    if let Some(tray) = app.tray_by_id("main") {
        let tooltip = if locked { "AMPass - Vault Locked" } else { "AMPass - Vault Unlocked" };
        let _ = tray.set_tooltip(Some(tooltip));
    }
}
