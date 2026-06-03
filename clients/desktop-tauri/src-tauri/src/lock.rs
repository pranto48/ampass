//! AMPass - Lock/Unlock State & Idle Detection
//! 
//! SECURITY: Auto-locks the vault after configurable inactivity period.
//! Clears vault key from memory on lock.
//! Also watches for browser unlock signal (native messaging IPC).

use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 1800; // 30 minutes

/// Set up a background task that checks for idle timeout and browser unlock signals
pub fn setup_lock_checker(app_handle: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2)); // Check every 2 seconds
            
            // Check for browser unlock signal
            if let Some(signal) = crate::native_messaging::read_and_clear_unlock_signal() {
                let action = signal.get("action").and_then(|v| v.as_str()).unwrap_or("");
                if action == "show_unlock" {
                    // Show/focus the main window and emit event to frontend
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("show-unlock-from-browser", signal.clone());
                    }
                }
            }

            // Check idle timeout (every 30 seconds is fine for this)
            let state = app_handle.state::<crate::AppState>();
            
            let locked = *state.locked.lock().unwrap_or_else(|e| e.into_inner());
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if locked {
                let _ = crate::storage::delete_session_file();
                continue; // Already locked, nothing to do
            }
            
            // Refresh session timestamp every 30 seconds
            if now % 30 < 2 {
                if let Some(ref key) = *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) {
                    let _ = crate::storage::write_session_state(key);
                }
            }
            
            let last_activity = *state.last_activity.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed = now.saturating_sub(last_activity);
            
            if elapsed >= DEFAULT_LOCK_TIMEOUT_SECS {
                // Auto-lock: clear vault key
                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *state.locked.lock().unwrap_or_else(|e| e.into_inner()) = true;
                
                // Notify frontend
                if let Some(window) = app_handle.get_webview_window("main") {
                    let _ = window.emit("auto-locked", ());
                }
                
                // Update tray
                crate::tray::update_tray_status(&app_handle, true);
            }
        }
    });
}
