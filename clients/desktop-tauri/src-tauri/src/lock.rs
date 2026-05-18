//! AMPass - Lock/Unlock State & Idle Detection
//! 
//! SECURITY: Auto-locks the vault after configurable inactivity period.
//! Clears vault key from memory on lock.

use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};

const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 900; // 15 minutes

/// Set up a background task that checks for idle timeout
pub fn setup_lock_checker(app_handle: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30)); // Check every 30 seconds
            
            let state = app_handle.state::<crate::AppState>();
            
            let locked = *state.locked.lock().unwrap_or_else(|e| e.into_inner());
            if locked {
                continue; // Already locked, nothing to do
            }
            
            let last_activity = *state.last_activity.lock().unwrap_or_else(|e| e.into_inner());
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
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
