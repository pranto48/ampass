//! AMPass - Lock/Unlock State & Idle Detection
//! 
//! SECURITY: Auto-locks the vault after configurable inactivity period.
//! Clears vault key from memory on lock.
//! Also watches for browser unlock signal (native messaging IPC).

use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 1800; // 30 minutes

#[cfg(target_os = "windows")]
mod win32 {
    use std::mem;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LASTINPUTINFO {
        cbSize: u32,
        dwTime: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetLastInputInfo(plii: *mut LASTINPUTINFO) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount() -> u32;
    }

    pub fn get_idle_time() -> u64 {
        let mut lii = LASTINPUTINFO {
            cbSize: mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        unsafe {
            if GetLastInputInfo(&mut lii) != 0 {
                let current_tick = GetTickCount();
                let elapsed = current_tick.wrapping_sub(lii.dwTime);
                elapsed as u64
            } else {
                0
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(
            state: i32,
            event_type: u32,
        ) -> f64;
    }

    pub fn get_idle_time() -> u64 {
        unsafe {
            let seconds = CGEventSourceSecondsSinceLastEventType(0, 0xFFFFFFFF);
            if seconds < 0.0 {
                0
            } else {
                (seconds * 1000.0) as u64
            }
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod fallback {
    pub fn get_idle_time() -> u64 {
        0
    }
}

/// Retrieve the system idle time in milliseconds.
pub fn get_system_idle_time_ms() -> u64 {
    #[cfg(target_os = "windows")]
    {
        win32::get_idle_time()
    }
    #[cfg(target_os = "macos")]
    {
        macos::get_idle_time()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        fallback::get_idle_time()
    }
}

/// Zero-fill string using volatile writes to prevent compiler optimization
pub fn zeroize_string(s: &mut String) {
    let bytes = unsafe { s.as_mut_vec() };
    for byte in bytes.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// Set up a background task that checks for idle timeout and browser unlock signals
pub fn setup_lock_checker(app_handle: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5)); // Check every 5 seconds
            
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

            // Check idle timeout
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
            if now % 30 < 5 {
                if let Some(ref key) = *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) {
                    let _ = crate::storage::write_session_state(key);
                }
            }
            
            // Read settings to get custom lockTimeoutMin
            let timeout_secs = if let Ok(Some(settings_str)) = crate::storage::load_config("settings") {
                if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&settings_str) {
                    if let Some(min) = settings.get("lockTimeoutMin").and_then(|v| v.as_u64()) {
                        min * 60
                    } else {
                        DEFAULT_LOCK_TIMEOUT_SECS
                    }
                } else {
                    DEFAULT_LOCK_TIMEOUT_SECS
                }
            } else {
                DEFAULT_LOCK_TIMEOUT_SECS
            };

            let last_activity = *state.last_activity.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed_internal = now.saturating_sub(last_activity);
            
            let system_idle_ms = get_system_idle_time_ms();
            let system_idle_secs = system_idle_ms / 1000;

            // Effective inactivity is the minimum of system idle time and internal application inactivity
            let elapsed = std::cmp::min(elapsed_internal, system_idle_secs);
            
            if elapsed >= timeout_secs {
                // Auto-lock: clear vault key with zeroization
                if let Ok(mut key_guard) = state.vault_key.lock() {
                    if let Some(ref mut key) = *key_guard {
                        zeroize_string(key);
                    }
                    *key_guard = None;
                }
                *state.locked.lock().unwrap_or_else(|e| e.into_inner()) = true;
                let _ = crate::storage::delete_session_file();
                
                // Notify browser extension via E2EE Native Messaging
                crate::native_messaging::send_critical_lock_event();

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
