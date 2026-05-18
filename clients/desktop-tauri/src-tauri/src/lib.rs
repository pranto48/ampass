//! AMPass Desktop App - Tauri v2
//! 
//! SECURITY: This app is a client for the AMPass PHP server.
//! - Never stores plaintext vault secrets on disk
//! - Vault key exists in memory only while unlocked
//! - Local cache is encrypted with a device key from OS keychain
//! - Master password is never stored

mod keychain;
mod storage;
mod tray;
mod lock;
mod backup;

use std::sync::Mutex;
use tauri::Manager;

/// Application state shared across commands
pub struct AppState {
    pub vault_key: Mutex<Option<String>>,
    pub server_url: Mutex<Option<String>>,
    pub auth_token: Mutex<Option<String>>,
    pub locked: Mutex<bool>,
    pub last_activity: Mutex<u64>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            vault_key: Mutex::new(None),
            server_url: Mutex::new(None),
            auth_token: Mutex::new(None),
            locked: Mutex::new(true),
            last_activity: Mutex::new(0),
        }
    }
}

#[tauri::command]
async fn get_app_state(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let locked = *state.locked.lock().map_err(|e| e.to_string())?;
    let has_token = state.auth_token.lock().map_err(|e| e.to_string())?.is_some();
    let server_url = state.server_url.lock().map_err(|e| e.to_string())?.clone();

    Ok(serde_json::json!({
        "locked": locked,
        "authenticated": has_token,
        "server_url": server_url,
        "configured": server_url.is_some()
    }))
}

#[tauri::command]
async fn set_server_url(url: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let trimmed = url.trim_end_matches('/').to_string();
    *state.server_url.lock().map_err(|e| e.to_string())? = Some(trimmed.clone());
    
    // Persist to config
    storage::save_config("server_url", &trimmed).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn store_auth_token(token: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Store in OS keychain
    keychain::store_token(&token).map_err(|e| e.to_string())?;
    *state.auth_token.lock().map_err(|e| e.to_string())? = Some(token);
    Ok(())
}

#[tauri::command]
async fn get_auth_token(state: tauri::State<'_, AppState>) -> Result<Option<String>, String> {
    let token = state.auth_token.lock().map_err(|e| e.to_string())?.clone();
    Ok(token)
}

#[tauri::command]
async fn unlock_vault(vault_key_hex: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Store vault key in memory only
    *state.vault_key.lock().map_err(|e| e.to_string())? = Some(vault_key_hex);
    *state.locked.lock().map_err(|e| e.to_string())? = false;
    
    // Update last activity
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    *state.last_activity.lock().map_err(|e| e.to_string())? = now;
    
    Ok(())
}

#[tauri::command]
async fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    // SECURITY: Clear vault key from memory
    *state.vault_key.lock().map_err(|e| e.to_string())? = None;
    *state.locked.lock().map_err(|e| e.to_string())? = true;
    Ok(())
}

#[tauri::command]
async fn is_vault_locked(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(*state.locked.lock().map_err(|e| e.to_string())?)
}

#[tauri::command]
async fn save_vault_cache(encrypted_items_json: String) -> Result<(), String> {
    storage::write_cache(&encrypted_items_json).map_err(|e| e.to_string())
}

#[tauri::command]
async fn load_vault_cache() -> Result<Option<String>, String> {
    storage::read_cache().map_err(|e| e.to_string())
}

#[tauri::command]
async fn wipe_local_data(state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Clear memory
    *state.vault_key.lock().map_err(|e| e.to_string())? = None;
    *state.auth_token.lock().map_err(|e| e.to_string())? = None;
    *state.locked.lock().map_err(|e| e.to_string())? = true;
    
    // Clear keychain
    let _ = keychain::delete_token();
    let _ = keychain::delete_device_key();
    
    // Clear local files
    storage::wipe_all().map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
async fn logout(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.vault_key.lock().map_err(|e| e.to_string())? = None;
    *state.auth_token.lock().map_err(|e| e.to_string())? = None;
    *state.locked.lock().map_err(|e| e.to_string())? = true;
    let _ = keychain::delete_token();
    Ok(())
}

#[tauri::command]
async fn record_activity(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    *state.last_activity.lock().map_err(|e| e.to_string())? = now;
    Ok(())
}

pub fn run() {
    let app_state = AppState::default();
    
    // Try to restore server URL from config
    if let Ok(Some(url)) = storage::load_config("server_url") {
        *app_state.server_url.lock().unwrap() = Some(url);
    }
    
    // Try to restore auth token from keychain
    if let Ok(Some(token)) = keychain::retrieve_token() {
        *app_state.auth_token.lock().unwrap() = Some(token);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_global_shortcut::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            set_server_url,
            store_auth_token,
            get_auth_token,
            unlock_vault,
            lock_vault,
            is_vault_locked,
            save_vault_cache,
            load_vault_cache,
            wipe_local_data,
            logout,
            record_activity,
            backup::pick_backup_file,
            backup::pick_save_location,
        ])
        .setup(|app| {
            // Set up system tray
            tray::setup_tray(app)?;
            
            // Set up idle lock checker
            lock::setup_lock_checker(app.handle().clone());
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running AMPass desktop app");
}
