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
pub mod native_messaging;

use std::sync::Mutex;
use tauri::{Emitter, Manager, WindowEvent};
/// Application state shared across commands
pub struct AppState {
    pub vault_key: Mutex<Option<String>>,
    pub server_url: Mutex<Option<String>>,
    pub auth_token: Mutex<Option<String>>,
    pub locked: Mutex<bool>,
    pub last_activity: Mutex<u64>,
    pub last_active_app: Mutex<Option<ActiveAppInfo>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            vault_key: Mutex::new(None),
            server_url: Mutex::new(None),
            auth_token: Mutex::new(None),
            locked: Mutex::new(true),
            last_activity: Mutex::new(0),
            last_active_app: Mutex::new(None),
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
async fn store_derivation_params(params_json: String) -> Result<(), String> {
    storage::save_secure_config("derivation_params", &params_json)
}

#[tauri::command]
async fn load_derivation_params() -> Result<Option<String>, String> {
    storage::load_secure_config("derivation_params")
}

#[tauri::command]
async fn clear_derivation_params() -> Result<(), String> {
    storage::delete_secure_config("derivation_params")
}

/// Check if a trusted session exists (token + server_url + derivation_params).
/// Used by frontend to decide whether to show Unlock or Login screen.
#[tauri::command]
async fn has_trusted_session(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let has_token = state.auth_token.lock().map_err(|e| e.to_string())?.is_some();
    let has_url = state.server_url.lock().map_err(|e| e.to_string())?.is_some();
    let has_params = storage::load_secure_config("derivation_params")
        .map(|v| v.is_some())
        .unwrap_or(false);
    Ok(has_token && has_url && has_params)
}

/// Save user display info (username/email) for trusted PC unlock screen.
/// SECURITY: Only stores display name, never passwords or keys.
#[tauri::command]
async fn save_user_summary(user_json: String) -> Result<(), String> {
    storage::save_secure_config("user_summary", &user_json)
}

/// Load user display info for trusted PC unlock screen.
#[tauri::command]
async fn load_user_summary() -> Result<Option<String>, String> {
    storage::load_secure_config("user_summary")
}

/// Clear all trusted PC data (token, derivation params, user summary).
/// Called on explicit sign-out or token revocation.
#[tauri::command]
async fn clear_trusted_pc(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.vault_key.lock().map_err(|e| e.to_string())? = None;
    *state.auth_token.lock().map_err(|e| e.to_string())? = None;
    *state.locked.lock().map_err(|e| e.to_string())? = true;
    let _ = keychain::delete_token();
    let _ = storage::delete_secure_config("derivation_params");
    let _ = storage::delete_secure_config("user_summary");
    Ok(())
}

#[tauri::command]
async fn unlock_vault(vault_key_hex: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Store vault key in memory only
    *state.vault_key.lock().map_err(|e| e.to_string())? = Some(vault_key_hex.clone());
    *state.locked.lock().map_err(|e| e.to_string())? = false;
    
    // Write encrypted session file
    storage::write_session_state(&vault_key_hex).map_err(|e| e.to_string())?;
    
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
    let _ = storage::delete_session_file();
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
    let _ = storage::delete_session_file();
    storage::wipe_all().map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
async fn logout(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.vault_key.lock().map_err(|e| e.to_string())? = None;
    *state.auth_token.lock().map_err(|e| e.to_string())? = None;
    *state.locked.lock().map_err(|e| e.to_string())? = true;
    let _ = keychain::delete_token();
    let _ = storage::delete_secure_config("derivation_params");
    let _ = storage::delete_session_file();
    Ok(())
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    let url = url.trim().to_string();
    if url.is_empty() {
        return Err("Empty URL".to_string());
    }
    if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("mailto:") {
        return Err("Unsupported URL protocol".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", &url])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn get_app_version() -> Result<String, String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
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

// ================================================================
// APP LAUNCH & REMOTE DESKTOP COMMANDS
// SECURITY: Never passes passwords as command-line arguments.
// ================================================================

/// Launch a desktop application by executable path.
/// SECURITY: Never passes passwords as command-line arguments.
/// Only accepts a single executable path — no arguments, no shell metacharacters.
#[tauri::command]
async fn launch_application(path: String) -> Result<(), String> {
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("Empty path".to_string());
    }

    // Reject dangerous patterns
    if path.contains('\0') || path.contains('\r') || path.contains('\n') {
        return Err("Path contains invalid characters".to_string());
    }
    if path.contains("..") {
        return Err("Path traversal not allowed".to_string());
    }

    // Reject shell metacharacters that could enable injection
    let dangerous_chars = ['|', '&', ';', '`', '$', '>', '<', '!', '{', '}'];
    for ch in &dangerous_chars {
        if path.contains(*ch) {
            return Err(format!("Path contains disallowed character: {}", ch));
        }
    }

    let path_obj = std::path::Path::new(&path);

    // Reject .bat and .cmd files (script injection risk)
    let ext = path_obj.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext == "bat" || ext == "cmd" || ext == "ps1" || ext == "vbs" || ext == "wsf" {
        return Err(format!("Script files (.{}) are not allowed for security reasons. Only .exe, .msi, .lnk are supported.", ext));
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        match ext.as_str() {
            "exe" | "msi" => {
                // Direct execution for real executables — no shell involved
                if !path_obj.exists() {
                    return Err(format!("Executable not found: {}", path));
                }
                Command::new(&path)
                    .spawn()
                    .map_err(|e| format!("Failed to launch: {}", e))?;
            }
            "lnk" => {
                // Shell links: use explorer to open safely
                Command::new("explorer.exe")
                    .arg(&path)
                    .spawn()
                    .map_err(|e| format!("Failed to open shortcut: {}", e))?;
            }
            _ => {
                // For other file types or paths without extension,
                // try direct execution if the file exists
                if path_obj.exists() {
                    Command::new(&path)
                        .spawn()
                        .map_err(|e| format!("Failed to launch: {}", e))?;
                } else {
                    return Err(format!("File not found: {}", path));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if !path_obj.exists() {
            return Err(format!("File not found: {}", path));
        }
        if path.ends_with(".app") || path_obj.is_dir() {
            Command::new("open")
                .arg(&path)
                .spawn()
                .map_err(|e| format!("Failed to launch .app bundle: {}", e))?;
        } else {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path)
                .map_err(|e| format!("Cannot read file: {}", e))?;
            if metadata.permissions().mode() & 0o111 == 0 {
                Command::new("open")
                    .arg(&path)
                    .spawn()
                    .map_err(|e| format!("Failed to open file: {}", e))?;
            } else {
                Command::new(&path)
                    .spawn()
                    .map_err(|e| format!("Failed to launch: {}", e))?;
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::process::Command;
        if !path_obj.exists() {
            return Err(format!("File not found: {}", path));
        }
        // Check if file is executable
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&path)
            .map_err(|e| format!("Cannot read file: {}", e))?;
        if metadata.permissions().mode() & 0o111 == 0 {
            // Not executable, try xdg-open
            Command::new("xdg-open")
                .arg(&path)
                .spawn()
                .map_err(|e| format!("Failed to open: {}", e))?;
        } else {
            Command::new(&path)
                .spawn()
                .map_err(|e| format!("Failed to launch: {}", e))?;
        }
    }

    Ok(())
}

/// Open a file's location in the file explorer.
#[tauri::command]
async fn open_file_location(path: String) -> Result<(), String> {
    let path = path.trim().to_string();
    if path.is_empty() { return Err("Empty path".to_string()); }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("explorer")
            .args(["/select,", &path])
            .spawn()
            .map_err(|e| format!("Failed to open location: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("open")
            .args(["-R", &path])
            .spawn()
            .map_err(|e| format!("Failed to open location: {}", e))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let parent = std::path::Path::new(&path).parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());
        use std::process::Command;
        Command::new("xdg-open")
            .arg(&parent)
            .spawn()
            .map_err(|e| format!("Failed to open location: {}", e))?;
    }

    Ok(())
}

/// Open an RDP connection by creating a temporary .rdp file.
/// SECURITY: Password is NEVER written to the .rdp file.
/// User must copy password separately and paste when prompted.
/// Validates host/username to prevent .rdp line injection via CR/LF.
#[tauri::command]
async fn open_rdp_connection(host: String, port: u16, username: String, redirect_clipboard: bool) -> Result<(), String> {
    // Validate host
    let host = host.trim().to_string();
    if host.is_empty() { return Err("Host is required".to_string()); }
    if host.len() > 255 { return Err("Host too long (max 255 chars)".to_string()); }

    // Reject CR, LF, null bytes, and control characters in host
    for ch in host.chars() {
        if ch == '\r' || ch == '\n' || ch == '\0' || ch.is_control() {
            return Err("Host contains invalid control characters".to_string());
        }
    }
    // Allow only hostname/IP characters: A-Z a-z 0-9 . - _ :
    if !host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':') {
        return Err("Host contains disallowed characters. Only alphanumeric, dot, dash, underscore, colon allowed.".to_string());
    }

    // Validate port
    if port == 0 { return Err("Port must be 1-65535".to_string()); }

    // Validate username (reject CR/LF/control chars)
    let username = username.trim().to_string();
    if username.len() > 256 { return Err("Username too long (max 256 chars)".to_string()); }
    for ch in username.chars() {
        if ch == '\r' || ch == '\n' || ch == '\0' || (ch.is_control() && ch != '\t') {
            return Err("Username contains invalid control characters".to_string());
        }
    }

    // Create temporary .rdp file content (NO password, NO secrets)
    let mut rdp_content = String::new();
    rdp_content.push_str(&format!("full address:s:{}:{}\r\n", host, port));
    if !username.is_empty() {
        rdp_content.push_str(&format!("username:s:{}\r\n", username));
    }
    rdp_content.push_str("screen mode id:i:2\r\n"); // fullscreen
    if redirect_clipboard {
        rdp_content.push_str("redirectclipboard:i:1\r\n");
    }
    rdp_content.push_str("prompt for credentials:i:1\r\n"); // Always prompt for password

    // Write to temp file
    let temp_dir = std::env::temp_dir();
    let rdp_filename = format!("ampass_rdp_{}.rdp", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis());
    let rdp_path = temp_dir.join(&rdp_filename);

    std::fs::write(&rdp_path, &rdp_content)
        .map_err(|e| format!("Failed to create .rdp file: {}", e))?;

    // Launch mstsc with the .rdp file
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("mstsc")
            .arg(rdp_path.to_string_lossy().to_string())
            .spawn()
            .map_err(|e| format!("Failed to launch mstsc: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let rdp_uri = if username.is_empty() {
            format!("rdp://full%20address=s:{}:{}", host, port)
        } else {
            format!("rdp://full%20address=s:{}:{}&username=s:{}", host, port, username)
        };
        let result = Command::new("open")
            .arg(&rdp_uri)
            .spawn();
        if result.is_err() {
            let result_x = Command::new("xfreerdp")
                .arg(format!("/v:{}:{}", host, port))
                .arg(format!("/u:{}", username))
                .arg("/cert:ignore")
                .spawn();
            if result_x.is_err() {
                Command::new("rdesktop")
                    .arg(format!("{}:{}", host, port))
                    .spawn()
                    .map_err(|e| format!("Failed to launch RDP client: {}", e))?;
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // On Linux, try xfreerdp or rdesktop
        use std::process::Command;
        let result = Command::new("xfreerdp")
            .arg(format!("/v:{}:{}", host, port))
            .arg(format!("/u:{}", username))
            .arg("/cert:ignore")
            .spawn();
        if result.is_err() {
            Command::new("rdesktop")
                .arg(format!("{}:{}", host, port))
                .spawn()
                .map_err(|e| format!("Failed to launch RDP client: {}", e))?;
        }
    }

    // Schedule temp file deletion after 45 seconds (gives mstsc time to read it)
    let rdp_path_clone = rdp_path.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(45));
        let _ = std::fs::remove_file(rdp_path_clone);
    });

    Ok(())
}

/// Pick an executable file using system file dialog.
/// SECURITY: Only allows .exe, .msi, .lnk — no .bat/.cmd (script injection risk).
#[tauri::command]
async fn pick_executable(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let file = app.dialog()
        .file()
        .add_filter("Applications", &["exe", "msi", "lnk"])
        .add_filter("All Files", &["*"])
        .set_title("Select Application")
        .blocking_pick_file();

    match file {
        Some(path) => {
            let path = path.into_path()
                .map_err(|_| "Selected file path is not accessible".to_string())?;
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None), // User cancelled
    }
}

/// List installed applications (Windows Start Menu + registry).
/// Does NOT require admin permissions.
#[tauri::command]
async fn list_installed_apps() -> Result<Vec<serde_json::Value>, String> {
    let mut apps: Vec<serde_json::Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Scan Start Menu shortcuts
        let start_menu_paths = vec![
            std::env::var("ProgramData").unwrap_or_default() + r"\Microsoft\Windows\Start Menu\Programs",
            std::env::var("APPDATA").unwrap_or_default() + r"\Microsoft\Windows\Start Menu\Programs",
        ];

        for base_path in &start_menu_paths {
            if let Ok(entries) = std::fs::read_dir(base_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "lnk").unwrap_or(false) {
                        let name = path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if !name.is_empty() && !name.starts_with("Uninstall") {
                            apps.push(serde_json::json!({
                                "name": name,
                                "path": path.to_string_lossy().to_string(),
                                "source": "start_menu"
                            }));
                        }
                    }
                }
            }
        }

        // Limit to avoid huge lists
        apps.truncate(200);
    }

    #[cfg(target_os = "macos")]
    {
        let macos_dirs = vec![
            "/Applications".to_string(),
            "/System/Applications".to_string(),
            format!("{}/Applications", std::env::var("HOME").unwrap_or_default()),
        ];
        for dir in &macos_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "app").unwrap_or(false) {
                        let name = path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if !name.is_empty() {
                            apps.push(serde_json::json!({
                                "name": name,
                                "path": path.to_string_lossy().to_string(),
                                "source": "macos_applications"
                            }));
                        }
                    }
                }
            }
        }
        apps.truncate(200);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // On Linux, scan .desktop files
        let desktop_dirs = vec![
            "/usr/share/applications".to_string(),
            format!("{}/.local/share/applications", std::env::var("HOME").unwrap_or_default()),
        ];
        for dir in &desktop_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "desktop").unwrap_or(false) {
                        let name = path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        apps.push(serde_json::json!({
                            "name": name,
                            "path": path.to_string_lossy().to_string(),
                            "source": "desktop_file"
                        }));
                    }
                }
            }
        }
        apps.truncate(200);
    }

    Ok(apps)
}

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let is_native_messaging = args.iter().any(|arg| {
        arg == "--native-messaging" 
            || arg.starts_with("chrome-extension://") 
            || arg.starts_with("moz-extension://")
    });

    if is_native_messaging {
        native_messaging::run_native_messaging_loop(
            || {
                storage::read_session_state().unwrap_or((true, None))
            },
            || {
                let _ = storage::delete_session_file();
            }
        );
        std::process::exit(0);
    }

    // Check for --show-unlock argument (launched by native messaging host)
    let show_unlock = args.iter().any(|a| a == "--show-unlock");

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
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            set_server_url,
            store_auth_token,
            get_auth_token,
            store_derivation_params,
            load_derivation_params,
            clear_derivation_params,
            has_trusted_session,
            save_user_summary,
            load_user_summary,
            clear_trusted_pc,
            unlock_vault,
            lock_vault,
            is_vault_locked,
            save_vault_cache,
            load_vault_cache,
            wipe_local_data,
            logout,
            record_activity,
            launch_application,
            open_file_location,
            open_rdp_connection,
            pick_executable,
            list_installed_apps,
            backup::pick_backup_file,
            backup::pick_save_location,
            open_url,
            get_app_version,
            get_detected_app,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            // Set up system tray
            tray::setup_tray(app)?;
            
            // Set up idle lock checker
            lock::setup_lock_checker(app.handle().clone());

            // Set up active application tracker background thread
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    if let Ok(info) = get_active_app_internal() {
                        // Ignore our own app
                        let own_names = ["ampass-desktop", "ampass", "AMPass", "ampass_desktop"];
                        let is_own = own_names.iter().any(|&name| {
                            info.name.to_lowercase().contains(name) || info.executable_path.to_lowercase().contains(name)
                        });
                        
                        if !is_own && !info.name.is_empty() {
                            let state = app_handle.state::<AppState>();
                            if let Ok(mut guard) = state.last_active_app.lock() {
                                *guard = Some(info);
                            };
                        }
                    }
                }
            });

            // If launched with --show-unlock, emit event to frontend after window is ready
            if show_unlock {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    if let Some(window) = handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("show-unlock-from-browser", serde_json::json!({"reason": "launched_by_native_host"}));
                    }
                });
            }
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running AMPass desktop app");
}

#[derive(serde::Serialize, Clone, Debug, Default)]
pub struct ActiveAppInfo {
    pub name: String,
    pub executable_path: String,
    pub title: String,
}

#[tauri::command]
async fn get_detected_app(state: tauri::State<'_, AppState>) -> Result<Option<ActiveAppInfo>, String> {
    let last = state.last_active_app.lock().map_err(|e| e.to_string())?.clone();
    Ok(last)
}

fn get_active_app_internal() -> Result<ActiveAppInfo, String> {
    #[cfg(target_os = "windows")]
    {
        get_active_app_windows()
    }
    #[cfg(target_os = "macos")]
    {
        get_active_app_macos()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Ok(ActiveAppInfo::default())
    }
}

#[cfg(target_os = "windows")]
fn get_active_app_windows() -> Result<ActiveAppInfo, String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
    use windows_sys::Win32::System::Threading::{GetWindowThreadProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExW;
    use windows_sys::Win32::Foundation::CloseHandle;

    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd == 0 {
            return Err("No active window".to_string());
        }

        // Get window title
        let mut title_buf = [0u16; 512];
        let title_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 512);
        let title = if title_len > 0 {
            String::from_utf16_lossy(&title_buf[..title_len as usize])
        } else {
            String::new()
        };

        // Get Process ID
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);

        if pid == 0 {
            return Ok(ActiveAppInfo {
                name: String::new(),
                executable_path: String::new(),
                title,
            });
        }

        // Open Process
        let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process_handle == 0 {
            return Ok(ActiveAppInfo {
                name: String::new(),
                executable_path: String::new(),
                title,
            });
        }

        // Get Executable Path
        let mut path_buf = [0u16; 1024];
        let mut path_len = 1024u32;
        let mut exe_path = String::new();
        let res = GetModuleFileNameExW(process_handle, 0, path_buf.as_mut_ptr(), path_len);
        if res > 0 {
            exe_path = String::from_utf16_lossy(&path_buf[..res as usize]);
        }
        CloseHandle(process_handle);

        let name = if !exe_path.is_empty() {
            std::path::Path::new(&exe_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        Ok(ActiveAppInfo {
            name,
            executable_path: exe_path,
            title,
        })
    }
}

#[cfg(target_os = "macos")]
fn get_active_app_macos() -> Result<ActiveAppInfo, String> {
    // Run `lsappinfo front` to get the active ASN
    let front_output = std::process::Command::new("lsappinfo")
        .arg("front")
        .output()
        .map_err(|e| e.to_string())?;
    
    let front_str = String::from_utf8_lossy(&front_output.stdout).trim().to_string();
    if front_str.is_empty() {
        return Err("No frontmost application found".to_string());
    }

    // Run `lsappinfo info [ASN]` to get info
    let info_output = std::process::Command::new("lsappinfo")
        .args(&["info", &front_str])
        .output()
        .map_err(|e| e.to_string())?;

    let info_str = String::from_utf8_lossy(&info_output.stdout);
    
    // Parse info
    let mut name = String::new();
    let mut exe_path = String::new();
    
    if let Some(first_line) = info_str.lines().next() {
        if let Some(quote_end) = first_line[1..].find('"') {
            name = first_line[1..quote_end + 1].to_string();
        }
    }

    for line in info_str.lines() {
        let line = line.trim();
        if line.starts_with("executable path=") {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start+1..].find('"') {
                    exe_path = line[start+1..start+1+end].to_string();
                }
            }
        }
    }

    let title = get_frontmost_window_title_macos().unwrap_or_default();

    Ok(ActiveAppInfo {
        name,
        executable_path: exe_path,
        title,
    })
}

#[cfg(target_os = "macos")]
fn get_frontmost_window_title_macos() -> Option<String> {
    let output = std::process::Command::new("osascript")
        .args(&["-e", "tell application \"System Events\" to get name of first window of (first process whose frontmost is true)"])
        .output()
        .ok()?;
    
    if output.status.success() {
        let title = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !title.is_empty() {
            return Some(title);
        }
    }
    None
}
