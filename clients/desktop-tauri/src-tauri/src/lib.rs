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

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_os = "windows"))]
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
            launch_application,
            open_file_location,
            open_rdp_connection,
            pick_executable,
            list_installed_apps,
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
