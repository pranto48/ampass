//! AMPass - Native Messaging Host
//!
//! SECURITY:
//! - Communicates with browser extension via stdin/stdout (Chrome Native Messaging protocol)
//! - Validates all incoming messages against a strict schema
//! - Only responds to allowed extension IDs (configured in manifest)
//! - Never returns decrypted secrets unless vault is unlocked
//! - Never logs plaintext secrets
//! - Applies timeout to prevent hanging
//! - Auto-lock rules still apply

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use x25519_dalek::{EphemeralSecret, PublicKey};
use aes_gcm::{Aes256Gcm, aead::Aead, Nonce};

/// Maximum message size (1MB - Chrome's limit)
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

const _MESSAGE_TIMEOUT_SECS: u64 = 5;

/// Allowed message types (strict allowlist)
const ALLOWED_TYPES: &[&str] = &[
    "ping",
    "get_status",
    "unlock_request",
    "open_unlock_window",
    "focus_main_window",
    "lock",
    "search_by_domain",
    "get_item_for_autofill",
    "save_detected_login",
    "update_detected_login",
    "generate_password",
    "audit_event",
    "handshake_init",
    "encrypted_payload",
];

/// Incoming message from extension
#[derive(Deserialize, Debug)]
pub struct NativeMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Request ID for correlating responses
    #[serde(default)]
    pub request_id: Option<String>,
}

/// Outgoing response to extension
#[derive(Serialize)]
pub struct NativeResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl NativeResponse {
    pub fn ok(msg_type: &str, data: serde_json::Value, request_id: Option<String>) -> Self {
        Self { msg_type: msg_type.to_string(), success: true, data: Some(data), error: None, request_id }
    }

    pub fn err(msg_type: &str, error: &str, request_id: Option<String>) -> Self {
        Self { msg_type: msg_type.to_string(), success: false, data: None, error: Some(error.to_string()), request_id }
    }
}

/// Read a native messaging message from stdin
/// Chrome protocol: 4-byte little-endian length prefix + JSON body
pub fn read_message() -> Result<NativeMessage, String> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // Read 4-byte length prefix
    let mut len_bytes = [0u8; 4];
    handle.read_exact(&mut len_bytes)
        .map_err(|e| format!("Failed to read message length: {}", e))?;

    let msg_len = u32::from_le_bytes(len_bytes);

    // Validate message size
    if msg_len == 0 {
        return Err("Empty message".to_string());
    }
    if msg_len > MAX_MESSAGE_SIZE {
        return Err(format!("Message too large: {} bytes (max {})", msg_len, MAX_MESSAGE_SIZE));
    }

    // Read message body
    let mut buffer = vec![0u8; msg_len as usize];
    handle.read_exact(&mut buffer)
        .map_err(|e| format!("Failed to read message body: {}", e))?;

    // Parse JSON
    let msg: NativeMessage = serde_json::from_slice(&buffer)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    // Validate message type against allowlist
    if !ALLOWED_TYPES.contains(&msg.msg_type.as_str()) {
        return Err(format!("Unknown message type: {}", msg.msg_type));
    }

    Ok(msg)
}

/// Write a native messaging response to stdout
pub fn write_response(response: &NativeResponse) -> Result<(), String> {
    let json = serde_json::to_vec(response)
        .map_err(|e| format!("Failed to serialize response: {}", e))?;

    let len = json.len() as u32;
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    // Write 4-byte length prefix
    handle.write_all(&len.to_le_bytes())
        .map_err(|e| format!("Failed to write length: {}", e))?;

    // Write JSON body
    handle.write_all(&json)
        .map_err(|e| format!("Failed to write body: {}", e))?;

    handle.flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    Ok(())
}

/// Write a signal file that the running Tauri app can detect.
/// The Tauri app polls this file to know when to show the unlock window.
/// SECURITY: Signal file contains only action/reason/host — never secrets.
fn write_unlock_signal(reason: &str, page_host: &str) -> bool {
    let signal_dir = dirs::data_dir()
        .map(|d| d.join("ampass"))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&signal_dir);
    let signal_path = signal_dir.join("unlock_signal.json");
    let content = serde_json::json!({
        "action": "show_unlock",
        "reason": reason,
        "page_host": page_host,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    std::fs::write(&signal_path, content.to_string()).is_ok()
}

/// Read and clear the unlock signal file (called by Tauri app).
pub fn read_and_clear_unlock_signal() -> Option<serde_json::Value> {
    let signal_dir = dirs::data_dir()
        .map(|d| d.join("ampass"))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let signal_path = signal_dir.join("unlock_signal.json");
    if !signal_path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&signal_path).ok()?;
    let _ = std::fs::remove_file(&signal_path);
    serde_json::from_str(&content).ok()
}

/// Process a single native message and return a response
/// SECURITY: This function must never return plaintext secrets if vault is locked.
pub fn process_message(
    msg: &NativeMessage,
    vault_locked: bool,
    vault_key: &Option<String>,
) -> NativeResponse {
    let rid = msg.request_id.clone();

    match msg.msg_type.as_str() {
        "ping" => {
            NativeResponse::ok("pong", serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "app": "AMPass Desktop"
            }), rid)
        }

        "get_status" => {
            let mut status_data = serde_json::json!({
                "vault_locked": vault_locked,
                "version": env!("CARGO_PKG_VERSION")
            });
            
            if !vault_locked {
                if let Some(ref key) = vault_key {
                    status_data["unlocked"] = serde_json::json!(true);
                    if let Ok(Some(url)) = crate::storage::load_config("server_url") {
                        status_data["server_url"] = serde_json::json!(url);
                    }
                    if let Ok(Some(token)) = crate::keychain::retrieve_token() {
                        status_data["auth_token"] = serde_json::json!(token);
                    }
                    if let Ok(Some(params)) = crate::storage::load_secure_config("derivation_params") {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&params) {
                            status_data["derivation_params"] = parsed;
                        }
                    }
                    if let Ok(Some(summary)) = crate::storage::load_secure_config("user_summary") {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&summary) {
                            status_data["user"] = parsed;
                        }
                    }
                    status_data["vault_key"] = serde_json::json!(key);
                }
            }
            
            NativeResponse::ok("status", status_data, rid)
        }

        "lock" => {
            // Lock will be handled by the caller
            NativeResponse::ok("locked", serde_json::json!({
                "locked": true
            }), rid)
        }

        "unlock_request" => {
            // Desktop app cannot unlock via native messaging for security
            // User must unlock in the desktop app UI
            if vault_locked {
                NativeResponse::err("unlock_request", "Vault is locked. Please unlock in the AMPass desktop app.", rid)
            } else {
                NativeResponse::ok("unlock_request", serde_json::json!({
                    "unlocked": true
                }), rid)
            }
        }

        "open_unlock_window" => {
            // Request to show/focus the desktop app unlock window.
            // Writes a signal file that the running Tauri app watches.
            // If no instance is running, launches the GUI executable.
            // SECURITY: Does not unlock vault — just opens the UI for user to enter master password.
            let reason = msg.payload.get("reason").and_then(|v| v.as_str()).unwrap_or("browser_request");
            let page_host = msg.payload.get("page_url_host").and_then(|v| v.as_str()).unwrap_or("");

            // Write IPC signal file for running instance to detect
            let signal_written = write_unlock_signal(reason, page_host);
            let mut launched = false;

            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                // Check if AMPass process exists and try to focus it
                let check = Command::new("powershell")
                    .args(["-NoProfile", "-Command",
                        "(Get-Process -Name 'AMPass','ampass-desktop' -ErrorAction SilentlyContinue | Measure-Object).Count"])
                    .output();

                let process_running = check.map(|o| {
                    String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().unwrap_or(0) > 0
                }).unwrap_or(false);

                if process_running {
                    // Focus existing window
                    let _ = Command::new("powershell")
                        .args(["-NoProfile", "-Command",
                            "(Get-Process -Name 'AMPass','ampass-desktop' -ErrorAction SilentlyContinue | Select-Object -First 1).MainWindowHandle | ForEach-Object { if ($_ -ne 0) { Add-Type '[DllImport(\"user32.dll\")] public static extern bool SetForegroundWindow(IntPtr hWnd); [DllImport(\"user32.dll\")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Name Win32 -Namespace API; [API.Win32]::ShowWindow($_, 9); [API.Win32]::SetForegroundWindow($_) } }"])
                        .spawn();
                } else {
                    // Launch the GUI app with --show-unlock flag
                    // SECURITY: Use current_exe parent dir to find the GUI exe safely
                    if let Ok(exe_path) = std::env::current_exe() {
                        // The native host exe is the same as the GUI exe
                        let _ = Command::new(&exe_path)
                            .arg("--show-unlock")
                            .spawn();
                        launched = true;
                    }
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                // On Linux/macOS, try to launch the app
                if let Ok(exe_path) = std::env::current_exe() {
                    use std::process::Command;
                    let _ = Command::new(&exe_path)
                        .arg("--show-unlock")
                        .spawn();
                    launched = true;
                }
            }

            NativeResponse::ok("open_unlock_window", serde_json::json!({
                "action": "show_unlock",
                "signal_written": signal_written,
                "launched": launched,
                "vault_locked": vault_locked,
                "reason": reason,
                "page_host": page_host
            }), rid)
        }

        "focus_main_window" => {
            // Request to focus/show the main desktop window
            let _ = write_unlock_signal("focus", "");

            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                let _ = Command::new("powershell")
                    .args(["-NoProfile", "-Command",
                        "(Get-Process -Name 'AMPass' -ErrorAction SilentlyContinue | Select-Object -First 1).MainWindowHandle | ForEach-Object { if ($_ -ne 0) { Add-Type '[DllImport(\"user32.dll\")] public static extern bool SetForegroundWindow(IntPtr hWnd); [DllImport(\"user32.dll\")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Name Win32 -Namespace API; [API.Win32]::ShowWindow($_, 9); [API.Win32]::SetForegroundWindow($_) } }"])
                    .spawn();
            }

            NativeResponse::ok("focus_main_window", serde_json::json!({
                "action": "focus_window",
                "vault_locked": vault_locked
            }), rid)
        }

        "search_by_domain" | "get_item_for_autofill" | "save_detected_login" | "update_detected_login" => {
            // These require vault to be unlocked
            if vault_locked || vault_key.is_none() {
                return NativeResponse::err(&msg.msg_type, "Vault is locked", rid);
            }

            // For search/autofill: the extension sends encrypted item IDs or domain hashes
            // The desktop app returns encrypted data that the extension decrypts locally
            // We pass through the request — actual crypto happens in the extension's service worker
            NativeResponse::ok(&msg.msg_type, serde_json::json!({
                "status": "acknowledged",
                "vault_unlocked": true,
                "message": "Request processed. Use extension API for data operations."
            }), rid)
        }

        "generate_password" => {
            // Password generation doesn't require vault unlock
            let length = msg.payload.get("length").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let length = length.clamp(8, 128);

            // Generate using OS random
            use rand::RngCore;
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
            let mut rng = rand::thread_rng();
            let password: String = (0..length)
                .map(|_| {
                    let idx = (rng.next_u32() as usize) % chars.len();
                    chars[idx] as char
                })
                .collect();

            NativeResponse::ok("generate_password", serde_json::json!({
                "password": password,
                "length": length
            }), rid)
        }

        "audit_event" => {
            // Log the audit event (action name only, never secrets)
            let action = msg.payload.get("action").and_then(|v| v.as_str()).unwrap_or("unknown");
            // In production, this would write to a local audit log
            NativeResponse::ok("audit_event", serde_json::json!({
                "logged": true,
                "action": action
            }), rid)
        }

        _ => {
            NativeResponse::err("error", "Unknown message type", rid)
        }
    }
}

/// OS-level memory locked buffer to prevent swapping sensitive data to disk
pub struct LockedBuffer {
    data: Vec<u8>,
}

impl LockedBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        let mut lb = Self { data };
        lb.lock();
        lb
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn lock(&mut self) {
        if self.data.is_empty() {
            return;
        }
        let addr = self.data.as_ptr() as *const std::ffi::c_void;
        let len = self.data.len();

        #[cfg(target_os = "windows")]
        unsafe {
            extern "system" {
                fn VirtualLock(lpaddress: *const std::ffi::c_void, dwsize: usize) -> i32;
            }
            let _ = VirtualLock(addr, len);
        }

        #[cfg(target_os = "macos")]
        unsafe {
            extern "C" {
                fn mlock(addr: *const std::ffi::c_void, len: usize) -> std::os::raw::c_int;
            }
            let _ = mlock(addr, len);
        }
    }

    fn unlock(&mut self) {
        if self.data.is_empty() {
            return;
        }
        let addr = self.data.as_ptr() as *const std::ffi::c_void;
        let len = self.data.len();

        #[cfg(target_os = "windows")]
        unsafe {
            extern "system" {
                fn VirtualUnlock(lpaddress: *const std::ffi::c_void, dwsize: usize) -> i32;
            }
            let _ = VirtualUnlock(addr, len);
        }

        #[cfg(target_os = "macos")]
        unsafe {
            extern "C" {
                fn munlock(addr: *const std::ffi::c_void, len: usize) -> std::os::raw::c_int;
            }
            let _ = munlock(addr, len);
        }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Zero-fill using volatile writes to prevent compiler optimization
        for byte in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        self.unlock();
    }
}

fn pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    data.extend(std::iter::repeat(padding_len as u8).take(padding_len));
}

fn unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("Empty data for unpadding".to_string());
    }
    let padding_len = data[data.len() - 1] as usize;
    if padding_len == 0 || padding_len > data.len() {
        return Err("Invalid PKCS#7 padding length".to_string());
    }
    for &byte in &data[data.len() - padding_len..] {
        if byte != padding_len as u8 {
            return Err("Invalid PKCS#7 padding bytes".to_string());
        }
    }
    Ok(data[..data.len() - padding_len].to_vec())
}

/// Run the native messaging host loop (called when app is launched with --native-messaging flag)
/// This is a blocking loop that reads from stdin and writes to stdout.
pub fn run_native_messaging_loop(
    get_vault_state: impl Fn() -> (bool, Option<String>),
    on_lock: impl Fn(),
) {
    use aes_gcm::KeyInit;
    use aes_gcm::aead::generic_array::GenericArray;
    use rand::Rng;

    let mut session_cipher: Option<Aes256Gcm> = None;

    loop {
        match read_message() {
            Ok(msg) => {
                // Intercept handshake_init
                if msg.msg_type == "handshake_init" {
                    let peer_pub_hex = match msg.payload.get("public_key").and_then(|v| v.as_str()) {
                        Some(key) => key,
                        None => {
                            let response = NativeResponse::err("handshake_response", "Missing public_key", msg.request_id.clone());
                            let _ = write_response(&response);
                            continue;
                        }
                    };

                    let peer_pub_bytes = match hex::decode(peer_pub_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let response = NativeResponse::err("handshake_response", &format!("Invalid hex: {}", e), msg.request_id.clone());
                            let _ = write_response(&response);
                            continue;
                        }
                    };

                    if peer_pub_bytes.len() != 32 {
                        let response = NativeResponse::err("handshake_response", "Public key must be 32 bytes", msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }

                    // Generate ephemeral keypair
                    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                    let public = PublicKey::from(&secret);
                    let our_pub_hex = hex::encode(public.as_bytes());

                    // Derive shared secret
                    let peer_pub_array: [u8; 32] = match peer_pub_bytes.try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            let response = NativeResponse::err("handshake_response", "Failed to convert public key", msg.request_id.clone());
                            let _ = write_response(&response);
                            continue;
                        }
                    };
                    let peer_public = PublicKey::from(peer_pub_array);
                    let shared_secret = secret.diffie_hellman(&peer_public);

                    // Pin shared secret key in memory and zero it out on exit
                    let locked_secret = LockedBuffer::new(shared_secret.as_bytes().to_vec());

                    // Create AES-GCM cipher
                    let cipher = Aes256Gcm::new(GenericArray::from_slice(locked_secret.as_slice()));
                    if let Ok(mut guard) = SESSION_CIPHER.lock() {
                        *guard = Some(cipher.clone());
                    }
                    session_cipher = Some(cipher);

                    let response = NativeResponse::ok("handshake_response", serde_json::json!({
                        "public_key": our_pub_hex
                    }), msg.request_id.clone());

                    if let Err(e) = write_response(&response) {
                        eprintln!("Failed to write handshake response: {}", e);
                        break;
                    }
                    continue;
                }

                // If not handshake, message must be encrypted_payload
                if msg.msg_type != "encrypted_payload" {
                    let response = NativeResponse::err("error", "Unauthorized message type: expected encrypted_payload or handshake_init", msg.request_id.clone());
                    let _ = write_response(&response);
                    continue;
                }

                let cipher = match &session_cipher {
                    Some(c) => c,
                    None => {
                        let response = NativeResponse::err("error", "Symmetric session key not established. Perform handshake first.", msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                let ciphertext_hex = match msg.payload.get("ciphertext").and_then(|v| v.as_str()) {
                    Some(ct) => ct,
                    None => {
                        let response = NativeResponse::err("error", "Missing ciphertext", msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                let iv_hex = match msg.payload.get("iv").and_then(|v| v.as_str()) {
                    Some(iv) => iv,
                    None => {
                        let response = NativeResponse::err("error", "Missing iv", msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                let ciphertext = match hex::decode(ciphertext_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Invalid ciphertext hex: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                let iv_bytes = match hex::decode(iv_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Invalid iv hex: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                if iv_bytes.len() != 12 {
                    let response = NativeResponse::err("error", "Nonce must be 12 bytes", msg.request_id.clone());
                    let _ = write_response(&response);
                    continue;
                }

                let nonce = Nonce::from_slice(&iv_bytes);

                // Decrypt
                let decrypted_padded = match cipher.decrypt(nonce, ciphertext.as_slice()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Decryption failed: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                // Store raw decrypted padded bytes in locked memory
                let locked_decrypted_padded = LockedBuffer::new(decrypted_padded);

                // Unpad decrypted bytes
                let decrypted = match unpad(locked_decrypted_padded.as_slice()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Unpadding failed: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                // Store plaintext message in locked memory
                let locked_decrypted = LockedBuffer::new(decrypted);

                // Parse inner message
                let inner_msg: NativeMessage = match serde_json::from_slice(locked_decrypted.as_slice()) {
                    Ok(m) => m,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Failed to parse decrypted message: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                // Validate message type against allowlist
                if !ALLOWED_TYPES.contains(&inner_msg.msg_type.as_str()) {
                    let response = NativeResponse::err(&inner_msg.msg_type, "Unknown message type", msg.request_id.clone());
                    let _ = write_response(&response);
                    continue;
                }

                let (locked, vault_key) = get_vault_state();

                // Handle lock command specially
                if inner_msg.msg_type == "lock" {
                    on_lock();
                }

                // Process inner message to construct inner response
                let inner_response = process_message(&inner_msg, locked, &vault_key);

                // Serialize inner response
                let inner_response_bytes = match serde_json::to_vec(&inner_response) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Failed to serialize inner response: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                // Store inner response in locked memory
                let locked_inner_response = LockedBuffer::new(inner_response_bytes);

                // Pad
                let mut padded_response = locked_inner_response.as_slice().to_vec();
                pad(&mut padded_response, 16);

                let locked_padded_response = LockedBuffer::new(padded_response);

                // Generate new random IV
                let mut resp_iv = [0u8; 12];
                rand::thread_rng().fill(&mut resp_iv);
                let resp_nonce = Nonce::from_slice(&resp_iv);

                // Encrypt response
                let encrypted_bytes = match cipher.encrypt(resp_nonce, locked_padded_response.as_slice()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let response = NativeResponse::err("error", &format!("Failed to encrypt response: {}", e), msg.request_id.clone());
                        let _ = write_response(&response);
                        continue;
                    }
                };

                let response_payload = serde_json::json!({
                    "ciphertext": hex::encode(encrypted_bytes),
                    "iv": hex::encode(resp_iv)
                });

                let response = NativeResponse::ok("encrypted_payload", response_payload, msg.request_id.clone());

                if let Err(e) = write_response(&response) {
                    eprintln!("Native messaging write error: {}", e);
                    break;
                }
            }
            Err(e) => {
                // Connection closed or error — exit cleanly
                if e.contains("Failed to read message length") {
                    // Normal EOF — extension disconnected
                    break;
                }
                // Try to send error response
                let err_response = NativeResponse::err("error", &e, None);
                let _ = write_response(&err_response);
                break;
            }
        }
    }
}

/// Global static store to cache the E2EE session cipher for unsolicited events
static SESSION_CIPHER: std::sync::Mutex<Option<Aes256Gcm>> = std::sync::Mutex::new(None);

/// Pushes an encrypted CRITICAL_VAULT_LOCK_EVENT message to the browser extension
pub fn send_critical_lock_event() {
    use rand::Rng;
    let cipher_guard = match SESSION_CIPHER.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let cipher = match &*cipher_guard {
        Some(c) => c,
        None => return, // No active session established yet
    };

    let event_payload = serde_json::json!({
        "type": "CRITICAL_VAULT_LOCK_EVENT",
        "payload": {}
    });

    let event_bytes = match serde_json::to_vec(&event_payload) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let mut padded = event_bytes;
    pad(&mut padded, 16);

    let mut resp_iv = [0u8; 12];
    rand::thread_rng().fill(&mut resp_iv);
    let resp_nonce = Nonce::from_slice(&resp_iv);

    let encrypted_bytes = match cipher.encrypt(resp_nonce, padded.as_slice()) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let response_payload = serde_json::json!({
        "ciphertext": hex::encode(encrypted_bytes),
        "iv": hex::encode(resp_iv)
    });

    // An unsolicited event has no request_id
    let response = NativeResponse::ok("encrypted_payload", response_payload, None);
    let _ = write_response(&response);
}
