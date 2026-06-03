//! AMPass - Encrypted Local Storage
//! 
//! SECURITY: The vault cache is encrypted with a device key from OS keychain.
//! Even if the cache file is stolen, it cannot be read without the keychain.
//! The cache contains only server-encrypted ciphertext (double encryption).

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

use crate::keychain;

/// Get the AMPass data directory
fn data_dir() -> Result<PathBuf, String> {
    let base = dirs::data_dir()
        .ok_or_else(|| "Cannot determine data directory".to_string())?;
    let dir = base.join("ampass");
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create data dir: {}", e))?;
    }
    Ok(dir)
}

/// Save a config value (plaintext — only for non-sensitive settings)
pub fn save_config(key: &str, value: &str) -> Result<(), String> {
    let dir = data_dir()?;
    let config_path = dir.join("config.json");
    
    let mut config: serde_json::Value = if config_path.exists() {
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    
    config[key] = serde_json::Value::String(value.to_string());
    
    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(&config_path, content)
        .map_err(|e| format!("Failed to write config: {}", e))
}

/// Load a config value
pub fn load_config(key: &str) -> Result<Option<String>, String> {
    let dir = data_dir()?;
    let config_path = dir.join("config.json");
    
    if !config_path.exists() {
        return Ok(None);
    }
    
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let config: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;
    
    Ok(config.get(key).and_then(|v| v.as_str()).map(|s| s.to_string()))
}

/// Write encrypted vault cache
/// SECURITY: Data is encrypted with device key from OS keychain before writing to disk.
pub fn write_cache(data: &str) -> Result<(), String> {
    let device_key = keychain::get_or_create_device_key()?;
    let encrypted = encrypt_data(data.as_bytes(), &device_key)?;
    
    let dir = data_dir()?;
    let cache_path = dir.join("cache.enc");
    fs::write(&cache_path, encrypted)
        .map_err(|e| format!("Failed to write cache: {}", e))
}

/// Read and decrypt vault cache
pub fn read_cache() -> Result<Option<String>, String> {
    let dir = data_dir()?;
    let cache_path = dir.join("cache.enc");
    
    if !cache_path.exists() {
        return Ok(None);
    }
    
    let encrypted = fs::read(&cache_path)
        .map_err(|e| format!("Failed to read cache: {}", e))?;
    
    let device_key = keychain::get_or_create_device_key()?;
    let decrypted = decrypt_data(&encrypted, &device_key)?;
    
    String::from_utf8(decrypted)
        .map(Some)
        .map_err(|e| format!("Cache data is not valid UTF-8: {}", e))
}

/// Wipe all local data
pub fn wipe_all() -> Result<(), String> {
    let dir = data_dir()?;
    
    // Delete cache
    let cache_path = dir.join("cache.enc");
    if cache_path.exists() {
        fs::remove_file(&cache_path)
            .map_err(|e| format!("Failed to delete cache: {}", e))?;
    }
    
    // Delete secure config (derivation params, etc.)
    let secure_config_path = dir.join("secure-config.enc");
    if secure_config_path.exists() {
        fs::remove_file(&secure_config_path)
            .map_err(|e| format!("Failed to delete secure config: {}", e))?;
    }
    
    // Delete config
    let config_path = dir.join("config.json");
    if config_path.exists() {
        fs::remove_file(&config_path)
            .map_err(|e| format!("Failed to delete config: {}", e))?;
    }
    
    Ok(())
}

/// Save encrypted secure config (derivation params, trusted device metadata)
/// SECURITY: Encrypted with device key from OS keychain. Never stores master password or vault key.
pub fn save_secure_config(key: &str, value: &str) -> Result<(), String> {
    let dir = data_dir()?;
    let path = dir.join("secure-config.enc");
    let device_key = keychain::get_or_create_device_key()?;

    // Load existing config or start fresh
    let mut config: serde_json::Value = if path.exists() {
        let encrypted = fs::read(&path).map_err(|e| format!("Failed to read secure config: {}", e))?;
        let decrypted = decrypt_data(&encrypted, &device_key).unwrap_or_else(|_| b"{}".to_vec());
        serde_json::from_slice(&decrypted).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    config[key] = serde_json::Value::String(value.to_string());

    let json = serde_json::to_string(&config).map_err(|e| format!("Serialize error: {}", e))?;
    let encrypted = encrypt_data(json.as_bytes(), &device_key)?;
    fs::write(&path, encrypted).map_err(|e| format!("Failed to write secure config: {}", e))
}

/// Load a value from encrypted secure config
pub fn load_secure_config(key: &str) -> Result<Option<String>, String> {
    let dir = data_dir()?;
    let path = dir.join("secure-config.enc");

    if !path.exists() {
        return Ok(None);
    }

    let device_key = keychain::get_or_create_device_key()?;
    let encrypted = fs::read(&path).map_err(|e| format!("Failed to read secure config: {}", e))?;
    let decrypted = decrypt_data(&encrypted, &device_key)?;
    let config: serde_json::Value = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse secure config: {}", e))?;

    Ok(config.get(key).and_then(|v| v.as_str()).map(|s| s.to_string()))
}

/// Delete a key from encrypted secure config
pub fn delete_secure_config(key: &str) -> Result<(), String> {
    let dir = data_dir()?;
    let path = dir.join("secure-config.enc");

    if !path.exists() {
        return Ok(());
    }

    let device_key = keychain::get_or_create_device_key()?;
    let encrypted = fs::read(&path).map_err(|e| format!("Failed to read secure config: {}", e))?;
    let decrypted = decrypt_data(&encrypted, &device_key).unwrap_or_else(|_| b"{}".to_vec());
    let mut config: serde_json::Value = serde_json::from_slice(&decrypted).unwrap_or(serde_json::json!({}));

    if let Some(obj) = config.as_object_mut() {
        obj.remove(key);
    }

    let json = serde_json::to_string(&config).map_err(|e| format!("Serialize error: {}", e))?;
    let encrypted = encrypt_data(json.as_bytes(), &device_key)?;
    fs::write(&path, encrypted).map_err(|e| format!("Failed to write secure config: {}", e))
}

/// Encrypt data with AES-256-GCM
/// Format: [12-byte nonce][ciphertext]
fn encrypt_data(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data with AES-256-GCM
fn decrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 13 { // 12 nonce + at least 1 byte
        return Err("Cache file too small or corrupted".to_string());
    }
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — cache may be corrupted or device key changed".to_string())
}

/// Write encrypted session file containing vault key.
/// SECURITY: This session file is encrypted with the keychain device key.
/// It contains: json with vault_key, timestamp, and active status.
pub fn write_session_state(vault_key: &str) -> Result<(), String> {
    let device_key = keychain::get_or_create_device_key()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let data = serde_json::json!({
        "vault_key": vault_key,
        "timestamp": now,
        "locked": false
    });
    let json_str = data.to_string();
    let encrypted = encrypt_data(json_str.as_bytes(), &device_key)?;
    let dir = data_dir()?;
    let session_path = dir.join("session.enc");
    fs::write(&session_path, encrypted)
        .map_err(|e| format!("Failed to write session state: {}", e))
}

/// Read and decrypt session state.
/// Returns (locked, vault_key).
/// SECURITY: Session file is valid only for 5 minutes. If older, it is ignored and deleted.
pub fn read_session_state() -> Result<(bool, Option<String>), String> {
    let dir = data_dir()?;
    let session_path = dir.join("session.enc");
    if !session_path.exists() {
        return Ok((true, None));
    }
    
    let encrypted = fs::read(&session_path)
        .map_err(|e| format!("Failed to read session state: {}", e))?;
    
    let device_key = keychain::get_or_create_device_key()?;
    let decrypted = match decrypt_data(&encrypted, &device_key) {
        Ok(d) => d,
        Err(_) => {
            let _ = fs::remove_file(&session_path);
            return Ok((true, None));
        }
    };
    
    let data: serde_json::Value = match serde_json::from_slice(&decrypted) {
        Ok(v) => v,
        Err(_) => {
            let _ = fs::remove_file(&session_path);
            return Ok((true, None));
        }
    };
    
    let timestamp = data.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    // Session state expires in 5 minutes (300 seconds)
    if now - timestamp > 300 {
        let _ = fs::remove_file(&session_path);
        return Ok((true, None));
    }
    
    let locked = data.get("locked").and_then(|v| v.as_bool()).unwrap_or(true);
    let vault_key = data.get("vault_key").and_then(|v| v.as_str()).map(|s| s.to_string());
    
    Ok((locked, vault_key))
}

/// Delete session state file.
pub fn delete_session_file() -> Result<(), String> {
    let dir = data_dir()?;
    let session_path = dir.join("session.enc");
    if session_path.exists() {
        let _ = fs::remove_file(&session_path);
    }
    Ok(())
}
