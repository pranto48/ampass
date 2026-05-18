//! AMPass - OS Keychain Integration
//! 
//! SECURITY: Stores only the bearer token and device key in the OS keychain.
//! Never stores the master password or vault key.
//! On Windows, uses Windows Credential Manager.

use keyring::Entry;

const SERVICE_NAME: &str = "ampass-desktop";
const TOKEN_KEY: &str = "auth-token";
const DEVICE_KEY: &str = "device-key";

/// Store the bearer token in OS keychain
pub fn store_token(token: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, TOKEN_KEY)
        .map_err(|e| format!("Keychain error: {}", e))?;
    entry.set_password(token)
        .map_err(|e| format!("Failed to store token: {}", e))
}

/// Retrieve the bearer token from OS keychain
pub fn retrieve_token() -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE_NAME, TOKEN_KEY)
        .map_err(|e| format!("Keychain error: {}", e))?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to retrieve token: {}", e)),
    }
}

/// Delete the bearer token from OS keychain
pub fn delete_token() -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, TOKEN_KEY)
        .map_err(|e| format!("Keychain error: {}", e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already gone
        Err(e) => Err(format!("Failed to delete token: {}", e)),
    }
}

/// Get or create the device key (used to encrypt local cache)
/// SECURITY: The device key is a random 256-bit key stored in OS keychain.
/// It protects the local vault cache file.
pub fn get_or_create_device_key() -> Result<Vec<u8>, String> {
    let entry = Entry::new(SERVICE_NAME, DEVICE_KEY)
        .map_err(|e| format!("Keychain error: {}", e))?;
    
    match entry.get_password() {
        Ok(hex_key) => {
            hex::decode(&hex_key).map_err(|e| format!("Invalid device key: {}", e))
        }
        Err(keyring::Error::NoEntry) => {
            // Generate new device key
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let hex_key = hex::encode(&key);
            entry.set_password(&hex_key)
                .map_err(|e| format!("Failed to store device key: {}", e))?;
            Ok(key)
        }
        Err(e) => Err(format!("Failed to retrieve device key: {}", e)),
    }
}

/// Delete the device key from OS keychain
pub fn delete_device_key() -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, DEVICE_KEY)
        .map_err(|e| format!("Keychain error: {}", e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete device key: {}", e)),
    }
}
