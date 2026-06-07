use std::fs;
use ampass_desktop::{keychain, storage};

fn main() {
    println!("Fetching device key from OS keychain...");
    match keychain::get_or_create_device_key() {
        Ok(device_key) => {
            println!("Device key (hex): {}", hex::encode(&device_key));
            
            // Decrypt session
            println!("\nAttempting to decrypt session.enc...");
            match ampass_desktop::storage::read_session_state() {
                Ok((locked, vault_key)) => {
                    println!("Session state: locked = {}, vault_key = {:?}", locked, vault_key);
                }
                Err(e) => {
                    println!("Failed to read session state: {}", e);
                }
            }

            // Decrypt cache
            println!("\nAttempting to decrypt cache.enc...");
            match ampass_desktop::storage::read_cache() {
                Ok(Some(cache_json)) => {
                    println!("Decrypted cache.enc (showing first 500 chars):");
                    if cache_json.len() > 500 {
                        println!("{}", &cache_json[..500]);
                    } else {
                        println!("{}", cache_json);
                    }
                    
                    // Parse cache and count items
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&cache_json) {
                        if let Some(arr) = val.as_array() {
                            println!("Total items in local cache: {}", arr.len());
                            if arr.len() > 0 {
                                println!("First item in local cache: {:#?}", arr[0]);
                            }
                        }
                    }
                }
                Ok(None) => {
                    println!("No cache.enc found.");
                }
                Err(e) => {
                    println!("Failed to decrypt cache.enc: {}", e);
                }
            }

            // Decrypt secure-config
            println!("\nAttempting to decrypt secure-config.enc...");
            match ampass_desktop::storage::load_secure_config("derivation_params") {
                Ok(Some(params)) => {
                    println!("derivation_params in secure-config: {}", params);
                }
                Ok(None) => {
                    println!("No derivation_params in secure-config.");
                }
                Err(e) => {
                    println!("Failed to read derivation_params: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to get device key: {}", e);
        }
    }
}
