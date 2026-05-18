//! AMPass - Backup File Operations
//! 
//! Provides native file picker for importing/exporting encrypted vault backups.
//! SECURITY: Backup files contain only encrypted ciphertext — same format as server.

use tauri_plugin_dialog::DialogExt;

/// Open a file picker to select a backup file for import
#[tauri::command]
pub async fn pick_backup_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let file = app.dialog()
        .file()
        .add_filter("AMPass Backup", &["json"])
        .add_filter("All Files", &["*"])
        .set_title("Import AMPass Backup")
        .blocking_pick_file();
    
    match file {
        Some(path) => {
            let content = std::fs::read_to_string(path.path)
                .map_err(|e| format!("Failed to read file: {}", e))?;
            Ok(Some(content))
        }
        None => Ok(None), // User cancelled
    }
}

/// Open a file picker to choose where to save a backup
#[tauri::command]
pub async fn pick_save_location(app: tauri::AppHandle, data: String) -> Result<bool, String> {
    let file = app.dialog()
        .file()
        .add_filter("AMPass Backup", &["json"])
        .set_title("Export AMPass Backup")
        .set_file_name(&format!("ampass_backup_{}.json", chrono::Local::now().format("%Y-%m-%d")))
        .blocking_save_file();
    
    match file {
        Some(path) => {
            std::fs::write(path.path, data)
                .map_err(|e| format!("Failed to write file: {}", e))?;
            Ok(true)
        }
        None => Ok(false), // User cancelled
    }
}
