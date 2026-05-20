# AMPass — Update System

## ⚠️ Security Warning

AMPass updater, remote backup, encrypted backup, email, 2FA, browser extension, desktop app, and web vault require professional security audit before real credential storage.

## Overview

AMPass can check GitHub for updates and apply them from the admin panel.

**Source:** https://github.com/pranto48/ampass-secure-vault

## Update Methods

### Method A: GitHub Releases (Default)
- Checks `https://api.github.com/repos/pranto48/ampass-secure-vault/releases/latest`
- Compares release tag version with installed version
- Downloads release ZIP

### Method B: GitHub Branch ZIP
- Checks latest commit SHA on `main` branch
- Compares with installed commit SHA
- Downloads branch archive ZIP

### Method C: Git CLI (Optional)
- Requires shell_exec and .git directory
- Not available on most cPanel shared hosting
- Use Method A or B instead

## How to Update

1. Login as admin
2. Go to **Admin → Updates**
3. Click **Check for Updates**
4. If update available, review release notes
5. Enter backup password (pre-update backup is created automatically)
6. Type `UPDATE AMPASS` to confirm
7. Click **Update Now**

## What Happens During Update

1. Encrypted backup created automatically
2. Maintenance mode enabled (users see "updating" page)
3. Update package downloaded from GitHub
4. **Safe ZIP extraction** — every entry validated BEFORE extraction:
   - Rejects path traversal (`../`), absolute paths, null bytes, drive letters
   - Rejects symlink entries
   - Extracts each file individually (never uses `extractTo()` on untrusted ZIP)
   - Final path verified to stay inside staging directory
5. Files copied to app root with rollback tracking:
   - Existing files backed up to rollback directory
   - Newly-created files tracked separately
   - New directories tracked for cleanup
6. Database migrations run
7. Maintenance mode disabled
8. Update history recorded

## What's Never Overwritten

- `config/config.php`
- `config/.install_lock`
- `app_storage/` (backups, releases, uploads)
- `.htaccess` (unless explicitly chosen)
- User-uploaded files

## Rollback

If update or migration fails:
- **Overwritten files** restored from rollback directory
- **Newly-created files** deleted (did not exist before update)
- **Empty directories** created during update removed (deepest first)
- Nothing outside app root is ever deleted
- Maintenance mode disabled
- Update marked as "failed" in history
- Pre-update backup available for manual restore
- Rollback summary logged to PHP error log

## Troubleshooting

### "GitHub API rate limited"
- Add a GitHub personal access token in Admin → Updates → Settings
- Free tier allows 60 requests/hour without token, 5000 with token

### Update fails on cPanel
- Ensure `app_storage/temp/` is writable
- Check PHP memory_limit (128MB+ recommended)
- Check max_execution_time (120+ seconds recommended)

### Migrations fail
- Check Admin → Updates for error details
- Run migrations manually via phpMyAdmin if needed
- Failed migrations are not marked as applied (safe to retry)

## Migration System

AMPass supports two migration formats:

### SQL Migrations (`.sql` files)
- Executed via `PDO::exec()`
- Good for simple DDL: CREATE TABLE, ALTER TABLE, INSERT
- **Limitation:** `DELIMITER` and `CREATE PROCEDURE` are NOT supported (these are mysql CLI commands, not SQL)

### PHP Migrations (`.php` files)
- For complex/conditional logic that SQL alone cannot handle
- Can query `INFORMATION_SCHEMA` to check if columns/indexes exist before adding
- Must `return true` on success or throw an Exception on failure
- Has access to `Database::getInstance()` (PDO)

### Precedence
- If both `006_example.sql` and `006_example.php` exist, the `.php` file takes precedence
- The runner checks `schema_migrations` for both `.sql` and `.php` variants to avoid double-applying

### Writing a PHP Migration

```php
<?php
// database/migrations/006_example.php
$pdo = Database::getInstance();
$dbName = $pdo->query("SELECT DATABASE()")->fetchColumn();

// Check if column exists before adding
$stmt = $pdo->prepare("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'my_table' AND COLUMN_NAME = 'my_column'");
$stmt->execute([$dbName]);
if ((int)$stmt->fetchColumn() === 0) {
    $pdo->exec("ALTER TABLE my_table ADD COLUMN my_column VARCHAR(64) NULL");
}

return true; // Required!
```
