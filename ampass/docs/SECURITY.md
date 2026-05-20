# AMPass — Security Architecture

## ⚠️ Security Warning

AMPass updater, remote backup, encrypted backup, email, 2FA, browser extension, desktop app, and web vault require professional security audit before real credential storage.

## Zero-Knowledge Encryption

- Vault key derived client-side from master password using PBKDF2 (600,000 iterations)
- Vault items encrypted with AES-256-GCM in the browser/extension/desktop
- Server stores only ciphertext, IVs, salts, and hashes
- Master password NEVER sent to server or stored anywhere
- Vault key exists only in memory, cleared on lock/quit/session end

## Authentication

- Passwords hashed with Argon2id (server-side account auth)
- Session fingerprinting (IP + User-Agent binding)
- CSRF tokens on all state-changing forms
- Rate limiting on login/register/unlock endpoints
- Extension/desktop use Bearer token auth (not session cookies)

## Update System Security

- ZIP entries validated BEFORE extraction (never `extractTo()` on untrusted ZIP)
- Rejects: path traversal (`../`), absolute paths, null bytes, drive letters, symlinks
- Each extracted file's final path verified inside staging directory
- Config files and app_storage NEVER overwritten
- Full rollback on failure (overwritten files restored, new files deleted)
- Failed migrations never marked as applied
- Maintenance mode during update
- Pre-update encrypted backup created automatically

## Remote Backup Security

- Only encrypted `.ampass-backup` files uploaded (never plaintext)
- Remote credentials encrypted at rest with AES-256-GCM using APP_SECRET
- FTP remote paths validated (no `..`, no null bytes, no backslashes)
- FTP file size verified after upload
- Remote filename pattern enforced
- OneDrive OAuth with state token (CSRF protection)
- OneDrive refresh token stored encrypted, never logged
- FTPS warning: PHP `ftp_ssl_connect` may not verify TLS certificates

## API Security

- Extension API uses Bearer token authentication
- Authorization header forwarded via .htaccess for Apache/XAMPP
- Multiple header sources checked (HTTP_AUTHORIZATION, REDIRECT_, apache_request_headers)
- CORS restricted to configured origins (extension/desktop only)
- Token expiry enforced server-side

## Input Validation

- All user input sanitized and validated
- Prepared statements for all database queries (no SQL injection)
- Output escaped with htmlspecialchars (no XSS)
- File uploads: strict extension allowlist, type-to-extension mapping
- Stored filenames randomized (no user-controlled paths)
- Path traversal protection on all file operations

## Headers

- Content-Security-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Strict-Transport-Security (when HTTPS)
- Referrer-Policy: strict-origin-when-cross-origin

## Installer Security

- Triple-lock: config file + .install_lock file + INSTALL_LOCKED constant
- Installer inaccessible after installation
- Admin account created during install with Argon2id hash
