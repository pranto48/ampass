# AMPass — QA Manual Test Checklist

## Fresh XAMPP Install

- [ ] Copy `ampass/` to `C:\xampp\htdocs\ampass`
- [ ] Start Apache + MySQL in XAMPP
- [ ] Visit `http://localhost/ampass/` → redirects to `/install/index.php`
- [ ] Step 1: Enter DB host=localhost, name=ampass_db, user=root, pass=(empty)
- [ ] Click "Test Connection & Continue" → proceeds to Step 2
- [ ] Step 2: Enter admin name, email, username, strong password
- [ ] Click "Install AMPass" → shows success page
- [ ] Verify `config/config.php` was created
- [ ] Verify `config/.install_lock` was created
- [ ] Verify `schema_migrations` table exists in database
- [ ] Verify `extension_devices`, `extension_tokens`, `extension_audit_logs` tables exist
- [ ] Visit `http://localhost/ampass/install/` → shows "already installed" (403)
- [ ] Delete `install/` directory
- [ ] Visit `http://localhost/ampass/login` → login page loads

## Fresh cPanel Install

- [ ] Upload `ampass/` to `public_html/ampass/`
- [ ] Create MySQL database and user in cPanel
- [ ] Visit `https://domain.com/ampass/` → redirects to installer
- [ ] Complete installation with cPanel DB credentials
- [ ] Verify HTTPS warning does NOT appear (if SSL active)
- [ ] Verify `.htaccess` blocks `/config/`, `/app/`, `/database/`

## Installer Lock Check

- [ ] After install, visiting `/install/` shows 403 (PHP lock)
- [ ] Deleting `config/.install_lock` alone still blocks (INSTALL_LOCKED constant)
- [ ] Deleting `config/config.php` makes installer accessible again (for re-install)

## Admin First Login

- [ ] Login with admin credentials → redirected to unlock page
- [ ] Unlock page shows master password prompt
- [ ] If vault is uninitialized (key_iterations=0), vault setup flow triggers
- [ ] After setup, vault key is generated browser-side and encrypted
- [ ] user_security record updated with real encrypted_vault_key, salt, IV, iterations=100000

## Vault Operations

- [ ] Add a login credential → encrypted_data stored (not plaintext)
- [ ] View the credential → decrypts correctly in browser
- [ ] Edit the credential → updates encrypted_data
- [ ] Delete the credential → removed from database
- [ ] Add to favorites → is_favorite toggled
- [ ] Search vault → filters by decrypted title/username
- [ ] Folder creation and assignment works
- [ ] Password generator produces strong passwords
- [ ] Export backup → JSON file with encrypted_data (no plaintext)
- [ ] Import backup → items restored

## Extension API

- [ ] `GET /api/extension/status` → returns API version, no auth required
- [ ] `POST /api/extension/login` with valid credentials → returns token + derivation_params
- [ ] `POST /api/extension/login` with wrong password → 401 + rate limited after 5 attempts
- [ ] `GET /api/extension/vault/list` with valid token → returns encrypted items
- [ ] `GET /api/extension/vault/list` without token → 401
- [ ] `GET /api/extension/vault/list` with revoked token → 401
- [ ] `POST /api/extension/vault/save` → creates encrypted item
- [ ] `POST /api/extension/logout` → revokes token
- [ ] Extension settings in admin panel load correctly
- [ ] Admin can revoke extension devices

## Extension Device Registration

- [ ] Login from extension creates entry in `extension_devices`
- [ ] Token stored in `extension_tokens` (hashed)
- [ ] Device visible in user Settings → Browser Extensions
- [ ] Device visible in Admin → Browser Extensions
- [ ] Revoking device invalidates all its tokens

## Migration Tables

- [ ] `schema_migrations` table exists after fresh install
- [ ] `001_extension_tables.sql` recorded in schema_migrations
- [ ] Extension tables (`extension_devices`, `extension_tokens`, `extension_audit_logs`) exist
- [ ] Extension app_settings rows exist (extension_api_enabled, etc.)

## HTTPS Warning

- [ ] On HTTP (non-localhost): red warning banner appears
- [ ] On HTTPS: no warning banner
- [ ] On localhost HTTP: no warning banner (development OK)

## Access Control

- [ ] `GET /config/config.php` → 403 Forbidden
- [ ] `GET /app/core/Database.php` → 403 Forbidden
- [ ] `GET /database/schema.sql` → 403 Forbidden
- [ ] `GET /docs/extension-api.md` → 403 Forbidden
- [ ] `GET /.htaccess` → 403 Forbidden
- [ ] `GET /README.md` → 403 Forbidden
- [ ] Static assets (`/public/css/app.css`, `/public/js/app.js`) → 200 OK
- [ ] `/settings` loads with full AMPass layout (sidebar, topbar, CSS)
- [ ] `/generator` loads with full AMPass layout
- [ ] Sidebar shows "Web Accounts" link
- [ ] Sidebar shows "Apps & Downloads" link
- [ ] Admin sidebar shows "Release Downloads" link
- [ ] `/downloads` page loads publicly
- [ ] `/downloads` empty state is clear before files are uploaded
- [ ] Extension stale token is cleared after DB reinstall
- [ ] Extension shows login screen instead of "invalid token" error
- [ ] Extension "Reset Connection" button works

## Security

- [ ] All POST forms include CSRF token
- [ ] Login rate limited (5 attempts / 15 min)
- [ ] Vault unlock rate limited (5 attempts / 5 min)
- [ ] Registration rate limited (3 attempts / hour)
- [ ] No plaintext passwords in database (check vault_items.encrypted_data)
- [ ] No plaintext in audit_logs.details
- [ ] Session regenerated after login
- [ ] Vault auto-locks after timeout
- [ ] All authenticated /api/extension/* endpoints reject HTTP (except localhost)
- [ ] Release delete cannot unlink files outside app_storage/releases
- [ ] Product type/file extension mismatch is rejected on upload
- [ ] Inactive release returns 404 on public download
- [ ] Public /downloads page shows only active releases
- [ ] Copy download URL button works in admin releases page
- [ ] Bearer token Authorization header works on XAMPP Apache
- [ ] Bearer token Authorization header works on cPanel
- [ ] /api/extension/debug-auth returns diagnostics on localhost
