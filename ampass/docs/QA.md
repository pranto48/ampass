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

## CSRF Token Handling

### Login Form CSRF
- [ ] Open `/login`, wait, submit with valid token → login works normally
- [ ] Open `/login` in two tabs, login from tab 1, submit old tab 2 → redirects to `/login` with "Security token expired" message (no raw JSON)
- [ ] Browser back button to old login page → no raw JSON shown on submit
- [ ] Manually POST invalid `csrf_token` to `/login/submit` → redirects to `/login` with friendly error
- [ ] Login page sends `Cache-Control: no-store` header (check in DevTools)

### Unlock Form CSRF
- [ ] Open `/unlock`, wait, submit with valid token → unlock works
- [ ] Submit stale CSRF on `/unlock` → redirects to `/unlock` with friendly message
- [ ] Unlock page sends `Cache-Control: no-store` header

### Register Form CSRF
- [ ] Submit stale CSRF on `/register` → redirects to `/register` with friendly message
- [ ] Register page sends `Cache-Control: no-store` header

### API/AJAX CSRF
- [ ] AJAX request with invalid CSRF to `/api/vault/save` → returns JSON `{"error": "...", "code": "CSRF_INVALID"}`
- [ ] `/api/auth/csrfToken` returns fresh token
- [ ] `/api/auth/status` returns current CSRF token

### Extension Compatibility
- [ ] Extension autofill does NOT fill hidden `csrf_token` fields
- [ ] Extension autofill does NOT modify hidden inputs named `_token` or `_csrf`
- [ ] Extension save-detector does NOT capture AMPass own login/unlock/register pages
- [ ] Extension does NOT submit AMPass login form in a way that drops CSRF token

## Browser Extension Field-Icon Autofill

### Basic Autofill Flow
- [ ] Save login for a website (e.g., example.com)
- [ ] Reload extension from chrome://extensions
- [ ] Open the website login page
- [ ] AMPass field icon appears near password field
- [ ] Click field icon while vault is LOCKED → shows "Unlock AMPass to autofill" message
- [ ] Unlock extension (via popup)
- [ ] Click field icon with ONE matching login → username/password fills automatically
- [ ] Success toast "Filled by AMPass" appears briefly
- [ ] Click field icon with MULTIPLE matches → dropdown appears with list
- [ ] Select one from dropdown → correct credential fills
- [ ] Dropdown closes after selection
- [ ] Escape key closes dropdown
- [ ] Click outside dropdown closes it

### Error States
- [ ] No saved login for current site → shows "No saved login for this site"
- [ ] HTTP non-localhost page → shows "Autofill blocked on HTTP page" (unless setting enabled)
- [ ] Localhost HTTP page → autofill works normally
- [ ] Decrypt failure → shows "Could not decrypt this item" toast
- [ ] Extension disconnected → shows "Could not connect to AMPass"

### Security
- [ ] AMPass own login/unlock/register pages are NOT autofilled
- [ ] Hidden csrf_token fields are NOT modified by autofill
- [ ] Hidden inputs named _token or _csrf are NOT filled
- [ ] No automatic form submission happens after fill
- [ ] React/Vue forms detect filled values (native setter + events dispatched)
- [ ] Plaintext credentials cleared from memory after fill
- [ ] Usage logged to server (item_id + action only, no secrets)

### Multiple Forms
- [ ] Page with multiple login forms → each gets its own icon
- [ ] Clicking icon fills the correct form (not always the first one)
- [ ] Icon repositions on scroll/resize

## Updater — Source Type & Commit Detection

### GitHub Release Mode
- [ ] Set source type to "Stable Releases" → save settings
- [ ] Check for updates with no GitHub releases → shows helpful warning, NOT false "up to date"
- [ ] Check for updates with a release → shows version comparison
- [ ] Same version but different commit → shows note about switching to Branch ZIP mode

### GitHub Branch ZIP Mode
- [ ] Set source type to "Latest Branch ZIP" → save settings
- [ ] Set branch to "main" → save
- [ ] installed_commit_sha is empty → check shows "update available"
- [ ] Push new commit to main → check shows "update available: new commit {sha}"
- [ ] Apply update → installed_commit_sha equals latest_commit_sha
- [ ] Check again → shows "up to date"
- [ ] Change branch setting to different branch → check uses that branch

### Update Settings UI
- [ ] /admin/updates shows Update Settings card
- [ ] Source type dropdown works (github_release / github_branch_zip)
- [ ] Repo owner/name/branch fields save correctly
- [ ] GitHub token saves encrypted (masked in UI)
- [ ] "Remove saved token" checkbox clears token
- [ ] Invalid GitHub token shows safe error on check
- [ ] Private repo with valid token works

### Mark as Installed
- [ ] "Mark Current as Installed" button sets installed_commit_sha = latest_commit_sha
- [ ] After marking, status shows "up to date"
- [ ] Button only appears after at least one check (latest_sha exists)

### Debug Info
- [ ] Admin page shows: source type, owner/repo, branch, installed commit, latest commit
- [ ] Commit message displayed after check
- [ ] Last check error displayed if any
- [ ] Download URL shown when update available
