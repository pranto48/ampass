# AMPass — cPanel Production Installation Guide

## Overview

This guide deploys AMPass on a shared hosting server with cPanel. AMPass runs on standard PHP/MySQL hosting — no Node.js, no Composer, no special server requirements.

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| PHP | 8.0+ |
| MySQL | 5.7+ or MariaDB 10.3+ |
| Apache | 2.4+ with mod_rewrite |
| SSL/TLS | Required (Let's Encrypt or commercial certificate) |
| cPanel | Any recent version |

### Required PHP Extensions
- `pdo` and `pdo_mysql`
- `openssl`
- `mbstring`

Most shared hosts include these by default. Check in cPanel → Select PHP Version.

---

## Step 1: Enable HTTPS

**AMPass requires HTTPS for production.** Without it, master passwords and session cookies can be intercepted.

1. Login to cPanel
2. Go to **SSL/TLS** or **Let's Encrypt SSL**
3. Install a free Let's Encrypt certificate for your domain
4. Verify https://yourdomain.com works

---

## Step 2: Create MySQL Database

1. In cPanel, go to **MySQL Databases**
2. Create a new database:
   - Database name: `ampass_db` (cPanel may prefix with your username, e.g., `user_ampass_db`)
3. Create a new user:
   - Username: `ampass_user`
   - Password: Generate a strong random password (save it for Step 4)
4. Add user to database:
   - Select the user and database
   - Grant **ALL PRIVILEGES**
   - Click "Make Changes"

---

## Step 3: Upload AMPass Files

### Option A: File Manager

1. In cPanel, go to **File Manager**
2. Navigate to `public_html/` (or a subdirectory like `public_html/ampass/`)
3. Upload the `ampass/` folder contents
4. Ensure the file structure is:

```
public_html/ampass/        (or public_html/ if AMPass is the only site)
├── index.php
├── .htaccess
├── config/
│   ├── .htaccess
│   └── config.sample.php
├── database/
│   ├── .htaccess
│   └── schema.sql
├── install/
│   ├── .htaccess
│   └── index.php
├── app/
│   ├── .htaccess
│   └── ...
├── public/
│   ├── css/
│   ├── js/
│   └── assets/
├── docs/
│   └── .htaccess
├── sw.js
└── manifest.webmanifest
```

### Option B: FTP/SFTP

1. Connect via FTP client (FileZilla, WinSCP)
2. Upload the `ampass/` folder to `public_html/ampass/`
3. Ensure `.htaccess` files are uploaded (they may be hidden — enable "show hidden files" in your FTP client)

---

## Step 4: Run the Installer

1. Open your browser
2. Navigate to: **https://yourdomain.com/ampass/install/**

### Step 4a: Database Configuration

| Field | Value |
|-------|-------|
| Database Host | `localhost` |
| Database Name | Your database name (e.g., `user_ampass_db`) |
| Database Username | Your database user (e.g., `user_ampass_user`) |
| Database Password | The password you created in Step 2 |
| Site Name | `AMPass` (or your preferred name) |
| Site URL | `https://yourdomain.com/ampass` |

Click **"Test Connection & Continue"**

### Step 4b: Admin Account

| Field | Requirements |
|-------|-------------|
| Full Name | Your name |
| Email | Valid email address |
| Username | 3+ characters, letters/numbers/underscores |
| Password | 12+ characters with uppercase, lowercase, number, and symbol |

Click **"Install AMPass"**

---

## Step 5: Post-Installation Security (CRITICAL)

### 5a: Delete the installer

In cPanel File Manager:
1. Navigate to `public_html/ampass/install/`
2. Select all files
3. Click **Delete** → confirm
4. Delete the `install/` directory itself

### 5b: Enable HTTPS redirect

Edit `public_html/ampass/.htaccess`:
- Find these lines (near the top):
  ```apache
  # RewriteCond %{HTTPS} off
  # RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
  ```
- Remove the `#` to uncomment them:
  ```apache
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
  ```

### 5c: Enable HSTS header

In the same `.htaccess`, find and uncomment:
```apache
# Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

### 5d: Set file permissions

In cPanel File Manager:
- `config/config.php` → Permissions: **640**
- `config/` directory → Permissions: **750**

### 5e: Verify security

Test these URLs — all should return 403 Forbidden:
- https://yourdomain.com/ampass/install/
- https://yourdomain.com/ampass/config/
- https://yourdomain.com/ampass/app/
- https://yourdomain.com/ampass/database/

---

## Step 6: Login

1. Go to **https://yourdomain.com/ampass/login**
2. Enter your admin username and password
3. Enter your master password to unlock the vault
4. Start adding credentials!

---

## Optional: Enable Extension API

For browser extension support:

1. In cPanel → phpMyAdmin, select your AMPass database
2. Click **Import** → choose `database/migrations/001_extension_tables.sql` → Go
3. Login to AMPass as admin
4. Go to **Admin Panel → Browser Extensions**
5. Check **"Enable Extension API"**
6. In **"Allowed Extension Origins"**, add your extension's origin:
   ```
   chrome-extension://YOUR_EXTENSION_ID_HERE
   ```
7. Save settings

---

## Updating AMPass

1. **Backup first**: Export your vault from AMPass (Settings → Export)
2. **Backup database**: phpMyAdmin → Export → SQL format
3. Upload new files (overwrite existing, but **do NOT overwrite** `config/config.php`)
4. Run any new migration SQL files from `database/migrations/`
5. Clear browser cache and reload

---

## Troubleshooting

### "500 Internal Server Error"
- Verify `.htaccess` is uploaded (it's a hidden file)
- Check if `mod_rewrite` is enabled (most cPanel hosts have it on by default)
- Check cPanel → Error Log for details
- Verify PHP version is 8.0+ in cPanel → MultiPHP Manager or Select PHP Version

### "Database connection failed" during install
- Double-check the database name includes your cPanel username prefix
- Verify the user has been added to the database with ALL PRIVILEGES
- Try the credentials in phpMyAdmin to confirm they work

### "403 Forbidden" on the main page
- Check that `index.php` exists in the correct directory
- Verify `.htaccess` RewriteEngine rules are correct
- Some hosts require `Options +FollowSymLinks` — add it to the top of `.htaccess` if needed

### Installer shows "already installed"
- The installer is locked after first run (this is correct behavior)
- To re-run: delete `config/config.php` and `config/.install_lock` via File Manager

### HTTPS not working
- Verify SSL certificate is installed in cPanel → SSL/TLS
- Wait a few minutes after installing Let's Encrypt (propagation)
- Try accessing https://yourdomain.com directly

### "Page not found" for vault/dashboard routes
- `mod_rewrite` must be enabled
- The `.htaccess` file must be in the AMPass root directory
- Some hosts need `AllowOverride All` — contact your host if routes don't work

---

## Performance Tips

- Enable PHP OPcache in cPanel → PHP Settings (usually on by default)
- The app is lightweight — no heavy frameworks, no build step
- Static assets (CSS/JS) are cached by the browser via service worker
- Database queries use indexes for fast lookups

---

## Security Checklist

After installation, verify:

- [ ] HTTPS is active and HTTP redirects to HTTPS
- [ ] `/install/` directory is deleted
- [ ] `/config/`, `/app/`, `/database/` return 403
- [ ] `config.php` permissions are 640
- [ ] Admin password is strong (12+ chars, mixed)
- [ ] HSTS header is enabled in `.htaccess`
- [ ] No warning banner appears in the app (means HTTPS is working)

---

## Support

- Full documentation: See `ampass/README.md`
- Extension API docs: See `ampass/docs/extension-api.md`
- Security details: See `release/SECURITY.md`
