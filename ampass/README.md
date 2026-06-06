# AMPass - Secure Password Vault

A zero-knowledge encrypted password manager built with PHP 8+, MySQL/MariaDB, and vanilla JavaScript. Designed for shared hosting (cPanel) and local development (XAMPP).

---

## ⚠️ CRITICAL SECURITY WARNING

**This software has NOT been professionally audited by a security firm.**

While AMPass implements industry-standard encryption (AES-256-GCM, PBKDF2, Argon2id) and follows security best practices, **no password manager should be trusted with real credentials until it has undergone a professional security audit** by qualified cryptographers and penetration testers.

**Before storing real passwords:**
1. Commission a professional security audit from a reputable firm
2. Have the cryptographic implementation reviewed by a cryptographer
3. Conduct penetration testing against the deployed instance
4. Review the client-side encryption code for timing attacks and key management flaws
5. Verify the zero-knowledge claims with formal analysis

**Known architectural limitations:**
- *Current PHP/MySQL architecture:* The master password IS sent to the server (over HTTPS) for verification. True zero-knowledge would require SRP or OPAQUE protocol.
- *Planned Firebase architecture:* Shift authentication entirely to Firebase Auth (performed client-side) and store only zero-knowledge encrypted vaults in Cloud Firestore. Since the client is hosted on static pages (GitHub Pages), the security guarantees will depend entirely on client-side JS execution safety and Firestore security rules.
- Client-side encryption relies on the integrity of JavaScript served by the hosting server (cPanel or GitHub Pages). A compromised host could serve malicious JavaScript that exfiltrates the decrypted vault key.
- Without a browser extension, the app cannot provide true autofill isolation.
- Session-based vault unlock means a compromised session/browser memory grants vault access.

**Use at your own risk. The authors accept no liability for data loss or security breaches.**

---

## Features

- **Client-side encryption**: All vault data encrypted in the browser using AES-256-GCM via Web Crypto API before transmission
- **Strong server-side hashing**: Argon2id (or bcrypt fallback) for all password hashes
- **Multiple vault item types**: Logins, secure notes, identities, payment cards, Wi-Fi, SSH, licenses, bank accounts
- **Password generator**: Cryptographically secure with customizable options and passphrase mode
- **Secure sharing**: Share credentials with other users using encrypted item keys
- **Admin panel**: User management, site settings, audit logs
- **PWA support**: Installable on desktop/mobile with offline locked screen
- **Dark/Light mode**: Modern, responsive UI
- **Import/Export**: Encrypted backup and restore
- **Comprehensive audit logging**: All security-relevant actions are logged

## Security Features

- CSRF protection on all state-changing operations
- Rate limiting on login, registration, vault unlock, password changes, and installer
- Session fingerprinting to detect hijacking
- Secure session cookies (HttpOnly, Secure, SameSite=Strict)
- Content Security Policy headers (no unsafe-inline for scripts)
- Input validation and output escaping throughout
- Prepared statements (PDO) for all database queries
- Installer lock file + constant + .htaccess triple protection
- .htaccess blocks access to config/, app/, database/, install/ directories
- HTTPS enforcement support with clear warnings when disabled
- No plaintext secrets stored in the database
- Password strength validation (12+ chars, mixed case, numbers, symbols)

## Requirements

- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB 10.3+
- Apache with mod_rewrite enabled
- **HTTPS (REQUIRED for production - the app is insecure without it)**
- PHP extensions: pdo, pdo_mysql, openssl, mbstring

## XAMPP Installation

1. Copy the `ampass` folder to `C:\xampp\htdocs\ampass`
2. Start Apache and MySQL from XAMPP Control Panel
3. Open your browser and go to `http://localhost/ampass/install/`
4. Follow the installation wizard:
   - Database Host: `localhost`
   - Database Name: `ampass_db` (will be created automatically)
   - Database Username: `root`
   - Database Password: (leave empty for XAMPP default)
5. Set up your admin account (password must be 12+ chars with mixed case, numbers, symbols)
6. **After installation, DELETE the `/install/` directory entirely**
7. Log in at `http://localhost/ampass/login`

Note: XAMPP on localhost is acceptable for development. For any network-accessible deployment, HTTPS is mandatory.

## cPanel Installation

1. Upload the `ampass` folder to your `public_html` directory (or a subdirectory)
2. Create a MySQL database and user in cPanel → MySQL Databases
3. **Ensure HTTPS/SSL is active** (use Let's Encrypt free SSL in cPanel)
4. Visit `https://yourdomain.com/ampass/install/`
5. Enter your database credentials and admin details
6. After installation:
   - **DELETE the `/install/` directory via File Manager**
   - Uncomment the HTTPS redirect lines in `.htaccess`
   - Uncomment the HSTS header in `.htaccess`
   - Verify `config/config.php` permissions are 640
   - Verify `/install/` returns 403 Forbidden

## Database Setup (Manual)

If the installer fails to create tables:

1. Open phpMyAdmin
2. Create a database named `ampass_db`
3. Import `database/schema.sql`
4. Import all files in `database/migrations/` in filename order
5. Copy `config/config.sample.php` to `config/config.php`
6. Edit `config/config.php` with your database credentials
7. Generate random keys using: `php -r "echo bin2hex(random_bytes(32));"`
8. Create the lock file: `touch config/.install_lock`

## Database Migrations

The installer automatically runs all `.sql` files in `database/migrations/` after the main schema. A `schema_migrations` table tracks which migrations have been applied to prevent duplicates.

For upgrades: if you update AMPass files, new migration files will be applied automatically on next install run, or you can import them manually via phpMyAdmin.

Current migrations:
- `001_extension_tables.sql` — Browser extension API tables (devices, tokens, audit logs)

## Browser Extension Setup

AMPass includes a browser extension API. After installation:

1. The extension tables are created automatically (no manual SQL import needed)
2. Login as admin → **Admin Panel → Browser Extensions**
3. Verify "Enable Extension API" is checked
4. Configure "Allowed Extension Origins" for production (e.g., `chrome-extension://your-id`)
5. Set token lifetime and max devices per user

The extension API is at `/api/extension/` — see `docs/extension-api.md` for full documentation.

## Admin Extension Settings

These settings are created automatically during installation:

| Setting | Default | Description |
|---------|---------|-------------|
| `extension_api_enabled` | `1` | Enable/disable the extension API |
| `extension_allowed_origins` | *(empty)* | Comma-separated allowed extension origins |
| `extension_token_lifetime_days` | `30` | How long extension tokens last |
| `extension_max_devices_per_user` | `10` | Max extension devices per user |

## Why HTTPS is REQUIRED

AMPass uses the Web Crypto API for client-side encryption. This API is only fully functional in secure contexts (HTTPS or localhost). Without HTTPS:

- **Master passwords are transmitted in plaintext** over the network
- **Session cookies can be stolen** via network sniffing
- **Man-in-the-middle attacks** can inject malicious JavaScript that steals vault keys
- **The entire security model collapses** - encryption is meaningless if the key can be intercepted

The app displays a prominent red warning banner when accessed without HTTPS. In production, uncomment the HTTPS redirect in `.htaccess` to enforce it at the server level.

## How the Encryption Works

1. **Registration**: Browser generates a random 256-bit vault key, derives a wrapping key from the master password using PBKDF2 (100k iterations), encrypts the vault key with AES-GCM, and sends only the encrypted vault key + salt + IV to the server.

2. **Vault Unlock**: Browser receives the encrypted vault key + salt from the server, derives the wrapping key from the master password locally, decrypts the vault key, and stores it in session memory (JavaScript variable + sessionStorage).

3. **Saving Items**: Browser encrypts all item fields (title, username, password, notes, etc.) as a JSON blob using AES-256-GCM with the vault key, then sends only the ciphertext + IV to the server.

4. **Reading Items**: Browser receives ciphertext from the server and decrypts it locally using the vault key in memory.

5. **Server stores**: Only ciphertext, IVs, salts, HMAC hashes (for search), and Argon2id password hashes. Never plaintext.

## Installer Security

The installer is protected by three independent layers:
1. `INSTALL_LOCKED` constant in `config/config.php`
2. Lock file at `config/.install_lock`
3. `.htaccess` rule blocking the `/install/` directory

Additionally, the installer has:
- CSRF protection on all forms
- Rate limiting (10 attempts per hour per IP)
- Database credentials stored in session (not hidden form fields)
- Input validation (alphanumeric DB names, strong password requirements)
- SQL injection prevention via parameterized queries

**Always delete the `/install/` directory after setup.**

## Audit Logging

The following actions are logged with timestamp, user, IP, and details:
- Login success/failure
- Vault unlock success/failure (form and API)
- Vault lock
- Vault item created/updated/deleted
- Item shared/accepted/revoked
- Vault exported/imported
- Password changed (success/failure)
- Profile updated
- User registered
- Admin actions (suspend, activate, settings change)
- Rate limit triggers

## Browser Autofill Limitation

AMPass is a web vault application. Full browser-wide autofill requires a browser extension. The web vault provides:
- One-click copy for usernames and passwords
- Auto-clear clipboard after 30 seconds for passwords
- Launch website button
- API structure ready for a future browser extension

## File Structure

```
ampass/
├── index.php              # Front controller
├── .htaccess              # Security rules & routing
├── sw.js                  # Service worker (PWA)
├── manifest.webmanifest   # PWA manifest
├── config/
│   ├── config.php         # Generated by installer (gitignored)
│   ├── config.sample.php  # Template
│   └── .install_lock      # Lock file (created by installer)
├── database/
│   └── schema.sql         # MySQL schema
├── install/
│   └── index.php          # Installation wizard (DELETE after setup)
├── app/
│   ├── core/              # Security & framework classes
│   ├── controllers/       # Page & API controllers
│   ├── models/            # Data models (prepared statements)
│   └── views/             # PHP templates
└── public/
    ├── css/app.css
    ├── js/crypto.js       # Web Crypto API encryption engine
    └── assets/            # Icons
```

## License

MIT License - Use freely for personal or commercial projects.

**Remember: Get a professional security audit before using this with real credentials.**
