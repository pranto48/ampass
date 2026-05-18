# AMPass — XAMPP Installation Guide

## Overview

This guide installs AMPass on a local XAMPP server for development and testing. For production deployment, see `INSTALL-CPANEL.md`.

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| XAMPP | 8.0+ (includes Apache + MySQL/MariaDB) |
| PHP | 8.0+ |
| MySQL | 5.7+ or MariaDB 10.3+ |
| OS | Windows 10/11, macOS, or Linux |
| Browser | Chrome, Edge, Firefox, or Safari with JavaScript enabled |

### Required PHP Extensions
- `pdo` and `pdo_mysql`
- `openssl`
- `mbstring`

These are included by default in XAMPP.

---

## Step 1: Install XAMPP

1. Download XAMPP from https://www.apachefriends.org/
2. Install with default settings (ensure Apache and MySQL are selected)
3. Open XAMPP Control Panel
4. Start **Apache** and **MySQL**

---

## Step 2: Copy AMPass Files

Copy the entire `ampass/` folder to your XAMPP web root:

**Windows:**
```
C:\xampp\htdocs\ampass\
```

**macOS:**
```
/Applications/XAMPP/htdocs/ampass/
```

**Linux:**
```
/opt/lampp/htdocs/ampass/
```

The folder structure should look like:
```
htdocs/
└── ampass/
    ├── index.php
    ├── .htaccess
    ├── config/
    ├── database/
    ├── install/
    ├── app/
    └── public/
```

---

## Step 3: Run the Installer

1. Open your browser
2. Navigate to: **http://localhost/ampass/install/**
3. You should see the AMPass installation wizard

### Step 3a: Database Configuration

| Field | Value |
|-------|-------|
| Database Host | `localhost` |
| Database Name | `ampass_db` |
| Database Username | `root` |
| Database Password | *(leave empty — XAMPP default has no password)* |
| Site Name | `AMPass` (or your preferred name) |
| Site URL | *(leave empty — auto-detected as http://localhost/ampass)* |

Click **"Test Connection & Continue"**

The installer will:
- Test the database connection
- Create the `ampass_db` database if it doesn't exist
- Proceed to admin account setup

### Step 3b: Admin Account

| Field | Requirements |
|-------|-------------|
| Full Name | Your name |
| Email | Valid email address |
| Username | 3+ characters, letters/numbers/underscores |
| Password | 12+ characters with uppercase, lowercase, number, and symbol |

Example password: `MyStr0ng!Pass2024`

Click **"Install AMPass"**

The installer will:
- Create all database tables
- Generate security keys
- Create your admin account
- Write the configuration file
- Lock the installer

---

## Step 4: Post-Installation Security

### Delete the installer (IMPORTANT)

Delete the entire `install/` directory:

**Windows:**
```
rmdir /s /q C:\xampp\htdocs\ampass\install
```

**Or** delete it manually via File Explorer.

### Verify the installer is locked

Visit http://localhost/ampass/install/ — you should see a 403 Forbidden error.

---

## Step 5: Login

1. Go to **http://localhost/ampass/login**
2. Enter your admin username and password
3. Enter your master password to unlock the vault
4. You're in!

---

## Optional: Enable Extension API

If you plan to use the AMPass browser extension:

1. Open phpMyAdmin: http://localhost/phpmyadmin
2. Select the `ampass_db` database
3. Click **Import** tab
4. Choose file: `ampass/database/migrations/001_extension_tables.sql`
5. Click **Go**
6. Login to AMPass as admin
7. Go to **Admin Panel → Browser Extensions**
8. Check **"Enable Extension API"**
9. Save settings

---

## Troubleshooting

### "Page not found" or blank page
- Ensure Apache is running in XAMPP Control Panel
- Verify `mod_rewrite` is enabled: Open `C:\xampp\apache\conf\httpd.conf`, find `LoadModule rewrite_module` and ensure it's not commented out
- Restart Apache after changes

### "Database connection failed"
- Ensure MySQL is running in XAMPP Control Panel
- Verify you're using `root` with empty password
- Try accessing phpMyAdmin (http://localhost/phpmyadmin) to confirm MySQL works

### "500 Internal Server Error"
- Check Apache error log: `C:\xampp\apache\logs\error.log`
- Ensure `.htaccess` file exists in the `ampass/` folder
- Verify PHP version is 8.0+ (XAMPP Control Panel → Apache → Config → PHP)

### Installer shows "already installed"
- The installer is locked after first run
- To re-run: delete `ampass/config/config.php` and `ampass/config/.install_lock`

---

## Notes

- XAMPP on localhost is for **development/testing only**
- HTTP is acceptable on localhost (Web Crypto API works in secure contexts including localhost)
- For any network-accessible deployment, **HTTPS is mandatory** — see `INSTALL-CPANEL.md`
- The app shows a warning banner when accessed without HTTPS on non-localhost
