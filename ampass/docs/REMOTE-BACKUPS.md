# AMPass — Remote Backup Destinations

## Overview

AMPass can upload encrypted `.ampass-backup` files to remote storage for offsite protection.

**Supported providers:**
- FTP
- FTPS (FTP over TLS) — recommended over plain FTP
- SFTP (SSH File Transfer) — requires PHP ssh2 extension
- OneDrive (Microsoft Graph API)

## Security

- Only encrypted `.ampass-backup` files are uploaded
- Plaintext database dumps are never sent remotely
- Remote credentials are encrypted at rest using APP_SECRET
- Credentials are masked in the admin UI
- Upload validates local file path before sending
- Remote filename enforced: `ampass-backup-YYYY-mm-dd-HHMMSS.ampass-backup`
- FTP: recursive directory creation with path validation (rejects `..`, null bytes, backslashes)
- FTP: file size verified after upload (local vs remote comparison)
- OneDrive: refresh token stored encrypted, never logged
- OneDrive: OAuth state token prevents CSRF on callback

## Setup

### FTP/FTPS

1. Admin → Backup Destinations → Add New
2. Select FTP or FTPS
3. Enter: host, port (21), username, password, remote directory
4. Enable passive mode (recommended for most servers)
5. Click **Test Connection**
6. Save

⚠️ Plain FTP transmits credentials in cleartext. PHP `ftp_ssl_connect` does not always verify TLS certificates. Use SFTP or OneDrive for stronger transport security.

**Nested directories:** Remote paths like `/ampass/backups/server1` are created recursively. Each path segment is validated (no `..`, no null bytes, no backslashes).

**Size verification:** After upload, remote file size is compared with local file. Size mismatch fails the upload.

### SFTP

Requires PHP `ssh2` extension. Check with `php -m | grep ssh2`.

1. Admin → Backup Destinations → Add New
2. Select SFTP
3. Enter: host, port (22), username, password, remote directory
4. Click **Test Connection**
5. Save

### OneDrive

1. Register an app at https://portal.azure.com → App registrations
2. Add redirect URI: `https://yourdomain.com/ampass/admin/backup-destinations/onedrive-callback`
3. Create a client secret
4. In AMPass: Admin → Backup Destinations → Add OneDrive
5. Enter client_id, client_secret
6. Click **Connect OneDrive** (OAuth flow)
7. Authorize access
8. Backups upload to `/AMPass Backups/` folder

## Automatic Upload

When creating a backup:
1. Check "Upload to enabled remote destinations"
2. Backup uploads to all enabled destinations after creation

## Scheduled Backups + Remote Upload

Configure in Admin → Backups:
- Enable automatic backup
- Set frequency (daily/weekly/monthly)
- Enable remote upload after backup

## Cron Setup

For scheduled backups on cPanel:
```
0 2 * * * curl -s "https://yourdomain.com/ampass/cron/backups?token=YOUR_CRON_TOKEN" > /dev/null
```

Generate cron token in Admin → Backups → Settings.

## Retention

Configure `backup_remote_retention_count` to automatically delete old remote backups (keeps last N files matching `ampass-backup-*.ampass-backup` pattern).

## Restore from Remote Backup

1. Download the `.ampass-backup` file from your remote storage
2. Go to Admin → Backups → Upload and Restore
3. Enter the backup password
4. Choose restore mode

## ⚠️ Not Production Ready

AMPass remote backup system requires professional security audit before real credential storage.
