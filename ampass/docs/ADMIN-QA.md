# AMPass — Admin QA Checklist

## ⚠️ Security Warning

AMPass updater, remote backup, encrypted backup, email, 2FA, browser extension, desktop app, and web vault require professional security audit before real credential storage.

## Routes

### Admin Navigation
- [ ] `/admin` — Dashboard with status cards
- [ ] `/admin/users` — User management
- [ ] `/admin/settings` — App settings
- [ ] `/admin/logs` — Audit logs
- [ ] `/admin/extensions` — Extension/device management
- [ ] `/admin/updates` — Update checker and applier
- [ ] `/admin/backups` — Backup management
- [ ] `/admin/backup-destinations` — Remote backup destinations (clean route)
- [ ] `/admin/backupDestinations` — Same as above (legacy route, still works)
- [ ] `/admin/releases` — Release/download management
- [ ] `/admin/email` — Email (Resend) settings

### Route Alias Verification
- [ ] `/admin/backup-destinations` loads correctly
- [ ] `/admin/backup-destinations/save` saves destination
- [ ] `/admin/backup-destinations/test` tests connection
- [ ] `/admin/backup-destinations/delete` deletes destination
- [ ] `/admin/backup-destinations/upload` uploads backup
- [ ] `/admin/backup-destinations/onedrive-connect` starts OAuth
- [ ] `/admin/backup-destinations/onedrive-callback` handles OAuth callback
- [ ] `/admin/backupDestinations` still works (backward compat)

## Update System Tests

- [ ] Check for updates shows latest version
- [ ] Malicious ZIP with `../` path traversal is rejected BEFORE extraction
- [ ] Malicious ZIP with absolute path `/etc/passwd` is rejected
- [ ] Malicious ZIP with drive letter `C:\windows` is rejected
- [ ] Malicious ZIP with null byte in filename is rejected
- [ ] Malicious ZIP with symlink entry is rejected
- [ ] Failed update deletes newly-created files during rollback
- [ ] Failed update restores overwritten files from rollback
- [ ] Failed update removes empty directories created during update
- [ ] Failed migration triggers full rollback
- [ ] Failed migration is NOT marked as applied in schema_migrations
- [ ] Maintenance mode activates during update
- [ ] Maintenance mode deactivates after update (success or failure)
- [ ] Update never marks completed unless files copied AND migrations succeeded

## Remote Backup Tests

- [ ] FTP: nested remote directory `/ampass/backups/server1` is created recursively
- [ ] FTP: path with `..` in remote directory is rejected
- [ ] FTP: file size mismatch after upload fails the operation
- [ ] FTP: remote filename matches pattern `ampass-backup-YYYY-mm-dd-HHMMSS.ampass-backup`
- [ ] FTPS: connection works with passive mode
- [ ] SFTP: upload works with ssh2 extension
- [ ] OneDrive: "Connect OneDrive" button redirects to Microsoft
- [ ] OneDrive: callback verifies state token (CSRF protection)
- [ ] OneDrive: callback stores refresh_token encrypted
- [ ] OneDrive: invalid state token shows error
- [ ] OneDrive: upload uses refresh token to get access token
- [ ] Only `.ampass-backup` files can be uploaded remotely

## Dashboard Status Cards

- [ ] Update available badge shows when update exists
- [ ] Last backup date displays correctly
- [ ] Remote backup status shows (OK/Failed/—)
- [ ] Email configured status shows correctly
- [ ] All status cards link to their respective admin pages

## Email Tests

- [ ] Save Resend API key (encrypted at rest)
- [ ] Send test email
- [ ] Masked API key shown in UI (not plaintext)
