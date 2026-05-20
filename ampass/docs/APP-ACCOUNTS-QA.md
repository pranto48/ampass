# AMPass — App Accounts & Remote Desktop QA

## Security Warning

AMPass app accounts, remote desktop accounts, browser extension, desktop app, updater, remote backup, and web vault require professional security audit before real credential storage.

## New Vault Item Types

### app_account
Stores credentials for desktop applications (Outlook, Zoom, Teams, Slack, custom .exe).

### remote_desktop
Stores credentials for remote connections (RDP, VNC, SSH).

## Database

### Fresh Install
- [ ] `schema.sql` creates vault_items with `app_account` and `remote_desktop` in enum
- [ ] `schema.sql` includes `host_hash` VARCHAR(64) column
- [ ] `schema.sql` includes `idx_vault_host_hash` index
- [ ] `schema.sql` includes `idx_vault_last_used` composite index

### Migration (Existing Install)
- [ ] Migration `006_app_accounts_remote_desktop.sql` runs successfully
- [ ] Migration is idempotent (safe to re-run without error)
- [ ] `host_hash` column added only if not already present
- [ ] Indexes added only if not already present
- [ ] Existing `login` items still work after migration

## Web Vault Tests

- [ ] `/vault?type=app_account` shows App Accounts filter
- [ ] `/vault?type=remote_desktop` shows Remote Desktop filter
- [ ] Add App Account form shows: title, application_name, executable_path, website, username, password, notes
- [ ] Add Remote Desktop form shows: title, protocol, host, port, domain, username, password, gateway, notes
- [ ] Remote Desktop form shows info about using Desktop App for launching
- [ ] App Account saves with item_type = app_account
- [ ] Remote Desktop saves with item_type = remote_desktop
- [ ] Both types appear in "All Items" view
- [ ] Copy username/password works for both types
- [ ] Edit/delete works for both types
- [ ] host_hash is computed and stored for remote_desktop items

## Desktop App Tests

### UI Structure
- [ ] Only ONE element with id="pageAppAccounts" exists (no duplicate)
- [ ] App Accounts page opens from sidebar
- [ ] Remote Desktop page opens from sidebar

### App Accounts Page
- [ ] Add Account modal shows correct fields (name, exe path, browse, username, password, website)
- [ ] Browse .exe button opens file picker (uses native dialog, not cmd.exe)
- [ ] Save creates encrypted app_account item
- [ ] App appears in list after save
- [ ] Copy Username button works
- [ ] Copy Password button works + auto-clear clipboard after 30s
- [ ] Launch App button launches executable directly (no cmd /C)
- [ ] Launch fails gracefully if path doesn't exist
- [ ] Launch rejects paths with shell metacharacters (|, &, ;, `, $, etc.)
- [ ] Launch rejects paths with null bytes, CR, LF
- [ ] Failed launch logs error via usage-log API

### Remote Desktop Page
- [ ] Add RDP Account modal shows correct fields
- [ ] Save creates encrypted remote_desktop item
- [ ] RDP item appears in list after save
- [ ] Open RDP creates temporary .rdp file WITHOUT password
- [ ] .rdp file contains `prompt for credentials:i:1`
- [ ] mstsc launches with the .rdp file
- [ ] Temporary .rdp file is deleted after 45 seconds
- [ ] Copy Host button works
- [ ] Copy Username button works
- [ ] Copy Password button works + auto-clear clipboard
- [ ] Failed RDP launch logs error

### RDP Security
- [ ] Host rejects CR/LF characters (prevents .rdp line injection)
- [ ] Host rejects null bytes and control characters
- [ ] Host allows only: alphanumeric, dot, dash, underscore, colon
- [ ] Host max length 255 enforced
- [ ] Username rejects CR/LF/null/control characters
- [ ] Username max length 256 enforced
- [ ] Port validated 1-65535
- [ ] Password NEVER written to .rdp file

### Launch Security
- [ ] launch_application does NOT use `cmd /C start` with untrusted path
- [ ] .exe files launched directly via Command::new(&path)
- [ ] .lnk files opened via explorer.exe (safe)
- [ ] Paths with `..` rejected
- [ ] Paths with shell metacharacters rejected
- [ ] Non-existent paths return error (not silent failure)

## Browser Extension Tests

### Web Password Save
- [ ] Save new website login works
- [ ] Update existing website login works
- [ ] Skip save works
- [ ] Does NOT capture AMPass own login/unlock/register pages
- [ ] Does NOT capture hidden password fields
- [ ] Does NOT save if password field is empty/whitespace
- [ ] Does NOT capture desktop app passwords (extension is web-only)
- [ ] Server offline: save is blocked (read-only mode)
- [ ] Autofill still works from offline cache
- [ ] Save prompt gives user time (30s timeout before auto-continue)

## API Tests

- [ ] `POST /api/extension/vault/save` accepts item_type=app_account
- [ ] `POST /api/extension/vault/save` accepts item_type=remote_desktop
- [ ] `GET /api/extension/vault/list?type=app_account` filters correctly
- [ ] `GET /api/extension/vault/list?type=remote_desktop` filters correctly
- [ ] `POST /api/extension/vault/usage-log` accepts valid actions
- [ ] `POST /api/extension/vault/usage-log` rejects invalid actions
- [ ] Usage log never contains plaintext secrets
- [ ] host_hash stored for remote_desktop items

## Import/Export Compatibility

- [ ] Import preserves host_hash field
- [ ] Import validates item_type against allowlist (invalid defaults to 'custom')
- [ ] Export includes app_account and remote_desktop items
- [ ] Existing backups still restore (backward compatible)
- [ ] Offline extension cache includes new item types
- [ ] Desktop offline cache includes new item types
