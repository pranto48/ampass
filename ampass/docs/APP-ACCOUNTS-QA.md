# AMPass — App Accounts & Remote Desktop QA

## ⚠️ Security Warning

AMPass app accounts, remote desktop accounts, browser extension, desktop app, updater, remote backup, and web vault require professional security audit before real credential storage.

## New Vault Item Types

### app_account
Stores credentials for desktop applications (Outlook, Zoom, Teams, Slack, custom .exe).

### remote_desktop
Stores credentials for remote connections (RDP, VNC, SSH).

## Database Migration

- [ ] Migration `006_app_accounts_remote_desktop.sql` runs successfully
- [ ] `vault_items.item_type` enum includes `app_account` and `remote_desktop`
- [ ] `host_hash` column added to `vault_items`
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

## Desktop App Tests

### App Accounts Page
- [ ] Sidebar shows "App Accounts" link
- [ ] App Accounts page renders with table
- [ ] Add Account modal shows correct fields
- [ ] Browse .exe button opens file picker
- [ ] Save creates encrypted app_account item
- [ ] App appears in list after save
- [ ] Copy Username button works
- [ ] Copy Password button works + auto-clear clipboard after 30s
- [ ] Launch App button launches executable
- [ ] Launch fails gracefully if path doesn't exist
- [ ] Failed launch logs error via usage-log API

### Remote Desktop Page
- [ ] Sidebar shows "Remote Desktop" link
- [ ] Remote Desktop page renders with table
- [ ] Add RDP Account modal shows correct fields
- [ ] Save creates encrypted remote_desktop item
- [ ] RDP item appears in list after save
- [ ] Open RDP creates temporary .rdp file WITHOUT password
- [ ] mstsc launches with the .rdp file
- [ ] Temporary .rdp file is deleted after 10 seconds
- [ ] Copy Host button works
- [ ] Copy Username button works
- [ ] Copy Password button works + auto-clear clipboard
- [ ] Failed RDP launch logs error

### Security Checks
- [ ] No plaintext passwords in database
- [ ] No plaintext passwords in logs
- [ ] No vault key in local storage/disk
- [ ] No keylogging
- [ ] App launch NEVER passes password via command line
- [ ] RDP file NEVER contains password
- [ ] Clipboard auto-clears after timeout
- [ ] Usage log never contains plaintext secrets

## Browser Extension Tests

### Web Password Save
- [ ] Save new website login works
- [ ] Update existing website login works
- [ ] Skip save works
- [ ] Does NOT capture AMPass own login/unlock/register pages
- [ ] Does NOT capture hidden password fields
- [ ] Does NOT save if password field is empty/whitespace
- [ ] Server offline: save is blocked (read-only mode)
- [ ] Autofill still works from offline cache
- [ ] Save prompt gives user time (30s timeout before auto-continue)
- [ ] Enter key login triggers save detection
- [ ] Button click login triggers save detection
- [ ] SPA login forms detected

### Extension Popup
- [ ] Shows all item types in search results
- [ ] App Account and Remote Desktop items show copy buttons
- [ ] Launch buttons show "Use AMPass Desktop" message for non-web items

## API Tests

- [ ] `POST /api/extension/vault/save` accepts item_type=app_account
- [ ] `POST /api/extension/vault/save` accepts item_type=remote_desktop
- [ ] `GET /api/extension/vault/list?type=app_account` filters correctly
- [ ] `GET /api/extension/vault/list?type=remote_desktop` filters correctly
- [ ] `POST /api/extension/vault/usage-log` accepts valid actions
- [ ] `POST /api/extension/vault/usage-log` rejects invalid actions
- [ ] `POST /api/extension/vault/usage-log` validates item belongs to user
- [ ] Usage log never contains plaintext secrets
- [ ] host_hash stored for remote_desktop items

## Audit Logging

### Actions Logged
- [ ] vault_item_created (web)
- [ ] vault_item_updated (web)
- [ ] vault_item_deleted (web)
- [ ] autosave_created (extension)
- [ ] autosave_updated (extension)
- [ ] copied_password (desktop/extension)
- [ ] copied_username (desktop/extension)
- [ ] copied_host (desktop)
- [ ] launched_app (desktop)
- [ ] app_launch_failed (desktop)
- [ ] opened_rdp (desktop)
- [ ] rdp_open_failed (desktop)
- [ ] autofilled (extension)
- [ ] autosave_prompt_shown (extension)
- [ ] autosave_skipped (extension)
- [ ] clipboard_cleared (desktop)

### Audit Security
- [ ] No plaintext passwords in audit logs
- [ ] No full usernames logged by default
- [ ] Only item_id, item_type, action, device_id, timestamp, IP stored
- [ ] Admin can filter audit by action/client/item_type

## Import/Export/Backup Compatibility

- [ ] Encrypted backup includes app_account and remote_desktop items
- [ ] Import handles app_account and remote_desktop types
- [ ] Export includes all item types
- [ ] Existing backups still restore (backward compatible)
- [ ] Offline extension cache includes new item types
- [ ] Desktop offline cache includes new item types
- [ ] Security dashboard counts include new types
