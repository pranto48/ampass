# AMPass — Trusted Devices QA

## Security Warning

AMPass trusted browser, trusted PC, extension, desktop app, autofill, backup, and updater require professional security audit before real credential storage.

## Browser Extension — Trusted Browser

### First Login
1. Install extension, set server URL
2. Login with username/password
3. Check "Trust this browser"
4. Unlock vault with master password
5. Vault opens, items sync

### After Browser Restart (Trusted)
1. Close browser completely
2. Reopen browser
3. Click AMPass extension icon
4. **Expected: Shows Unlock Vault screen (NOT login)**
5. Shows: "Trusted browser • Server: host"
6. Enter master password only
7. Vault unlocks

### After Browser Restart (Not Trusted)
1. Login WITHOUT "Trust this browser"
2. Close browser
3. Reopen browser
4. Click AMPass extension icon
5. **Expected: Shows Login screen (username/password required)**

### Idle Lock (30 minutes)
1. Unlock vault
2. Wait 30 minutes (or set shorter timeout in settings for testing)
3. Click extension icon
4. **Expected: Shows Unlock screen (not login)**
5. Trusted token preserved
6. Enter master password
7. Vault unlocks

### Token Revoked
1. Admin revokes extension device from /admin/extensions
2. Extension tries to sync
3. Server returns AUTH_REQUIRED
4. **Expected: Clears trusted token, shows Login**
5. Message: "Session expired. Please login again."

### Sign Out
1. On unlock screen, click "Sign Out"
2. **Expected: Shows Login screen**
3. Trusted token cleared
4. Next open requires username/password

### Offline Mode
1. Unlock vault while online (items cached)
2. Disconnect network / stop server
3. Close and reopen browser
4. Click extension icon
5. **Expected: Shows Unlock screen**
6. Enter master password
7. **Expected: Vault opens with cached items (read-only)**

## Desktop App — Trusted PC

### First Login
1. Open AMPass Desktop
2. Enter server URL
3. Login with username/password
4. Check "Trust this PC"
5. Unlock vault with master password
6. Vault opens

### After App Restart (Trusted)
1. Close AMPass Desktop (X hides to tray, Quit exits)
2. Reopen AMPass Desktop
3. **Expected: Shows Unlock Vault screen (NOT login)**
4. Shows: "Trusted PC: username • Server: host"
5. Enter master password only
6. Vault unlocks

### After App Restart (Not Trusted)
1. Login WITHOUT "Trust this PC"
2. Quit app from tray
3. Reopen app
4. **Expected: Shows Login screen**

### Server Offline (Trusted PC)
1. Complete trusted PC login while online
2. Stop server / disconnect network
3. Quit and reopen app
4. **Expected: Shows Unlock screen (NOT server error)**
5. Enter master password
6. **Expected: Vault opens from encrypted cache (read-only)**

### Server Unreachable (No Trusted Data)
1. First time opening app with wrong server URL
2. **Expected: Shows Server Connection Problem screen**
3. Shows current URL and error
4. Buttons: "Save & Retry", "Retry", "Work Offline"
5. Change URL to correct server
6. Login works

### Token Revoked
1. Admin revokes device
2. Desktop tries background token validation
3. Server returns AUTH_REQUIRED
4. **Expected: Clears trusted PC data, shows Login**
5. Message: "Trusted PC session expired. Please sign in again."

### Sign Out from Unlock Screen
1. On unlock screen, click "Sign Out"
2. **Expected: Clears token, derivation params, user summary**
3. Shows Login screen
4. Next open requires username/password

### Change Server from Unlock Screen
1. On unlock screen, click "Change Server"
2. **Expected: Shows Welcome/Connect screen**
3. Enter new server URL
4. Login to new server

## Browser-to-Desktop Unlock

### Desktop Bridge Available
1. Enable "Use Desktop Bridge" in extension settings
2. Desktop app running (in tray)
3. Visit website login page
4. AMPass field icon appears
5. Vault is locked (idle timeout)
6. Click field icon
7. Click "Open AMPass"
8. **Expected: Desktop app window appears/focuses**
9. Desktop shows Unlock screen
10. Enter master password in desktop
11. Desktop unlocks
12. Click field icon again in browser
13. **Expected: Autofill works**

### Desktop Bridge Not Available
1. Desktop app not installed or bridge disabled
2. Click "Open AMPass" from field icon
3. **Expected: Shows fallback message**
4. "Click the AMPass extension icon to unlock, or open AMPass Desktop."

## Close-to-Tray (Desktop)

1. Open AMPass Desktop
2. Click window X button
3. **Expected: Window hides, app stays in system tray**
4. Tray icon visible
5. Click tray icon or "Open AMPass" from tray menu
6. **Expected: Window reappears**
7. Click "Lock Vault" from tray menu
8. **Expected: Vault locks, unlock screen shown on next open**
9. Click "Quit AMPass" from tray menu
10. **Expected: App process exits completely**

## Security Checks

- [ ] Master password is NEVER stored (browser or desktop)
- [ ] Vault key is NEVER stored on disk (only in memory/session)
- [ ] Trusted token stored in: OS keychain (desktop) or chrome.storage.local (browser)
- [ ] Derivation params stored encrypted with device key (desktop) or in chrome.storage.local (browser — safe because encrypted_vault_key is ciphertext)
- [ ] Encrypted vault cache is double-encrypted (items are AES-GCM ciphertext)
- [ ] Network errors do NOT clear trusted session
- [ ] Only explicit auth failures (401/revoked) clear trusted session
- [ ] Idle lock clears vault key only, preserves trusted data
- [ ] No plaintext passwords in logs, storage, or IPC signals
