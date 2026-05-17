# AMPass Browser Extension

Chrome/Edge Manifest V3 browser extension for the AMPass password manager. Provides autofill, autosave, password generation, and vault search directly in the browser.

## Features

- **Autofill**: Detects login forms and fills credentials with one click
- **Autosave**: Offers to save new logins or update changed passwords
- **Password Generator**: Generate strong passwords from the popup
- **Vault Search**: Search all vault items from the popup
- **Domain Matching**: Automatically shows matching credentials for the current site
- **Badge Count**: Shows number of matching credentials on the extension icon
- **Auto-Lock**: Vault locks after configurable inactivity timeout
- **Zero-Knowledge**: All encryption/decryption happens locally in the extension

## Loading Unpacked in Chrome/Edge

1. Open `chrome://extensions/` (or `edge://extensions/`)
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `clients/browser-extension/` folder
5. The AMPass icon appears in your toolbar

**Note:** The placeholder icon files need to be replaced with actual PNG images for the extension to display properly. You can generate them from the SVG favicon.

## Connecting to Local XAMPP AMPass

1. Start XAMPP (Apache + MySQL)
2. Ensure AMPass is installed at `http://localhost/ampass`
3. Run the extension migration: Import `ampass/database/migrations/001_extension_tables.sql`
4. In AMPass Admin → Browser Extensions: ensure API is enabled
5. Click the AMPass extension icon → enter server URL: `http://localhost/ampass`
6. Log in with your AMPass credentials
7. Enter your master password to unlock the vault

## Connecting to cPanel AMPass

1. Ensure AMPass is deployed with HTTPS: `https://yourdomain.com/ampass`
2. Import the migration SQL into your database
3. In AMPass Admin → Browser Extensions:
   - Enable the extension API
   - Add your extension's origin to "Allowed Extension Origins":
     ```
     chrome-extension://YOUR_EXTENSION_ID_HERE
     ```
   - To find your extension ID: go to `chrome://extensions/` and copy the ID shown under your loaded extension
4. Click the AMPass extension icon → enter your server URL
5. Log in and unlock

## Required AMPass Backend Settings

Before the extension can connect, ensure:

1. **Migration applied**: `database/migrations/001_extension_tables.sql` imported
2. **Extension API enabled**: Admin → Browser Extensions → Enable Extension API ✓
3. **CORS configured** (production only): Add your extension origin to allowed origins
4. **HTTPS active** (production): The extension API requires HTTPS except on localhost

## Security Limitations

- **Vault key in session storage**: The vault key is stored in `chrome.storage.session` which is cleared when the browser closes. If the browser process is compromised, the key could be extracted.
- **Content script injection**: Content scripts run in the page context. A malicious page could potentially detect the AMPass icon or interfere with autofill.
- **No phishing protection**: The extension does basic domain matching but does not have a comprehensive phishing database.
- **HTTP warning**: Autofill is disabled on HTTP pages by default. Users can override this in settings (not recommended).
- **Clipboard access**: Copied passwords remain in clipboard until cleared (default 30 seconds).
- **Service worker lifecycle**: Chrome may terminate the service worker after inactivity. The vault key persists in `chrome.storage.session` and is restored on wake.

## How to Test Autofill/Autosave

1. Load the extension in Chrome/Edge
2. Connect to your AMPass server and unlock the vault
3. Open `test-pages/login-test.html` in a browser tab
4. **Test form detection**: The AMPass icon should appear on password fields
5. **Test autofill**: Click the extension popup → click the autofill button for a matching item
6. **Test autosave**: Fill in credentials manually and submit the form → a save prompt should appear
7. **Test password update**: Autofill a form, change the password, submit → an update prompt should appear

## Architecture

```
src/
├── background/
│   └── service-worker.js    # Holds vault key, handles crypto, API calls
├── content/
│   ├── form-detector.js     # Detects login forms, adds AMPass icon
│   ├── autofill.js          # Fills credentials into form fields
│   └── save-detector.js     # Detects form submissions, shows save prompt
├── popup/
│   ├── index.html           # Popup UI
│   ├── popup.css            # Popup styles
│   └── popup.js             # Popup logic
├── options/
│   ├── options.html         # Settings page
│   ├── options.css
│   └── options.js
└── shared/
    ├── api-client.js        # HTTP client for AMPass API
    ├── crypto-client.js     # Web Crypto API (AES-256-GCM, PBKDF2)
    ├── domain-utils.js      # URL/domain normalization
    ├── password-generator.js
    ├── security.js          # HTTPS checks, phishing detection
    └── storage.js           # chrome.storage wrapper
```

## Security Model

1. **Service worker** is the only component that holds the vault key
2. **Content scripts** never have access to the vault key or decrypted items
3. **Popup** requests decrypted data from the service worker via messages
4. **Autofill** receives plaintext credentials only during the fill operation
5. **Server** never receives plaintext vault data — only encrypted ciphertext
6. **All crypto** uses Web Crypto API (same algorithms as the web vault)

## Development

No build step required. The extension uses plain JavaScript, HTML, and CSS.

To make changes:
1. Edit files in `src/`
2. Go to `chrome://extensions/`
3. Click the refresh icon on the AMPass extension
4. Changes take effect immediately (except service worker changes which may need a full reload)

## Generating Real Icons

Replace the placeholder icon files with actual PNGs. You can use the AMPass SVG favicon as a source:

```bash
# Using ImageMagick (if installed)
convert -background none -resize 16x16 ampass/public/assets/favicon.svg assets/icons/icon-16.png
convert -background none -resize 32x32 ampass/public/assets/favicon.svg assets/icons/icon-32.png
convert -background none -resize 48x48 ampass/public/assets/favicon.svg assets/icons/icon-48.png
convert -background none -resize 128x128 ampass/public/assets/favicon.svg assets/icons/icon-128.png
```

Or use any image editor to create 16, 32, 48, and 128px square PNG icons.
