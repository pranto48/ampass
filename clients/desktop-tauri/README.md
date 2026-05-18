# AMPass Desktop App (Tauri v2)

A native Windows desktop client for the AMPass password manager. Provides offline vault access, system tray integration, OS keychain storage, and encrypted local cache.

## ⚠️ Security Warning

**This application has NOT been professionally audited. Do not use for real credentials until audited.**

## Features

- Native Windows app with system tray
- Offline encrypted vault cache
- OS keychain integration (Windows Credential Manager)
- Auto-lock on idle (configurable, default 15 min)
- Manual lock button
- Password generator
- Vault search
- Encrypted backup export/import via native file picker
- Wipe local data option
- Background sync every 5 minutes

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) 18+ (for Tauri CLI only)
- Windows 10/11 (primary target)
- AMPass PHP server running with extension API enabled

## Setup

```bash
cd clients/desktop-tauri

# Install Tauri CLI
cargo install tauri-cli --version "^2"

# Development mode (hot reload)
cargo tauri dev

# Production build
cargo tauri build
```

The production build outputs:
- `src-tauri/target/release/bundle/msi/AMPass_1.0.0_x64.msi`
- `src-tauri/target/release/bundle/nsis/AMPass_1.0.0_x64-setup.exe`

## Connecting to AMPass Server

1. Launch the desktop app
2. Enter your AMPass server URL (e.g., `https://yourdomain.com/ampass`)
3. Sign in with your AMPass credentials
4. Enter your master password to unlock the vault
5. Your vault syncs and is cached locally (encrypted)

### Local XAMPP Development

Use `http://localhost/ampass` as the server URL. The app allows HTTP for localhost.

### Production Server

Use `https://yourdomain.com/ampass`. Ensure:
- Extension API is enabled in AMPass Admin → Browser Extensions
- HTTPS is active
- The desktop app registers as a device (visible in admin panel)

## Architecture

```
┌──────────────────────────────────────────┐
│ Frontend (HTML/CSS/JS in Tauri WebView)   │
│  - Web Crypto API for vault decryption    │
│  - API client for server communication    │
│  - UI rendering                           │
└────────────────────┬─────────────────────┘
                     │ Tauri invoke()
┌────────────────────┴─────────────────────┐
│ Rust Backend                              │
│  - OS Keychain (token + device key)       │
│  - Encrypted local cache (AES-256-GCM)   │
│  - System tray                            │
│  - Idle detection + auto-lock             │
│  - Native file picker                     │
└──────────────────────────────────────────┘
```

## Security Model

| Data | Storage | Protection |
|------|---------|------------|
| Bearer token | Windows Credential Manager | OS-level encryption |
| Device key | Windows Credential Manager | OS-level encryption |
| Vault cache | `%APPDATA%/ampass/cache.enc` | AES-256-GCM with device key |
| Server URL | `%APPDATA%/ampass/config.json` | Plaintext (non-sensitive) |
| Vault key | Memory only | Cleared on lock/exit |
| Master password | Never stored | Used transiently for PBKDF2 |

## Data Location

All local data is stored in:
```
%APPDATA%\ampass\
├── config.json     (server URL, preferences)
└── cache.enc       (encrypted vault cache)
```

## Wipe Local Data

Settings → "Wipe Local Data" will:
1. Delete `cache.enc`
2. Delete `config.json`
3. Remove all keychain entries
4. Reset app to fresh state
5. Server data is NOT affected

## Limitations

- Offline mode is read-only (cannot save new items without server)
- Must be online to unlock (server verifies master password)
- Windows only (macOS/Linux support possible with Tauri but untested)
- No native messaging bridge in v1 (planned for v2)
- Icons are placeholders (replace before distribution)

## Development

The frontend is plain HTML/CSS/JS — no build step needed. Edit files in `src/` and they reload automatically in dev mode.

The Rust backend is in `src-tauri/src/`. After Rust changes, the dev server recompiles automatically.

## License

MIT License
