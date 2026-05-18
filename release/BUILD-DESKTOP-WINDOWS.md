# Build AMPass Desktop App for Windows

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain
- [Node.js](https://nodejs.org/) 18+ (for Tauri CLI)
- Windows 10/11 with Visual Studio Build Tools

## Build Steps

```bash
cd clients/desktop-tauri

# Install Tauri CLI (first time only)
cargo install tauri-cli --version "^2"

# Development mode (hot reload)
cargo tauri dev

# Production build
cargo tauri build
```

## Output Files

After `cargo tauri build`:

```
src-tauri/target/release/bundle/
├── nsis/
│   └── AMPass_1.0.0_x64-setup.exe    ← NSIS installer
└── msi/
    └── AMPass_1.0.0_x64.msi          ← MSI installer
```

## Upload to AMPass Downloads

1. Login to AMPass web app as admin
2. Go to Admin → Release Downloads
3. Upload the `.exe` file as "Windows EXE"
4. Upload the `.msi` file as "Windows MSI"
5. Set version number and release notes
6. Enable the release

## Icons

Replace placeholder icons in `src-tauri/icons/` with real PNG/ICO files before building for distribution.

To regenerate icons from scratch, run:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/generate-icons.ps1
```

### Troubleshooting: RC2175 icon format error

If you see:
```
RC2175: resource file src-tauri/icons/icon.ico is not in 3.00 format
```

This means `icon.ico` is not a valid Windows ICO file. Fix:
1. Run `scripts/generate-icons.ps1` to regenerate all icons
2. Or create a proper `.ico` file containing 16x16, 32x32, 48x48, 64x64, 128x128, and 256x256 sizes
3. Tools: IcoFX, GIMP (export as .ico), or ImageMagick

## Code Signing

For production distribution, sign the installer with a Windows code signing certificate. Set environment variables before building:

```
TAURI_SIGNING_PRIVATE_KEY=...
TAURI_SIGNING_PRIVATE_KEY_PASSWORD=...
```
