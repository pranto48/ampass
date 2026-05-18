---
inclusion: fileMatch
fileMatchPattern: "clients/desktop-tauri/**"
---

# AMPass Desktop App (Tauri v2) — Development Guide

## Status: SPECIFICATION COMPLETE — AWAITING APPROVAL

The full specification is at `clients/desktop-tauri/SPEC.md`. Do not begin implementation until the user explicitly approves.

## Key Constraints

1. **The PHP web app remains the server/backend** — the desktop app is a client only.
2. **Uses the same Extension API** (`/api/extension/*`) as the browser extension.
3. **Same crypto algorithms** — AES-256-GCM, PBKDF2, same hex encoding.
4. **Never stores plaintext secrets on disk** — only encrypted cache + OS keychain for device key.
5. **Rust backend for native features only** — crypto stays in the frontend (Web Crypto API) for consistency with web vault and extension.
6. **No Node.js runtime dependency** — Tauri bundles a native binary.

## Architecture Summary

- **Frontend**: HTML/CSS/JS (same design system as extension popup)
- **Rust backend**: Keychain, encrypted file I/O, tray, idle detection, native messaging
- **Sync**: Full vault fetch from PHP server on unlock, background poll every 5 min
- **Offline**: Read-only from encrypted local cache (v1: must be online to unlock)
- **Lock**: Auto-lock on idle (15 min default), on sleep, manual button

## Security Rules

- Vault key exists in memory ONLY while unlocked
- Master password is NEVER stored (used transiently for PBKDF2)
- Local cache is double-encrypted: items are already AES-GCM ciphertext, cache file is additionally encrypted with device key from OS keychain
- "Wipe Local Data" must delete all local files and keychain entries
- Native messaging requires explicit user approval per session
