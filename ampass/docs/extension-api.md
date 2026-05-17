# AMPass Extension API Documentation

## Overview

The Extension API allows browser extensions to authenticate, access encrypted vault data, and perform CRUD operations. All vault data remains encrypted — the server never sees plaintext secrets.

**Base URL:** `https://your-ampass-server.com/api/extension/`

## Authentication

The Extension API uses **Bearer Token** authentication. Obtain a token via the `/login` endpoint, then include it in all subsequent requests:

```
Authorization: Bearer <64-char-hex-token>
```

Tokens are:
- SHA-256 hashed before storage (database leak doesn't expose tokens)
- Tied to a specific device
- Configurable expiry (default 30 days)
- Revocable by user or admin

## Security Requirements

- **HTTPS required** (except localhost for development)
- **Rate limiting** on all endpoints
- **Never returns plaintext vault fields** — only encrypted ciphertext
- **Audit logging** on all actions
- **CORS** restricted to configured extension origins

## Error Format

All errors return JSON:
```json
{
    "error": "Human-readable error message",
    "code": "MACHINE_READABLE_CODE"
}
```

Common error codes: `AUTH_REQUIRED`, `AUTH_FAILED`, `RATE_LIMITED`, `HTTPS_REQUIRED`, `API_DISABLED`, `MAX_DEVICES`, `NOT_FOUND`, `ACCOUNT_SUSPENDED`

---

## Endpoints

### GET /api/extension/status

Check API availability. No authentication required.

**Response:**
```json
{
    "success": true,
    "api_version": "1.0",
    "app_version": "1.0.0",
    "authenticated": false,
    "https": true,
    "server_time": "2026-05-17T12:00:00+00:00"
}
```

---

### POST /api/extension/login

Authenticate and register a new extension device.

**Request Body:**
```json
{
    "username": "john",
    "password": "user-login-password",
    "device_name": "Chrome on Windows",
    "browser_name": "Chrome",
    "extension_id": "abcdefghijklmnop"
}
```

**Response (200):**
```json
{
    "success": true,
    "token": "64-char-hex-bearer-token",
    "token_prefix": "a1b2c3d4",
    "expires_at": "2026-06-16 12:00:00",
    "device_id": 1,
    "user": {
        "id": 1,
        "username": "john",
        "full_name": "John Doe",
        "email": "john@example.com"
    },
    "derivation_params": {
        "encryption_salt": "hex-salt",
        "key_iterations": 100000,
        "encrypted_vault_key": "hex-ciphertext",
        "vault_key_iv": "hex-iv"
    }
}
```

**Rate Limit:** 5 attempts per 15 minutes per IP.

---

### POST /api/extension/logout

Revoke the current token. Requires authentication.

**Response:**
```json
{
    "success": true,
    "message": "Token revoked"
}
```

---

### GET /api/extension/session

Check current session state. Requires authentication.

**Response:**
```json
{
    "success": true,
    "user": { "id": 1, "username": "john", "full_name": "John Doe" },
    "device_id": 1,
    "token_id": 5
}
```

---

### GET /api/extension/vault/list

List all encrypted vault items. Requires authentication.

**Query Parameters:**
- `type` (optional): Filter by item type (login, secure_note, payment_card, etc.)
- `folder_id` (optional): Filter by folder

**Response:**
```json
{
    "success": true,
    "items": [
        {
            "id": 1,
            "item_type": "login",
            "encrypted_data": "hex-ciphertext",
            "encryption_iv": "hex-iv",
            "title_hash": "hmac-hex",
            "url_hash": "hmac-hex",
            "is_favorite": 1,
            "password_strength": 85,
            "last_used_at": "2026-05-17 10:00:00",
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-05-17 10:00:00"
        }
    ],
    "folders": [...],
    "count": 42
}
```

---

### GET /api/extension/vault/get?id={id}

Get a single encrypted vault item. Marks it as recently used.

**Response:**
```json
{
    "success": true,
    "item": { ... }
}
```

---

### GET /api/extension/vault/match-domain?url_hash={hash}

Find vault items matching a URL hash (for autofill). The extension computes `HMAC-SHA256(url)` client-side and sends the hash.

**Query Parameters:**
- `url_hash` (required): 64-char hex HMAC-SHA256 of the domain/URL

**Response:**
```json
{
    "success": true,
    "items": [...],
    "count": 2
}
```

---

### POST /api/extension/vault/save

Create a new encrypted vault item (autosave).

**Request Body:**
```json
{
    "item_type": "login",
    "encrypted_data": "hex-ciphertext-of-json-blob",
    "encryption_iv": "hex-iv",
    "title_hash": "hmac-hex",
    "url_hash": "hmac-hex",
    "folder_id": null,
    "is_favorite": 0,
    "password_strength": 75,
    "is_weak": 0,
    "is_reused": 0
}
```

**Response:**
```json
{
    "success": true,
    "id": 43,
    "message": "Item created"
}
```

---

### POST /api/extension/vault/update

Update an existing encrypted vault item.

**Request Body:** Same as save, plus `"id": 43`

---

### POST /api/extension/vault/delete

Delete a vault item.

**Request Body:**
```json
{ "id": 43 }
```

---

### GET /api/extension/generator/policy

Get password generation policy defaults.

---

### GET /api/extension/audit?limit=50&offset=0

Get recent extension audit logs for the current user.

---

### GET /api/extension/devices

List user's registered extension devices.

---

### POST /api/extension/revokeDevice

Revoke a device and all its tokens.

**Request Body:**
```json
{ "device_id": 1 }
```

---

## Setup Instructions

### For Users

1. Install the AMPass browser extension from the Chrome Web Store (or load unpacked for development)
2. Click the extension icon → Settings
3. Enter your AMPass server URL (e.g., `https://yourdomain.com/ampass`)
4. Log in with your AMPass username and password
5. Enter your master password to unlock the vault
6. The extension is now connected and will suggest autofill on login pages

### For Administrators

1. Run the migration: Import `database/migrations/001_extension_tables.sql` into your database
2. Go to Admin Panel → Browser Extensions
3. Configure:
   - Enable/disable the extension API
   - Set allowed extension origins (for production, specify your extension's ID)
   - Set token lifetime and max devices per user
4. Monitor connected devices and audit logs

### CORS Configuration

For production, add your extension's origin to the "Allowed Extension Origins" setting:
```
chrome-extension://your-extension-id-here
```

For development on localhost, any extension origin is allowed by default.

### HTTPS Requirement

The extension API requires HTTPS for all non-localhost connections. This is enforced at the API level — requests over HTTP will receive a 403 error with code `HTTPS_REQUIRED`.
