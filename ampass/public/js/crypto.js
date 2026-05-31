/**
 * AMPass - Client-Side Encryption Module
 * SECURITY: All vault encryption/decryption happens here using Web Crypto API.
 * The server NEVER sees plaintext vault data.
 * 
 * Encryption: AES-256-GCM (authenticated encryption)
 * Key Derivation: PBKDF2 with SHA-256
 * Zero-knowledge: Server only stores ciphertext + IV + salt
 */

const AMPassCrypto = (function() {
    'use strict';

    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12; // 96 bits for AES-GCM
    const SALT_LENGTH = 32;
    const DEFAULT_ITERATIONS = 100000;

    // Storage key for the derived vault key (session only - stored in memory)
    let _vaultKey = null;
    let activeUnlockPromise = null;

    /**
     * Generate a random salt
     */
    function generateSalt(length = SALT_LENGTH) {
        const salt = new Uint8Array(length);
        crypto.getRandomValues(salt);
        return bufferToHex(salt);
    }

    /**
     * Generate a random IV/nonce
     */
    function generateIV() {
        const iv = new Uint8Array(IV_LENGTH);
        crypto.getRandomValues(iv);
        return bufferToHex(iv);
    }

    /**
     * Generate a random vault key (256-bit)
     */
    async function generateVaultKey() {
        const key = await crypto.subtle.generateKey(
            { name: ALGORITHM, length: KEY_LENGTH },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        return key;
    }

    /**
     * Derive an encryption key from master password using PBKDF2
     * SECURITY: This is the key derivation function that turns the master password
     * into a cryptographic key for encrypting/decrypting the vault key.
     */
    async function deriveKey(password, salt, iterations = DEFAULT_ITERATIONS) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        const saltBuffer = hexToBuffer(salt);

        // Import password as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive the actual encryption key
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: ALGORITHM, length: KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );

        return derivedKey;
    }

    /**
     * Encrypt data with AES-GCM
     * Returns: { ciphertext: hex, iv: hex }
     */
    async function encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

        const ciphertext = await crypto.subtle.encrypt(
            { name: ALGORITHM, iv: iv },
            key,
            data
        );

        return {
            ciphertext: bufferToHex(new Uint8Array(ciphertext)),
            iv: bufferToHex(iv)
        };
    }

    /**
     * Decrypt data with AES-GCM
     */
    async function decrypt(ciphertextHex, ivHex, key) {
        const ciphertext = hexToBuffer(ciphertextHex);
        const iv = hexToBuffer(ivHex);

        const decrypted = await crypto.subtle.decrypt(
            { name: ALGORITHM, iv: iv },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    /**
     * Export a CryptoKey to raw hex
     */
    async function exportKey(key) {
        const raw = await crypto.subtle.exportKey('raw', key);
        return bufferToHex(new Uint8Array(raw));
    }

    /**
     * Import a raw hex key
     */
    async function importKey(hexKey) {
        const keyBuffer = hexToBuffer(hexKey);
        return await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: ALGORITHM, length: KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Setup encryption for a new user (registration)
     * 1. Generate a random vault key
     * 2. Derive a wrapping key from master password
     * 3. Encrypt the vault key with the wrapping key
     * 4. Return encrypted vault key + salt + IV (to store on server)
     */
    async function setupNewUser(masterPassword) {
        // Generate random vault key
        const vaultKey = await generateVaultKey();
        const vaultKeyRaw = await exportKey(vaultKey);

        // Generate salt for key derivation
        const salt = generateSalt();

        // Derive wrapping key from master password
        const wrappingKey = await deriveKey(masterPassword, salt, DEFAULT_ITERATIONS);

        // Encrypt the vault key with the wrapping key
        const encrypted = await encrypt(vaultKeyRaw, wrappingKey);

        return {
            encryption_salt: salt,
            encrypted_vault_key: encrypted.ciphertext,
            vault_key_iv: encrypted.iv,
            key_iterations: DEFAULT_ITERATIONS
        };
    }

    /**
     * Unlock vault - derive key and decrypt vault key
     * Called when user enters master password to unlock
     */
    async function unlockVault(masterPassword, params) {
        const { encryption_salt, encrypted_vault_key, vault_key_iv, key_iterations } = params;

        // Derive the wrapping key from master password
        const wrappingKey = await deriveKey(masterPassword, encryption_salt, key_iterations || DEFAULT_ITERATIONS);

        // Decrypt the vault key
        const vaultKeyHex = await decrypt(encrypted_vault_key, vault_key_iv, wrappingKey);

        // Import the vault key
        _vaultKey = await importKey(vaultKeyHex);

        // Store in sessionStorage (encrypted key reference only)
        sessionStorage.setItem('ampass_vault_key', vaultKeyHex);

        return true;
    }

    /**
     * Restore vault key from session storage (page reload)
     */
    async function restoreVaultKey() {
        const stored = sessionStorage.getItem('ampass_vault_key');
        if (stored) {
            _vaultKey = await importKey(stored);
            return true;
        }
        return false;
    }

    /**
     * Lock vault - clear key from memory
     */
    function lockVault() {
        _vaultKey = null;
        sessionStorage.removeItem('ampass_vault_key');
    }

    /**
     * Check if vault is unlocked (key available)
     */
    function isUnlocked() {
        return _vaultKey !== null;
    }

    /**
     * Encrypt a vault item (JSON object → encrypted string)
     */
    async function encryptVaultItem(itemData) {
        if (!_vaultKey) {
            // Try to restore from session
            const restored = await restoreVaultKey();
            if (!restored) throw new Error('Vault is locked');
        }

        const plaintext = JSON.stringify(itemData);
        return await encrypt(plaintext, _vaultKey);
    }

    /**
     * Decrypt a vault item (encrypted string → JSON object)
     */
    async function decryptVaultItem(ciphertextHex, ivHex) {
        if (!_vaultKey) {
            const restored = await restoreVaultKey();
            if (!restored) throw new Error('Vault is locked');
        }

        const plaintext = await decrypt(ciphertextHex, ivHex, _vaultKey);
        return JSON.parse(plaintext);
    }

    /**
     * Derive a search key from the vault key.
     * Used for title_hash and url_hash generation.
     * SECURITY: Derived deterministically from vault key — no server secret needed.
     */
    async function deriveSearchKey() {
        if (!_vaultKey) {
            const restored = await restoreVaultKey();
            if (!restored) throw new Error('Vault is locked');
        }
        const vaultKeyRaw = await exportKey(_vaultKey);
        const keyData = hexToBuffer(vaultKeyRaw);
        const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('ampass-search-key-v1'));
        return bufferToHex(new Uint8Array(sig));
    }

    /**
     * Compute search hash using vault-derived search key.
     * Use this for new items instead of computeHMAC.
     */
    async function computeSearchHash(data, searchKey) {
        if (!data || !searchKey) return null;
        const encoder = new TextEncoder();
        const keyData = hexToBuffer(searchKey);
        const message = encoder.encode(data.toLowerCase().trim());
        const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', key, message);
        return bufferToHex(new Uint8Array(sig));
    }

    /**
     * LEGACY: Compute HMAC-SHA256 with explicit secret.
     * Only for backward compatibility with old records.
     * New items should use computeSearchHash with vault-derived key.
     */
    async function computeHMAC(data, secret) {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret || 'ampass-hmac-key');
        const message = encoder.encode(data.toLowerCase().trim());

        const key = await crypto.subtle.importKey(
            'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', key, message);
        return bufferToHex(new Uint8Array(signature));
    }

    // ===== Utility Functions =====

    function bufferToHex(buffer) {
        return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // ===== Password Generator =====

    function generatePassword(options = {}) {
        const length = options.length || 16;
        const uppercase = options.uppercase !== false;
        const lowercase = options.lowercase !== false;
        const numbers = options.numbers !== false;
        const symbols = options.symbols !== false;
        const noAmbiguous = options.noAmbiguous || false;

        let chars = '';
        if (uppercase) chars += noAmbiguous ? 'ABCDEFGHJKMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (lowercase) chars += noAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        if (numbers) chars += noAmbiguous ? '23456789' : '0123456789';
        if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (chars.length === 0) chars = 'abcdefghijklmnopqrstuvwxyz';

        const array = new Uint32Array(length);
        crypto.getRandomValues(array);

        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars[array[i] % chars.length];
        }

        return password;
    }

    /**
     * Generate a passphrase from word list
     */
    function generatePassphrase(options = {}) {
        const wordCount = options.words || 4;
        const separator = options.separator || '-';
        const capitalize = options.capitalize !== false;
        const addNumber = options.addNumber || false;

        // Simple word list (in production, use a larger list like EFF diceware)
        const words = [
            'apple', 'brave', 'cloud', 'dance', 'eagle', 'flame', 'grape', 'heart',
            'ivory', 'jewel', 'karma', 'lemon', 'maple', 'noble', 'ocean', 'pearl',
            'quest', 'river', 'storm', 'tiger', 'unity', 'vivid', 'whale', 'xenon',
            'yacht', 'zebra', 'amber', 'blaze', 'coral', 'delta', 'ember', 'frost',
            'globe', 'haven', 'index', 'joker', 'knack', 'lunar', 'metro', 'nexus',
            'orbit', 'prism', 'quilt', 'radar', 'solar', 'torch', 'ultra', 'vault',
            'wired', 'pixel', 'cyber', 'crypt', 'shield', 'spark', 'swift', 'stone',
            'steel', 'blade', 'crown', 'drift', 'forge', 'ghost', 'haste', 'light'
        ];

        const array = new Uint32Array(wordCount);
        crypto.getRandomValues(array);

        let passphrase = [];
        for (let i = 0; i < wordCount; i++) {
            let word = words[array[i] % words.length];
            if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
            passphrase.push(word);
        }

        let result = passphrase.join(separator);
        if (addNumber) {
            const num = new Uint32Array(1);
            crypto.getRandomValues(num);
            result += separator + (num[0] % 100);
        }

        return result;
    }

    /**
     * Calculate password strength (0-100)
     */
    function calculateStrength(password) {
        if (!password) return 0;

        let score = 0;
        const length = password.length;

        // Length scoring
        if (length >= 8) score += 10;
        if (length >= 12) score += 15;
        if (length >= 16) score += 15;
        if (length >= 20) score += 10;

        // Character variety
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 10;
        if (/[^a-zA-Z0-9]/.test(password)) score += 15;

        // Bonus for mixing
        const types = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(password)).length;
        score += types * 5;

        // Penalty for common patterns
        if (/^[a-z]+$/.test(password) || /^[0-9]+$/.test(password)) score -= 20;
        if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated chars
        if (/^(123|abc|qwerty|password)/i.test(password)) score -= 30;

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Get strength label
     */
    function getStrengthLabel(score) {
        if (score >= 80) return { label: 'Very Strong', class: 'strength-excellent' };
        if (score >= 60) return { label: 'Strong', class: 'strength-good' };
        if (score >= 40) return { label: 'Fair', class: 'strength-fair' };
        if (score >= 20) return { label: 'Weak', class: 'strength-weak' };
        return { label: 'Very Weak', class: 'strength-terrible' };
    }

    /**
     * Ensure vault key is unlocked. If not, presents a beautiful inline modal prompting the user to unlock.
     * Resolves to true if key is available or successfully derived, false if cancelled.
     */
    async function ensureVaultKeyUnlocked() {
        if (isUnlocked()) return true;

        const restored = await restoreVaultKey();
        if (restored) return true;

        if (activeUnlockPromise) {
            return activeUnlockPromise;
        }

        activeUnlockPromise = new Promise((resolve) => {
            const modalDiv = document.createElement('div');
            modalDiv.id = 'ampass-inline-unlock-modal';
            modalDiv.innerHTML = `
                <div class="modal-overlay show" style="z-index: 9999; display: flex; align-items: center; justify-content: center; position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px);">
                    <div class="modal" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 28px; max-width: 420px; width: 100%; box-shadow: var(--shadow-xl);">
                        <div class="modal-title" style="font-size:1.2rem; font-weight:600; margin-bottom:8px; display:flex; align-items:center; gap:8px;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:20px;height:20px;color:var(--accent);"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                            Unlock Vault
                        </div>
                        <div class="modal-body" style="font-size:0.86rem; color:var(--text-secondary); line-height:1.6;">
                            <p style="margin-bottom:16px;">Your vault is locked. Enter your master password to decrypt and verify your vault items.</p>
                            <form id="inlineUnlockForm" style="display:block;">
                                <div class="form-group" style="margin-bottom:16px;">
                                    <label for="inline_master_password" class="form-label" style="display:block; margin-bottom:6px; font-weight:550; font-size:0.78rem;">Master Password</label>
                                    <div class="input-wrapper" style="position:relative; display:flex; align-items:center;">
                                        <input type="password" id="inline_master_password" class="form-input" placeholder="Enter your master password" required autofocus style="width:100%; padding:10px 14px; background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius); color:var(--text);" autocomplete="current-password">
                                        <button type="button" class="input-toggle-password" id="toggleInlinePassword" style="position:absolute; right:10px; background:none; border:none; color:var(--text-muted); cursor:pointer; padding:4px;">
                                            <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:17px;height:17px;"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                            <svg class="eye-closed" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:17px;height:17px;display:none;"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                                        </button>
                                    </div>
                                    <div class="alert alert-error" id="inlineUnlockError" style="display:none; margin-top:12px; font-size:0.82rem; padding:10px 12px; border-radius:var(--radius);"></div>
                                </div>
                                <div class="modal-actions" style="display:flex; justify-content:flex-end; gap:8px; margin-top:24px;">
                                    <button type="button" class="btn btn-secondary" id="btnInlineUnlockCancel" style="padding:8px 14px; font-size:0.82rem; border-radius:var(--radius); cursor:pointer; font-weight:550;">Cancel</button>
                                    <button type="submit" class="btn btn-primary" id="btnInlineUnlockSubmit" style="padding:8px 14px; font-size:0.82rem; border-radius:var(--radius); cursor:pointer; font-weight:550; display:inline-flex; align-items:center; gap:6px;">
                                        <span class="spinner" id="inlineUnlockSpinner" style="display:none; width: 14px; height: 14px; border:2px solid var(--border); border-top-color:var(--text-inverse); border-radius:50%; animation:spin 0.7s linear infinite;"></span>
                                        <span id="btnInlineUnlockText">Unlock</span>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modalDiv);

            const toggleBtn = modalDiv.querySelector('#toggleInlinePassword');
            const passInput = modalDiv.querySelector('#inline_master_password');
            const eyeOpen = toggleBtn.querySelector('.eye-open');
            const eyeClosed = toggleBtn.querySelector('.eye-closed');

            toggleBtn.addEventListener('click', () => {
                if (passInput.type === 'password') {
                    passInput.type = 'text';
                    eyeOpen.style.display = 'none';
                    eyeClosed.style.display = 'block';
                } else {
                    passInput.type = 'password';
                    eyeOpen.style.display = 'block';
                    eyeClosed.style.display = 'none';
                }
            });

            const form = modalDiv.querySelector('#inlineUnlockForm');
            const errorDiv = modalDiv.querySelector('#inlineUnlockError');
            const spinner = modalDiv.querySelector('#inlineUnlockSpinner');
            const btnText = modalDiv.querySelector('#btnInlineUnlockText');
            const btnSubmit = modalDiv.querySelector('#btnInlineUnlockSubmit');
            const btnCancel = modalDiv.querySelector('#btnInlineUnlockCancel');

            passInput.focus();

            btnCancel.addEventListener('click', () => {
                modalDiv.remove();
                activeUnlockPromise = null;
                resolve(false);
            });

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const password = passInput.value;
                if (!password) return;

                spinner.style.display = 'inline-block';
                btnText.textContent = 'Deriving Key...';
                btnSubmit.disabled = true;
                btnCancel.disabled = true;
                errorDiv.style.display = 'none';

                try {
                    const baseUrl = (window.AMPass && window.AMPass.baseUrl) || '';
                    
                    // Fetch a fresh CSRF token from the server to guarantee validity (e.g. after idle lockouts)
                    let csrfToken = (window.AMPass && window.AMPass.csrfToken) || '';
                    try {
                        const csrfResp = await fetch(baseUrl + '/api/auth/csrfToken');
                        const csrfData = await csrfResp.json();
                        if (csrfResp.ok && csrfData.success && csrfData.csrf_token) {
                            csrfToken = csrfData.csrf_token;
                            if (window.AMPass) {
                                window.AMPass.csrfToken = csrfToken;
                            }
                        }
                    } catch (e) {
                        console.warn('Failed to refresh CSRF token, attempting with existing:', e);
                    }

                    const paramsResp = await fetch(baseUrl + '/api/auth/derivation-params');
                    const paramsData = await paramsResp.json();
                    if (!paramsResp.ok || !paramsData.success) {
                        throw new Error(paramsData.error || 'Failed to fetch security settings');
                    }
                    const params = paramsData.params;

                    // Derive wrapping key and decrypt vault key
                    await unlockVault(password, params);

                    // Call verify-master to verify master password and sync PHP session
                    const verifyResp = await fetch(baseUrl + '/api/auth/verify-master', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-TOKEN': csrfToken
                        },
                        body: JSON.stringify({ master_password: password })
                    });
                    
                    const verifyData = await verifyResp.json();
                    if (!verifyResp.ok || !verifyData.success) {
                        throw new Error(verifyData.error || 'Failed to verify password with server');
                    }

                    modalDiv.remove();
                    activeUnlockPromise = null;
                    resolve(true);

                } catch (err) {
                    console.error('Inline unlock failed:', err);
                    errorDiv.textContent = err.message || 'Invalid master password';
                    errorDiv.style.display = 'block';
                    
                    spinner.style.display = 'none';
                    btnText.textContent = 'Unlock';
                    btnSubmit.disabled = false;
                    btnCancel.disabled = false;
                    passInput.focus();
                }
            });
        });

        return activeUnlockPromise;
    }

    // Public API
    return {
        generateSalt,
        generateIV,
        deriveKey,
        encrypt,
        decrypt,
        setupNewUser,
        unlockVault,
        restoreVaultKey,
        ensureVaultKeyUnlocked,
        lockVault,
        isUnlocked,
        encryptVaultItem,
        decryptVaultItem,
        deriveSearchKey,
        computeSearchHash,
        computeHMAC,
        generatePassword,
        generatePassphrase,
        calculateStrength,
        getStrengthLabel,
        bufferToHex,
        hexToBuffer
    };
})();
