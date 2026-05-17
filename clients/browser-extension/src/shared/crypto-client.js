/**
 * AMPass Extension - Crypto Client
 * SECURITY: Identical algorithms to the web vault's crypto.js.
 * AES-256-GCM encryption, PBKDF2 key derivation.
 * All decryption happens locally — never on the server.
 */

const CryptoClient = {
  ALGORITHM: 'AES-GCM',
  KEY_LENGTH: 256,
  IV_LENGTH: 12,
  DEFAULT_ITERATIONS: 100000,

  // ===== Utility =====
  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  },

  // ===== Key Derivation =====
  async deriveKey(password, saltHex, iterations) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: this.hexToBuffer(saltHex), iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  },

  async importKey(hexKey) {
    return await crypto.subtle.importKey(
      'raw', this.hexToBuffer(hexKey),
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      true, ['encrypt', 'decrypt']
    );
  },

  async exportKey(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return this.bufferToHex(new Uint8Array(raw));
  },

  // ===== Encrypt / Decrypt =====
  async encrypt(plaintext, key) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const ciphertext = await crypto.subtle.encrypt(
      { name: this.ALGORITHM, iv }, key, encoder.encode(plaintext)
    );
    return {
      ciphertext: this.bufferToHex(new Uint8Array(ciphertext)),
      iv: this.bufferToHex(iv)
    };
  },

  async decrypt(ciphertextHex, ivHex, key) {
    const decrypted = await crypto.subtle.decrypt(
      { name: this.ALGORITHM, iv: this.hexToBuffer(ivHex) },
      key, this.hexToBuffer(ciphertextHex)
    );
    return new TextDecoder().decode(decrypted);
  },

  // ===== Vault Operations =====

  /**
   * Unlock vault: derive wrapping key → decrypt vault key
   * Returns the raw vault key hex (to store in session)
   */
  async unlockVault(masterPassword, params) {
    const { encryption_salt, encrypted_vault_key, vault_key_iv, key_iterations } = params;
    const wrappingKey = await this.deriveKey(masterPassword, encryption_salt, key_iterations || this.DEFAULT_ITERATIONS);
    const vaultKeyHex = await this.decrypt(encrypted_vault_key, vault_key_iv, wrappingKey);
    return vaultKeyHex;
  },

  /**
   * Decrypt a vault item's encrypted_data blob
   */
  async decryptItem(encryptedData, iv, vaultKeyHex) {
    const key = await this.importKey(vaultKeyHex);
    const plaintext = await this.decrypt(encryptedData, iv, key);
    return JSON.parse(plaintext);
  },

  /**
   * Encrypt a vault item (for autosave)
   */
  async encryptItem(itemData, vaultKeyHex) {
    const key = await this.importKey(vaultKeyHex);
    const plaintext = JSON.stringify(itemData);
    return await this.encrypt(plaintext, key);
  },

  /**
   * Compute HMAC-SHA256 for domain matching (same as web vault)
   */
  async computeHMAC(data, secret) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret || 'ampass-hmac-key');
    const message = encoder.encode(data.toLowerCase().trim());
    const key = await crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, message);
    return this.bufferToHex(new Uint8Array(sig));
  },

  // ===== Password Generator =====
  generatePassword(options = {}) {
    const length = options.length || 20;
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
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, v => chars[v % chars.length]).join('');
  },

  calculateStrength(password) {
    if (!password) return 0;
    let score = 0;
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 15;
    if (password.length >= 20) score += 10;
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;
    const types = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(password)).length;
    score += types * 5;
    return Math.max(0, Math.min(100, score));
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.CryptoClient = CryptoClient;
}
