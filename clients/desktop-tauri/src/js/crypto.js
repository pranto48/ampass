/**
 * AMPass Desktop - Crypto (identical to browser extension)
 * AES-256-GCM, PBKDF2 key derivation via Web Crypto API.
 */
const Crypto = {
  async deriveKey(password, saltHex, iterations) {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: this.hexToBuffer(saltHex), iterations, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  },
  async importKey(hex) {
    return crypto.subtle.importKey('raw', this.hexToBuffer(hex), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },
  async decrypt(ctHex, ivHex, key) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.hexToBuffer(ivHex) }, key, this.hexToBuffer(ctHex));
    return new TextDecoder().decode(pt);
  },
  async encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    return { ciphertext: this.bufToHex(new Uint8Array(ct)), iv: this.bufToHex(iv) };
  },
  async unlockVault(masterPassword, params) {
    const wk = await this.deriveKey(masterPassword, params.encryption_salt, params.key_iterations || 100000);
    return await this.decrypt(params.encrypted_vault_key, params.vault_key_iv, wk);
  },
  async decryptItem(encData, iv, vaultKeyHex) {
    const key = await this.importKey(vaultKeyHex);
    const pt = await this.decrypt(encData, iv, key);
    return JSON.parse(pt);
  },
  async encryptItem(data, vaultKeyHex) {
    const key = await this.importKey(vaultKeyHex);
    return await this.encrypt(JSON.stringify(data), key);
  },
  generatePassword(opts = {}) {
    const len = opts.length || 20;
    let chars = '';
    if (opts.uppercase !== false) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (opts.lowercase !== false) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (opts.numbers !== false) chars += '0123456789';
    if (opts.symbols !== false) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    return Array.from(arr, v => chars[v % chars.length]).join('');
  },
  strength(pw) {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8) s += 10; if (pw.length >= 12) s += 15; if (pw.length >= 16) s += 15; if (pw.length >= 20) s += 10;
    if (/[a-z]/.test(pw)) s += 10; if (/[A-Z]/.test(pw)) s += 10; if (/[0-9]/.test(pw)) s += 10; if (/[^a-zA-Z0-9]/.test(pw)) s += 15;
    s += [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(pw)).length * 5;
    return Math.max(0, Math.min(100, s));
  },
  bufToHex(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); },
  hexToBuffer(hex) { const b = new Uint8Array(hex.length / 2); for (let i = 0; i < hex.length; i += 2) b[i/2] = parseInt(hex.substr(i, 2), 16); return b; }
};
