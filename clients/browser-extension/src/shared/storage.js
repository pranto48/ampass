/**
 * AMPass Extension - Storage Wrapper
 * 
 * SECURITY:
 * - vaultKeyHex: ONLY in chrome.storage.session (cleared on browser close)
 * - authToken: session by default, local if "Trust this browser" enabled
 * - derivationParams: local (encrypted_vault_key is already encrypted with master password)
 * - encryptedVaultCache: local (items are AES-GCM ciphertext — safe to persist)
 * - plaintext passwords/notes: NEVER stored anywhere
 * - master password: NEVER stored anywhere
 */

const Storage = {
  // ===== Session Storage (cleared on browser close) =====
  async getSession(key) {
    const result = await chrome.storage.session.get(key);
    return result[key] ?? null;
  },
  async setSession(key, value) { await chrome.storage.session.set({ [key]: value }); },
  async removeSession(key) { await chrome.storage.session.remove(key); },
  async clearSession() { await chrome.storage.session.clear(); },

  // ===== Local Storage (persists across browser restarts) =====
  async getLocal(key) {
    const result = await chrome.storage.local.get(key);
    return result[key] ?? null;
  },
  async setLocal(key, value) { await chrome.storage.local.set({ [key]: value }); },
  async removeLocal(key) { await chrome.storage.local.remove(key); },

  // ===== Server URL =====
  async getServerUrl() { return await this.getLocal('serverUrl') || ''; },
  async setServerUrl(url) { await this.setLocal('serverUrl', url.replace(/\/+$/, '')); },

  // ===== Auth Token =====
  // Token can be in session (default) or local (trusted browser)
  async getToken() {
    return (await this.getSession('authToken')) || (await this.getLocal('trustedToken')) || null;
  },
  async setToken(token, trusted = false) {
    if (trusted) {
      await this.setLocal('trustedToken', token);
    }
    await this.setSession('authToken', token);
  },
  async removeToken() {
    await this.removeSession('authToken');
    await this.removeLocal('trustedToken');
  },

  // ===== Vault Key (MEMORY/SESSION ONLY — never local) =====
  async getVaultKey() { return await this.getSession('vaultKeyHex'); },
  async setVaultKey(keyHex) { await this.setSession('vaultKeyHex', keyHex); },

  // ===== Derivation Params (safe to persist — encrypted_vault_key is ciphertext) =====
  async getDerivationParams() {
    return (await this.getSession('derivationParams')) || (await this.getLocal('cachedDerivationParams')) || null;
  },
  async setDerivationParams(params) {
    await this.setSession('derivationParams', params);
    // Also cache locally for offline unlock
    await this.setLocal('cachedDerivationParams', params);
  },
  async removeDerivationParams() {
    await this.removeSession('derivationParams');
    await this.removeLocal('cachedDerivationParams');
  },

  // ===== Encrypted Vault Cache (safe to persist — all items are ciphertext) =====
  async getEncryptedVaultCache() { return await this.getLocal('encryptedVaultCache'); },
  async setEncryptedVaultCache(items) {
    await this.setLocal('encryptedVaultCache', items);
    await this.setLocal('vaultCacheTimestamp', Date.now());
  },
  async removeEncryptedVaultCache() {
    await this.removeLocal('encryptedVaultCache');
    await this.removeLocal('vaultCacheTimestamp');
  },
  async getVaultCacheTimestamp() { return await this.getLocal('vaultCacheTimestamp'); },

  // ===== Settings =====
  async getSettings() {
    const defaults = {
      serverUrl: '',
      deviceName: 'AMPass Browser Extension',
      autofillBehavior: 'click',
      autosaveBehavior: 'ask',
      clipboardClearSeconds: 30,
      lockTimeoutMinutes: 30,
      theme: 'system',
      allowHttpAutofill: true,
      useDesktopBridge: false,
      trustBrowser: false
    };
    const stored = await this.getLocal('settings');
    return { ...defaults, ...(stored || {}) };
  },
  async saveSettings(settings) { await this.setLocal('settings', settings); },

  // ===== State Checks =====
  async isAuthenticated() { return !!(await this.getToken()); },
  async isVaultUnlocked() { return !!(await this.getVaultKey()); },
  async hasOfflineCache() {
    const params = await this.getLocal('cachedDerivationParams');
    const cache = await this.getLocal('encryptedVaultCache');
    return !!(params && cache);
  },

  // ===== Lock Vault (keeps offline cache intact) =====
  async lockVault() {
    await this.removeSession('vaultKeyHex');
    await this.removeSession('vaultItems');
    // DO NOT remove encryptedVaultCache or cachedDerivationParams
  },

  // ===== Full Logout (clears everything) =====
  async logout() {
    await this.clearSession();
    await this.removeToken();
    await this.removeDerivationParams();
    await this.removeEncryptedVaultCache();
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.Storage = Storage;
}
