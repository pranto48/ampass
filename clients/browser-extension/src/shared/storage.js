/**
 * AMPass Extension - Storage Wrapper
 * SECURITY: Never stores plaintext master password or vault passwords.
 * Uses chrome.storage.session for sensitive data (cleared on browser close).
 * Uses chrome.storage.local for persistent settings.
 */

const Storage = {
  // ===== Session Storage (cleared on browser close) =====
  async getSession(key) {
    const result = await chrome.storage.session.get(key);
    return result[key] ?? null;
  },

  async setSession(key, value) {
    await chrome.storage.session.set({ [key]: value });
  },

  async removeSession(key) {
    await chrome.storage.session.remove(key);
  },

  async clearSession() {
    await chrome.storage.session.clear();
  },

  // ===== Local Storage (persists) =====
  async getLocal(key) {
    const result = await chrome.storage.local.get(key);
    return result[key] ?? null;
  },

  async setLocal(key, value) {
    await chrome.storage.local.set({ [key]: value });
  },

  async removeLocal(key) {
    await chrome.storage.local.remove(key);
  },

  // ===== Convenience Methods =====
  async getServerUrl() {
    return await this.getLocal('serverUrl') || '';
  },

  async setServerUrl(url) {
    await this.setLocal('serverUrl', url.replace(/\/+$/, ''));
  },

  async getToken() {
    return await this.getSession('authToken');
  },

  async setToken(token) {
    await this.setSession('authToken', token);
  },

  async getVaultKey() {
    return await this.getSession('vaultKeyHex');
  },

  async setVaultKey(keyHex) {
    await this.setSession('vaultKeyHex', keyHex);
  },

  async getDerivationParams() {
    return await this.getSession('derivationParams');
  },

  async setDerivationParams(params) {
    await this.setSession('derivationParams', params);
  },

  async getSettings() {
    const defaults = {
      serverUrl: '',
      deviceName: 'AMPass Browser Extension',
      autofillBehavior: 'click', // 'ask', 'click', 'never'
      autosaveBehavior: 'ask',   // 'ask', 'never'
      clipboardClearSeconds: 30,
      lockTimeoutMinutes: 15,
      theme: 'system',
      allowHttpAutofill: false
    };
    const stored = await this.getLocal('settings');
    return { ...defaults, ...(stored || {}) };
  },

  async saveSettings(settings) {
    await this.setLocal('settings', settings);
  },

  async isAuthenticated() {
    const token = await this.getToken();
    return !!token;
  },

  async isVaultUnlocked() {
    const key = await this.getVaultKey();
    return !!key;
  },

  async lockVault() {
    await this.removeSession('vaultKeyHex');
    await this.removeSession('vaultItems');
  },

  async logout() {
    await this.clearSession();
  }
};

// Export for use in different contexts
if (typeof globalThis !== 'undefined') {
  globalThis.Storage = Storage;
}
