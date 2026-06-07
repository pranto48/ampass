/**
 * AMPass Desktop / Web Vault — PHP Backend API Client
 *
 * Replaces the previous Firebase Firestore client.
 * All vault operations now go through the PHP backend at /api/extension/…
 * This keeps the desktop/web vault and browser extension in sync on the same backend.
 *
 * SECURITY: All requests are Bearer-token authenticated over HTTPS.
 *           Vault data is always encrypted before it reaches this client.
 */
const Api = {
  serverUrl: '',
  token: '',

  // ---- URL Utilities ----

  normalizeServerUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
  },

  setServerUrl(url) {
    this.serverUrl = this.normalizeServerUrl(url);
  },

  // ---- Core Request ----

  /**
   * Make an authenticated JSON request to the PHP extension API.
   * @param {string} endpoint  e.g. 'vault/list'
   * @param {object} options   { method, body }
   */
  async request(endpoint, options = {}) {
    if (!this.serverUrl) throw Object.assign(new Error('Server URL not configured'), { code: 'NO_SERVER' });

    const url = this.serverUrl + '/api/extension/' + endpoint.replace(/^\//, '');
    const headers = {
      'Content-Type': 'application/json',
      'X-AMPass-Version': '1.107',
      'X-AMPass-Client': 'desktop-web'
    };
    if (this.token) headers['Authorization'] = 'Bearer ' + this.token;

    const config = { method: options.method || (options.body ? 'POST' : 'GET'), headers };
    if (options.body) config.body = JSON.stringify(options.body);

    let response;
    try {
      response = await fetch(url, config);
    } catch (networkErr) {
      throw Object.assign(
        new Error('AMPass server is offline or unreachable'),
        { code: 'NETWORK_OFFLINE', status: 0 }
      );
    }

    // Safely parse — PHP errors often return HTML
    let data;
    try {
      const text = await response.text();
      data = JSON.parse(text);
    } catch {
      throw Object.assign(
        new Error('Server returned invalid response (HTTP ' + response.status + ')'),
        { code: 'PARSE_ERROR', status: response.status }
      );
    }

    if (!response.ok) {
      throw Object.assign(
        new Error(data.error || 'Request failed'),
        { code: data.code || (response.status >= 500 ? 'SERVER_ERROR' : 'UNKNOWN'), status: response.status }
      );
    }

    return data;
  },

  // ---- Auth ----

  /**
   * Login to the PHP backend.
   * Returns { token, device_id, derivation_params, user }
   */
  async login(username, password, deviceName, deviceId = null, twoFactorCode = '') {
    // Detect browser/platform for the device name if not provided
    const platform = (typeof navigator !== 'undefined')
      ? (navigator.userAgent.includes('Edg') ? 'Edge'
        : navigator.userAgent.includes('Chrome') ? 'Chrome'
        : navigator.userAgent.includes('Firefox') ? 'Firefox'
        : 'Browser')
      : 'Desktop';

    const result = await this.request('login', {
      body: {
        username,
        password,
        device_name: deviceName || ('AMPass Web on ' + platform),
        browser_name: platform,
        device_id: deviceId,
        two_factor_code: twoFactorCode || ''
      }
    });

    // Store token immediately so subsequent calls are authenticated
    this.token = result.token;

    return {
      token:             result.token,
      device_id:         result.device_id || null,
      derivation_params: result.derivation_params || {},
      user:              result.user || {}
    };
  },

  async logout() {
    try {
      await this.request('logout', { method: 'POST', body: {} });
    } catch { /* ignore network errors on logout */ }
    this.token = '';
  },

  /** Verify session is still valid */
  async status() {
    return await this.request('session');
  },

  // ---- Vault Key Management ----

  /**
   * Store the encrypted vault key on the server (first-time setup).
   * Server stores only the encrypted key — never the plaintext.
   */
  async initVaultKey(encryptionSalt, encryptedVaultKey, vaultKeyIv, keyIterations) {
    await this.request('vault/init-key', {
      body: {
        encryption_salt:    encryptionSalt,
        encrypted_vault_key: encryptedVaultKey,
        vault_key_iv:       vaultKeyIv,
        key_iterations:     keyIterations
      }
    });
  },

  /**
   * Fetch the user's key derivation parameters (salt, encrypted vault key, IV, iterations).
   * Returns { success: true, params: { encryption_salt, encrypted_vault_key, vault_key_iv, key_iterations } }
   */
  async derivationParams() {
    const result = await this.request('vault/key-params');
    return { success: true, params: result.params || result };
  },

  // ---- Vault CRUD ----

  /**
   * List all encrypted vault items for the logged-in user.
   * Returns { items: [ { id, item_type, encrypted_data, encryption_iv, is_favorite, is_weak, last_used_at } ] }
   */
  async listVault() {
    const result = await this.request('vault/list');
    return { items: result.items || [] };
  },

  async getItem(id) {
    const result = await this.request('vault/get?id=' + encodeURIComponent(id));
    return result.item || result;
  },

  /**
   * Save a new vault item.
   * @param {object} data  { item_type, encrypted_data, encryption_iv, url_hash?, title_hash?, password_strength?, is_weak?, is_favorite? }
   * Returns { id: string }
   */
  async saveItem(data) {
    const result = await this.request('vault/save', { body: data });
    return { id: String(result.id) };
  },

  /**
   * Update an existing vault item.
   * @param {object} data  { id, encrypted_data, encryption_iv, ... }
   */
  async updateItem(data) {
    await this.request('vault/update', { body: data });
    return { success: true };
  },

  async deleteItem(id) {
    await this.request('vault/delete', { body: { id } });
    return { success: true };
  },

  // ---- Sharing ----

  /**
   * Get shared items (sent and received).
   * Returns { received: [], sent: [] }
   */
  async shareList() {
    try {
      const result = await this.request('vault/shares');
      return {
        received: result.received || [],
        sent:     result.sent     || []
      };
    } catch {
      return { received: [], sent: [] };
    }
  },

  // ---- Audit / Usage ----

  /**
   * Log a vault item usage event (non-blocking, best-effort).
   * SECURITY: Never logs plaintext credentials. Only item_id, action, client_type.
   */
  async usageLog(itemId, action, clientType) {
    try {
      await this.request('vault/usage-log', {
        body: { item_id: itemId, action, client_type: clientType || 'desktop' }
      });
    } catch { /* non-critical — don't break on logging failure */ }
    return { success: true };
  }
};
