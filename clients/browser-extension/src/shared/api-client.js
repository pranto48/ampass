/**
 * AMPass Extension - API Client
 * Communicates with the AMPass PHP backend extension API.
 * SECURITY: All requests use bearer token auth over HTTPS.
 */

const ApiClient = {
  /**
   * Make an authenticated API request
   */
  async request(endpoint, options = {}) {
    const serverUrl = await Storage.getServerUrl();
    if (!serverUrl) throw new Error('Server URL not configured');

    const token = await Storage.getToken();
    const url = serverUrl + '/api/extension/' + endpoint.replace(/^\//, '');

    const headers = {
      'Content-Type': 'application/json',
      'X-AMPass-Version': '1.0'
    };

    if (token) {
      headers['Authorization'] = 'Bearer ' + token;
    }

    const config = { method: options.method || 'GET', headers };
    if (options.body) {
      config.method = 'POST';
      config.body = JSON.stringify(options.body);
    }

    const response = await fetch(url, config);

    // Handle non-JSON responses safely
    let data;
    try {
      data = await response.json();
    } catch (parseErr) {
      const error = new Error('Server returned invalid response');
      error.code = 'PARSE_ERROR';
      error.status = response.status;
      throw error;
    }

    if (!response.ok) {
      const error = new Error(data.error || 'Request failed');
      error.code = data.code || 'UNKNOWN';
      error.status = response.status;
      throw error;
    }

    return data;
  },

  // ===== Auth Endpoints =====

  async checkStatus() {
    return await this.request('status');
  },

  async login(username, password, deviceName, browserName) {
    return await this.request('login', {
      body: { username, password, device_name: deviceName, browser_name: browserName }
    });
  },

  async logout() {
    return await this.request('logout', { method: 'POST', body: {} });
  },

  async getSession() {
    return await this.request('session');
  },

  // ===== Vault Endpoints =====

  async listVault(type = null) {
    let endpoint = 'vault/list';
    if (type) endpoint += '?type=' + encodeURIComponent(type);
    return await this.request(endpoint);
  },

  async getVaultItem(id) {
    return await this.request('vault/get?id=' + id);
  },

  async matchDomain(urlHash) {
    return await this.request('vault/match-domain?url_hash=' + encodeURIComponent(urlHash));
  },

  async saveVaultItem(itemData) {
    return await this.request('vault/save', { body: itemData });
  },

  async updateVaultItem(itemData) {
    return await this.request('vault/update', { body: itemData });
  },

  async deleteVaultItem(id) {
    return await this.request('vault/delete', { body: { id } });
  },

  // ===== Utility =====

  async getGeneratorPolicy() {
    return await this.request('generator/policy');
  },

  async getAuditLogs(limit = 20) {
    return await this.request('audit?limit=' + limit);
  },

  async getDevices() {
    return await this.request('devices');
  },

  async revokeDevice(deviceId) {
    return await this.request('revokeDevice', { body: { device_id: deviceId } });
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.ApiClient = ApiClient;
}
