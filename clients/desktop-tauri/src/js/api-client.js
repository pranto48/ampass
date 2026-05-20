/**
 * AMPass Desktop - API Client
 * Uses the Extension API with bearer token auth.
 */
const Api = {
  serverUrl: '',
  token: '',

  normalizeServerUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
  },

  setServerUrl(url) {
    this.serverUrl = this.normalizeServerUrl(url);
  },

  async request(endpoint, opts = {}) {
    if (!this.serverUrl) throw new Error('Server URL not configured');
    const baseUrl = this.normalizeServerUrl(this.serverUrl);
    const url = baseUrl + '/api/extension/' + endpoint.replace(/^\//, '');
    const headers = { 'Content-Type': 'application/json', 'X-AMPass-Version': '1.0' };
    if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
    const config = { method: opts.method || 'GET', headers };
    if (opts.body) { config.method = 'POST'; config.body = JSON.stringify(opts.body); }
    let res;
    try {
      res = await fetch(url, config);
    } catch (err) {
      throw new Error('Cannot reach AMPass server. Check that XAMPP Apache is running and the server URL is ' + baseUrl);
    }
    let data;
    try {
      data = await res.json();
    } catch (err) {
      throw new Error('AMPass server returned an invalid response from ' + baseUrl);
    }
    if (!res.ok) { const e = new Error(data.error || 'Request failed'); e.code = data.code; throw e; }
    return data;
  },

  async login(username, password, deviceName) {
    return this.request('login', { body: { username, password, device_name: deviceName, browser_name: 'AMPass Desktop' } });
  },
  async logout() { return this.request('logout', { method: 'POST', body: {} }); },
  async listVault() { return this.request('vault/list'); },
  async getItem(id) { return this.request('vault/get?id=' + id); },
  async saveItem(data) { return this.request('vault/save', { body: data }); },
  async updateItem(data) { return this.request('vault/update', { body: data }); },
  async deleteItem(id) { return this.request('vault/delete', { body: { id } }); },
  async usageLog(itemId, action, clientType) { return this.request('vault/usage-log', { body: { item_id: itemId, action, client_type: clientType || 'desktop' } }); },
  async status() { return this.request('status'); }
};
