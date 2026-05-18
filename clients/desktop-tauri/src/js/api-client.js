/**
 * AMPass Desktop - API Client
 * Communicates with the AMPass PHP server via Extension API.
 */
const Api = {
  serverUrl: '',
  token: '',

  async request(endpoint, opts = {}) {
    if (!this.serverUrl) throw new Error('Server URL not configured');
    const url = this.serverUrl + '/api/extension/' + endpoint.replace(/^\//, '');
    const headers = { 'Content-Type': 'application/json', 'X-AMPass-Version': '1.0' };
    if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
    const config = { method: opts.method || 'GET', headers };
    if (opts.body) { config.method = 'POST'; config.body = JSON.stringify(opts.body); }
    const res = await fetch(url, config);
    const data = await res.json();
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
  async status() { return this.request('status'); }
};
