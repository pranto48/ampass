/**
 * AMPass Extension - Firebase REST API Client
 *
 * Communicates directly with Firebase Auth and Cloud Firestore REST API.
 * All requests use HTTPS. Vault data is encrypted/decrypted client-side.
 */

const ApiClient = {
  serverUrl: '',
  token: '',

  // ---- Config Retrieval ----

  async ensureInitialized() {
    let apiKey = await Storage.getLocal('firebaseApiKey');
    let projectId = await Storage.getLocal('firebaseProjectId');

    if (apiKey && projectId) {
      return { apiKey, projectId };
    }

    const serverUrl = this.serverUrl || await Storage.getServerUrl();
    if (!serverUrl) throw new Error('Server URL not configured');

    let config = null;
    const configUrl = serverUrl.replace(/\/+$/, '') + '/firebase-config.json';
    try {
      const res = await fetch(configUrl);
      if (res.ok) {
        config = await res.json();
      }
    } catch (err) {
      console.warn('Could not fetch remote firebase-config.json:', err);
    }

    if (!config) {
      throw new Error('Cannot load Firebase configuration from ' + serverUrl);
    }

    await Storage.setLocal('firebaseApiKey', config.apiKey);
    await Storage.setLocal('firebaseProjectId', config.projectId);

    return { apiKey: config.apiKey, projectId: config.projectId };
  },

  async clearConfig() {
    await Storage.removeLocal('firebaseApiKey');
    await Storage.removeLocal('firebaseProjectId');
    await Storage.removeLocal('firebaseRefreshToken');
    await Storage.removeLocal('firebaseUid');
  },

  // ---- Firebase Requests ----

  async authRequest(action, body) {
    const { apiKey } = await this.ensureInitialized();
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:${action}?key=${apiKey}`;

    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    } catch (err) {
      const error = new Error('Firebase Auth is offline or unreachable');
      error.code = 'NETWORK_OFFLINE';
      error.status = 0;
      throw error;
    }

    const data = await res.json();
    if (!res.ok) {
      const error = new Error(data.error?.message || 'Authentication failed');
      error.code = data.error?.errors?.[0]?.reason || 'AUTH_ERROR';
      error.status = res.status;
      throw error;
    }
    return data;
  },

  async refreshAuthToken() {
    try {
      const { apiKey } = await this.ensureInitialized();
      const refreshToken = await Storage.getLocal('firebaseRefreshToken');
      if (!refreshToken) return false;

      const res = await fetch(`https://securetoken.googleapis.com/v1/token?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
      });

      if (res.ok) {
        const data = await res.json();
        this.token = data.id_token;
        // Update stored tokens
        const trusted = !!(await Storage.getLocal('trustedToken'));
        await Storage.setToken(data.id_token, trusted);
        await Storage.setLocal('firebaseRefreshToken', data.refresh_token);
        return true;
      }
    } catch (e) {
      console.error('Token refresh failed:', e);
    }
    return false;
  },

  async firestoreRequest(method, path, body = null, isRetry = false) {
    const { projectId } = await this.ensureInitialized();
    const token = this.token || await Storage.getToken();
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${path}`;

    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = 'Bearer ' + token;
    }

    const config = { method, headers };
    if (body) {
      config.body = JSON.stringify(body);
    }

    let res;
    try {
      res = await fetch(url, config);
    } catch (err) {
      const error = new Error('Firestore is offline or unreachable');
      error.code = 'NETWORK_OFFLINE';
      error.status = 0;
      throw error;
    }

    if (res.status === 401 && !isRetry) {
      const refreshed = await this.refreshAuthToken();
      if (refreshed) {
        return await this.firestoreRequest(method, path, body, true);
      }
    }

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      const error = new Error('Invalid response from Firestore');
      error.code = 'PARSE_ERROR';
      error.status = res.status;
      throw error;
    }

    if (!res.ok) {
      const error = new Error(data.error?.message || 'Request failed');
      error.code = data.error?.status || 'FIRESTORE_ERROR';
      error.status = res.status;
      throw error;
    }

    return data;
  },

  // ---- Field conversion helpers ----

  fromFirestoreFields(fields) {
    const res = {};
    if (!fields) return res;
    for (const [key, val] of Object.entries(fields)) {
      if ('stringValue' in val) res[key] = val.stringValue;
      else if ('integerValue' in val) res[key] = parseInt(val.integerValue, 10);
      else if ('doubleValue' in val) res[key] = parseFloat(val.doubleValue);
      else if ('booleanValue' in val) res[key] = val.booleanValue;
    }
    return res;
  },

  toFirestoreFields(obj) {
    const fields = {};
    for (const [key, val] of Object.entries(obj)) {
      if (val === null || val === undefined) continue;
      if (typeof val === 'string') {
        fields[key] = { stringValue: val };
      } else if (typeof val === 'number') {
        if (Number.isInteger(val)) {
          fields[key] = { integerValue: String(val) };
        } else {
          fields[key] = { doubleValue: val };
        }
      } else if (typeof val === 'boolean') {
        fields[key] = { booleanValue: val };
      }
    }
    return fields;
  },

  // ===== Auth Endpoints =====

  async checkStatus() {
    const token = await Storage.getToken();
    if (!token) {
      const refreshed = await this.refreshAuthToken();
      if (refreshed) return { status: 'ok', authenticated: true };
      throw new Error('Not authenticated');
    }
    return { status: 'ok', authenticated: true };
  },

  async login(username, password, deviceName, browserName, deviceId = null, twoFactorCode = '') {
    // Force configuration reload
    await this.clearConfig();

    let email = username;
    if (!email.includes('@')) {
      email = email + '@ampass.local';
    }

    const result = await this.authRequest('signInWithPassword', {
      email,
      password,
      returnSecureToken: true
    });

    const token = result.idToken;
    const refreshToken = result.refreshToken;
    const uid = result.localId;

    await Storage.setLocal('firebaseRefreshToken', refreshToken);
    await Storage.setLocal('firebaseUid', uid);

    // Fetch key derivation parameters
    let derivationParams;
    try {
      const doc = await this.firestoreRequest('GET', `user_security/${uid}`);
      derivationParams = this.fromFirestoreFields(doc.fields);
      derivationParams.needs_setup = false;
    } catch (e) {
      if (e.status === 404) {
        derivationParams = {
          needs_setup: true,
          encryption_salt: '',
          encrypted_vault_key: 'VAULT_NOT_INITIALIZED',
          vault_key_iv: '',
          key_iterations: 0
        };
      } else {
        throw e;
      }
    }

    return {
      token,
      device_id: deviceId || 'firebase-device',
      derivation_params: derivationParams,
      user: {
        username: email.split('@')[0],
        email: email,
        full_name: email.split('@')[0]
      }
    };
  },

  async logout() {
    await this.clearConfig();
    await Storage.logout();
  },

  async getSession() {
    return await this.checkStatus();
  },

  // ===== Vault Endpoints =====

  async listVault(type = null) {
    const uid = await Storage.getLocal('firebaseUid');
    if (!uid) throw new Error('Not authenticated');

    const result = await this.firestoreRequest('POST', ':runQuery', {
      structuredQuery: {
        from: [{ collectionId: 'vault_items' }],
        where: {
          fieldFilter: {
            field: { fieldPath: 'user_id' },
            op: 'EQUAL',
            value: { stringValue: uid }
          }
        }
      }
    });

    const items = [];
    if (Array.isArray(result)) {
      for (const item of result) {
        if (item.document) {
          const fields = this.fromFirestoreFields(item.document.fields);
          const id = item.document.name.split('/').pop();
          
          if (type && fields.item_type !== type) continue;

          items.push({
            id: id,
            item_type: fields.item_type || 'login',
            encrypted_data: fields.encrypted_data,
            encryption_iv: fields.encryption_iv,
            is_favorite: fields.is_favorite || 0,
            is_weak: fields.is_weak || 0,
            last_used_at: fields.last_used_at || null
          });
        }
      }
    }
    return { items };
  },

  async getVaultItem(id) {
    const doc = await this.firestoreRequest('GET', `vault_items/${id}`);
    const fields = this.fromFirestoreFields(doc.fields);
    return {
      id: id,
      item_type: fields.item_type || 'login',
      encrypted_data: fields.encrypted_data,
      encryption_iv: fields.encryption_iv,
      is_favorite: fields.is_favorite || 0,
      is_weak: fields.is_weak || 0,
      last_used_at: fields.last_used_at || null
    };
  },

  async matchDomain(urlHash) {
    // Query items using the urlHash index in firestore
    const uid = await Storage.getLocal('firebaseUid');
    if (!uid) throw new Error('Not authenticated');

    const result = await this.firestoreRequest('POST', ':runQuery', {
      structuredQuery: {
        from: [{ collectionId: 'vault_items' }],
        where: {
          compositeFilter: {
            op: 'AND',
            filters: [
              {
                fieldFilter: {
                  field: { fieldPath: 'user_id' },
                  op: 'EQUAL',
                  value: { stringValue: uid }
                }
              },
              {
                fieldFilter: {
                  field: { fieldPath: 'url_hash' },
                  op: 'EQUAL',
                  value: { stringValue: urlHash }
                }
              }
            ]
          }
        }
      }
    });

    const items = [];
    if (Array.isArray(result)) {
      for (const item of result) {
        if (item.document) {
          const fields = this.fromFirestoreFields(item.document.fields);
          const id = item.document.name.split('/').pop();
          items.push({
            id: id,
            item_type: fields.item_type || 'login',
            encrypted_data: fields.encrypted_data,
            encryption_iv: fields.encryption_iv,
            is_favorite: fields.is_favorite || 0,
            is_weak: fields.is_weak || 0,
            last_used_at: fields.last_used_at || null
          });
        }
      }
    }
    return { items };
  },

  async saveVaultItem(itemData) {
    const uid = await Storage.getLocal('firebaseUid');
    if (!uid) throw new Error('Not authenticated');

    const fields = this.toFirestoreFields({
      user_id: uid,
      item_type: itemData.item_type || 'login',
      encrypted_data: itemData.encrypted_data,
      encryption_iv: itemData.encryption_iv,
      url_hash: itemData.url_hash || '',
      title_hash: itemData.title_hash || '',
      host_hash: itemData.host_hash || '',
      password_strength: itemData.password_strength || 0,
      is_weak: itemData.is_weak || 0,
      is_favorite: itemData.is_favorite || 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    const doc = await this.firestoreRequest('POST', 'vault_items', { fields });
    const id = doc.name.split('/').pop();
    return { id };
  },

  async updateVaultItem(itemData) {
    const fieldsToUpdate = {
      encrypted_data: itemData.encrypted_data,
      encryption_iv: itemData.encryption_iv,
      url_hash: itemData.url_hash || '',
      title_hash: itemData.title_hash || '',
      password_strength: itemData.password_strength || 0,
      is_weak: itemData.is_weak || 0,
      updated_at: new Date().toISOString()
    };
    if (typeof itemData.is_favorite !== 'undefined') {
      fieldsToUpdate.is_favorite = itemData.is_favorite;
    }

    const queryParams = Object.keys(fieldsToUpdate).map(k => `updateMask.fieldPaths=${k}`).join('&');
    const path = `vault_items/${itemData.id}?${queryParams}`;

    await this.firestoreRequest('PATCH', path, {
      fields: this.toFirestoreFields(fieldsToUpdate)
    });
    return { success: true };
  },

  async deleteVaultItem(id) {
    await this.firestoreRequest('DELETE', `vault_items/${id}`);
    return { success: true };
  },

  // ===== Utility =====

  async getGeneratorPolicy() {
    return { success: true, policy: { length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true } };
  },

  async getAuditLogs(limit = 20) {
    return [];
  },

  async getDevices() {
    return [];
  },

  async revokeDevice(deviceId) {
    return { success: true };
  },

  // ===== Service Worker compatibility =====

  async request(endpoint, options = {}) {
    const cleanEndpoint = endpoint.replace(/^\//, '');

    if (cleanEndpoint === 'vault/init-key') {
      const body = options.body;
      const uid = await Storage.getLocal('firebaseUid');
      if (!uid) throw new Error('Not authenticated');

      await this.firestoreRequest('PATCH', `user_security/${uid}`, {
        fields: this.toFirestoreFields({
          encryption_salt: body.encryption_salt,
          encrypted_vault_key: body.encrypted_vault_key,
          vault_key_iv: body.vault_key_iv,
          key_iterations: body.key_iterations
        })
      });
      return { success: true };
    }

    if (cleanEndpoint === 'vault/usage-log') {
      const body = options.body;
      try {
        const fields = { last_used_at: new Date().toISOString() };
        const path = `vault_items/${body.item_id}?updateMask.fieldPaths=last_used_at`;
        await this.firestoreRequest('PATCH', path, {
          fields: this.toFirestoreFields(fields)
        });
      } catch {}
      return { success: true };
    }

    throw new Error('Endpoint not implemented: ' + endpoint);
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.ApiClient = ApiClient;
}
