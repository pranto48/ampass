/**
 * AMPass Desktop / Web Vault — Firebase REST API Client
 *
 * Replaces the PHP backend API client with direct calls to Firebase.
 * All vault operations now go through the Firebase Auth and Firestore REST API.
 *
 * SECURITY: All requests are authenticated over HTTPS.
 *           Vault data is always encrypted before it leaves this client.
 */
const Api = {
  serverUrl: '',
  token: '', // idToken
  refreshToken: '',
  uid: '', // localId
  apiKey: '',
  projectId: '',
  isInitialized: false,

  // ---- URL Utilities ----

  normalizeServerUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
  },

  setServerUrl(url) {
    this.serverUrl = this.normalizeServerUrl(url);
    this.apiKey = '';
    this.projectId = '';
    this.isInitialized = false;
  },

  async ensureInitialized() {
    if (this.isInitialized) return;

    let config = null;

    // 1. Fetch from the configured server URL (GitHub pages subdomain)
    if (this.serverUrl) {
      const configUrl = this.serverUrl + '/firebase-config.json';
      try {
        const res = await fetch(configUrl);
        if (res.ok) {
          config = await res.json();
        }
      } catch (err) {
        console.warn('Could not fetch remote firebase-config.json:', err);
      }
    }

    // 2. Fallback to local config file
    if (!config) {
      try {
        const localRes = await fetch('firebase-config.json');
        if (localRes.ok) {
          config = await localRes.json();
        }
      } catch (err) {
        console.warn('Could not fetch local firebase-config.json:', err);
      }
    }

    if (!config) {
      throw new Error('Cannot load Firebase configuration. Please configure the correct Server URL or place firebase-config.json in the static folder.');
    }

    this.apiKey = config.apiKey;
    this.projectId = config.projectId;
    this.isInitialized = true;
  },

  // ---- Firebase Helpers ----

  async authRequest(action, body) {
    await this.ensureInitialized();
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:${action}?key=${this.apiKey}`;
    
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    } catch (err) {
      throw Object.assign(new Error('Firebase service is offline or unreachable'), { code: 'NETWORK_OFFLINE', status: 0 });
    }

    const data = await res.json();
    if (!res.ok) {
      const errMsg = data.error?.message || 'Authentication request failed';
      throw Object.assign(new Error(errMsg), { code: data.error?.errors?.[0]?.reason || 'AUTH_ERROR', status: res.status });
    }
    return data;
  },

  async refreshAuthToken() {
    if (!this.refreshToken) return false;
    try {
      const res = await fetch(`https://securetoken.googleapis.com/v1/token?key=${this.apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: this.refreshToken
        })
      });
      if (res.ok) {
        const data = await res.json();
        this.token = data.id_token;
        this.refreshToken = data.refresh_token;
        // Persist token
        if (typeof invoke === 'function') {
          await invoke('store_auth_token', { token: this.token });
        } else {
          localStorage.setItem('auth_token', this.token);
        }
        localStorage.setItem('refresh_token', this.refreshToken);
        return true;
      }
    } catch (e) {
      console.error('Failed to refresh Firebase token:', e);
    }
    return false;
  },

  async firestoreRequest(method, path, body = null, isRetry = false) {
    await this.ensureInitialized();
    const url = `https://firestore.googleapis.com/v1/projects/${this.projectId}/databases/(default)/documents/${path}`;
    
    const headers = {
      'Content-Type': 'application/json'
    };
    if (this.token) {
      headers['Authorization'] = 'Bearer ' + this.token;
    }

    const config = { method, headers };
    if (body) {
      config.body = JSON.stringify(body);
    }

    let res;
    try {
      res = await fetch(url, config);
    } catch (err) {
      throw Object.assign(new Error('Firestore database is offline or unreachable'), { code: 'NETWORK_OFFLINE', status: 0 });
    }

    // Auto-refresh token on 401 (Unauthorized)
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
    } catch {
      throw Object.assign(new Error('Invalid response from Firestore (HTTP ' + res.status + ')'), { code: 'PARSE_ERROR', status: res.status });
    }

    if (!res.ok) {
      const errMsg = data.error?.message || 'Firestore request failed';
      throw Object.assign(new Error(errMsg), { code: data.error?.status || 'FIRESTORE_ERROR', status: res.status });
    }

    return data;
  },

  // ---- Field conversion helpers for Firestore REST API ----

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

  // ---- Auth API ----

  async login(username, password, deviceName, deviceId = null, twoFactorCode = '') {
    // Firebase Auth requires email, if username doesn't have @, append a mock domain
    let email = username;
    if (!email.includes('@')) {
      email = email + '@ampass.local';
    }

    const result = await this.authRequest('signInWithPassword', {
      email,
      password,
      returnSecureToken: true
    });

    this.token = result.idToken;
    this.refreshToken = result.refreshToken;
    this.uid = result.localId;

    // Cache tokens in localStorage for persistence
    localStorage.setItem('refresh_token', this.refreshToken);
    localStorage.setItem('uid', this.uid);

    // Fetch key derivation parameters
    let derivationParams;
    try {
      const pResult = await this.derivationParams();
      derivationParams = pResult.params;
    } catch (e) {
      // If not found, means first-time setup
      derivationParams = {
        needs_setup: true,
        encryption_salt: '',
        encrypted_vault_key: 'VAULT_NOT_INITIALIZED',
        vault_key_iv: '',
        key_iterations: 0
      };
    }

    return {
      token: this.token,
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
    this.token = '';
    this.refreshToken = '';
    this.uid = '';
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('uid');
  },

  async status() {
    // Verify session
    if (!this.token) {
      // Try restoring from localStorage
      this.refreshToken = localStorage.getItem('refresh_token') || '';
      this.uid = localStorage.getItem('uid') || '';
      if (this.refreshToken) {
        const refreshed = await this.refreshAuthToken();
        if (refreshed) {
          return { status: 'ok', authenticated: true };
        }
      }
      throw new Error('Not authenticated');
    }
    return { status: 'ok', authenticated: true };
  },

  // ---- Vault Key Management ----

  async initVaultKey(encryptionSalt, encryptedVaultKey, vaultKeyIv, keyIterations) {
    if (!this.uid) this.uid = localStorage.getItem('uid') || '';
    if (!this.uid) throw new Error('Not authenticated');

    await this.firestoreRequest('PATCH', `user_security/${this.uid}`, {
      fields: this.toFirestoreFields({
        encryption_salt: encryptionSalt,
        encrypted_vault_key: encryptedVaultKey,
        vault_key_iv: vaultKeyIv,
        key_iterations: keyIterations
      })
    });
  },

  async derivationParams() {
    if (!this.uid) this.uid = localStorage.getItem('uid') || '';
    if (!this.uid) throw new Error('Not authenticated');

    try {
      const doc = await this.firestoreRequest('GET', `user_security/${this.uid}`);
      const params = this.fromFirestoreFields(doc.fields);
      params.needs_setup = false;
      return { success: true, params };
    } catch (e) {
      if (e.status === 404) {
        return {
          success: true,
          params: {
            needs_setup: true,
            encryption_salt: '',
            encrypted_vault_key: 'VAULT_NOT_INITIALIZED',
            vault_key_iv: '',
            key_iterations: 0
          }
        };
      }
      throw e;
    }
  },

  // ---- Vault CRUD ----

  async listVault() {
    if (!this.uid) this.uid = localStorage.getItem('uid') || '';
    if (!this.uid) throw new Error('Not authenticated');

    const result = await this.firestoreRequest('POST', ':runQuery', {
      structuredQuery: {
        from: [{ collectionId: 'vault_items' }],
        where: {
          fieldFilter: {
            field: { fieldPath: 'user_id' },
            op: 'EQUAL',
            value: { stringValue: this.uid }
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

  async getItem(id) {
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

  async saveItem(data) {
    if (!this.uid) this.uid = localStorage.getItem('uid') || '';
    if (!this.uid) throw new Error('Not authenticated');

    const fields = this.toFirestoreFields({
      user_id: this.uid,
      item_type: data.item_type || 'login',
      encrypted_data: data.encrypted_data,
      encryption_iv: data.encryption_iv,
      url_hash: data.url_hash || '',
      title_hash: data.title_hash || '',
      host_hash: data.host_hash || '',
      password_strength: data.password_strength || 0,
      is_weak: data.is_weak || 0,
      is_favorite: data.is_favorite || 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    const doc = await this.firestoreRequest('POST', 'vault_items', { fields });
    const id = doc.name.split('/').pop();
    return { id };
  },

  async updateItem(data) {
    const fieldsToUpdate = {
      encrypted_data: data.encrypted_data,
      encryption_iv: data.encryption_iv,
      url_hash: data.url_hash || '',
      title_hash: data.title_hash || '',
      password_strength: data.password_strength || 0,
      is_weak: data.is_weak || 0,
      updated_at: new Date().toISOString()
    };
    if (typeof data.is_favorite !== 'undefined') {
      fieldsToUpdate.is_favorite = data.is_favorite;
    }

    const queryParams = Object.keys(fieldsToUpdate).map(k => `updateMask.fieldPaths=${k}`).join('&');
    const path = `vault_items/${data.id}?${queryParams}`;

    await this.firestoreRequest('PATCH', path, {
      fields: this.toFirestoreFields(fieldsToUpdate)
    });
    return { success: true };
  },

  async deleteItem(id) {
    await this.firestoreRequest('DELETE', `vault_items/${id}`);
    return { success: true };
  },

  // ---- Sharing & Usage (Stubs for Serverless) ----

  async shareList() {
    return { received: [], sent: [] };
  },

  async usageLog(itemId, action, clientType) {
    try {
      const fields = { last_used_at: new Date().toISOString() };
      const path = `vault_items/${itemId}?updateMask.fieldPaths=last_used_at`;
      await this.firestoreRequest('PATCH', path, {
        fields: this.toFirestoreFields(fields)
      });
    } catch {}
    return { success: true };
  },

  async post(path, body) {
    if (path === '/api/vault/import-bulk') {
      return await this.importBulk(body.items, body.source);
    }
    throw new Error('Not implemented');
  },

  async importBulk(items, source) {
    if (!this.uid) this.uid = localStorage.getItem('uid') || '';
    if (!this.uid) throw new Error('Not authenticated');

    const writes = items.map(item => {
      const autoId = Array.from(crypto.getRandomValues(new Uint8Array(15)), b => b.toString(36)).join('').slice(0, 20);
      return {
        update: {
          name: `projects/${this.projectId}/databases/(default)/documents/vault_items/${autoId}`,
          fields: this.toFirestoreFields({
            user_id: this.uid,
            item_type: item.item_type || 'login',
            encrypted_data: item.encrypted_data,
            encryption_iv: item.encryption_iv,
            url_hash: item.url_hash || '',
            title_hash: item.title_hash || '',
            password_strength: item.password_strength || 0,
            is_weak: item.is_weak || 0,
            is_favorite: 0,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          })
        }
      };
    });

    await this.firestoreRequest('POST', ':commit', { writes });
    return {
      success: true,
      imported: writes.length,
      skipped: 0,
      failed: 0
    };
  }
};
