/**
 * AMPass Desktop - Firebase API Client
 * Uses Firebase client SDK to store encrypted vault data in Google Cloud.
 */
const Api = {
  serverUrl: '',
  token: '',
  firebaseInitialized: false,
  currentUser: null,

  normalizeServerUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
  },

  setServerUrl(url) {
    this.serverUrl = this.normalizeServerUrl(url);
  },

  async initializeFirebase() {
    if (this.firebaseInitialized) return;
    
    let config;
    
    // Attempt 1: Fetch config dynamically from the server URL
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
    
    // Attempt 2: Fallback to local config file
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
    
    if (typeof firebase === 'undefined') {
      throw new Error('Firebase SDK is not loaded. Check script tags in index.html.');
    }
    
    if (firebase.apps.length === 0) {
      firebase.initializeApp(config);
    }
    
    this.firebaseInitialized = true;
  },

  async login(email, password, deviceName, deviceId = null, twoFactorCode = '') {
    await this.initializeFirebase();
    try {
      const userCredential = await firebase.auth().signInWithEmailAndPassword(email, password);
      this.currentUser = userCredential.user;
      
      const db = firebase.firestore();
      const securityDoc = await db.collection('user_security').doc(this.currentUser.uid).get();
      
      let derivationParams;
      if (securityDoc.exists) {
        derivationParams = securityDoc.data();
        derivationParams.needs_setup = false;
      } else {
        derivationParams = {
          needs_setup: true,
          encryption_salt: '',
          encrypted_vault_key: 'VAULT_NOT_INITIALIZED',
          vault_key_iv: '',
          key_iterations: 0
        };
      }
      
      this.token = this.currentUser.uid;
      
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
    } catch (err) {
      throw new Error('Authentication failed: ' + err.message);
    }
  },

  async logout() {
    if (this.firebaseInitialized) {
      await firebase.auth().signOut();
    }
    this.currentUser = null;
    this.token = '';
  },

  async initVaultKey(encryptionSalt, encryptedVaultKey, vaultKeyIv, keyIterations) {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const data = {
      encryption_salt: encryptionSalt,
      encrypted_vault_key: encryptedVaultKey,
      vault_key_iv: vaultKeyIv,
      key_iterations: keyIterations
    };
    await db.collection('user_security').doc(this.currentUser.uid).set(data);
  },

  async listVault() {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const snapshot = await db.collection('vault_items')
      .where('user_id', '==', this.currentUser.uid)
      .get();
      
    const items = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      items.push({
        id: doc.id,
        item_type: data.item_type,
        encrypted_data: data.encrypted_data,
        encryption_iv: data.encryption_iv,
        is_favorite: data.is_favorite || 0,
        is_weak: data.is_weak || 0,
        last_used_at: data.last_used_at || null
      });
    });
    return { items };
  },

  async getItem(id) {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const doc = await db.collection('vault_items').doc(id).get();
    if (!doc.exists) throw new Error('Item not found');
    const data = doc.data();
    if (data.user_id !== this.currentUser.uid) throw new Error('Permission denied');
    return {
      id: doc.id,
      item_type: data.item_type,
      encrypted_data: data.encrypted_data,
      encryption_iv: data.encryption_iv,
      is_favorite: data.is_favorite || 0,
      is_weak: data.is_weak || 0,
      last_used_at: data.last_used_at || null
    };
  },

  async saveItem(data) {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const docData = {
      user_id: this.currentUser.uid,
      item_type: data.item_type || 'login',
      encrypted_data: data.encrypted_data,
      encryption_iv: data.encryption_iv,
      url_hash: data.url_hash || null,
      title_hash: data.title_hash || null,
      host_hash: data.host_hash || null,
      password_strength: data.password_strength || 0,
      is_weak: data.is_weak || 0,
      is_favorite: data.is_favorite || 0,
      created_at: firebase.firestore.FieldValue.serverTimestamp(),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };
    const ref = await db.collection('vault_items').add(docData);
    return { id: ref.id };
  },

  async updateItem(data) {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const docRef = db.collection('vault_items').doc(data.id);
    const doc = await docRef.get();
    if (!doc.exists) throw new Error('Item not found');
    if (doc.data().user_id !== this.currentUser.uid) throw new Error('Permission denied');
    
    const docData = {
      encrypted_data: data.encrypted_data,
      encryption_iv: data.encryption_iv,
      url_hash: data.url_hash || null,
      title_hash: data.title_hash || null,
      host_hash: data.host_hash || null,
      password_strength: data.password_strength || 0,
      is_weak: data.is_weak || 0,
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };
    if (typeof data.is_favorite !== 'undefined') docData.is_favorite = data.is_favorite;
    await docRef.update(docData);
    return { success: true };
  },

  async deleteItem(id) {
    await this.initializeFirebase();
    if (!this.currentUser) throw new Error('Not authenticated');
    const db = firebase.firestore();
    const docRef = db.collection('vault_items').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) throw new Error('Item not found');
    if (doc.data().user_id !== this.currentUser.uid) throw new Error('Permission denied');
    await docRef.delete();
    return { success: true };
  },

  async usageLog(itemId, action, clientType) {
    return { success: true };
  },

  async status() {
    await this.initializeFirebase();
    return { status: 'ok', firebase: true };
  },

  async derivationParams() {
    await this.initializeFirebase();
    if (!this.currentUser) return { key_iterations: 100000 };
    const db = firebase.firestore();
    const doc = await db.collection('user_security').doc(this.currentUser.uid).get();
    if (!doc.exists) return { key_iterations: 100000 };
    return doc.data();
  },

  async shareList() {
    return { items: [] };
  }
};
