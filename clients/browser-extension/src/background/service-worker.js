/**
 * AMPass Extension - Service Worker (Background Script)
 * SECURITY: Holds vault key in memory. Handles all crypto operations.
 * Content scripts and popup communicate via chrome.runtime messages.
 */

importScripts(
  '../shared/storage.js',
  '../shared/security.js',
  '../shared/domain-utils.js',
  '../shared/crypto-client.js',
  '../shared/api-client.js',
  '../shared/password-generator.js',
  '../shared/native-client.js'
);

// ===== State =====
let cachedVaultItems = null;
let lastFetchTime = 0;
const CACHE_TTL = 60000; // 1 minute
const PENDING_SAVE_TTL = 120000; // 2 minutes
const pendingSaveCandidates = new Map();

// ===== Message Handler =====
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // SECURITY: Only allow messages from extension pages (popup, options, content scripts)
  // chrome.runtime.onMessage only receives from the extension itself, but we verify sender
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: 'Unauthorized sender' });
    return false;
  }

  handleMessage(msg, sender).then(sendResponse).catch(err => {
    // SECURITY: Never expose internal error details that might contain secrets
    const safeError = err.message || 'Operation failed';
    sendResponse({ success: false, error: safeError, code: err.code });
  });
  return true; // Keep channel open for async response
});

async function handleMessage(msg, sender) {
  switch (msg.type) {
    case 'GET_STATUS':
      return await getStatus();
    case 'LOGIN':
      return await login(msg.payload);
    case 'UNLOCK':
      return await unlock(msg.payload);
    case 'LOCK':
      return await lock();
    case 'LOGOUT':
      return await logout();
    case 'GET_MATCHES':
      return await getMatches(msg.payload.url);
    case 'GET_ALL_ITEMS':
      return await getAllItems();
    case 'GET_IDENTITIES':
      return await getIdentities();
    case 'DECRYPT_ITEM':
      return await decryptItem(msg.payload.id);
    case 'SEARCH':
      return await searchVault(msg.payload.query);
    case 'SAVE_ITEM':
      return await saveItem(msg.payload);
    case 'UPDATE_ITEM':
      return await updateItem(msg.payload);
    case 'DELETE_ITEM':
      return await deleteItem(msg.payload.id);
    case 'FAVORITE_ITEM':
      return await favoriteItem(msg.payload.id, msg.payload.isFavorite);
    case 'CAPTURE_SAVE_CANDIDATE':
      return captureSaveCandidate(msg.payload, sender);
    case 'CHECK_PENDING_SAVE':
      return popPendingSaveCandidate(sender);
    case 'CLEAR_PENDING_SAVE':
      return clearPendingSaveCandidate(sender);
    case 'GENERATE_PASSWORD':
      return { success: true, password: CryptoClient.generatePassword(msg.payload || {}) };
    case 'GENERATE_TOTP':
      return await generateTotp(msg.payload.secret);
    case 'COPY_TO_CLIPBOARD':
      // Clipboard is handled directly by popup context (has navigator.clipboard access).
      // Service worker cannot write to clipboard in MV3 — return text for caller to use.
      return { success: true, text: msg.payload.text };
    case 'GET_SETTINGS':
      return { success: true, settings: await Storage.getSettings() };
    case 'RESET_EXTENSION':
      return await resetExtension();
    case 'LOG_USAGE':
      return await logUsage(msg.payload);
    case 'OPEN_POPUP':
      // Chrome doesn't allow programmatic popup opening from content scripts.
      return { success: false, error: 'Click the AMPass extension icon to open.' };
    case 'OPEN_DESKTOP_UNLOCK':
      return await openDesktopUnlock(msg.payload || {});
    case 'AUTOFILL_PAGE_LOAD':
      return await autofillPageLoad(msg.payload);
    case 'GET_AUTOFILL_SETTINGS':
      return await getAutofillSettings();
    default:
      return { success: false, error: 'Unknown message type' };
  }
}

function getSenderTabKey(sender) {
  const tabId = sender && sender.tab && Number.isInteger(sender.tab.id) ? sender.tab.id : null;
  return tabId === null ? null : String(tabId);
}

function cleanupPendingSaveCandidates() {
  const now = Date.now();
  for (const [key, candidate] of pendingSaveCandidates.entries()) {
    if (!candidate || now - candidate.capturedAt > PENDING_SAVE_TTL) {
      if (candidate && candidate.data) {
        candidate.data.password = null;
        candidate.data.username = null;
      }
      pendingSaveCandidates.delete(key);
    }
  }
}

function captureSaveCandidate(payload, sender) {
  cleanupPendingSaveCandidates();

  const key = getSenderTabKey(sender);
  const data = payload && payload.data;
  if (!key || !data || !data.password) {
    return { success: false, error: 'No credential data captured' };
  }

  pendingSaveCandidates.set(key, {
    data: {
      url: String(data.url || ''),
      title: String(data.title || ''),
      username: String(data.username || ''),
      password: String(data.password || ''),
      domain: String(data.domain || '')
    },
    capturedAt: Date.now()
  });

  return { success: true };
}

function popPendingSaveCandidate(sender) {
  cleanupPendingSaveCandidates();

  const key = getSenderTabKey(sender);
  if (!key || !pendingSaveCandidates.has(key)) {
    return { success: true, data: null };
  }

  const candidate = pendingSaveCandidates.get(key);
  pendingSaveCandidates.delete(key);

  if (!candidate || Date.now() - candidate.capturedAt > PENDING_SAVE_TTL) {
    return { success: true, data: null };
  }

  return { success: true, data: candidate.data };
}

function clearPendingSaveCandidate(sender) {
  const key = getSenderTabKey(sender);
  const candidate = key ? pendingSaveCandidates.get(key) : null;
  if (candidate && candidate.data) {
    candidate.data.password = null;
    candidate.data.username = null;
  }
  if (key) pendingSaveCandidates.delete(key);
  return { success: true };
}

async function resetExtension() {
  await Storage.clearSession();
  await Storage.removeLocal('serverUrl');
  cachedVaultItems = null;
  return { success: true };
}

// ===== Core Operations =====

// Track online/offline state
let isOnline = true;

async function getStatus() {
  const serverUrl = await Storage.getServerUrl();
  const configured = !!serverUrl;
  let authenticated = await Storage.isAuthenticated();
  const unlocked = await Storage.isVaultUnlocked();
  let online = true;
  const offlineAvailable = await Storage.hasOfflineCache();

  // Verify token with server if we think we're authenticated
  if (authenticated && configured) {
    try {
      ApiClient.serverUrl = serverUrl;
      ApiClient.token = await Storage.getToken();
      await ApiClient.getSession();
      online = true;
    } catch (e) {
      if (e.code === 'NETWORK_OFFLINE' || e.code === 'SERVER_ERROR') {
        // Server offline — do NOT clear token, allow offline mode
        online = false;
      } else {
        // Auth error (token expired/invalid) — clear token
        await Storage.removeToken();
        await Storage.removeSession('vaultKeyHex');
        await Storage.removeSession('vaultItems');
        authenticated = false;
        online = true; // Server responded, just rejected us
      }
    }
  }

  isOnline = online;
  return { success: true, authenticated, unlocked, online, offlineAvailable, serverUrl, configured };
}

async function login(payload) {
  const { serverUrl, username, password, deviceName, trustBrowser, twoFactorCode } = payload;
  await Storage.setServerUrl(serverUrl);

  const browserName = navigator.userAgent.includes('Edg') ? 'Edge' :
                      navigator.userAgent.includes('Chrome') ? 'Chrome' : 'Browser';

  const deviceId = await Storage.getLocal('deviceId');

  const result = await ApiClient.login(
    username, 
    password, 
    deviceName || 'AMPass Extension', 
    browserName, 
    deviceId, 
    twoFactorCode
  );

  if (result.device_id) {
    await Storage.setLocal('deviceId', result.device_id);
  }

  await Storage.setToken(result.token, !!trustBrowser);
  await Storage.setDerivationParams(result.derivation_params);
  await Storage.setSession('user', result.user);

  return { success: true, user: result.user, needsUnlock: true };
}

async function unlock(payload) {
  const { masterPassword } = payload;
  let params = null;

  // Attempt to fetch fresh params from server if online
  if (isOnline) {
    try {
      const uid = await Storage.getLocal('firebaseUid');
      if (uid) {
        const doc = await ApiClient.firestoreRequest('GET', `user_security/${uid}`);
        const freshParams = ApiClient.fromFirestoreFields(doc.fields);
        freshParams.needs_setup = false;
        await Storage.setDerivationParams(freshParams);
        params = freshParams;
      }
    } catch (e) {
      console.warn("Could not fetch fresh derivation params from server on unlock, falling back to cache:", e);
    }
  }

  if (!params) {
    params = await Storage.getDerivationParams();
  }

  if (!params) throw new Error('No vault data available. Please login first.');

  // Check if vault needs first-time initialization
  if (params.needs_setup || params.key_iterations === 0 || params.encrypted_vault_key === 'VAULT_NOT_INITIALIZED') {
    if (!isOnline) throw new Error('Server required for first-time vault setup. Please connect to AMPass server.');
    const setupResult = await initializeVault(masterPassword, params);
    await Storage.setVaultKey(setupResult.vaultKeyHex);
    await Storage.setDerivationParams(setupResult.newParams);
  } else {
    // Normal unlock: derive wrapping key and decrypt existing vault key
    const vaultKeyHex = await CryptoClient.unlockVault(masterPassword, params);
    await Storage.setVaultKey(vaultKeyHex);
  }

  // Try to fetch vault items from server
  let offline = false;
  try {
    await fetchVaultItems();
    // Save encrypted cache for offline use
    if (cachedVaultItems && cachedVaultItems.length > 0) {
      await Storage.setEncryptedVaultCache(cachedVaultItems);
    }
    isOnline = true;
  } catch (e) {
    if (e.code === 'NETWORK_OFFLINE' || e.code === 'SERVER_ERROR') {
      // Server offline — load from encrypted cache
      offline = true;
      isOnline = false;
      await loadFromOfflineCache();
    } else if (e.code === 'AUTH_REQUIRED' || e.code === 'AUTH_HEADER_MISSING') {
      throw new Error('Session expired. Please login again.');
    } else {
      // Unknown error — try offline cache as fallback
      offline = true;
      isOnline = false;
      await loadFromOfflineCache();
    }
  }

  // Set up auto-lock alarm
  const settings = await Storage.getSettings();
  const timeout = settings.lockTimeoutMinutes || 30;
  chrome.alarms.create('autoLock', { delayInMinutes: timeout });

  return { success: true, offline, itemCount: (cachedVaultItems || []).length };
}

async function loadFromOfflineCache() {
  const cached = await Storage.getEncryptedVaultCache();
  if (cached && Array.isArray(cached)) {
    cachedVaultItems = cached;
    lastFetchTime = Date.now();
  } else {
    cachedVaultItems = [];
  }
}

async function lock() {
  await Storage.lockVault();
  cachedVaultItems = null;
  chrome.alarms.clear('autoLock');
  updateBadge(0);
  return { success: true };
}

async function logout() {
  try { await ApiClient.logout(); } catch (e) { /* ignore */ }
  await Storage.logout();
  cachedVaultItems = null;
  chrome.alarms.clear('autoLock');
  updateBadge(0);
  return { success: true };
}

// ===== Vault Operations =====

/**
 * Initialize vault for first-time setup.
 * Generates a new vault key, encrypts it with the master password,
 * and sends the encrypted vault key to the server.
 * SECURITY: The raw vault key never leaves this function except as the return value
 * stored in memory. The server only receives the encrypted version.
 */
async function initializeVault(masterPassword, currentParams) {
  // Generate a random 256-bit vault key
  const vaultKeyRaw = CryptoClient.bufferToHex(crypto.getRandomValues(new Uint8Array(32)));

  // Generate a new salt for key derivation
  const salt = CryptoClient.bufferToHex(crypto.getRandomValues(new Uint8Array(32)));
  const iterations = 100000;

  // Derive wrapping key from master password
  const wrappingKey = await CryptoClient.deriveKey(masterPassword, salt, iterations);

  // Encrypt the vault key with the wrapping key
  const encrypted = await CryptoClient.encrypt(vaultKeyRaw, wrappingKey);

  // Send the encrypted vault key to the server to update user_security
  try {
    await ApiClient.request('vault/init-key', {
      body: {
        encryption_salt: salt,
        encrypted_vault_key: encrypted.ciphertext,
        vault_key_iv: encrypted.iv,
        key_iterations: iterations
      }
    });
  } catch (e) {
    throw new Error('Failed to save vault key to server: ' + (e.message || 'Unknown error'));
  }

  const newParams = {
    encryption_salt: salt,
    encrypted_vault_key: encrypted.ciphertext,
    vault_key_iv: encrypted.iv,
    key_iterations: iterations,
    needs_setup: false
  };

  return { vaultKeyHex: vaultKeyRaw, newParams };
}

async function fetchVaultItems() {
  const cachedItems = await Storage.getEncryptedVaultCache();
  const cachedUpdatedAt = await Storage.getLocal('vault_updated_at');
  
  const uid = await Storage.getLocal('firebaseUid');
  let freshParams = null;
  
  if (uid) {
    try {
      const doc = await ApiClient.firestoreRequest('GET', `user_security/${uid}`);
      freshParams = ApiClient.fromFirestoreFields(doc.fields);
    } catch (e) {
      console.warn('Could not fetch fresh user security params, trying offline cache:', e);
      if (cachedItems && cachedItems.length > 0) {
        cachedVaultItems = cachedItems;
        lastFetchTime = Date.now();
        return;
      }
      throw e;
    }
  }

  const serverUpdatedAt = freshParams && freshParams.vault_updated_at;

  if (cachedItems && cachedItems.length > 0 && cachedUpdatedAt && serverUpdatedAt && cachedUpdatedAt === serverUpdatedAt) {
    cachedVaultItems = cachedItems;
    lastFetchTime = Date.now();
    return;
  }

  const result = await ApiClient.listVault();
  cachedVaultItems = result.items || [];
  lastFetchTime = Date.now();

  // Save to persistent offline cache
  if (cachedVaultItems.length > 0) {
    await Storage.setEncryptedVaultCache(cachedVaultItems);
  }
  if (serverUpdatedAt) {
    await Storage.setLocal('vault_updated_at', serverUpdatedAt);
  }
}

/**
 * Ensure vault items are loaded from any available source.
 */
async function ensureVaultItemsLoaded() {
  if (cachedVaultItems && cachedVaultItems.length > 0) return;

  // Try persistent offline cache
  const offlineItems = await Storage.getEncryptedVaultCache();
  if (offlineItems && offlineItems.length > 0) {
    cachedVaultItems = offlineItems;
    return;
  }

  cachedVaultItems = [];
}

async function getAllItems() {
  if (!await Storage.isVaultUnlocked()) {
    return { success: false, error: 'Vault is locked' };
  }

  await ensureVaultItemsLoaded();

  // Decrypt titles for display (not full items)
  const vaultKeyHex = await Storage.getVaultKey();
  const items = [];
  for (const item of cachedVaultItems) {
    try {
      const decrypted = await CryptoClient.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
      items.push({
        id: item.id,
        item_type: item.item_type,
        title: decrypted.title || 'Untitled',
        username: decrypted.username || decrypted.email || (decrypted.first_name ? (decrypted.first_name + ' ' + (decrypted.last_name || '')) : ''),
        url: decrypted.url || '',
        is_favorite: item.is_favorite
      });
    } catch (e) {
      items.push({ id: item.id, item_type: item.item_type, title: '[Decrypt Error]', username: '', url: '' });
    }
  }

  return { success: true, items };
}

async function getMatches(url) {
  if (!await Storage.isVaultUnlocked()) {
    return { success: false, code: 'VAULT_LOCKED', error: 'Vault is locked', items: [], count: 0 };
  }

  const domain = DomainUtils.getBaseDomain(url);
  if (!domain) return { success: true, items: [], count: 0 };

  // Ensure items are loaded (works offline from cache)
  await ensureVaultItemsLoaded();

  const vaultKeyHex = await Storage.getVaultKey();
  const matches = [];
  for (const item of (cachedVaultItems || [])) {
    if (item.item_type !== 'login') continue;
    try {
      const decrypted = await CryptoClient.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
      if (decrypted.url && DomainUtils.isUrlMatch(decrypted.url, url)) {
        matches.push({
          id: item.id,
          title: decrypted.title || 'Untitled',
          username: decrypted.username || decrypted.email || '',
          url: decrypted.url || ''
        });
      }
    } catch (e) { /* skip items that fail to decrypt */ }
  }

  updateBadge(matches.length);
  return { success: true, items: matches, count: matches.length };
}

async function getIdentities() {
  if (!await Storage.isVaultUnlocked()) {
    return { success: false, code: 'VAULT_LOCKED', error: 'Vault is locked' };
  }
  await ensureVaultItemsLoaded();
  const vaultKeyHex = await Storage.getVaultKey();
  const items = [];
  for (const item of (cachedVaultItems || [])) {
    if (item.item_type !== 'identity') continue;
    try {
      const decrypted = await CryptoClient.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
      items.push({
        id: item.id,
        title: decrypted.title || 'Untitled',
        email: decrypted.email || '',
        name: decrypted.full_name || (decrypted.first_name ? (decrypted.first_name + ' ' + (decrypted.last_name || '')) : '')
      });
    } catch (e) { /* skip */ }
  }
  return { success: true, items };
}

async function decryptItem(id) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');

  const vaultKeyHex = await Storage.getVaultKey();
  await ensureVaultItemsLoaded();

  const item = cachedVaultItems.find(i => i.id === id);
  if (!item) throw new Error('Item not found');

  const decrypted = await CryptoClient.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
  return { success: true, item: decrypted };
}

/**
 * Try to open the AMPass desktop app unlock window via native messaging bridge.
 * SECURITY: Does not send any secrets. Only tells desktop to show unlock UI.
 */
async function openDesktopUnlock(payload) {
  try {
    const available = await NativeClient.isAvailable();
    if (!available) {
      return { success: false, error: 'AMPass Desktop bridge not available. Open AMPass Desktop manually or click the extension icon.' };
    }
    const response = await NativeClient.openUnlockWindow(
      payload.reason || 'browser_autofill',
      payload.pageHost || ''
    );
    if (response && response.success) {
      return { success: true, vault_locked: response.data?.vault_locked ?? true };
    }
    return { success: false, error: 'Desktop app did not respond' };
  } catch (e) {
    return { success: false, error: 'Cannot reach AMPass Desktop: ' + (e.message || 'connection failed') };
  }
}

/**
 * Log a usage action to the server (non-blocking).
 * SECURITY: Never logs plaintext credentials. Only item_id, action, client_type.
 */
async function logUsage(payload) {
  if (!payload || !payload.item_id || !payload.action) {
    return { success: false, error: 'Missing item_id or action' };
  }
  // Fire and forget — don't block autofill on logging
  try {
    if (isOnline) {
      await ApiClient.request('vault/usage-log', {
        body: {
          item_id: payload.item_id,
          action: payload.action,
          client_type: payload.client_type || 'extension'
        }
      });
    }
  } catch (e) {
    // Non-critical — don't fail on logging errors
  }
  return { success: true };
}

async function searchVault(query) {
  const result = await getAllItems();
  if (!result.success) return result;

  const q = query.toLowerCase();
  const filtered = result.items.filter(item =>
    (item.title && item.title.toLowerCase().includes(q)) ||
    (item.username && item.username.toLowerCase().includes(q)) ||
    (item.url && item.url.toLowerCase().includes(q))
  );

  return { success: true, items: filtered };
}

async function saveItem(payload) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');
  if (!isOnline) return { success: false, code: 'OFFLINE_READ_ONLY', error: 'Server offline. Offline mode is read-only.' };

  const vaultKeyHex = await Storage.getVaultKey();
  const searchKey = await CryptoClient.deriveSearchKey(vaultKeyHex);
  const encrypted = await CryptoClient.encryptItem(payload.itemData, vaultKeyHex);
  const urlHash = payload.itemData.url ? await CryptoClient.computeSearchHash(DomainUtils.getBaseDomain(payload.itemData.url), searchKey) : null;
  const titleHash = payload.itemData.title ? await CryptoClient.computeSearchHash(payload.itemData.title, searchKey) : null;

  try {
    const result = await ApiClient.saveVaultItem({
      item_type: payload.itemData.item_type || 'login',
      encrypted_data: encrypted.ciphertext,
      encryption_iv: encrypted.iv,
      url_hash: urlHash,
      title_hash: titleHash,
      password_strength: CryptoClient.calculateStrength(payload.itemData.password || ''),
      is_weak: CryptoClient.calculateStrength(payload.itemData.password || '') < 40 ? 1 : 0
    });
    await fetchVaultItems();
    return { success: true, id: result.id };
  } catch (e) {
    if (e.code === 'NETWORK_OFFLINE') {
      isOnline = false;
      return { success: false, code: 'OFFLINE_READ_ONLY', error: 'Server offline. Cannot save changes.' };
    }
    throw e;
  }
}

async function updateItem(payload) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');
  if (!isOnline) return { success: false, code: 'OFFLINE_READ_ONLY', error: 'Server offline. Offline mode is read-only.' };

  const vaultKeyHex = await Storage.getVaultKey();
  const searchKey = await CryptoClient.deriveSearchKey(vaultKeyHex);
  const encrypted = await CryptoClient.encryptItem(payload.itemData, vaultKeyHex);
  const urlHash = payload.itemData.url ? await CryptoClient.computeSearchHash(DomainUtils.getBaseDomain(payload.itemData.url), searchKey) : null;
  const titleHash = payload.itemData.title ? await CryptoClient.computeSearchHash(payload.itemData.title, searchKey) : null;

  const result = await ApiClient.updateVaultItem({
    id: payload.id,
    item_type: payload.itemData.item_type || 'login',
    encrypted_data: encrypted.ciphertext,
    encryption_iv: encrypted.iv,
    url_hash: urlHash,
    title_hash: titleHash,
    password_strength: CryptoClient.calculateStrength(payload.itemData.password || ''),
    is_weak: CryptoClient.calculateStrength(payload.itemData.password || '') < 40 ? 1 : 0
  });

  await fetchVaultItems();
  return { success: true, id: result.id };
}

async function deleteItem(id) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');
  if (!isOnline) return { success: false, code: 'OFFLINE_READ_ONLY', error: 'Server offline. Offline mode is read-only.' };

  await ApiClient.deleteVaultItem(id);
  // Remove from local cache immediately
  if (cachedVaultItems) {
    cachedVaultItems = cachedVaultItems.filter(i => i.id !== id);
    await Storage.setEncryptedVaultCache(cachedVaultItems);
  }
  return { success: true };
}

async function favoriteItem(id, isFavorite) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');
  if (!isOnline) return { success: false, code: 'OFFLINE_READ_ONLY', error: 'Server offline. Offline mode is read-only.' };

  // NOTE: The PHP API uses vault/update to toggle is_favorite — there is no separate vault/favorite endpoint.
  // We send only the is_favorite field alongside the id; the server ignores missing optional fields.
  await ApiClient.updateVaultItem({ id, is_favorite: isFavorite ? 1 : 0 });
  // Update local cache
  if (cachedVaultItems) {
    const item = cachedVaultItems.find(i => i.id === id);
    if (item) item.is_favorite = isFavorite ? 1 : 0;
    await Storage.setEncryptedVaultCache(cachedVaultItems);
  }
  return { success: true };
}

/**
 * Generate a TOTP code (RFC 6238) using Web Crypto.
 * SECURITY: secret is base32-encoded and never stored in plaintext
 * outside of the encrypted vault item.
 */
async function generateTotp(secret) {
  if (!secret) return { success: false, error: 'No TOTP secret provided' };
  try {
    const code = await computeTotp(secret);
    const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    return { success: true, code, remaining };
  } catch (e) {
    return { success: false, error: 'Invalid TOTP secret: ' + (e.message || 'unknown') };
  }
}

/**
 * TOTP implementation (RFC 6238 / RFC 4226) using Web Crypto HMAC-SHA1.
 * No external libraries required.
 */
async function computeTotp(base32Secret) {
  // Decode base32 secret
  const bytes = base32Decode(base32Secret.toUpperCase().replace(/\s/g, ''));

  // Get current 30-second time step
  const timeStep = Math.floor(Date.now() / 1000 / 30);

  // Build 8-byte big-endian counter
  const counter = new ArrayBuffer(8);
  const view = new DataView(counter);
  // JavaScript numbers are safe for the high 32 bits for many years
  view.setUint32(0, Math.floor(timeStep / 0x100000000), false);
  view.setUint32(4, timeStep >>> 0, false);

  // HMAC-SHA1
  const key = await crypto.subtle.importKey(
    'raw', bytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));

  // Dynamic truncation
  const offset = hmac[19] & 0xf;
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % 1000000;

  return String(code).padStart(6, '0');
}

/** Base32 decoder for TOTP secrets. */
function base32Decode(encoded) {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of encoded) {
    if (char === '=') break;
    const idx = CHARS.indexOf(char);
    if (idx === -1) throw new Error('Invalid base32 character: ' + char);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes).buffer;
}

// ===== Badge =====
function updateBadge(count) {
  const text = count > 0 ? String(count) : '';
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color: count > 0 ? '#6366f1' : '#71717a' });
}

// ===== Auto-Lock Alarm =====
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'autoLock') {
    await lock();
  }
});

// ===== Tab Change - Update Badge =====
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      const result = await getMatches(tab.url);
      updateBadge(result.count);
    }
  } catch (e) { /* ignore */ }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active && tab.url) {
    const result = await getMatches(tab.url);
    updateBadge(result.count);
  }
});

// ===== Keyboard Command: Direct Autofill (Ctrl+Shift+F) =====
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== 'autofill_current') return;

  // Must be unlocked
  if (!await Storage.isVaultUnlocked()) return;

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith('http')) return;

  // Find matches for the current tab's URL
  const result = await getMatches(tab.url);
  if (!result.success || result.count === 0) return;

  // Pick the first match and decrypt
  const match = result.items[0];
  const vaultKeyHex = await Storage.getVaultKey();
  const encItem = (cachedVaultItems || []).find(i => i.id === match.id);
  if (!encItem) return;

  const decrypted = await CryptoClient.decryptItem(encItem.encrypted_data, encItem.encryption_iv, vaultKeyHex);

  // Send to content script for autofill
  chrome.tabs.sendMessage(tab.id, {
    type: 'AUTOFILL',
    payload: { username: decrypted.username || decrypted.email || '', password: decrypted.password || '' }
  }).catch(() => {});
});

chrome.runtime.onMessage.addListener(() => {
  // Any message resets the auto-lock timer
  Storage.getSettings().then(settings => {
    const timeout = settings.lockTimeoutMinutes || 30;
    chrome.alarms.create('autoLock', { delayInMinutes: timeout });
  });
});

// AMPass service worker ready

// ===== Context Menu Setup =====
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'ampass-fill-login',
    title: 'Fill login with AMPass',
    contexts: ['editable']
  });
  chrome.contextMenus.create({
    id: 'ampass-fill-identity',
    title: 'Fill identity info with AMPass',
    contexts: ['editable']
  });
  chrome.contextMenus.create({
    id: 'ampass-generate-password',
    title: 'Generate password',
    contexts: ['editable']
  });
  chrome.contextMenus.create({
    id: 'ampass-open',
    title: 'Open AMPass',
    contexts: ['all']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id || !tab.url || !tab.url.startsWith('http')) return;

  if (info.menuItemId === 'ampass-open') {
    chrome.action.openPopup();
    return;
  }

  if (!await Storage.isVaultUnlocked()) return;

  if (info.menuItemId === 'ampass-fill-login') {
    const result = await getMatches(tab.url);
    if (result.success && result.count > 0) {
      const match = result.items[0];
      const vaultKeyHex = await Storage.getVaultKey();
      const encItem = (cachedVaultItems || []).find(i => i.id === match.id);
      if (encItem) {
        const decrypted = await CryptoClient.decryptItem(encItem.encrypted_data, encItem.encryption_iv, vaultKeyHex);
        chrome.tabs.sendMessage(tab.id, {
          type: 'AUTOFILL',
          payload: { username: decrypted.username || decrypted.email || '', password: decrypted.password || '' }
        }).catch(() => {});
      }
    }
  } else if (info.menuItemId === 'ampass-fill-identity') {
    const idResult = await getIdentities();
    if (idResult.success && idResult.items && idResult.items.length > 0) {
      const match = idResult.items[0];
      const vaultKeyHex = await Storage.getVaultKey();
      const encItem = (cachedVaultItems || []).find(i => i.id === match.id);
      if (encItem) {
        const decrypted = await CryptoClient.decryptItem(encItem.encrypted_data, encItem.encryption_iv, vaultKeyHex);
        chrome.tabs.sendMessage(tab.id, {
          type: 'AUTOFILL_IDENTITY',
          payload: decrypted
        }).catch(() => {});
      }
    }
  } else if (info.menuItemId === 'ampass-generate-password') {
    const password = CryptoClient.generatePassword({ length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true });
    chrome.tabs.sendMessage(tab.id, {
      type: 'AUTOFILL',
      payload: { username: '', password: password }
    }).catch(() => {});
  }
});

// ===== Auto-fill on Page Load =====
async function autofillPageLoad(payload) {
  if (!payload || !payload.url) return { success: false };
  if (!await Storage.isVaultUnlocked()) return { success: false, code: 'VAULT_LOCKED' };

  // Check if auto-fill on load is enabled
  const settings = await Storage.getSettings();
  if (settings.autoFillOnLoad === false) return { success: false, code: 'DISABLED' };

  const result = await getMatches(payload.url);
  if (!result.success || result.count !== 1) return { success: false, code: 'NO_SINGLE_MATCH', count: result.count };

  // Exactly 1 match — decrypt and return for auto-fill
  const match = result.items[0];
  const vaultKeyHex = await Storage.getVaultKey();
  const encItem = (cachedVaultItems || []).find(i => i.id === match.id);
  if (!encItem) return { success: false };

  const decrypted = await CryptoClient.decryptItem(encItem.encrypted_data, encItem.encryption_iv, vaultKeyHex);
  return {
    success: true,
    credentials: { username: decrypted.username || decrypted.email || '', password: decrypted.password || '' },
    itemId: match.id
  };
}

async function getAutofillSettings() {
  const settings = await Storage.getSettings();
  return {
    success: true,
    autoFillOnLoad: settings.autoFillOnLoad !== false, // default true
    allowHttpAutofill: !!settings.allowHttpAutofill
  };
}

// ===== Critical OS Inactivity Watchdog Auto-Lock Event =====
globalThis.onCriticalVaultLock = async function() {
  console.log('CRITICAL: Received vault lock event from native host. Locking extension.');
  await lock();
  
  // Close any tabs that are showing extension pages (options page, options tab, etc.)
  const extensionPrefix = chrome.runtime.getURL('');
  chrome.tabs.query({}, (tabs) => {
    if (tabs) {
      for (const tab of tabs) {
        if (tab.url && tab.url.startsWith(extensionPrefix)) {
          chrome.tabs.remove(tab.id).catch(() => {});
        }
      }
    }
  });

  // Notify any active extension pages (like the popup if it's currently open)
  chrome.runtime.sendMessage({ type: 'VAULT_LOCKED' }).catch(() => {});
};
