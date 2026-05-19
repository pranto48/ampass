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
    sendResponse({ success: false, error: safeError });
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
    case 'DECRYPT_ITEM':
      return await decryptItem(msg.payload.id);
    case 'SEARCH':
      return await searchVault(msg.payload.query);
    case 'SAVE_ITEM':
      return await saveItem(msg.payload);
    case 'UPDATE_ITEM':
      return await updateItem(msg.payload);
    case 'CAPTURE_SAVE_CANDIDATE':
      return captureSaveCandidate(msg.payload, sender);
    case 'CHECK_PENDING_SAVE':
      return popPendingSaveCandidate(sender);
    case 'CLEAR_PENDING_SAVE':
      return clearPendingSaveCandidate(sender);
    case 'GENERATE_PASSWORD':
      return { success: true, password: CryptoClient.generatePassword(msg.payload || {}) };
    case 'COPY_TO_CLIPBOARD':
      return await copyToClipboard(msg.payload);
    case 'GET_SETTINGS':
      return { success: true, settings: await Storage.getSettings() };
    case 'RESET_EXTENSION':
      return await resetExtension();
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
  const { serverUrl, username, password, deviceName, trustBrowser } = payload;
  await Storage.setServerUrl(serverUrl);

  const browserName = navigator.userAgent.includes('Edg') ? 'Edge' :
                      navigator.userAgent.includes('Chrome') ? 'Chrome' : 'Browser';

  const result = await ApiClient.login(username, password, deviceName || 'AMPass Extension', browserName);

  await Storage.setToken(result.token, !!trustBrowser);
  await Storage.setDerivationParams(result.derivation_params);
  await Storage.setSession('user', result.user);

  return { success: true, user: result.user, needsUnlock: true };
}

async function unlock(payload) {
  const { masterPassword } = payload;
  const params = await Storage.getDerivationParams();
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
  const timeout = settings.lockTimeoutMinutes || 15;
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
  const result = await ApiClient.listVault();
  cachedVaultItems = result.items || [];
  lastFetchTime = Date.now();
  await Storage.setSession('vaultItems', cachedVaultItems);
  // Save to persistent offline cache
  if (cachedVaultItems.length > 0) {
    await Storage.setEncryptedVaultCache(cachedVaultItems);
  }
}

/**
 * Ensure vault items are loaded from any available source.
 */
async function ensureVaultItemsLoaded() {
  if (cachedVaultItems && cachedVaultItems.length > 0) return;

  // Try session storage
  const sessionItems = await Storage.getSession('vaultItems');
  if (sessionItems && sessionItems.length > 0) {
    cachedVaultItems = sessionItems;
    return;
  }

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
        username: decrypted.username || decrypted.email || '',
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
    return { success: true, items: [], count: 0 };
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
      const itemDomain = DomainUtils.getBaseDomain(decrypted.url || '');
      if (itemDomain && itemDomain === domain) {
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

async function decryptItem(id) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');

  const vaultKeyHex = await Storage.getVaultKey();
  if (!cachedVaultItems) {
    const stored = await Storage.getSession('vaultItems');
    cachedVaultItems = stored || [];
  }

  const item = cachedVaultItems.find(i => i.id === id);
  if (!item) throw new Error('Item not found');

  const decrypted = await CryptoClient.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
  return { success: true, item: decrypted };
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
      item_type: 'login',
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
    item_type: 'login',
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

async function copyToClipboard(payload) {
  // Use offscreen document or fallback
  // In MV3, clipboard access from service worker is limited
  // We'll handle this in the popup/content script instead
  return { success: true, text: payload.text };
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

// ===== Reset lock timer on activity =====
chrome.runtime.onMessage.addListener(() => {
  // Any message resets the auto-lock timer
  Storage.getSettings().then(settings => {
    const timeout = settings.lockTimeoutMinutes || 15;
    chrome.alarms.create('autoLock', { delayInMinutes: timeout });
  });
});

// AMPass service worker ready
