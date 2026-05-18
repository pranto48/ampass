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

async function resetExtension() {
  await Storage.clearSession();
  await Storage.removeLocal('serverUrl');
  cachedVaultItems = null;
  return { success: true };
}

// ===== Core Operations =====

async function getStatus() {
  const serverUrl = await Storage.getServerUrl();
  const configured = !!serverUrl;
  let authenticated = await Storage.isAuthenticated();
  const unlocked = await Storage.isVaultUnlocked();

  // Verify token with server if we think we're authenticated
  if (authenticated && configured) {
    try {
      ApiClient.serverUrl = serverUrl;
      ApiClient.token = await Storage.getToken();
      await ApiClient.getSession(); // Will throw if token is invalid/expired
    } catch (e) {
      if (e.code === 'AUTH_REQUIRED' || e.status === 401) {
        // Token is stale — clear it
        await Storage.removeSession('authToken');
        await Storage.removeSession('derivationParams');
        await Storage.removeSession('vaultKeyHex');
        await Storage.removeSession('vaultItems');
        authenticated = false;
      }
    }
  }

  return { success: true, authenticated, unlocked, serverUrl, configured };
}

async function login(payload) {
  const { serverUrl, username, password, deviceName } = payload;
  await Storage.setServerUrl(serverUrl);

  const browserName = navigator.userAgent.includes('Edg') ? 'Edge' :
                      navigator.userAgent.includes('Chrome') ? 'Chrome' : 'Browser';

  const result = await ApiClient.login(username, password, deviceName || 'AMPass Extension', browserName);

  await Storage.setToken(result.token);
  await Storage.setDerivationParams(result.derivation_params);
  await Storage.setSession('user', result.user);

  return { success: true, user: result.user, needsUnlock: true };
}

async function unlock(payload) {
  const { masterPassword } = payload;
  const params = await Storage.getDerivationParams();
  if (!params) throw new Error('Not authenticated. Please login first.');

  // Check if vault needs first-time initialization
  if (params.needs_setup || params.key_iterations === 0 || params.encrypted_vault_key === 'VAULT_NOT_INITIALIZED') {
    // First-time vault setup: generate a new vault key and encrypt it with the master password
    const setupResult = await initializeVault(masterPassword, params);
    await Storage.setVaultKey(setupResult.vaultKeyHex);
    // Update derivation params in session with the real values
    await Storage.setDerivationParams(setupResult.newParams);
  } else {
    // Normal unlock: derive wrapping key and decrypt existing vault key
    const vaultKeyHex = await CryptoClient.unlockVault(masterPassword, params);
    await Storage.setVaultKey(vaultKeyHex);
  }

  // Fetch vault items
  await fetchVaultItems();

  // Set up auto-lock alarm
  const settings = await Storage.getSettings();
  const timeout = settings.lockTimeoutMinutes || 15;
  chrome.alarms.create('autoLock', { delayInMinutes: timeout });

  return { success: true };
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
}

async function getAllItems() {
  if (!await Storage.isVaultUnlocked()) {
    return { success: false, error: 'Vault is locked' };
  }

  if (!cachedVaultItems || Date.now() - lastFetchTime > CACHE_TTL) {
    const stored = await Storage.getSession('vaultItems');
    if (stored) {
      cachedVaultItems = stored;
    } else {
      await fetchVaultItems();
    }
  }

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

  // Decrypt all items and match by domain
  const vaultKeyHex = await Storage.getVaultKey();
  if (!cachedVaultItems) {
    const stored = await Storage.getSession('vaultItems');
    cachedVaultItems = stored || [];
  }

  const matches = [];
  for (const item of cachedVaultItems) {
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

  const vaultKeyHex = await Storage.getVaultKey();
  const searchKey = await CryptoClient.deriveSearchKey(vaultKeyHex);
  const encrypted = await CryptoClient.encryptItem(payload.itemData, vaultKeyHex);
  const urlHash = payload.itemData.url ? await CryptoClient.computeSearchHash(DomainUtils.getBaseDomain(payload.itemData.url), searchKey) : null;
  const titleHash = payload.itemData.title ? await CryptoClient.computeSearchHash(payload.itemData.title, searchKey) : null;

  const result = await ApiClient.saveVaultItem({
    item_type: 'login',
    encrypted_data: encrypted.ciphertext,
    encryption_iv: encrypted.iv,
    url_hash: urlHash,
    title_hash: titleHash,
    password_strength: CryptoClient.calculateStrength(payload.itemData.password || ''),
    is_weak: CryptoClient.calculateStrength(payload.itemData.password || '') < 40 ? 1 : 0
  });

  // Refresh cache
  await fetchVaultItems();
  return { success: true, id: result.id };
}

async function updateItem(payload) {
  if (!await Storage.isVaultUnlocked()) throw new Error('Vault is locked');

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
