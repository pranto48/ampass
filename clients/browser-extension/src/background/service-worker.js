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
  '../shared/password-generator.js'
);

// ===== State =====
let cachedVaultItems = null;
let lastFetchTime = 0;
const CACHE_TTL = 60000; // 1 minute

// ===== Message Handler =====
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => {
    sendResponse({ success: false, error: err.message || 'Unknown error' });
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
    default:
      return { success: false, error: 'Unknown message type' };
  }
}

// ===== Core Operations =====

async function getStatus() {
  const authenticated = await Storage.isAuthenticated();
  const unlocked = await Storage.isVaultUnlocked();
  const serverUrl = await Storage.getServerUrl();
  return { success: true, authenticated, unlocked, serverUrl, configured: !!serverUrl };
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

  // Derive vault key locally
  const vaultKeyHex = await CryptoClient.unlockVault(masterPassword, params);
  await Storage.setVaultKey(vaultKeyHex);

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
  const encrypted = await CryptoClient.encryptItem(payload.itemData, vaultKeyHex);
  const urlHash = payload.itemData.url ? await CryptoClient.computeHMAC(DomainUtils.getBaseDomain(payload.itemData.url)) : null;
  const titleHash = payload.itemData.title ? await CryptoClient.computeHMAC(payload.itemData.title) : null;

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
  const encrypted = await CryptoClient.encryptItem(payload.itemData, vaultKeyHex);
  const urlHash = payload.itemData.url ? await CryptoClient.computeHMAC(DomainUtils.getBaseDomain(payload.itemData.url)) : null;
  const titleHash = payload.itemData.title ? await CryptoClient.computeHMAC(payload.itemData.title) : null;

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

console.log('AMPass service worker initialized');
