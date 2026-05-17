/**
 * AMPass Extension - Popup Logic
 * SECURITY: Communicates with service worker for all crypto/vault operations.
 * Never holds vault key directly.
 */

(function() {
  'use strict';

  // ===== DOM Elements =====
  const views = {
    setup: document.getElementById('viewSetup'),
    login: document.getElementById('viewLogin'),
    unlock: document.getElementById('viewUnlock'),
    vault: document.getElementById('viewVault'),
    generator: document.getElementById('viewGenerator')
  };

  const els = {
    statusBar: document.getElementById('statusBar'),
    btnSettings: document.getElementById('btnSettings'),
    btnLock: document.getElementById('btnLock'),
    setupUrl: document.getElementById('setupUrl'),
    btnSetupSave: document.getElementById('btnSetupSave'),
    loginUsername: document.getElementById('loginUsername'),
    loginPassword: document.getElementById('loginPassword'),
    btnLogin: document.getElementById('btnLogin'),
    loginError: document.getElementById('loginError'),
    unlockPassword: document.getElementById('unlockPassword'),
    btnUnlock: document.getElementById('btnUnlock'),
    unlockError: document.getElementById('unlockError'),
    searchInput: document.getElementById('searchInput'),
    matchesSection: document.getElementById('matchesSection'),
    matchesList: document.getElementById('matchesList'),
    allItemsSection: document.getElementById('allItemsSection'),
    allItemsList: document.getElementById('allItemsList'),
    itemCount: document.getElementById('itemCount'),
    emptyState: document.getElementById('emptyState'),
    btnAddNew: document.getElementById('btnAddNew'),
    btnGenerate: document.getElementById('btnGenerate'),
    btnBackFromGen: document.getElementById('btnBackFromGen'),
    genPassword: document.getElementById('genPassword'),
    btnCopyGen: document.getElementById('btnCopyGen'),
    genLength: document.getElementById('genLength'),
    genLengthVal: document.getElementById('genLengthVal'),
    btnRegenerate: document.getElementById('btnRegenerate'),
    genStrength: document.getElementById('genStrength')
  };

  // ===== View Management =====
  function showView(name) {
    Object.values(views).forEach(v => v.style.display = 'none');
    if (views[name]) views[name].style.display = 'block';
    els.btnLock.style.display = (name === 'vault' || name === 'generator') ? 'flex' : 'none';
  }

  function showStatus(msg, type = 'warning') {
    els.statusBar.textContent = msg;
    els.statusBar.className = 'status-bar ' + type;
    els.statusBar.style.display = 'block';
  }

  function hideStatus() {
    els.statusBar.style.display = 'none';
  }

  // ===== Send message to service worker =====
  function sendMsg(type, payload = {}) {
    return chrome.runtime.sendMessage({ type, payload });
  }

  // ===== Initialize =====
  async function init() {
    const status = await sendMsg('GET_STATUS');
    if (!status.success) { showView('setup'); return; }

    if (!status.configured) {
      showView('setup');
    } else if (!status.authenticated) {
      showView('login');
    } else if (!status.unlocked) {
      showView('unlock');
    } else {
      showView('vault');
      await loadVault();
    }

    // Check HTTPS
    if (status.serverUrl && !status.serverUrl.startsWith('https://') && !status.serverUrl.includes('localhost')) {
      showStatus('⚠️ Server is not using HTTPS. Your data may be at risk.', 'warning');
    }
  }

  // ===== Setup =====
  els.btnSetupSave.addEventListener('click', async () => {
    const url = els.setupUrl.value.trim();
    if (!url) return;
    await Storage.setServerUrl(url);
    showView('login');
  });

  // ===== Login =====
  els.btnLogin.addEventListener('click', async () => {
    const username = els.loginUsername.value.trim();
    const password = els.loginPassword.value;
    if (!username || !password) return;

    els.btnLogin.disabled = true;
    els.btnLogin.textContent = 'Signing in...';
    els.loginError.style.display = 'none';

    try {
      const serverUrl = await Storage.getServerUrl();
      const result = await sendMsg('LOGIN', { serverUrl, username, password });
      if (result.success) {
        showView('unlock');
      } else {
        throw new Error(result.error || 'Login failed');
      }
    } catch (e) {
      els.loginError.textContent = e.message;
      els.loginError.style.display = 'block';
    } finally {
      els.btnLogin.disabled = false;
      els.btnLogin.textContent = 'Sign In';
      els.loginPassword.value = '';
    }
  });

  // Enter key on login
  els.loginPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') els.btnLogin.click();
  });

  // ===== Unlock =====
  els.btnUnlock.addEventListener('click', async () => {
    const password = els.unlockPassword.value;
    if (!password) return;

    els.btnUnlock.disabled = true;
    els.btnUnlock.textContent = 'Unlocking...';
    els.unlockError.style.display = 'none';

    try {
      const result = await sendMsg('UNLOCK', { masterPassword: password });
      if (result.success) {
        showView('vault');
        await loadVault();
      } else {
        throw new Error(result.error || 'Invalid master password');
      }
    } catch (e) {
      els.unlockError.textContent = e.message;
      els.unlockError.style.display = 'block';
    } finally {
      els.btnUnlock.disabled = false;
      els.btnUnlock.textContent = 'Unlock';
      els.unlockPassword.value = '';
    }
  });

  els.unlockPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') els.btnUnlock.click();
  });

  // ===== Vault =====
  async function loadVault() {
    // Get current tab URL for matching
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrl = tab?.url || '';

    // Get matches for current site
    if (currentUrl && currentUrl.startsWith('http')) {
      const matchResult = await sendMsg('GET_MATCHES', { url: currentUrl });
      if (matchResult.success && matchResult.items.length > 0) {
        els.matchesSection.style.display = 'block';
        renderItems(els.matchesList, matchResult.items, true);
      } else {
        els.matchesSection.style.display = 'none';
      }
    }

    // Get all items
    const allResult = await sendMsg('GET_ALL_ITEMS');
    if (allResult.success) {
      els.itemCount.textContent = allResult.items.length;
      if (allResult.items.length > 0) {
        renderItems(els.allItemsList, allResult.items, false);
        els.emptyState.style.display = 'none';
      } else {
        els.allItemsList.innerHTML = '';
        els.emptyState.style.display = 'block';
      }
    }
  }

  function renderItems(container, items, showAutofill) {
    container.innerHTML = items.map(item => `
      <div class="item" data-id="${item.id}">
        <div class="item-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        </div>
        <div class="item-info">
          <span class="item-title">${Security.escapeHtml(item.title)}</span>
          <span class="item-subtitle">${Security.escapeHtml(item.username)}</span>
        </div>
        <div class="item-actions">
          ${showAutofill ? `<button class="icon-btn btn-autofill" data-id="${item.id}" title="Autofill"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg></button>` : ''}
          <button class="icon-btn btn-copy-user" data-id="${item.id}" title="Copy username"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></button>
          <button class="icon-btn btn-copy-pass" data-id="${item.id}" title="Copy password"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>
        </div>
      </div>
    `).join('');

    // Bind events
    container.querySelectorAll('.btn-autofill').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); autofillItem(parseInt(btn.dataset.id)); });
    });
    container.querySelectorAll('.btn-copy-user').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); copyField(parseInt(btn.dataset.id), 'username'); });
    });
    container.querySelectorAll('.btn-copy-pass').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); copyField(parseInt(btn.dataset.id), 'password'); });
    });
  }

  async function autofillItem(id) {
    const result = await sendMsg('DECRYPT_ITEM', { id });
    if (!result.success) return;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    chrome.tabs.sendMessage(tab.id, {
      type: 'AUTOFILL',
      payload: { username: result.item.username || result.item.email || '', password: result.item.password || '' }
    });

    // Close popup after autofill
    window.close();
  }

  async function copyField(id, field) {
    const result = await sendMsg('DECRYPT_ITEM', { id });
    if (!result.success) return;

    const value = result.item[field] || '';
    await navigator.clipboard.writeText(value);
    showStatus('Copied ' + field, 'success');
    setTimeout(hideStatus, 2000);

    // Auto-clear clipboard
    const settings = await Storage.getSettings();
    const clearTime = (settings.clipboardClearSeconds || 30) * 1000;
    setTimeout(async () => {
      try {
        const current = await navigator.clipboard.readText();
        if (current === value) await navigator.clipboard.writeText('');
      } catch (e) { /* can't read clipboard */ }
    }, clearTime);
  }

  // ===== Search =====
  let searchTimeout;
  els.searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
      const query = els.searchInput.value.trim();
      if (!query) { await loadVault(); return; }
      const result = await sendMsg('SEARCH', { query });
      if (result.success) {
        els.matchesSection.style.display = 'none';
        renderItems(els.allItemsList, result.items, false);
        els.itemCount.textContent = result.items.length;
      }
    }, 250);
  });

  // ===== Lock =====
  els.btnLock.addEventListener('click', async () => {
    await sendMsg('LOCK');
    showView('unlock');
  });

  // ===== Settings =====
  els.btnSettings.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // ===== Generator =====
  els.btnGenerate.addEventListener('click', () => {
    showView('generator');
    generatePassword();
  });

  els.btnBackFromGen.addEventListener('click', () => {
    showView('vault');
  });

  els.genLength.addEventListener('input', () => {
    els.genLengthVal.textContent = els.genLength.value;
    generatePassword();
  });

  els.btnRegenerate.addEventListener('click', generatePassword);
  els.btnCopyGen.addEventListener('click', async () => {
    await navigator.clipboard.writeText(els.genPassword.value);
    showStatus('Password copied!', 'success');
    setTimeout(hideStatus, 2000);
  });

  function generatePassword() {
    const pw = CryptoClient.generatePassword({
      length: parseInt(els.genLength.value),
      uppercase: document.getElementById('genUpper').checked,
      lowercase: document.getElementById('genLower').checked,
      numbers: document.getElementById('genNumbers').checked,
      symbols: document.getElementById('genSymbols').checked
    });
    els.genPassword.value = pw;

    // Update strength bar
    const score = CryptoClient.calculateStrength(pw);
    const fill = els.genStrength.querySelector('.strength-fill');
    fill.style.width = score + '%';
    fill.style.background = score >= 80 ? '#22c55e' : score >= 60 ? '#84cc16' : score >= 40 ? '#f59e0b' : '#ef4444';
  }

  // ===== Add New =====
  els.btnAddNew.addEventListener('click', async () => {
    // Open the web vault in a new tab for adding items
    const serverUrl = await Storage.getServerUrl();
    if (serverUrl) {
      chrome.tabs.create({ url: serverUrl + '/vault/add' });
    }
  });

  // ===== Init =====
  init();
})();
