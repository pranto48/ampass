/**
 * AMPass Desktop - Main Application Logic
 * SECURITY: Vault key held in Rust backend memory. Frontend uses it transiently for crypto.
 */
(function() {
  'use strict';

  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  let vaultKeyHex = null;
  let vaultItems = [];
  let derivationParams = null;

  // ===== Views =====
  const views = { setup: 'viewSetup', login: 'viewLogin', unlock: 'viewUnlock', vault: 'viewVault', generator: 'viewGenerator', settings: 'viewSettings' };

  function showView(name) {
    Object.values(views).forEach(id => { document.getElementById(id).style.display = 'none'; });
    document.getElementById(views[name]).style.display = (name === 'setup' || name === 'login' || name === 'unlock') ? 'flex' : 'block';
    document.getElementById('sidebar').style.display = (name === 'vault' || name === 'generator' || name === 'settings') ? 'flex' : 'none';
    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === name));
  }

  // ===== Init =====
  async function init() {
    try {
      const state = await invoke('get_app_state');
      if (!state.configured) { showView('setup'); return; }
      Api.serverUrl = state.server_url;
      if (!state.authenticated) { showView('login'); return; }
      const token = await invoke('get_auth_token');
      if (token) Api.token = token;
      if (state.locked) { showView('unlock'); return; }
      showView('vault');
      await loadVault();
    } catch (e) { showView('setup'); }
  }

  // ===== Setup =====
  document.getElementById('btnSetupSave').addEventListener('click', async () => {
    const url = document.getElementById('setupUrl').value.trim();
    if (!url) return;
    await invoke('set_server_url', { url });
    Api.serverUrl = url;
    showView('login');
  });

  // ===== Login =====
  document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    if (!user || !pass) return;
    const errEl = document.getElementById('loginError');
    errEl.style.display = 'none';
    try {
      const result = await Api.login(user, pass, 'AMPass Desktop');
      Api.token = result.token;
      await invoke('store_auth_token', { token: result.token });
      derivationParams = result.derivation_params;
      document.getElementById('loginPass').value = '';
      showView('unlock');
    } catch (e) {
      errEl.textContent = e.message; errEl.style.display = 'block';
      document.getElementById('loginPass').value = '';
    }
  });

  document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnLogin').click(); });

  // ===== Unlock =====
  document.getElementById('btnUnlock').addEventListener('click', async () => {
    const pass = document.getElementById('unlockPass').value;
    if (!pass) return;
    const errEl = document.getElementById('unlockError');
    errEl.style.display = 'none';
    try {
      if (!derivationParams) {
        // Fetch derivation params if not cached
        const token = await invoke('get_auth_token');
        if (token) Api.token = token;
        // We need to get params from server - use session endpoint or re-login
        throw new Error('Session expired. Please login again.');
      }
      vaultKeyHex = await Crypto.unlockVault(pass, derivationParams);
      await invoke('unlock_vault', { vaultKeyHex });
      document.getElementById('unlockPass').value = '';
      showView('vault');
      await loadVault();
    } catch (e) {
      errEl.textContent = e.message || 'Invalid master password'; errEl.style.display = 'block';
      document.getElementById('unlockPass').value = '';
    }
  });

  document.getElementById('unlockPass').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnUnlock').click(); });

  // ===== Vault =====
  async function loadVault() {
    try {
      const result = await Api.listVault();
      vaultItems = result.items || [];
      // Cache encrypted items locally
      await invoke('save_vault_cache', { encryptedItemsJson: JSON.stringify(vaultItems) });
      renderVault(vaultItems);
    } catch (e) {
      // Try loading from cache
      const cached = await invoke('load_vault_cache');
      if (cached) {
        vaultItems = JSON.parse(cached);
        renderVault(vaultItems);
        showStatus('Offline — showing cached data', 'offline');
      }
    }
    await invoke('record_activity');
  }

  async function renderVault(items) {
    const list = document.getElementById('vaultList');
    const empty = document.getElementById('vaultEmpty');
    if (!items.length) { list.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';

    const rendered = [];
    for (const item of items) {
      try {
        const dec = await Crypto.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
        rendered.push({ id: item.id, title: dec.title || 'Untitled', username: dec.username || dec.email || '', type: item.item_type });
      } catch { rendered.push({ id: item.id, title: '[Decrypt Error]', username: '', type: item.item_type }); }
    }

    list.innerHTML = rendered.map(i => `
      <div class="vault-item" data-id="${i.id}">
        <div class="vault-item-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div>
        <div class="vault-item-info">
          <span class="vault-item-title">${esc(i.title)}</span>
          <span class="vault-item-sub">${esc(i.username)}</span>
        </div>
        <div class="vault-item-actions">
          <button title="Copy password" data-action="copy-pass" data-id="${i.id}">📋</button>
        </div>
      </div>
    `).join('');

    list.querySelectorAll('[data-action="copy-pass"]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = parseInt(btn.dataset.id);
        const item = vaultItems.find(x => x.id === id);
        if (!item) return;
        const dec = await Crypto.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
        if (dec.password) {
          await navigator.clipboard.writeText(dec.password);
          showStatus('Password copied (clears in 30s)', 'success');
          setTimeout(async () => { try { const c = await navigator.clipboard.readText(); if (c === dec.password) await navigator.clipboard.writeText(''); } catch {} }, 30000);
        }
      });
    });
  }

  // ===== Search =====
  let searchTimer;
  document.getElementById('searchInput').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) { renderVault(vaultItems); return; }
      const filtered = [];
      for (const item of vaultItems) {
        try {
          const dec = await Crypto.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
          if ((dec.title || '').toLowerCase().includes(q) || (dec.username || '').toLowerCase().includes(q) || (dec.url || '').toLowerCase().includes(q)) {
            filtered.push(item);
          }
        } catch {}
      }
      renderVault(filtered);
    }, 200);
  });

  // ===== Lock =====
  document.getElementById('btnLock').addEventListener('click', async () => {
    vaultKeyHex = null;
    await invoke('lock_vault');
    showView('unlock');
  });

  // ===== Sync =====
  document.getElementById('btnSync').addEventListener('click', loadVault);

  // ===== Generator =====
  function genPw() {
    const pw = Crypto.generatePassword({
      length: parseInt(document.getElementById('genLen').value),
      uppercase: document.getElementById('genUpper').checked,
      lowercase: document.getElementById('genLower').checked,
      numbers: document.getElementById('genNums').checked,
      symbols: document.getElementById('genSyms').checked
    });
    document.getElementById('genPassword').value = pw;
    const s = Crypto.strength(pw);
    const fill = document.getElementById('genStrengthFill');
    fill.style.width = s + '%';
    fill.style.background = s >= 80 ? '#22c55e' : s >= 60 ? '#84cc16' : s >= 40 ? '#f59e0b' : '#ef4444';
  }
  document.getElementById('btnRegen').addEventListener('click', genPw);
  document.getElementById('genLen').addEventListener('input', (e) => { document.getElementById('genLenVal').textContent = e.target.value; genPw(); });
  document.getElementById('btnCopyGen').addEventListener('click', async () => {
    await navigator.clipboard.writeText(document.getElementById('genPassword').value);
    showStatus('Copied!', 'success');
  });

  // ===== Settings =====
  document.getElementById('btnExport').addEventListener('click', async () => {
    const data = JSON.stringify({ version: '1.0', exported_at: new Date().toISOString(), items: vaultItems });
    await invoke('pick_save_location', { data });
  });
  document.getElementById('btnImport').addEventListener('click', async () => {
    const content = await invoke('pick_backup_file');
    if (content) { showStatus('Import not yet implemented in v1', 'offline'); }
  });
  document.getElementById('btnWipe').addEventListener('click', async () => {
    if (!confirm('Wipe ALL local data? This cannot be undone. Server data is not affected.')) return;
    await invoke('wipe_local_data');
    vaultKeyHex = null; vaultItems = []; derivationParams = null;
    showView('setup');
  });
  document.getElementById('btnLogout').addEventListener('click', async () => {
    try { await Api.logout(); } catch {}
    await invoke('logout');
    vaultKeyHex = null; vaultItems = []; derivationParams = null; Api.token = '';
    showView('login');
  });

  // ===== Nav =====
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', (e) => { e.preventDefault(); showView(el.dataset.view); });
  });

  // ===== Tauri Events =====
  listen('tray-lock', async () => { vaultKeyHex = null; await invoke('lock_vault'); showView('unlock'); });
  listen('auto-locked', () => { vaultKeyHex = null; showView('unlock'); });

  // ===== Helpers =====
  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function showStatus(msg, type) {
    const bar = document.getElementById('statusBar');
    bar.textContent = msg; bar.className = 'status-bar ' + type; bar.style.display = 'block';
    if (type === 'success') setTimeout(() => { bar.style.display = 'none'; }, 3000);
  }

  // ===== Background Sync =====
  setInterval(async () => {
    if (vaultKeyHex) { await invoke('record_activity'); await loadVault(); }
  }, 300000); // Every 5 minutes

  // ===== Start =====
  init();
  // Generate initial password
  setTimeout(genPw, 100);
})();
