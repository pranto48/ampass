/**
 * AMPass Desktop — Main Application
 * SECURITY: Vault key in memory only. Cleared on lock/quit.
 */
(function() {
  'use strict';

  // ===== Tauri Availability Check =====
  if (!window.__TAURI__ || !window.__TAURI__.core) {
    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('app').innerHTML = `
        <div class="auth-screen" style="display:flex;">
          <div class="auth-card">
            <h2 class="auth-title">AMPass Desktop</h2>
            <p class="auth-sub">This application requires the Tauri desktop runtime.</p>
            <p style="font-size:12px;color:#64748b;margin-top:12px;">To run in development:<br><code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">cargo tauri dev</code></p>
          </div>
        </div>`;
    });
    return; // Stop execution — not in Tauri
  }

  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  let vaultKeyHex = null;
  let vaultItems = [];
  let derivationParams = null;
  let searchKey = null; // Derived from vault key for title_hash/url_hash
  let allDecrypted = [];
  let appSettings = { lockTimeoutMin: 15, clipboardClearSec: 30 };

  // ===== Views =====
  function showAuth(id) {
    ['viewWelcome','viewLogin','viewUnlock','viewMain'].forEach(v => document.getElementById(v).style.display = 'none');
    document.getElementById(id).style.display = id === 'viewMain' ? 'flex' : 'flex';
  }

  /**
   * Show server connection error with options to change URL, retry, or work offline.
   */
  function showServerError(currentUrl, errorMsg) {
    ['viewWelcome','viewLogin','viewUnlock','viewMain'].forEach(v => document.getElementById(v).style.display = 'none');
    // Reuse viewWelcome with error content
    const card = document.querySelector('#viewWelcome .auth-card');
    if (!card) { showAuth('viewWelcome'); return; }
    card.innerHTML = `
      <div class="auth-logo"><svg width="56" height="56" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#dc2626"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg></div>
      <h1 class="auth-title">Server Connection Problem</h1>
      <p class="auth-sub" style="margin-bottom:8px;">Cannot reach AMPass server</p>
      <div style="background:#27272a;border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:0.8rem;">
        <div style="color:#a1a1aa;">Current server:</div>
        <div style="color:#fafafa;word-break:break-all;">${currentUrl || 'Not set'}</div>
        <div style="color:#ef4444;margin-top:6px;font-size:0.75rem;">${errorMsg || 'Server unreachable'}</div>
      </div>
      <div class="auth-form">
        <label class="field-label">Change Server URL</label>
        <input type="url" id="serverErrorUrl" class="field-input" value="${currentUrl || ''}" placeholder="https://ampass.arif.bd">
        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
          <button id="btnServerErrorSave" class="btn-primary" style="flex:1;">Save & Retry</button>
          <button id="btnServerErrorRetry" class="btn-ghost-sm" style="padding:10px 16px;">Retry</button>
        </div>
        <button id="btnServerErrorOffline" class="btn-ghost-sm" style="margin-top:8px;width:100%;opacity:0.7;">Work Offline (cached vault)</button>
      </div>
      <p class="auth-warning">⚠️ Not professionally audited.</p>
    `;
    document.getElementById('viewWelcome').style.display = 'flex';

    document.getElementById('btnServerErrorSave').addEventListener('click', async () => {
      const newUrl = document.getElementById('serverErrorUrl').value.trim();
      if (!newUrl) return;
      const normalized = Api.normalizeServerUrl(newUrl);
      await invoke('set_server_url', { url: normalized });
      Api.setServerUrl(normalized);
      // Clear old token if domain changed
      if (currentUrl && new URL(normalized).host !== new URL(currentUrl).host) {
        await invoke('logout');
        Api.token = '';
      }
      location.reload();
    });

    document.getElementById('btnServerErrorRetry').addEventListener('click', () => location.reload());

    document.getElementById('btnServerErrorOffline').addEventListener('click', async () => {
      // Try to load from offline cache
      if (derivationParams) {
        showAuth('viewUnlock');
      } else {
        const storedParams = await invoke('load_derivation_params');
        if (storedParams) {
          derivationParams = JSON.parse(storedParams);
          showAuth('viewUnlock');
        } else {
          alert('No offline data available. Please connect to server first.');
        }
      }
    });
  }

  function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const page = document.getElementById('page' + name.charAt(0).toUpperCase() + name.slice(1));
    if (page) page.classList.add('active');
    document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.page === name));
  }

  // ===== Init =====
  async function init() {
    // Check if Tauri is available (won't be in browser preview)
    if (!window.__TAURI__) {
      document.getElementById('app').innerHTML = '<div class="auth-screen"><div class="auth-card"><h2>AMPass Desktop</h2><p class="auth-sub">This app requires the Tauri desktop runtime.<br>Please launch via <code>cargo tauri dev</code>.</p></div></div>';
      return;
    }
    try {
      const state = await invoke('get_app_state');
      if (!state.configured) { showAuth('viewWelcome'); return; }
      Api.setServerUrl(state.server_url);
      if (!state.authenticated) {
        // Show server info on login screen
        const infoEl = document.getElementById('loginServerInfo');
        if (infoEl && state.server_url) { try { infoEl.textContent = 'Server: ' + new URL(state.server_url).host; } catch { infoEl.textContent = 'Server: ' + state.server_url; } }
        showAuth('viewLogin');
        return;
      }
      Api.token = (await invoke('get_auth_token')) || '';

      // Prefer locally encrypted trusted-device params so restart goes straight to Unlock.
      if (!derivationParams) {
        const storedParams = await invoke('load_derivation_params');
        if (storedParams) {
          derivationParams = JSON.parse(storedParams);
        }
      }

      // If the encrypted local params are missing, fetch once and store them.
      if (!derivationParams && Api.token) {
        try {
          const paramResult = await Api.derivationParams();
          if (paramResult.success && paramResult.params) {
            derivationParams = paramResult.params;
            await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
          }
        } catch (e) {
          if (e.code === 'AUTH_REQUIRED' || e.code === 'AUTH_HEADER_MISSING') {
            // Token expired/revoked — must login again
            await invoke('clear_derivation_params');
            document.getElementById('loginErr').textContent = 'Trusted PC session expired. Please sign in again.';
            showAuth('viewLogin');
            return;
          }
          // Network error — show server connection problem, not login
          showServerError(Api.serverUrl || state.server_url, e.message);
          return;
        }
      }

      // If still no derivation params and no network, allow offline if cache exists
      if (!derivationParams) {
        showServerError(Api.serverUrl || state.server_url, 'Cannot load vault parameters. Server may be offline.');
        return;
      }

      if (state.locked) { showAuth('viewUnlock'); return; }
      showAuth('viewMain');
      await loadVault();
    } catch (e) { showAuth('viewWelcome'); }
  }

  // ===== Connect =====
  document.getElementById('btnConnect').addEventListener('click', async () => {
    const url = document.getElementById('welcomeUrl').value.trim();
    if (!url) return;
    const serverUrl = Api.normalizeServerUrl(url);
    await invoke('set_server_url', { url: serverUrl });
    Api.setServerUrl(serverUrl);
    // Show server info on login screen
    const infoEl = document.getElementById('loginServerInfo');
    if (infoEl) { try { infoEl.textContent = 'Server: ' + new URL(serverUrl).host; } catch { infoEl.textContent = 'Server: ' + serverUrl; } }
    showAuth('viewLogin');
  });

  // ===== Login =====
  document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    const trustPC = document.getElementById('loginTrustPC')?.checked ?? true;
    if (!user || !pass) return;
    document.getElementById('loginErr').textContent = '';
    try {
      const result = await Api.login(user, pass, 'AMPass Desktop on Windows');
      Api.token = result.token;
      await invoke('store_auth_token', { token: result.token });
      derivationParams = result.derivation_params;
      if (trustPC) {
        await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
        // Save user info for display on unlock screen
        const userSummary = { username: result.user?.username || user, email: result.user?.email || '', full_name: result.user?.full_name || '' };
        await invoke('save_user_summary', { userJson: JSON.stringify(userSummary) });
      }
      document.getElementById('loginPass').value = '';
      showAuth('viewUnlock');
    } catch (e) {
      document.getElementById('loginErr').textContent = e.message;
      document.getElementById('loginPass').value = '';
    }
  });
  document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnLogin').click(); });

  // Login: Change Server button
  document.getElementById('btnLoginChangeServer').addEventListener('click', () => {
    showAuth('viewWelcome');
  });

  // ===== Unlock =====
  // Refresh trusted PC info on unlock screen
  async function refreshUnlockInfo() {
    try {
      const userJson = await invoke('load_user_summary');
      const state = await invoke('get_app_state');
      const infoEl = document.getElementById('unlockTrustInfo');
      if (!infoEl) return;
      let parts = [];
      if (userJson) {
        const user = JSON.parse(userJson);
        parts.push('Trusted PC: ' + (user.username || user.email || ''));
      }
      if (state.server_url) {
        try { parts.push('Server: ' + new URL(state.server_url).host); } catch { parts.push('Server: ' + state.server_url); }
      }
      if (parts.length > 0) infoEl.textContent = parts.join(' \u2022 ');
    } catch {}
  }
  // Show info on initial load
  refreshUnlockInfo();

  document.getElementById('btnUnlock').addEventListener('click', async () => {
    const pass = document.getElementById('unlockPass').value;
    if (!pass) return;
    document.getElementById('unlockErr').textContent = '';
    try {
      if (!derivationParams) {
        Api.token = (await invoke('get_auth_token')) || '';
        throw new Error('Session expired. Please login again.');
      }
      // Check if vault needs initialization
      if (derivationParams.needs_setup || derivationParams.key_iterations === 0 || derivationParams.encrypted_vault_key === 'VAULT_NOT_INITIALIZED') {
        await initializeVault(pass);
      } else {
        vaultKeyHex = await Crypto.unlockVault(pass, derivationParams);
      }
      await invoke('unlock_vault', { vaultKeyHex });
      // Derive search key from vault key for HMAC hashing
      searchKey = await Crypto.deriveSearchKey(vaultKeyHex);
      document.getElementById('unlockPass').value = '';
      showAuth('viewMain');
      await loadVault();
    } catch (e) {
      document.getElementById('unlockErr').textContent = e.message || 'Invalid master password';
      document.getElementById('unlockPass').value = '';
    }
  });
  document.getElementById('unlockPass').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnUnlock').click(); });

  // Unlock screen: Sign Out
  document.getElementById('btnUnlockSignOut').addEventListener('click', async () => {
    await invoke('clear_trusted_pc');
    Api.token = '';
    derivationParams = null;
    showAuth('viewLogin');
  });

  // Unlock screen: Change Server
  document.getElementById('btnUnlockChangeServer').addEventListener('click', () => {
    showAuth('viewWelcome');
  });

  async function initializeVault(masterPassword) {
    const vaultKeyRaw = Crypto.bufToHex(crypto.getRandomValues(new Uint8Array(32)));
    const salt = Crypto.bufToHex(crypto.getRandomValues(new Uint8Array(32)));
    const iterations = 100000;
    const wrappingKey = await Crypto.deriveKey(masterPassword, salt, iterations);
    const encrypted = await Crypto.encrypt(vaultKeyRaw, wrappingKey);
    await Api.request('vault/init-key', { body: { encryption_salt: salt, encrypted_vault_key: encrypted.ciphertext, vault_key_iv: encrypted.iv, key_iterations: iterations } });
    derivationParams = { encryption_salt: salt, encrypted_vault_key: encrypted.ciphertext, vault_key_iv: encrypted.iv, key_iterations: iterations, needs_setup: false };
    await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
    vaultKeyHex = vaultKeyRaw;
  }

  // ===== Load Vault =====
  async function loadVault() {
    try {
      const result = await Api.listVault();
      vaultItems = result.items || [];
      await invoke('save_vault_cache', { encryptedItemsJson: JSON.stringify(vaultItems) });
    } catch (e) {
      const cached = await invoke('load_vault_cache');
      if (cached) { vaultItems = JSON.parse(cached); toast('Offline — cached data'); }
    }
    await decryptAll();
    renderQuickAccess();
    renderWebAccounts();
    renderAppAccounts();
    renderRemoteDesktop();
    renderIdentities();
    renderMemos();
    await renderBookmarks();
    await renderSharing();
    updateSyncTime();
    await invoke('record_activity');
  }

  async function decryptAll() {
    allDecrypted = [];
    for (const item of vaultItems) {
      try {
        const dec = await Crypto.decryptItem(item.encrypted_data, item.encryption_iv, vaultKeyHex);
        allDecrypted.push({ ...dec, _id: item.id, _type: item.item_type, _fav: item.is_favorite, _weak: item.is_weak, _used: item.last_used_at });
      } catch { allDecrypted.push({ title: '[Decrypt Error]', _id: item.id, _type: item.item_type }); }
    }
  }

  // ===== Render Functions =====
  function renderQuickAccess() {
    document.getElementById('statTotal').textContent = allDecrypted.length;
    document.getElementById('statFavorites').textContent = allDecrypted.filter(i => i._fav).length;
    document.getElementById('statWeak').textContent = allDecrypted.filter(i => i._weak).length;
    const score = allDecrypted.length > 0 ? Math.max(0, 100 - Math.round(allDecrypted.filter(i => i._weak).length / allDecrypted.length * 100)) : '—';
    document.getElementById('statScore').textContent = score + (typeof score === 'number' ? '%' : '');
    document.getElementById('secScore').textContent = score + (typeof score === 'number' ? '%' : '');
    document.getElementById('secWeak').textContent = allDecrypted.filter(i => i._weak).length;
    document.getElementById('secReused').textContent = '0';

    const recent = [...allDecrypted].filter(i => i._used).sort((a, b) => (b._used || '').localeCompare(a._used || '')).slice(0, 5);
    document.getElementById('recentList').innerHTML = recent.length ? recent.map(i => itemRow(i)).join('') : '<p class="empty-hint">No recently used items</p>';
    const favs = allDecrypted.filter(i => i._fav).slice(0, 5);
    document.getElementById('favoritesList').innerHTML = favs.length ? favs.map(i => itemRow(i)).join('') : '<p class="empty-hint">No favorites yet</p>';
  }

  function renderWebAccounts() {
    const items = allDecrypted.filter(i => i._type === 'login');
    document.getElementById('webAccountsList').innerHTML = items.length ? items.map(i => itemRow(i)).join('') : '<p class="empty-hint">No web accounts</p>';
  }

  function renderAppAccounts() {
    const items = allDecrypted.filter(i => i._type === 'app_account');
    document.getElementById('appAccountsList').innerHTML = items.length ? items.map(i => appAccountRow(i)).join('') : '<p class="empty-hint">No app accounts. Add accounts for desktop applications like Outlook, Zoom, Teams.</p>';
  }

  function renderRemoteDesktop() {
    const items = allDecrypted.filter(i => i._type === 'remote_desktop');
    document.getElementById('remoteDesktopList').innerHTML = items.length ? items.map(i => rdpRow(i)).join('') : '<p class="empty-hint">No remote desktop accounts. Add RDP, VNC, or other remote connections.</p>';
  }

  function renderIdentities() {
    const items = allDecrypted.filter(i => i._type === 'identity');
    document.getElementById('identitiesList').innerHTML = items.length ? items.map(i => itemRow(i)).join('') : '<p class="empty-hint">No identities</p>';
  }

  function renderMemos() {
    const items = allDecrypted.filter(i => i._type === 'secure_note');
    document.getElementById('memosList').innerHTML = items.length ? items.map(i => itemRow(i)).join('') : '<p class="empty-hint">No secure memos</p>';
  }

  function renderBookmarks() {
    // Bookmarks: vault items tagged as bookmarks OR items of type 'login' pinned as favorites
    const items = allDecrypted.filter(i => i._fav && i._type === 'login');
    const el = document.getElementById('bookmarksList');
    if (!el) return;
    el.innerHTML = items.length
      ? items.map(i => `<div class="item-row" data-id="${i._id}">
          <div class="item-icon">🔖</div>
          <div class="item-info">
            <span class="item-title">${esc(i.title || 'Untitled')}</span>
            <span class="item-sub">${esc(i.username || i.url || '')}</span>
          </div>
          <div class="item-actions">
            <button class="btn-ghost-sm" data-copy-user="${i._id}" title="Copy username">👤</button>
            <button class="btn-ghost-sm" data-copy-pass="${i._id}" title="Copy password">📋</button>
            ${i.url ? `<button class="btn-ghost-sm" onclick="window.__TAURI__?.shell?.open('${esc(i.url)}')" title="Open URL">🌐</button>` : ''}
          </div>
        </div>`).join('')
      : '<p class="empty-hint">No bookmarks yet. Mark a Web Account as ⭐ Favorite to pin it here.</p>';
  }

  async function renderSharing() {
    const el = document.getElementById('sharingList');
    if (!el) return;
    // Try to fetch shared items from server API
    try {
      const result = await Api.shareList();
      const received = (result.received || []);
      const sent = (result.sent || []);
      let html = '';
      if (received.length === 0 && sent.length === 0) {
        el.innerHTML = '<p class="empty-hint">No shared credentials. Use the web vault to share items with other AMPass users.</p>';
        return;
      }
      if (received.length > 0) {
        html += '<h3 class="section-title">Received</h3>';
        html += received.map(s => `<div class="item-row">
          <div class="item-icon">📨</div>
          <div class="item-info">
            <span class="item-title">${esc(s.title || 'Shared Item')}</span>
            <span class="item-sub">From: ${esc(s.shared_by || 'Unknown')} &bull; ${esc(s.status || 'pending')}</span>
          </div>
        </div>`).join('');
      }
      if (sent.length > 0) {
        html += '<h3 class="section-title">Sent</h3>';
        html += sent.map(s => `<div class="item-row">
          <div class="item-icon">📤</div>
          <div class="item-info">
            <span class="item-title">${esc(s.title || 'Shared Item')}</span>
            <span class="item-sub">To: ${esc(s.shared_with || 'Unknown')} &bull; ${esc(s.status || 'pending')}</span>
          </div>
        </div>`).join('');
      }
      el.innerHTML = html;
    } catch {
      el.innerHTML = '<p class="empty-hint">Sharing data unavailable offline.</p>';
    }
  }

  function appAccountRow(item) {
    const appName = item.application_name || item.title || 'Unknown App';
    const login = item.username || item.login_hint || '';
    const exePath = item.executable_path || '';
    return `<div class="item-row" data-id="${item._id}">
      <div class="item-icon">💻</div>
      <div class="item-info">
        <span class="item-title">${esc(appName)}</span>
        <span class="item-sub">${esc(login)}${exePath ? ' — ' + esc(exePath.split('\\\\').pop().split('/').pop()) : ''}</span>
      </div>
      <div class="item-actions">
        <button class="btn-ghost-sm" title="Launch App" onclick="launchApp(${item._id})">🚀</button>
        <button class="btn-ghost-sm" title="Copy Username" onclick="copyField(${item._id},'username')">👤</button>
        <button class="btn-ghost-sm" title="Copy Password" onclick="copyField(${item._id},'password')">🔑</button>
      </div>
    </div>`;
  }

  function rdpRow(item) {
    const name = item.title || item.connection_name || 'RDP Connection';
    const host = item.host || '';
    const login = item.username || '';
    const protocol = (item.protocol || 'rdp').toUpperCase();
    return `<div class="item-row" data-id="${item._id}">
      <div class="item-icon">🖥️</div>
      <div class="item-info">
        <span class="item-title">${esc(name)}</span>
        <span class="item-sub">${esc(host)} — ${esc(login)} (${protocol})</span>
      </div>
      <div class="item-actions">
        <button class="btn-ghost-sm" title="Open RDP" onclick="openRdp(${item._id})">🔗</button>
        <button class="btn-ghost-sm" title="Copy Host" onclick="copyField(${item._id},'host')">🌐</button>
        <button class="btn-ghost-sm" title="Copy Username" onclick="copyField(${item._id},'username')">👤</button>
        <button class="btn-ghost-sm" title="Copy Password" onclick="copyField(${item._id},'password')">🔑</button>
      </div>
    </div>`;
  }

  function itemRow(item) {
    let icon = item._type === 'login' ? '🌐' : item._type === 'identity' ? '👤' : item._type === 'secure_note' ? '📝' : '📦';
    if (item._type === 'login' && item.url) {
      const domain = extractDomain(item.url);
      if (domain) {
        icon = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${domain}" alt="" style="width:20px; height:20px; border-radius:4px; object-fit:contain; display:block;" onerror="this.outerHTML='🌐'">`;
      }
    }
    let subtitle = item.username || item.email || '';
    if (item.url) {
      subtitle = subtitle ? subtitle + ' • ' + item.url : item.url;
    }
    return `<div class="item-row" data-id="${item._id}">
      <div class="item-icon">${icon}</div>
      <div class="item-info"><div class="item-title">${esc(item.title || 'Untitled')}</div><div class="item-sub">${esc(subtitle || '')}</div></div>
      <div class="item-actions"><button class="btn-ghost-sm" data-copy-user="${item._id}" title="Copy username">👤</button><button class="btn-ghost-sm" data-copy-pass="${item._id}" title="Copy password">📋</button></div>
    </div>`;
  }

  // ===== Item Actions =====
  document.addEventListener('click', async (e) => {
    const copyUser = e.target.closest('[data-copy-user]');
    if (copyUser) { e.stopPropagation(); await copyField(parseInt(copyUser.dataset.copyUser), 'username'); return; }
    const copyPass = e.target.closest('[data-copy-pass]');
    if (copyPass) { e.stopPropagation(); await copyField(parseInt(copyPass.dataset.copyPass), 'password'); return; }
    const row = e.target.closest('.item-row');
    if (row) { showItemDetail(parseInt(row.dataset.id)); return; }
    const addBtn = e.target.closest('[data-add]');
    if (addBtn) { showAddModal(addBtn.dataset.add); return; }
  });

  async function copyField(id, field) {
    const item = allDecrypted.find(i => i._id === id);
    if (!item || !item[field]) { toast('Nothing to copy'); return; }
    await navigator.clipboard.writeText(item[field]);
    toast(field === 'password' ? 'Password copied (clears in 30s)' : 'Copied!');
    if (field === 'password') setTimeout(async () => { try { const c = await navigator.clipboard.readText(); if (c === item[field]) await navigator.clipboard.writeText(''); } catch {} }, 30000);
    // Log usage
    try { await Api.usageLog(id, 'copied_' + field, 'desktop'); } catch {}
  }

  // Make copyField available globally for inline onclick handlers
  window.copyField = copyField;

  /**
   * Launch a desktop application.
   * SECURITY: Never passes password as command-line argument.
   */
  async function launchApp(id) {
    const item = allDecrypted.find(i => i._id === id);
    if (!item) { toast('Item not found'); return; }
    const exePath = item.executable_path || item.launch_command || '';
    if (!exePath) { toast('No executable path configured'); return; }
    try {
      await invoke('launch_application', { path: exePath });
      toast('App launched: ' + (item.application_name || item.title));
      try { await Api.usageLog(id, 'launched_app', 'desktop'); } catch {}
    } catch (e) {
      toast('Launch failed: ' + e.message);
      try { await Api.usageLog(id, 'app_launch_failed', 'desktop'); } catch {}
    }
  }
  window.launchApp = launchApp;

  /**
   * Open Remote Desktop connection.
   * Creates temporary .rdp file WITHOUT password, launches mstsc.
   * SECURITY: Password is never written to .rdp file. User must paste manually.
   */
  async function openRdp(id) {
    const item = allDecrypted.find(i => i._id === id);
    if (!item) { toast('Item not found'); return; }
    const host = item.host || '';
    const port = item.port || 3389;
    const username = item.username || '';
    const domain = item.domain || '';
    if (!host) { toast('No host configured'); return; }
    try {
      const fullUser = domain ? domain + '\\' + username : username;
      await invoke('open_rdp_connection', { host, port, username: fullUser, redirectClipboard: true });
      toast('RDP launched — paste password when prompted');
      try { await Api.usageLog(id, 'opened_rdp', 'desktop'); } catch {}
    } catch (e) {
      toast('RDP launch failed: ' + e.message);
      try { await Api.usageLog(id, 'rdp_open_failed', 'desktop'); } catch {}
    }
  }
  window.openRdp = openRdp;

  function showItemDetail(id) {
    const item = allDecrypted.find(i => i._id === id);
    if (!item) return;
    document.getElementById('modalTitle').textContent = item.title || 'Item Details';
    let html = '';
    if (item.url) html += `<div class="field-label">URL</div><div class="field-input" style="margin-bottom:8px;">${esc(item.url)}</div>`;
    if (item.username) html += `<div class="field-label">Username</div><div class="field-input" style="margin-bottom:8px;">${esc(item.username)}</div>`;
    if (item.password) html += `<div class="field-label">Password</div><div class="field-input" style="margin-bottom:8px;">••••••••</div>`;
    if (item.notes) html += `<div class="field-label">Notes</div><div class="field-input" style="margin-bottom:8px;white-space:pre-wrap;">${esc(item.notes)}</div>`;
    document.getElementById('modalBody').innerHTML = html || '<p class="empty-hint">No details</p>';
    document.getElementById('modalFooter').innerHTML = `<button class="btn-ghost-sm" onclick="document.getElementById('itemModal').style.display='none'">Close</button>`;
    document.getElementById('itemModal').style.display = 'flex';
  }

  function showAddModal(type) {
    const titles = { login: 'Add Web Account', identity: 'Add Identity', secure_note: 'Add Secure Memo', app_account: 'Add App Account', remote_desktop: 'Add Remote Desktop' };
    document.getElementById('modalTitle').textContent = titles[type] || 'Add Item';
    let html = '<div class="auth-form">';
    html += '<label class="field-label">Title</label><input type="text" id="addTitle" class="field-input">';
    if (type === 'login') {
      html += '<label class="field-label">URL</label><input type="url" id="addUrl" class="field-input">';
      html += '<label class="field-label">Username</label><input type="text" id="addUser" class="field-input">';
      html += '<label class="field-label">Password</label><input type="password" id="addPass" class="field-input">';
    } else if (type === 'app_account') {
      html += '<label class="field-label">Application Name</label><input type="text" id="addAppName" class="field-input" placeholder="e.g. Microsoft Outlook">';
      html += '<label class="field-label">Executable Path</label><div style="display:flex;gap:4px;"><input type="text" id="addExePath" class="field-input" placeholder="C:\\Program Files\\...\\app.exe" style="flex:1;"><button class="btn-ghost-sm" id="btnBrowseExe" title="Browse">📂</button></div>';
      html += '<label class="field-label">Username / Login</label><input type="text" id="addUser" class="field-input">';
      html += '<label class="field-label">Password</label><input type="password" id="addPass" class="field-input">';
      html += '<label class="field-label">Website (optional)</label><input type="url" id="addUrl" class="field-input">';
    } else if (type === 'remote_desktop') {
      html += '<label class="field-label">Host / IP</label><input type="text" id="addHost" class="field-input" placeholder="192.168.1.10">';
      html += '<label class="field-label">Port</label><input type="number" id="addPort" class="field-input" value="3389">';
      html += '<label class="field-label">Protocol</label><select id="addProtocol" class="field-input"><option value="rdp">RDP</option><option value="vnc">VNC</option><option value="ssh">SSH</option></select>';
      html += '<label class="field-label">Domain (optional)</label><input type="text" id="addDomain" class="field-input">';
      html += '<label class="field-label">Username</label><input type="text" id="addUser" class="field-input">';
      html += '<label class="field-label">Password</label><input type="password" id="addPass" class="field-input">';
      html += '<label class="field-label">Gateway (optional)</label><input type="text" id="addGateway" class="field-input">';
    }
    html += '<label class="field-label">Notes</label><textarea id="addNotes" class="field-input" rows="3"></textarea>';
    html += '</div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFooter').innerHTML = `<button class="btn-ghost-sm" onclick="document.getElementById('itemModal').style.display='none'">Cancel</button><button class="btn-primary" style="width:auto;margin:0;padding:8px 16px;" id="btnSaveNew">Save</button>`;
    document.getElementById('itemModal').style.display = 'flex';
    document.getElementById('btnSaveNew').addEventListener('click', () => saveNewItem(type));
    // Browse exe button
    const browseBtn = document.getElementById('btnBrowseExe');
    if (browseBtn) browseBtn.addEventListener('click', async () => {
      try { const path = await invoke('pick_executable'); if (path) document.getElementById('addExePath').value = path; } catch {}
    });
  }

  async function saveNewItem(type) {
    const data = { title: document.getElementById('addTitle')?.value || '', notes: document.getElementById('addNotes')?.value || '' };
    if (type === 'login') {
      data.url = document.getElementById('addUrl')?.value || '';
      data.username = document.getElementById('addUser')?.value || '';
      data.password = document.getElementById('addPass')?.value || '';
    } else if (type === 'app_account') {
      data.application_name = document.getElementById('addAppName')?.value || data.title;
      data.executable_path = document.getElementById('addExePath')?.value || '';
      data.username = document.getElementById('addUser')?.value || '';
      data.password = document.getElementById('addPass')?.value || '';
      data.website = document.getElementById('addUrl')?.value || '';
    } else if (type === 'remote_desktop') {
      data.host = document.getElementById('addHost')?.value || '';
      data.port = parseInt(document.getElementById('addPort')?.value || '3389');
      data.protocol = document.getElementById('addProtocol')?.value || 'rdp';
      data.domain = document.getElementById('addDomain')?.value || '';
      data.username = document.getElementById('addUser')?.value || '';
      data.password = document.getElementById('addPass')?.value || '';
      data.gateway = document.getElementById('addGateway')?.value || '';
    }
    if (!data.title) { toast('Title is required'); return; }
    try {
      const encrypted = await Crypto.encryptItem(data, vaultKeyHex);
      const urlHash = data.url ? await Crypto.computeSearchHash(data.url, searchKey) : null;
      const titleHash = await Crypto.computeSearchHash(data.title, searchKey);
      const hostHash = data.host ? await Crypto.computeSearchHash(data.host, searchKey) : null;
      await Api.saveItem({ item_type: type, encrypted_data: encrypted.ciphertext, encryption_iv: encrypted.iv, url_hash: urlHash, title_hash: titleHash, host_hash: hostHash, password_strength: Crypto.strength(data.password || ''), is_weak: Crypto.strength(data.password || '') < 40 ? 1 : 0 });
      document.getElementById('itemModal').style.display = 'none';
      toast('Item saved!');
      await loadVault();
    } catch (e) { toast('Save failed: ' + e.message); }
  }

  // ===== Navigation =====
  document.getElementById('sidebarNav').addEventListener('click', (e) => {
    const link = e.target.closest('.nav-link');
    if (link) { e.preventDefault(); showPage(link.dataset.page); }
  });

  // ===== Search =====
  document.getElementById('searchInput').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) { renderQuickAccess(); renderWebAccounts(); renderAppAccounts(); renderRemoteDesktop(); renderIdentities(); renderMemos(); return; }
    const filtered = allDecrypted.filter(i =>
      (i.title||'').toLowerCase().includes(q) ||
      (i.username||'').toLowerCase().includes(q) ||
      (i.url||'').toLowerCase().includes(q) ||
      (i.application_name||'').toLowerCase().includes(q) ||
      (i.host||'').toLowerCase().includes(q) ||
      (i.connection_name||'').toLowerCase().includes(q)
    );
    document.getElementById('webAccountsList').innerHTML = filtered.filter(i => i._type === 'login').map(i => itemRow(i)).join('') || '<p class="empty-hint">No results</p>';
    document.getElementById('appAccountsList').innerHTML = filtered.filter(i => i._type === 'app_account').map(i => appAccountRow(i)).join('') || '';
    document.getElementById('remoteDesktopList').innerHTML = filtered.filter(i => i._type === 'remote_desktop').map(i => rdpRow(i)).join('') || '';
    showPage('webAccounts');
  });

  // ===== Lock =====
  document.getElementById('btnLockVault').addEventListener('click', async () => { vaultKeyHex = null; searchKey = null; allDecrypted = []; await invoke('lock_vault'); showAuth('viewUnlock'); });

  // ===== Sync =====
  document.getElementById('btnSyncNow').addEventListener('click', loadVault);
  function updateSyncTime() { document.getElementById('syncTime').textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); }

  // ===== Generator =====
  function genPw() {
    const pw = Crypto.generatePassword({ length: parseInt(document.getElementById('genLen').value), uppercase: document.getElementById('genUpper').checked, lowercase: document.getElementById('genLower').checked, numbers: document.getElementById('genNums').checked, symbols: document.getElementById('genSyms').checked });
    document.getElementById('genPw').value = pw;
    const s = Crypto.strength(pw);
    const fill = document.getElementById('genStrFill');
    fill.style.width = s + '%';
    fill.style.background = s >= 80 ? '#16a34a' : s >= 60 ? '#84cc16' : s >= 40 ? '#d97706' : '#dc2626';
  }
  document.getElementById('btnRegenerate').addEventListener('click', genPw);
  document.getElementById('genLen').addEventListener('input', (e) => { document.getElementById('genLenVal').textContent = e.target.value; genPw(); });
  document.getElementById('btnCopyGen').addEventListener('click', async () => { await navigator.clipboard.writeText(document.getElementById('genPw').value); toast('Copied!'); });
  // Save generated password as a new vault item
  document.getElementById('btnSaveGenerated').addEventListener('click', () => {
    const pw = document.getElementById('genPw').value;
    if (!pw) { genPw(); }
    // Open add modal pre-filled with generated password
    showAddModal('login');
    // Pre-fill password field after modal renders
    setTimeout(() => {
      const passField = document.getElementById('addPass');
      if (passField) passField.value = document.getElementById('genPw').value;
    }, 50);
  });

  // ===== Settings =====

  // Load persisted settings on startup
  async function loadSettings() {
    try {
      const raw = await invoke('load_derivation_params'); // reuse secure config slot
      // Use a dedicated settings key via save_config instead
      const stored = await storage_load_settings();
      if (stored) {
        appSettings = { ...appSettings, ...stored };
        const lockEl = document.getElementById('setLockMin');
        const clipEl = document.getElementById('setClipSec');
        if (lockEl) lockEl.value = appSettings.lockTimeoutMin;
        if (clipEl) clipEl.value = appSettings.clipboardClearSec;
      }
    } catch {}
  }

  async function storage_load_settings() {
    try {
      const val = await invoke('load_derivation_params'); // placeholder — use local storage workaround
      const ls = localStorage.getItem('ampass_settings');
      return ls ? JSON.parse(ls) : null;
    } catch { return null; }
  }

  function saveSettings() {
    appSettings.lockTimeoutMin = parseInt(document.getElementById('setLockMin')?.value || '15');
    appSettings.clipboardClearSec = parseInt(document.getElementById('setClipSec')?.value || '30');
    localStorage.setItem('ampass_settings', JSON.stringify(appSettings));
    toast('Settings saved');
  }

  document.getElementById('setLockMin')?.addEventListener('change', saveSettings);
  document.getElementById('setClipSec')?.addEventListener('change', saveSettings);

  // Show server URL in settings
  async function refreshSettingsUrl() {
    const state = await invoke('get_app_state').catch(() => ({}));
    const el = document.getElementById('settingUrl');
    if (el && state.server_url) el.textContent = state.server_url;
  }

  document.getElementById('btnLogout').addEventListener('click', async () => { try { await Api.logout(); } catch {} await invoke('logout'); await invoke('clear_derivation_params'); vaultKeyHex = null; searchKey = null; allDecrypted = []; derivationParams = null; Api.token = ''; showAuth('viewLogin'); });
  document.getElementById('btnWipeCache').addEventListener('click', async () => { if (!confirm('Wipe all local data?')) return; await invoke('wipe_local_data'); vaultKeyHex = null; searchKey = null; allDecrypted = []; derivationParams = null; showAuth('viewWelcome'); });
  document.getElementById('btnExportBackup').addEventListener('click', async () => { const data = JSON.stringify({ version: '1.0', exported_at: new Date().toISOString(), items: vaultItems }); await invoke('pick_save_location', { data }); toast('Backup exported'); });

  // Load settings and server URL on startup
  loadSettings();
  refreshSettingsUrl();

  // ===== Tauri Events =====
  listen('tray-lock', async () => { vaultKeyHex = null; searchKey = null; allDecrypted = []; await invoke('lock_vault'); await refreshUnlockInfo(); showAuth('viewUnlock'); });
  listen('auto-locked', () => { vaultKeyHex = null; searchKey = null; allDecrypted = []; refreshUnlockInfo(); showAuth('viewUnlock'); });
  listen('show-unlock-from-browser', (event) => {
    // Browser extension requested unlock via native messaging
    if (vaultKeyHex) {
      // Already unlocked — just show main window
      showAuth('viewMain');
    } else {
      // Locked — show unlock screen
      refreshUnlockInfo();
      showAuth('viewUnlock');
      // Focus the password input
      setTimeout(() => document.getElementById('unlockPass')?.focus(), 100);
    }
  });

  // ===== Helpers =====
  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.style.display = 'block'; setTimeout(() => t.style.display = 'none', 3000); }

  // ===== Modal close =====
  document.getElementById('modalClose').addEventListener('click', () => document.getElementById('itemModal').style.display = 'none');

  // ===== Background sync =====
  setInterval(async () => { if (vaultKeyHex) { await invoke('record_activity'); await loadVault(); } }, 300000);

  // ===== Import Data Module =====
  (function setupImport() {
    const importSource = document.getElementById('importSource');
    const btnFile = document.getElementById('btnImportFile');
    const fileName = document.getElementById('importFileName');
    const previewArea = document.getElementById('importPreviewArea');
    const previewCount = document.getElementById('importPreviewCount');
    const previewBody = document.getElementById('importPreviewBody');
    const checkAll = document.getElementById('importCheckAll');
    const btnStart = document.getElementById('btnImportStart');
    const btnCancel = document.getElementById('btnImportCancel');
    const progressArea = document.getElementById('importProgressArea');
    const progressBar = document.getElementById('importProgressBar');
    const progressText = document.getElementById('importProgressText');
    const resultArea = document.getElementById('importResultArea');
    const resultContent = document.getElementById('importResultContent');
    const btnSelectAll = document.getElementById('btnImportSelectAll');
    const btnUnselectAll = document.getElementById('btnImportUnselectAll');

    if (!importSource) return; // Page not loaded yet

    let parsedItems = [];
    let selectedSource = '';

    importSource.addEventListener('change', () => {
      selectedSource = importSource.value;
      btnFile.disabled = !selectedSource;
      fileName.textContent = '';
      parsedItems = [];
      previewArea.style.display = 'none';
      resultArea.style.display = 'none';
    });

    btnFile.addEventListener('click', async () => {
      if (!selectedSource) return;
      const filters = selectedSource === 'sticky_password'
        ? [{ name: 'Text files', extensions: ['txt'] }]
        : [{ name: 'CSV files', extensions: ['csv'] }];

      let filePath;
      try {
        const dialog = window.__TAURI__.dialog;
        if (dialog && dialog.open) {
          filePath = await dialog.open({ filters, multiple: false });
        } else {
          // Fallback for Tauri v2
          filePath = await invoke('pick_file', { filters: selectedSource === 'sticky_password' ? 'txt' : 'csv' });
        }
      } catch (e) {
        // Try Tauri v2 plugin import
        try {
          const { open } = await import('@tauri-apps/plugin-dialog');
          filePath = await open({ filters, multiple: false });
        } catch {
          toast('File picker not available');
          return;
        }
      }

      if (!filePath) return;
      const name = typeof filePath === 'string' ? filePath.split(/[\\/]/).pop() : filePath.name || 'file';
      fileName.textContent = name;

      // Read file contents
      let text;
      try {
        const fs = window.__TAURI__.fs;
        if (fs && fs.readTextFile) {
          text = await fs.readTextFile(filePath);
        } else {
          text = await invoke('read_text_file', { path: filePath });
        }
      } catch (e) {
        try {
          const { readTextFile } = await import('@tauri-apps/plugin-fs');
          text = await readTextFile(filePath);
        } catch {
          toast('Could not read file: ' + (e.message || e));
          return;
        }
      }

      // Parse
      try {
        if (selectedSource === 'sticky_password') {
          parsedItems = parseStickyPasswordTxt(text);
        } else if (selectedSource === 'lastpass') {
          parsedItems = parsePasswordCsv(text, ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping']);
        } else if (selectedSource === 'bitwarden') {
          parsedItems = parsePasswordCsv(text, ['name', 'login_uri', 'login_username', 'login_password', 'notes', 'type', 'folder']);
        } else if (selectedSource === '1password') {
          parsedItems = parsePasswordCsv(text, ['title', 'url', 'username', 'password', 'notes']);
        } else {
          parsedItems = parsePasswordCsv(text, ['name', 'url', 'username', 'password']);
        }
        renderPreview();
      } catch (e) {
        toast('Parse error: ' + e.message);
      }
    });

    function renderPreview() {
      previewCount.textContent = parsedItems.length;
      previewBody.innerHTML = parsedItems.map((it, i) => `<tr>
        <td><input type="checkbox" class="import-check" data-idx="${i}" ${it._selected ? 'checked' : ''}></td>
        <td>${esc(it.title)}</td>
        <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(it.url)}">${esc(it.url)}</td>
        <td>${esc(it.username)}</td>
        <td>••••••</td>
      </tr>`).join('');
      previewArea.style.display = 'block';
      btnStart.disabled = parsedItems.filter(i => i._selected).length === 0;
    }

    previewBody.addEventListener('change', (e) => {
      if (e.target.classList.contains('import-check')) {
        const idx = parseInt(e.target.dataset.idx);
        if (parsedItems[idx]) parsedItems[idx]._selected = e.target.checked;
        btnStart.disabled = parsedItems.filter(i => i._selected).length === 0;
      }
    });

    checkAll.addEventListener('change', () => {
      parsedItems.forEach(i => i._selected = checkAll.checked);
      previewBody.querySelectorAll('.import-check').forEach(cb => cb.checked = checkAll.checked);
      btnStart.disabled = !checkAll.checked;
    });

    btnSelectAll.addEventListener('click', () => { checkAll.checked = true; checkAll.dispatchEvent(new Event('change')); });
    btnUnselectAll.addEventListener('click', () => { checkAll.checked = false; checkAll.dispatchEvent(new Event('change')); });

    btnCancel.addEventListener('click', () => {
      parsedItems = [];
      previewArea.style.display = 'none';
      fileName.textContent = '';
    });

    btnStart.addEventListener('click', async () => {
      const selected = parsedItems.filter(i => i._selected);
      if (selected.length === 0) return;
      if (!vaultKeyHex) { toast('Vault is locked'); return; }

      btnStart.disabled = true;
      progressArea.style.display = 'block';
      resultArea.style.display = 'none';

      const BATCH = 50;
      let imported = 0, failed = 0, skipped = 0;

      for (let i = 0; i < selected.length; i += BATCH) {
        const batch = selected.slice(i, i + BATCH);
        const encBatch = [];

        for (const item of batch) {
          try {
            const plainData = { title: item.title, url: item.url, username: item.username, password: item.password, notes: item.notes || '' };
            const enc = await DesktopCrypto.encryptItem(JSON.stringify(plainData), vaultKeyHex);
            const titleHash = searchKey ? await DesktopCrypto.hmacHash(item.title || '', searchKey) : null;
            const urlHash = (searchKey && item.url) ? await DesktopCrypto.hmacHash(extractDomain(item.url), searchKey) : null;
            const strength = estimateStrength(item.password);

            encBatch.push({
              encrypted_data: enc.ciphertext,
              encryption_iv: enc.iv,
              item_type: 'login',
              title_hash: titleHash,
              url_hash: urlHash,
              password_strength: strength,
              is_weak: strength < 40 ? 1 : 0
            });
          } catch (e) {
            failed++;
          }
        }

        if (encBatch.length > 0) {
          try {
            const res = await Api.post('/api/vault/import-bulk', { items: encBatch, source: selectedSource });
            if (res.imported) imported += res.imported;
            if (res.skipped) skipped += res.skipped;
            if (res.failed) failed += res.failed;
          } catch (e) {
            failed += encBatch.length;
          }
        }

        const pct = Math.round(((i + batch.length) / selected.length) * 100);
        progressBar.style.width = pct + '%';
        progressText.textContent = `Importing... ${Math.min(i + batch.length, selected.length)}/${selected.length}`;
      }

      progressArea.style.display = 'none';
      resultArea.style.display = 'block';
      resultContent.innerHTML = `
        <div style="text-align:center;">
          <div style="font-size:1.8rem;margin-bottom:6px;">${imported > 0 ? '✅' : '❌'}</div>
          <h3 style="margin:0 0 8px;">Import Complete</h3>
          <div style="display:flex;gap:16px;justify-content:center;font-size:0.85rem;">
            <div><strong style="color:#22c55e;">${imported}</strong> Imported</div>
            <div><strong style="color:#eab308;">${skipped}</strong> Skipped</div>
            <div><strong style="color:#ef4444;">${failed}</strong> Failed</div>
          </div>
        </div>
      `;

      if (imported > 0) {
        await loadVault(); // Refresh vault items
        toast(`Imported ${imported} items`);
      }
    });

    // ===== Parsers =====
    function parseStickyPasswordTxt(text) {
      if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
      const lines = text.split(/\r?\n/);
      const items = [];
      let currentGroup = '';
      let currentEntry = null;

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('---')) { if (currentEntry && currentEntry.password) items.push(currentEntry); currentEntry = null; continue; }
        if (!line.startsWith(' ') && !line.startsWith('\t') && !trimmed.includes(':')) {
          if (currentEntry && currentEntry.password) items.push(currentEntry);
          currentEntry = null;
          currentGroup = trimmed;
          continue;
        }
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        const key = trimmed.substring(0, colonIdx).trim().toLowerCase();
        const val = trimmed.substring(colonIdx + 1).trim();

        if (['name', 'title', 'description'].includes(key)) {
          currentEntry = currentEntry || { title: '', url: '', username: '', password: '', notes: '', _selected: true, _index: items.length };
          currentEntry.title = val;
        } else if (['web', 'url', 'website', 'link'].includes(key)) {
          currentEntry = currentEntry || { title: '', url: '', username: '', password: '', notes: '', _selected: true, _index: items.length };
          currentEntry.url = val;
          if (!currentEntry.title && val) { try { currentEntry.title = new URL(val).hostname; } catch { currentEntry.title = val; } }
        } else if (['login', 'user', 'username', 'user name', 'email'].includes(key)) {
          currentEntry = currentEntry || { title: '', url: '', username: '', password: '', notes: '', _selected: true, _index: items.length };
          currentEntry.username = val;
        } else if (['password', 'pass'].includes(key)) {
          currentEntry = currentEntry || { title: '', url: '', username: '', password: '', notes: '', _selected: true, _index: items.length };
          currentEntry.password = val;
        } else if (['comment', 'note', 'notes'].includes(key)) {
          if (currentEntry) currentEntry.notes = val;
        }
      }
      if (currentEntry && currentEntry.password) items.push(currentEntry);
      return items;
    }

    function parsePasswordCsv(text, expectedCols) {
      if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
      const rows = parseCsvRows(text);
      if (rows.length < 2) return [];

      const headers = rows[0].map(h => h.toLowerCase().trim());
      const find = (names) => { for (const n of names) { const idx = headers.indexOf(n); if (idx >= 0) return idx; } return -1; };
      const titleCol = find(['title', 'name', 'account']);
      const urlCol = find(['url', 'login_uri', 'web site', 'website', 'urls']);
      const userCol = find(['username', 'login_username', 'user', 'login name', 'login']);
      const passCol = find(['password', 'login_password', 'pass']);
      const noteCol = find(['notes', 'extra', 'comments', 'notesplain']);

      if (passCol === -1) throw new Error('Cannot find password column');

      const items = [];
      for (let i = 1; i < rows.length; i++) {
        const r = rows[i];
        if (r.length < 2) continue;
        const password = r[passCol] || '';
        if (!password) continue;
        const url = urlCol >= 0 ? (r[urlCol] || '') : '';
        let title = titleCol >= 0 ? (r[titleCol] || '') : '';
        if (!title && url) { try { title = new URL(url).hostname; } catch { title = url; } }
        if (!title) title = 'Imported Login';
        // Skip LastPass secure note placeholder
        const cleanUrl = (url === 'http://sn' || url === 'http://') ? '' : url;
        items.push({ title, url: cleanUrl, username: userCol >= 0 ? (r[userCol] || '') : '', password, notes: noteCol >= 0 ? (r[noteCol] || '') : '', _selected: true, _index: items.length });
      }
      return items;
    }

    function parseCsvRows(text) {
      const rows = []; let row = []; let cell = ''; let inQuotes = false;
      for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (inQuotes) {
          if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else { inQuotes = false; } }
          else { cell += ch; }
        } else {
          if (ch === '"') { inQuotes = true; }
          else if (ch === ',') { row.push(cell); cell = ''; }
          else if (ch === '\n' || (ch === '\r' && text[i + 1] === '\n')) { row.push(cell); cell = ''; rows.push(row); row = []; if (ch === '\r') i++; }
          else if (ch === '\r') { row.push(cell); cell = ''; rows.push(row); row = []; }
          else { cell += ch; }
        }
      }
      if (cell || row.length) { row.push(cell); rows.push(row); }
      return rows;
    }

    function extractDomain(url) {
      if (!url) return '';
      let host = url;
      try {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
          url = 'https://' + url;
        }
        host = new URL(url).hostname;
      } catch (e) {
        // Keep as is
      }
      if (host.startsWith('www.')) {
        host = host.substring(4);
      }
      return host;
    }

    function estimateStrength(pw) {
      if (!pw) return 0;
      let score = 0;
      if (pw.length >= 8) score += 20;
      if (pw.length >= 12) score += 15;
      if (pw.length >= 16) score += 10;
      if (/[A-Z]/.test(pw)) score += 15;
      if (/[a-z]/.test(pw)) score += 10;
      if (/[0-9]/.test(pw)) score += 15;
      if (/[^A-Za-z0-9]/.test(pw)) score += 15;
      return Math.min(100, score);
    }
  })();

  // ===== Start =====
  init();
  setTimeout(genPw, 200);
})();
