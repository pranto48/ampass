/**
 * AMPass Desktop — Main Application
 * SECURITY: Vault key in memory only. Cleared on lock/quit.
 */
(function() {
  'use strict';

  // ===== Tauri Compatibility Polyfill for Web/Browser Mode =====
  let invoke = null;
  let listen = null;

  if (window.__TAURI__ && window.__TAURI__.core) {
    invoke = window.__TAURI__.core.invoke;
    listen = window.__TAURI__.event.listen;
  } else {
    // We are in Web Browser mode (e.g. GitHub Pages)
    listen = function(event, callback) {
      // No-op for events
      return () => {};
    };
    
    invoke = async function(cmd, args = {}) {
      switch (cmd) {
        case 'set_server_url':
          localStorage.setItem('server_url', args.url || '');
          return;
        case 'get_app_state':
          const server_url = localStorage.getItem('server_url') || '';
          const token = localStorage.getItem('auth_token') || '';
          return {
            configured: !!server_url,
            server_url: server_url,
            authenticated: !!token,
            locked: true
          };
        case 'store_auth_token':
          localStorage.setItem('auth_token', args.token || '');
          return;
        case 'get_auth_token':
          return localStorage.getItem('auth_token') || '';
        case 'store_derivation_params':
          localStorage.setItem('derivation_params', args.paramsJson || '');
          return;
        case 'load_derivation_params':
          return localStorage.getItem('derivation_params') || '';
        case 'clear_derivation_params':
          localStorage.removeItem('derivation_params');
          return;
        case 'save_user_summary':
          localStorage.setItem('user_summary', args.userJson || '');
          return;
        case 'load_user_summary':
          return localStorage.getItem('user_summary') || '';
        case 'logout':
        case 'clear_trusted_pc':
          localStorage.removeItem('auth_token');
          localStorage.removeItem('derivation_params');
          localStorage.removeItem('user_summary');
          localStorage.removeItem('vault_cache');
          return;
        case 'save_vault_cache':
          localStorage.setItem('vault_cache', args.encryptedItemsJson || '');
          return;
        case 'load_vault_cache':
          return localStorage.getItem('vault_cache') || '';
        case 'get_app_version':
          return '1.107.0';
        case 'unlock_vault':
        case 'lock_vault':
        case 'record_activity':
          return;
        case 'pick_executable':
          return '';
        case 'launch_application':
          throw new Error('Launching applications is only supported on the Desktop App');
        case 'get_detected_app':
          return null;
        default:
          console.warn('Unhandled mock Tauri command:', cmd);
          return null;
      }
    };
  }

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
      try {
        if (currentUrl && new URL(normalized).host !== new URL(currentUrl).host) {
          await invoke('clear_trusted_pc');
          Api.token = '';
        }
      } catch { Api.token = ''; }
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

  function initGoogleSignIn() {
    if (window.__TAURI__) {
      const gBtn = document.getElementById('googleBtn');
      if (gBtn) gBtn.style.display = 'none';
      return;
    }

    if (typeof google === 'undefined' || !google.accounts) {
      setTimeout(initGoogleSignIn, 500);
      return;
    }
    
    try {
      google.accounts.id.initialize({
        client_id: '871705608594-uc23ekferb43dqo1bsjh255v1c02oj1o.apps.googleusercontent.com',
        callback: handleGoogleLogin
      });
      google.accounts.id.renderButton(
        document.getElementById('googleBtn'),
        { theme: 'outline', size: 'large', width: 280, text: 'signin_with' }
      );
    } catch (e) {
      console.warn('Google Sign-In initialization failed:', e);
    }
  }

  async function handleGoogleLogin(response) {
    if (!response || !response.credential) return;
    document.getElementById('loginErr').textContent = '';
    try {
      const deviceId = localStorage.getItem('deviceId');
      const result = await Api.loginWithGoogle(response.credential, deviceId);
      
      if (result.device_id) {
        localStorage.setItem('deviceId', result.device_id);
      }
      
      Api.token = result.token;
      await invoke('store_auth_token', { token: result.token });
      derivationParams = result.derivation_params;
      
      // Trust the PC by default for Google logins
      await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
      const userSummary = { 
        username: result.user?.username || 'google_user', 
        email: result.user?.email || '', 
        full_name: result.user?.full_name || 'Google User' 
      };
      await invoke('save_user_summary', { userJson: JSON.stringify(userSummary) });
      
      showAuth('viewUnlock');
    } catch (e) {
      document.getElementById('loginErr').textContent = e.message || 'Google Authentication failed';
    }
  }

  function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const page = document.getElementById('page' + name.charAt(0).toUpperCase() + name.slice(1));
    if (page) page.classList.add('active');
    document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.page === name));
  }

  // ===== Init =====
  async function init() {
    // Tauri checked by compatibility polyfill at startup
    try {
      // Load and display version
      try {
        const appVer = await invoke('get_app_version');
        const aboutEl = document.getElementById('aboutVersion');
        if (aboutEl) aboutEl.textContent = 'V' + appVer;
      } catch (verErr) {
        console.warn("Failed to retrieve version:", verErr);
      }
      let state = await invoke('get_app_state');
      if (!state.configured) {
        if (!(window.__TAURI__ && window.__TAURI__.core)) {
          const currentOrigin = window.location.origin;
          await invoke('set_server_url', { url: currentOrigin });
          Api.setServerUrl(currentOrigin);
          state = await invoke('get_app_state');
        } else {
          showAuth('viewWelcome');
          return;
        }
      }
      Api.setServerUrl(state.server_url);
      if (!state.authenticated) {
        // Show server info on login screen
        const infoEl = document.getElementById('loginServerInfo');
        if (infoEl && state.server_url) { try { infoEl.textContent = 'Server: ' + new URL(state.server_url).host; } catch { infoEl.textContent = 'Server: ' + state.server_url; } }
        showAuth('viewLogin');
        initGoogleSignIn();
        return;
      }
      Api.token = (await invoke('get_auth_token')) || '';

      // Fetch fresh parameters from server if authenticated and online
      let freshParamsLoaded = false;
      if (Api.token) {
        try {
          const paramResult = await Api.derivationParams();
          if (paramResult.success && paramResult.params) {
            derivationParams = paramResult.params;
            await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
            freshParamsLoaded = true;
          }
        } catch (e) {
          if (e.code === 'AUTH_REQUIRED' || e.code === 'AUTH_HEADER_MISSING') {
            // Token expired/revoked — must login again
            await invoke('clear_derivation_params');
            document.getElementById('loginErr').textContent = 'Trusted PC session expired. Please sign in again.';
            showAuth('viewLogin');
            return;
          }
          console.warn("Could not fetch fresh derivation params from server, will fall back to cache:", e);
        }
      }

      // Fall back to locally stored params if server is unreachable or we are offline
      if (!freshParamsLoaded && !derivationParams) {
        const storedParams = await invoke('load_derivation_params');
        if (storedParams) {
          derivationParams = JSON.parse(storedParams);
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
  // If running as a web page (GitHub Pages), pre-fill the API server URL.
  // The static site at ampass.arif.bd cannot run PHP — the PHP server is separate.
  (function prefillServerUrl() {
    const input = document.getElementById('welcomeUrl');
    if (!input) return;
    const saved = localStorage.getItem('server_url') || '';
    if (saved) {
      input.value = saved;
    } else if (window.__TAURI__) {
      // Tauri: leave blank, user must enter
    } else {
      // Web browser mode: the user's PHP server is at the same domain
      // (if cPanel serves both the vault and the API at the same host).
      // OR the user may be on GitHub Pages pointing to a different host.
      // Suggest the current origin as a starting point — the user can change it.
      input.value = window.location.origin;
    }
  })();

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
      const deviceId = localStorage.getItem('deviceId');
      const twoFactorCode = document.getElementById('login2faCode')?.value.trim() || '';
      const result = await Api.login(user, pass, 'AMPass Desktop on macOS', deviceId, twoFactorCode);
      
      if (result.device_id) {
        localStorage.setItem('deviceId', result.device_id);
      }
      
      document.getElementById('login2faContainer').style.display = 'none';
      document.getElementById('login2faCode').value = '';
      
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
      if (e.code === 'TWO_FACTOR_REQUIRED') {
        document.getElementById('login2faContainer').style.display = 'block';
        document.getElementById('login2faCode').focus();
        document.getElementById('loginErr').textContent = '2FA code required. Please enter your authenticator code.';
      } else {
        document.getElementById('loginErr').textContent = e.message;
      }
      document.getElementById('loginPass').value = '';
    }
  });
  document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnLogin').click(); });
  document.getElementById('login2faCode').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('btnLogin').click(); });

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
    await Api.initVaultKey(salt, encrypted.ciphertext, encrypted.iv, iterations);
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
    try { await updateActiveAppSuggestion(); } catch (e) {}
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
            ${i.url ? `<button class="btn-ghost-sm" data-open-url="${esc(i.url)}" title="Open URL">🌐</button>` : ''}
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
        icon = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${domain}" alt="" style="width:20px; height:20px; border-radius:4px; object-fit:contain; display:block;" onerror="this.outerHTML='<span>🌐</span>'">`;
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
    if (copyUser) { e.stopPropagation(); await copyField(String(copyUser.dataset.copyUser), 'username'); return; }
    const copyPass = e.target.closest('[data-copy-pass]');
    if (copyPass) { e.stopPropagation(); await copyField(String(copyPass.dataset.copyPass), 'password'); return; }
    const row = e.target.closest('.item-row');
    if (row) { showItemDetail(String(row.dataset.id)); return; }
    const addBtn = e.target.closest('[data-add]');
    if (addBtn) { showAddModal(addBtn.dataset.add); return; }
    const openUrlBtn = e.target.closest('[data-open-url]');
    if (openUrlBtn) { e.stopPropagation(); openUrl(openUrlBtn.dataset.openUrl); return; }
  });

  async function copyField(id, field) {
    const sid = String(id);
    const item = allDecrypted.find(i => String(i._id) === sid);
    if (!item || !item[field]) { toast('Nothing to copy'); return; }
    await navigator.clipboard.writeText(item[field]);
    toast(field === 'password' ? 'Password copied (clears in 30s)' : 'Copied!');
    if (field === 'password') setTimeout(async () => { try { const c = await navigator.clipboard.readText(); if (c === item[field]) await navigator.clipboard.writeText(''); } catch {} }, 30000);
    // Log usage
    try { await Api.usageLog(sid, 'copied_' + field, 'desktop'); } catch {}
  }

  // Make copyField available globally for inline onclick handlers
  window.copyField = copyField;

  /**
   * Launch a desktop application.
   * SECURITY: Never passes password as command-line argument.
   */
  async function launchApp(id) {
    const sid = String(id);
    const item = allDecrypted.find(i => String(i._id) === sid);
    if (!item) { toast('Item not found'); return; }
    const exePath = item.executable_path || item.launch_command || '';
    if (!exePath) { toast('No executable path configured'); return; }
    try {
      await invoke('launch_application', { path: exePath });
      toast('App launched: ' + (item.application_name || item.title));
      try { await Api.usageLog(sid, 'launched_app', 'desktop'); } catch {}
    } catch (e) {
      toast('Launch failed: ' + e.message);
      try { await Api.usageLog(sid, 'app_launch_failed', 'desktop'); } catch {}
    }
  }
  window.launchApp = launchApp;

  /**
   * Open Remote Desktop connection.
   * Creates temporary .rdp file WITHOUT password, launches mstsc.
   * SECURITY: Password is never written to .rdp file. User must paste manually.
   */
  async function openRdp(id) {
    const sid = String(id);
    const item = allDecrypted.find(i => String(i._id) === sid);
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

  async function openUrl(url) {
    try {
      await invoke('open_url', { url });
    } catch (e) {
      toast('Failed to open link: ' + e.message);
    }
  }
  window.openUrl = openUrl;

  function toggleDetailPass() {
    const el = document.getElementById('detailPassVal');
    if (el) {
      el.type = el.type === 'password' ? 'text' : 'password';
    }
  }
  window.toggleDetailPass = toggleDetailPass;

  function showItemDetail(id) {
    const sid = String(id);
    const item = allDecrypted.find(i => String(i._id) === sid);
    if (!item) return;
    document.getElementById('modalTitle').textContent = item.title || 'Item Details';
    let html = '<div class="auth-form">';
    const type = item._type || 'login';

    if (type === 'login') {
      if (item.url) {
        html += `
          <div class="field-label">URL</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.url)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="openUrl('${esc(item.url)}')" style="padding:6px 10px;" title="Open Link">🔗</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'url')" style="padding:6px 10px;" title="Copy URL">📋</button>
          </div>
        `;
      }
      
      const parsed = parseWebAddress(item.url || '');
      const subdomain = item.subdomain || parsed.subdomain;
      const domain = item.domain || parsed.domain;
      const port = item.port || parsed.port;
      const path = item.path || parsed.path;

      if (subdomain) {
        html += `
          <div class="field-label">Subdomain</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(subdomain)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="navigator.clipboard.writeText('${esc(subdomain)}'); toast('Copied Subdomain!');" style="padding:6px 10px;" title="Copy Subdomain">📋</button>
          </div>
        `;
      }
      if (domain) {
        html += `
          <div class="field-label">Domain</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(domain)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="navigator.clipboard.writeText('${esc(domain)}'); toast('Copied Domain!');" style="padding:6px 10px;" title="Copy Domain">📋</button>
          </div>
        `;
      }
      if (port) {
        html += `
          <div class="field-label">Port</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(port)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="navigator.clipboard.writeText('${esc(port)}'); toast('Copied Port!');" style="padding:6px 10px;" title="Copy Port">📋</button>
          </div>
        `;
      }
      if (path) {
        html += `
          <div class="field-label">Path</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(path)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="navigator.clipboard.writeText('${esc(path)}'); toast('Copied Path!');" style="padding:6px 10px;" title="Copy Path">📋</button>
          </div>
        `;
      }
      if (item.username) {
        html += `
          <div class="field-label">Username</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.username)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'username')" style="padding:6px 10px;" title="Copy Username">📋</button>
          </div>
        `;
      }
      if (item.password) {
        html += `
          <div class="field-label">Password</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="password" class="field-input" id="detailPassVal" value="${esc(item.password)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="toggleDetailPass()" style="padding:6px 10px;" title="Toggle Password">👁️</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'password')" style="padding:6px 10px;" title="Copy Password">📋</button>
          </div>
        `;
      }
      if (item.totp_secret) {
        html += `
          <div class="field-label">TOTP Secret</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.totp_secret)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'totp_secret')" style="padding:6px 10px;" title="Copy TOTP Secret">📋</button>
          </div>
        `;
      }
    } else if (type === 'identity') {
      const fieldMap = {
        first_name: 'First Name',
        last_name: 'Last Name',
        email: 'Email',
        phone: 'Phone',
        company: 'Company',
        address_line1: 'Address Line 1',
        address_line2: 'Address Line 2',
        city: 'City',
        state: 'State / Region',
        postcode: 'Post Code',
        country: 'Country',
        date_of_birth: 'Date of Birth'
      };
      for (const [key, label] of Object.entries(fieldMap)) {
        if (item[key]) {
          html += `
            <div class="field-label">${label}</div>
            <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
              <input type="text" class="field-input" value="${esc(item[key])}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
              <button class="btn-ghost-sm" onclick="copyField(${item._id}, '${key}')" style="padding:6px 10px;" title="Copy ${label}">📋</button>
            </div>
          `;
        }
      }
    } else if (type === 'app_account') {
      if (item.application_name) html += `<div class="field-label">Application Name</div><div class="field-input" style="margin-bottom:8px;">${esc(item.application_name)}</div>`;
      if (item.executable_path) {
        html += `
          <div class="field-label">Executable Path</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.executable_path)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="launchApp(${item._id})" style="padding:6px 10px;" title="Launch App">🚀</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'executable_path')" style="padding:6px 10px;" title="Copy Path">📋</button>
          </div>
        `;
      }
      if (item.username) {
        html += `
          <div class="field-label">Username</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.username)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'username')" style="padding:6px 10px;" title="Copy Username">📋</button>
          </div>
        `;
      }
      if (item.password) {
        html += `
          <div class="field-label">Password</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="password" class="field-input" id="detailPassVal" value="${esc(item.password)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="toggleDetailPass()" style="padding:6px 10px;" title="Toggle Password">👁️</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'password')" style="padding:6px 10px;" title="Copy Password">📋</button>
          </div>
        `;
      }
      if (item.website) {
        html += `
          <div class="field-label">Website</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.website)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="openUrl('${esc(item.website)}')" style="padding:6px 10px;" title="Open Link">🔗</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'website')" style="padding:6px 10px;" title="Copy Website">📋</button>
          </div>
        `;
      }
    } else if (type === 'remote_desktop') {
      if (item.host) {
        html += `
          <div class="field-label">Host / IP</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.host)}:${item.port || 3389}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="openRdp(${item._id})" style="padding:6px 10px;" title="Launch RDP">🖥️ Connect</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'host')" style="padding:6px 10px;" title="Copy Host">📋</button>
          </div>
        `;
      }
      if (item.protocol) html += `<div class="field-label">Protocol</div><div class="field-input" style="margin-bottom:8px;">${esc(item.protocol.toUpperCase())}</div>`;
      if (item.domain) {
        html += `
          <div class="field-label">Domain</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.domain)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'domain')" style="padding:6px 10px;" title="Copy Domain">📋</button>
          </div>
        `;
      }
      if (item.username) {
        html += `
          <div class="field-label">Username</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.username)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'username')" style="padding:6px 10px;" title="Copy Username">📋</button>
          </div>
        `;
      }
      if (item.password) {
        html += `
          <div class="field-label">Password</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="password" class="field-input" id="detailPassVal" value="${esc(item.password)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="toggleDetailPass()" style="padding:6px 10px;" title="Toggle Password">👁️</button>
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'password')" style="padding:6px 10px;" title="Copy Password">📋</button>
          </div>
        `;
      }
      if (item.gateway) {
        html += `
          <div class="field-label">Gateway</div>
          <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center;">
            <input type="text" class="field-input" value="${esc(item.gateway)}" readonly style="flex:1;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;">
            <button class="btn-ghost-sm" onclick="copyField(${item._id}, 'gateway')" style="padding:6px 10px;" title="Copy Gateway">📋</button>
          </div>
        `;
      }
    }

    if (item.notes) {
      html += `
        <div class="field-label">Notes</div>
        <textarea readonly class="field-input" style="width:100%;height:80px;background:#27272a;border:1px solid #3f3f46;color:#e4e4e7;resize:none;margin-bottom:8px;white-space:pre-wrap;">${esc(item.notes)}</textarea>
      `;
    }

    html += '</div>';
    document.getElementById('modalBody').innerHTML = html;
    
    document.getElementById('modalFooter').innerHTML = `
      <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
        <div style="display:flex; gap:6px;">
          <button class="btn-ghost-sm" style="color:#6366f1;" onclick="showEditModal(${item._id})">Edit</button>
          <button class="btn-ghost-sm" style="color:#ef4444;" onclick="deleteItem(${item._id})">Delete</button>
        </div>
        <button class="btn-ghost-sm" onclick="document.getElementById('itemModal').style.display='none'">Close</button>
      </div>
    `;
    
    document.getElementById('itemModal').style.display = 'flex';
  }

  function showAddModal(type) {
    const titles = { login: 'Add Web Account', identity: 'Add Identity', secure_note: 'Add Secure Memo', app_account: 'Add App Account', remote_desktop: 'Add Remote Desktop' };
    document.getElementById('modalTitle').textContent = titles[type] || 'Add Item';
    let html = '<div class="auth-form">';
    html += '<label class="field-label">Title</label><input type="text" id="addTitle" class="field-input">';
    if (type === 'login') {
      html += '<label class="field-label">URL</label><input type="url" id="addUrl" class="field-input" placeholder="https://example.com/login">';
      
      html += '<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">';
      html += '  <div><label class="field-label">Subdomain</label><input type="text" id="addSubdomain" class="field-input" placeholder="e.g. ampass.arif.bd"></div>';
      html += '  <div><label class="field-label">Domain</label><input type="text" id="addDomain" class="field-input" placeholder="e.g. arif.bd"></div>';
      html += '</div>';
      html += '<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">';
      html += '  <div><label class="field-label">Port</label><input type="text" id="addPort" class="field-input" placeholder="e.g. 6655"></div>';
      html += '  <div><label class="field-label">Path</label><input type="text" id="addPath" class="field-input" placeholder="e.g. /ampass"></div>';
      html += '</div>';

      html += '<label class="field-label">Username</label><input type="text" id="addUser" class="field-input">';
      html += '<label class="field-label">Password</label><input type="password" id="addPass" class="field-input">';
      html += '<label class="field-label">TOTP Secret (optional)</label><input type="text" id="addTotp" class="field-input">';
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
    } else if (type === 'identity') {
      html += '<div style="display:flex;gap:8px;">';
      html += '  <div style="flex:1;"><label class="field-label">First Name</label><input type="text" id="addFirstName" class="field-input"></div>';
      html += '  <div style="flex:1;"><label class="field-label">Last Name</label><input type="text" id="addLastName" class="field-input"></div>';
      html += '</div>';
      html += '<label class="field-label">Email</label><input type="email" id="addEmail" class="field-input">';
      html += '<label class="field-label">Phone</label><input type="tel" id="addPhone" class="field-input">';
      html += '<label class="field-label">Company</label><input type="text" id="addCompany" class="field-input">';
      html += '<label class="field-label">Address Line 1</label><input type="text" id="addAddress1" class="field-input">';
      html += '<label class="field-label">Address Line 2</label><input type="text" id="addAddress2" class="field-input">';
      html += '<div style="display:flex;gap:8px;">';
      html += '  <div style="flex:1;"><label class="field-label">City</label><input type="text" id="addCity" class="field-input"></div>';
      html += '  <div style="flex:1;"><label class="field-label">State / Region</label><input type="text" id="addState" class="field-input"></div>';
      html += '</div>';
      html += '<div style="display:flex;gap:8px;">';
      html += '  <div style="flex:1;"><label class="field-label">Post Code</label><input type="text" id="addPostcode" class="field-input"></div>';
      html += '  <div style="flex:1;"><label class="field-label">Country</label><input type="text" id="addCountry" class="field-input"></div>';
      html += '</div>';
      html += '<label class="field-label">Date of Birth</label><input type="date" id="addDob" class="field-input">';
    }
    html += '<label class="field-label">Notes</label><textarea id="addNotes" class="field-input" rows="3"></textarea>';
    html += '</div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFooter').innerHTML = `<button class="btn-ghost-sm" onclick="document.getElementById('itemModal').style.display='none'">Cancel</button><button class="btn-primary" style="width:auto;margin:0;padding:8px 16px;" id="btnSaveNew">Save</button>`;
    document.getElementById('itemModal').style.display = 'flex';
    document.getElementById('btnSaveNew').addEventListener('click', () => saveNewItem(type));
    
    if (type === 'login') {
      const urlInput = document.getElementById('addUrl');
      if (urlInput) {
        urlInput.addEventListener('input', () => {
          const parsed = parseWebAddress(urlInput.value);
          document.getElementById('addSubdomain').value = parsed.subdomain;
          document.getElementById('addDomain').value = parsed.domain;
          document.getElementById('addPort').value = parsed.port;
          document.getElementById('addPath').value = parsed.path;
        });
      }
    }

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
      data.subdomain = document.getElementById('addSubdomain')?.value || '';
      data.domain = document.getElementById('addDomain')?.value || '';
      data.port = document.getElementById('addPort')?.value || '';
      data.path = document.getElementById('addPath')?.value || '';
      data.username = document.getElementById('addUser')?.value || '';
      data.password = document.getElementById('addPass')?.value || '';
      data.totp_secret = document.getElementById('addTotp')?.value || '';
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
    } else if (type === 'identity') {
      data.first_name = document.getElementById('addFirstName')?.value || '';
      data.last_name = document.getElementById('addLastName')?.value || '';
      data.email = document.getElementById('addEmail')?.value || '';
      data.phone = document.getElementById('addPhone')?.value || '';
      data.company = document.getElementById('addCompany')?.value || '';
      data.address_line1 = document.getElementById('addAddress1')?.value || '';
      data.address_line2 = document.getElementById('addAddress2')?.value || '';
      data.city = document.getElementById('addCity')?.value || '';
      data.state = document.getElementById('addState')?.value || '';
      data.postcode = document.getElementById('addPostcode')?.value || '';
      data.country = document.getElementById('addCountry')?.value || '';
      data.date_of_birth = document.getElementById('addDob')?.value || '';
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

  function showEditModal(id) {
    const item = allDecrypted.find(i => i._id === id);
    if (!item) return;
    const type = item._type || 'login';
    const titles = { login: 'Edit Web Account', identity: 'Edit Identity', secure_note: 'Edit Secure Memo', app_account: 'Edit App Account', remote_desktop: 'Edit Remote Desktop' };
    document.getElementById('modalTitle').textContent = titles[type] || 'Edit Item';
    
    let html = '<div class="auth-form">';
    html += `<label class="field-label">Title</label><input type="text" id="editTitle" class="field-input" value="${esc(item.title || '')}">`;
    
    if (type === 'login') {
      const parsed = parseWebAddress(item.url || '');
      const subdomain = item.subdomain || parsed.subdomain;
      const domain = item.domain || parsed.domain;
      const port = item.port || parsed.port;
      const path = item.path || parsed.path;

      html += `<label class="field-label">URL</label><input type="url" id="editUrl" class="field-input" value="${esc(item.url || '')}">`;

      html += '<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">';
      html += `  <div><label class="field-label">Subdomain</label><input type="text" id="editSubdomain" class="field-input" value="${esc(subdomain)}" placeholder="e.g. ampass.arif.bd"></div>`;
      html += `  <div><label class="field-label">Domain</label><input type="text" id="editDomain" class="field-input" value="${esc(domain)}" placeholder="e.g. arif.bd"></div>`;
      html += '</div>';
      html += '<div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">';
      html += `  <div><label class="field-label">Port</label><input type="text" id="editPort" class="field-input" value="${esc(port)}" placeholder="e.g. 6655"></div>`;
      html += `  <div><label class="field-label">Path</label><input type="text" id="editPath" class="field-input" value="${esc(path)}" placeholder="e.g. /ampass"></div>`;
      html += '</div>';

      html += `<label class="field-label">Username</label><input type="text" id="editUser" class="field-input" value="${esc(item.username || '')}">`;
      html += `<label class="field-label">Password</label><input type="password" id="editPass" class="field-input" value="${esc(item.password || '')}">`;
      html += `<label class="field-label">TOTP Secret (optional)</label><input type="text" id="editTotp" class="field-input" value="${esc(item.totp_secret || '')}">`;
    } else if (type === 'app_account') {
      html += `<label class="field-label">Application Name</label><input type="text" id="editAppName" class="field-input" value="${esc(item.application_name || '')}">`;
      html += `<label class="field-label">Executable Path</label><div style="display:flex;gap:4px;"><input type="text" id="editExePath" class="field-input" value="${esc(item.executable_path || '')}" style="flex:1;"><button class="btn-ghost-sm" id="btnBrowseExeEdit" title="Browse">📂</button></div>`;
      html += `<label class="field-label">Username / Login</label><input type="text" id="editUser" class="field-input" value="${esc(item.username || '')}">`;
      html += `<label class="field-label">Password</label><input type="password" id="editPass" class="field-input" value="${esc(item.password || '')}">`;
      html += `<label class="field-label">Website (optional)</label><input type="url" id="editUrl" class="field-input" value="${esc(item.website || '')}">`;
    } else if (type === 'remote_desktop') {
      html += `<label class="field-label">Host / IP</label><input type="text" id="editHost" class="field-input" value="${esc(item.host || '')}">`;
      html += `<label class="field-label">Port</label><input type="number" id="editPort" class="field-input" value="${item.port || 3389}">`;
      
      const protocols = ['rdp', 'vnc', 'ssh'];
      let protocolOptions = '';
      protocols.forEach(p => {
        const selected = (item.protocol || 'rdp') === p ? 'selected' : '';
        protocolOptions += `<option value="${p}" ${selected}>${p.toUpperCase()}</option>`;
      });
      html += `<label class="field-label">Protocol</label><select id="editProtocol" class="field-input">${protocolOptions}</select>`;
      
      html += `<label class="field-label">Domain (optional)</label><input type="text" id="editDomain" class="field-input" value="${esc(item.domain || '')}">`;
      html += `<label class="field-label">Username</label><input type="text" id="editUser" class="field-input" value="${esc(item.username || '')}">`;
      html += `<label class="field-label">Password</label><input type="password" id="editPass" class="field-input" value="${esc(item.password || '')}">`;
      html += `<label class="field-label">Gateway (optional)</label><input type="text" id="editGateway" class="field-input" value="${esc(item.gateway || '')}">`;
    } else if (type === 'identity') {
      html += '<div style="display:flex;gap:8px;">';
      html += `  <div style="flex:1;"><label class="field-label">First Name</label><input type="text" id="editFirstName" class="field-input" value="${esc(item.first_name || '')}"></div>`;
      html += `  <div style="flex:1;"><label class="field-label">Last Name</label><input type="text" id="editLastName" class="field-input" value="${esc(item.last_name || '')}"></div>`;
      html += '</div>';
      html += `<label class="field-label">Email</label><input type="email" id="editEmail" class="field-input" value="${esc(item.email || '')}">`;
      html += `<label class="field-label">Phone</label><input type="tel" id="editPhone" class="field-input" value="${esc(item.phone || '')}">`;
      html += `<label class="field-label">Company</label><input type="text" id="editCompany" class="field-input" value="${esc(item.company || '')}">`;
      html += `<label class="field-label">Address Line 1</label><input type="text" id="editAddress1" class="field-input" value="${esc(item.address_line1 || '')}">`;
      html += `<label class="field-label">Address Line 2</label><input type="text" id="editAddress2" class="field-input" value="${esc(item.address_line2 || '')}">`;
      html += '<div style="display:flex;gap:8px;">';
      html += `  <div style="flex:1;"><label class="field-label">City</label><input type="text" id="editCity" class="field-input" value="${esc(item.city || '')}"></div>`;
      html += `  <div style="flex:1;"><label class="field-label">State / Region</label><input type="text" id="editState" class="field-input" value="${esc(item.state || '')}"></div>`;
      html += '</div>';
      html += '<div style="display:flex;gap:8px;">';
      html += `  <div style="flex:1;"><label class="field-label">Post Code</label><input type="text" id="editPostcode" class="field-input" value="${esc(item.postcode || '')}"></div>`;
      html += `  <div style="flex:1;"><label class="field-label">Country</label><input type="text" id="editCountry" class="field-input" value="${esc(item.country || '')}"></div>`;
      html += '</div>';
      html += `<label class="field-label">Date of Birth</label><input type="date" id="editDob" class="field-input" value="${item.date_of_birth || ''}">`;
    }
    
    html += `<label class="field-label">Notes</label><textarea id="editNotes" class="field-input" rows="3">${esc(item.notes || '')}</textarea>`;
    html += '</div>';
    
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFooter').innerHTML = `<button class="btn-ghost-sm" onclick="showItemDetail(${item._id})">Cancel</button><button class="btn-primary" style="width:auto;margin:0;padding:8px 16px;" id="btnSaveEdit">Save</button>`;
    document.getElementById('itemModal').style.display = 'flex';
    
    document.getElementById('btnSaveEdit').addEventListener('click', () => saveEditItem(id, type));
    
    if (type === 'login') {
      const urlInput = document.getElementById('editUrl');
      if (urlInput) {
        urlInput.addEventListener('input', () => {
          const parsed = parseWebAddress(urlInput.value);
          document.getElementById('editSubdomain').value = parsed.subdomain;
          document.getElementById('editDomain').value = parsed.domain;
          document.getElementById('editPort').value = parsed.port;
          document.getElementById('editPath').value = parsed.path;
        });
      }
    }

    const browseBtn = document.getElementById('btnBrowseExeEdit');
    if (browseBtn) browseBtn.addEventListener('click', async () => {
      try { const path = await invoke('pick_executable'); if (path) document.getElementById('editExePath').value = path; } catch {}
    });
  }
  window.showEditModal = showEditModal;

  async function saveEditItem(id, type) {
    const data = { title: document.getElementById('editTitle')?.value || '', notes: document.getElementById('editNotes')?.value || '' };
    if (type === 'login') {
      data.url = document.getElementById('editUrl')?.value || '';
      data.subdomain = document.getElementById('editSubdomain')?.value || '';
      data.domain = document.getElementById('editDomain')?.value || '';
      data.port = document.getElementById('editPort')?.value || '';
      data.path = document.getElementById('editPath')?.value || '';
      data.username = document.getElementById('editUser')?.value || '';
      data.password = document.getElementById('editPass')?.value || '';
      data.totp_secret = document.getElementById('editTotp')?.value || '';
    } else if (type === 'app_account') {
      data.application_name = document.getElementById('editAppName')?.value || data.title;
      data.executable_path = document.getElementById('editExePath')?.value || '';
      data.username = document.getElementById('editUser')?.value || '';
      data.password = document.getElementById('editPass')?.value || '';
      data.website = document.getElementById('editUrl')?.value || '';
    } else if (type === 'remote_desktop') {
      data.host = document.getElementById('editHost')?.value || '';
      data.port = parseInt(document.getElementById('editPort')?.value || '3389');
      data.protocol = document.getElementById('editProtocol')?.value || 'rdp';
      data.domain = document.getElementById('editDomain')?.value || '';
      data.username = document.getElementById('editUser')?.value || '';
      data.password = document.getElementById('editPass')?.value || '';
      data.gateway = document.getElementById('editGateway')?.value || '';
    } else if (type === 'identity') {
      data.first_name = document.getElementById('editFirstName')?.value || '';
      data.last_name = document.getElementById('editLastName')?.value || '';
      data.email = document.getElementById('editEmail')?.value || '';
      data.phone = document.getElementById('editPhone')?.value || '';
      data.company = document.getElementById('editCompany')?.value || '';
      data.address_line1 = document.getElementById('editAddress1')?.value || '';
      data.address_line2 = document.getElementById('editAddress2')?.value || '';
      data.city = document.getElementById('editCity')?.value || '';
      data.state = document.getElementById('editState')?.value || '';
      data.postcode = document.getElementById('editPostcode')?.value || '';
      data.country = document.getElementById('editCountry')?.value || '';
      data.date_of_birth = document.getElementById('editDob')?.value || '';
    }
    if (!data.title) { toast('Title is required'); return; }
    try {
      const encrypted = await Crypto.encryptItem(data, vaultKeyHex);
      const urlHash = data.url ? await Crypto.computeSearchHash(data.url, searchKey) : null;
      const titleHash = await Crypto.computeSearchHash(data.title, searchKey);
      const hostHash = data.host ? await Crypto.computeSearchHash(data.host, searchKey) : null;
      await Api.updateItem({ id, item_type: type, encrypted_data: encrypted.ciphertext, encryption_iv: encrypted.iv, url_hash: urlHash, title_hash: titleHash, host_hash: hostHash, password_strength: Crypto.strength(data.password || ''), is_weak: Crypto.strength(data.password || '') < 40 ? 1 : 0 });
      document.getElementById('itemModal').style.display = 'none';
      toast('Item updated!');
      await loadVault();
    } catch (e) { toast('Save failed: ' + e.message); }
  }
  window.saveEditItem = saveEditItem;

  async function deleteItem(id) {
    if (!confirm('Are you sure you want to delete this item?')) return;
    try {
      await Api.deleteItem(id);
      document.getElementById('itemModal').style.display = 'none';
      toast('Item deleted');
      await loadVault();
    } catch (e) { toast('Delete failed: ' + e.message); }
  }
  window.deleteItem = deleteItem;

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

  document.getElementById('btnResetServerVault')?.addEventListener('click', async () => {
    if (!confirm('WARNING: This will permanently delete all vault items on the server and delete your security keys. You will lose access to all your passwords unless you have a backup. Are you sure you want to proceed?')) {
      return;
    }
    if (!confirm('Please confirm once more: Do you really want to reset your server vault?')) {
      return;
    }
    
    toast('Resetting server vault...');
    try {
      await Api.resetServerVault();
      
      // Clear local state
      vaultKeyHex = null;
      searchKey = null;
      allDecrypted = [];
      derivationParams = null;
      
      await invoke('wipe_local_data');
      await invoke('clear_derivation_params');
      Api.token = '';
      
      toast('Server vault reset successfully!');
      showAuth('viewWelcome');
    } catch (e) {
      alert('Failed to reset server vault: ' + (e.message || 'Unknown error'));
    }
  });

  // Change Login Password
  document.getElementById('btnUpdateLoginPass')?.addEventListener('click', async () => {
    const newPass = document.getElementById('setNewLoginPass').value;
    const confirmPass = document.getElementById('setConfirmLoginPass').value;
    const msgEl = document.getElementById('changeLoginPassMsg');
    
    if (!newPass || !confirmPass) {
      msgEl.textContent = 'Please fill in all fields.';
      msgEl.style.color = '#ef4444';
      return;
    }
    if (newPass !== confirmPass) {
      msgEl.textContent = 'Passwords do not match.';
      msgEl.style.color = '#ef4444';
      return;
    }
    
    msgEl.textContent = 'Updating...';
    msgEl.style.color = '#38bdf8';
    
    try {
      await Api.changeLoginPassword(newPass);
      msgEl.textContent = 'Login password updated successfully!';
      msgEl.style.color = '#22c55e';
      document.getElementById('setNewLoginPass').value = '';
      document.getElementById('setConfirmLoginPass').value = '';
    } catch (e) {
      msgEl.textContent = e.message || 'Failed to update login password.';
      msgEl.style.color = '#ef4444';
    }
  });

  // Change Master Password (re-encrypt vault key)
  document.getElementById('btnUpdateMasterPass')?.addEventListener('click', async () => {
    const newMasterPass = document.getElementById('setNewMasterPass').value;
    const confirmMasterPass = document.getElementById('setConfirmMasterPass').value;
    const msgEl = document.getElementById('changeMasterPassMsg');
    
    if (!vaultKeyHex) {
      msgEl.textContent = 'Vault is locked. Unlock the vault first.';
      msgEl.style.color = '#ef4444';
      return;
    }
    if (!newMasterPass || !confirmMasterPass) {
      msgEl.textContent = 'Please fill in all fields.';
      msgEl.style.color = '#ef4444';
      return;
    }
    if (newMasterPass !== confirmMasterPass) {
      msgEl.textContent = 'Passwords do not match.';
      msgEl.style.color = '#ef4444';
      return;
    }
    
    msgEl.textContent = 'Deriving and re-encrypting vault key...';
    msgEl.style.color = '#38bdf8';
    
    try {
      const salt = Crypto.bufToHex(crypto.getRandomValues(new Uint8Array(32)));
      const iterations = 100000;
      const wrappingKey = await Crypto.deriveKey(newMasterPass, salt, iterations);
      const encrypted = await Crypto.encrypt(vaultKeyHex, wrappingKey);
      
      await Api.initVaultKey(salt, encrypted.ciphertext, encrypted.iv, iterations);
      
      derivationParams = {
        encryption_salt: salt,
        encrypted_vault_key: encrypted.ciphertext,
        vault_key_iv: encrypted.iv,
        key_iterations: iterations,
        needs_setup: false
      };
      
      await invoke('store_derivation_params', { paramsJson: JSON.stringify(derivationParams) });
      
      msgEl.textContent = 'Master password updated successfully!';
      msgEl.style.color = '#22c55e';
      document.getElementById('setNewMasterPass').value = '';
      document.getElementById('setConfirmMasterPass').value = '';
    } catch (e) {
      msgEl.textContent = e.message || 'Failed to update master password.';
      msgEl.style.color = '#ef4444';
    }
  });

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
    return host.toLowerCase().trim();
  }

  function parseWebAddress(urlString) {
    if (!urlString) return { domain: '', subdomain: '', port: '', path: '' };
    let tempUrl = urlString.trim();
    if (!/^https?:\/\//i.test(tempUrl)) {
      tempUrl = 'http://' + tempUrl;
    }
    try {
      const parsed = new URL(tempUrl);
      const hostname = parsed.hostname;
      const port = parsed.port;
      let path = parsed.pathname;
      if (path === '/') path = '';
      path += parsed.search + parsed.hash;
      
      const parts = hostname.split('.');
      let domain = hostname;
      let subdomain = '';
      const secondLevelTlds = ['com', 'co', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'mil'];
      
      if (parts.length > 2) {
        const penultimate = parts[parts.length - 2].toLowerCase();
        const isSecondLevel = secondLevelTlds.includes(penultimate);
        if (isSecondLevel && parts.length >= 3) {
          domain = parts.slice(-3).join('.');
        } else {
          domain = parts.slice(-2).join('.');
        }
        if (hostname !== domain) {
          subdomain = hostname;
        }
      }
      return { domain, subdomain, port, path };
    } catch (e) {
      return { domain: '', subdomain: '', port: '', path: '' };
    }
  }

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
      if (!(window.__TAURI__ && window.__TAURI__.core)) {
        // Standard Web Browser file picker
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = selectedSource === 'sticky_password' ? '.txt' : '.csv';
        input.onchange = (event) => {
          const file = event.target.files[0];
          if (!file) return;
          fileName.textContent = file.name;
          const reader = new FileReader();
          reader.onload = (e) => {
            const text = e.target.result;
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
            } catch (err) {
              toast('Parse error: ' + err.message);
            }
          };
          reader.onerror = () => {
            toast('Failed to read file');
          };
          reader.readAsText(file);
        };
        input.click();
        return;
      }

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
            const enc = await Crypto.encryptItem(plainData, vaultKeyHex);
            const titleHash = searchKey ? await Crypto.computeSearchHash(item.title || '', searchKey) : null;
            const urlHash = (searchKey && item.url) ? await Crypto.computeSearchHash(parseWebAddress(item.url).domain, searchKey) : null;
            const strength = Crypto.strength(item.password || '');

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

    async function updateActiveAppSuggestion() {
      if (typeof vaultKeyHex === 'undefined' || !vaultKeyHex) return; // Only if unlocked
      try {
        const activeApp = await invoke('get_detected_app');
        const container = document.getElementById('detectedAppSection');
        const listEl = document.getElementById('detectedAppList');
        const nameEl = document.getElementById('detectedAppName');
        
        if (!container || !listEl || !nameEl) return;
        
        if (!activeApp || (!activeApp.name && !activeApp.title)) {
          container.style.display = 'none';
          return;
        }
        
        // Filter decrypted items of type 'app_account', 'login' or 'remote_desktop' that match activeApp
        const matching = allDecrypted.filter(item => {
          if (item._type !== 'app_account' && item._type !== 'login' && item._type !== 'remote_desktop') return false;
          
          const appName = (item.application_name || item.title || '').toLowerCase();
          const exePath = (item.executable_path || item.url || '').toLowerCase();
          const activeName = (activeApp.name || '').toLowerCase();
          const activeExe = (activeApp.executable_path || '').toLowerCase();
          const activeTitle = (activeApp.title || '').toLowerCase();
          
          // Special case for Remote Desktop
          if (item._type === 'remote_desktop') {
            const activeFile = activeExe.split('\\').pop().split('/').pop();
            if (
              activeExe.endsWith('mstsc.exe') ||
              activeName.includes('remote desktop') ||
              activeName.includes('credentialuibroker') ||
              activeName.includes('windows security') ||
              activeFile.includes('credentialuibroker') ||
              activeTitle.includes('windows security') ||
              activeTitle.includes('remote desktop') ||
              activeTitle.includes('credentials')
            ) {
              // Always show RDP items if the Remote Desktop client or Windows Security prompt is the active app
              return true;
            }
          }
          
          // Exact match on executable path filename
          if (exePath && (activeExe.endsWith(exePath) || exePath.endsWith(activeExe))) {
            return true;
          }
          
          // Substring match on app name / title
          if (appName && (activeName.includes(appName) || appName.includes(activeName))) {
            return true;
          }
          
          // Substring match on executable name
          const activeFile = activeExe.split('\\').pop().split('/').pop();
          if (appName && activeFile.includes(appName)) {
            return true;
          }
          
          return false;
        });
        
        if (matching.length > 0) {
          nameEl.textContent = activeApp.name || activeApp.title;
          listEl.innerHTML = matching.map(i => {
            if (i._type === 'app_account') {
              return appAccountRow(i);
            } else if (i._type === 'remote_desktop') {
              return rdpRow(i);
            } else {
              return itemRow(i);
            }
          }).join('');
          container.style.display = 'block';
        } else {
          container.style.display = 'none';
        }
      } catch (e) {
        console.error('Error fetching active app suggestions:', e);
      }
    }

    window.addEventListener('focus', () => {
      updateActiveAppSuggestion().catch(() => {});
    });
    setInterval(() => {
      updateActiveAppSuggestion().catch(() => {});
    }, 2000);
  })();

  // ===== Start =====
  init();
  setTimeout(genPw, 200);
})();
