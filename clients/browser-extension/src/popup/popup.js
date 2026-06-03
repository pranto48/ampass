/**
 * AMPass Extension - Popup Logic
 * SECURITY: Communicates with service worker for all crypto/vault operations.
 * Never holds vault key directly.
 */

(function() {
  'use strict';

  // ===== State =====
  let currentDetailItem = null;  // full decrypted item currently shown in detail view
  let currentDetailMeta = null;  // encrypted metadata (id, is_favorite, item_type)
  let totpInterval = null;       // interval timer for TOTP countdown
  let fromGenerator = false;     // flag: generator was opened from edit form
  let isOnCurrentSite = false;   // true when vault view is showing site matches

  // ===== View Management =====
  const ALL_VIEWS = ['viewLoading','viewSetup','viewLogin','viewUnlock','viewVault','viewDetail','viewEdit','viewGenerator'];

  function showView(name, { showBack = false, showLock = true } = {}) {
    ALL_VIEWS.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = el.id === name ? 'block' : 'none';
    });
    const btnBack = document.getElementById('btnBack');
    const btnLock = document.getElementById('btnLock');
    if (btnBack) btnBack.style.display = showBack ? 'flex' : 'none';
    if (btnLock) btnLock.style.display = (showLock && (name === 'viewVault' || name === 'viewDetail' || name === 'viewEdit' || name === 'viewGenerator')) ? 'flex' : 'none';
    // Clear TOTP timer when leaving detail
    if (name !== 'viewDetail') stopTotpTimer();
  }

  function showStatus(msg, type = 'warning') {
    const bar = document.getElementById('statusBar');
    bar.textContent = msg;
    bar.className = 'status-bar ' + type;
    bar.style.display = 'block';
  }
  function hideStatus() { document.getElementById('statusBar').style.display = 'none'; }

  // ===== Messaging =====
  function sendMsg(type, payload = {}) {
    return chrome.runtime.sendMessage({ type, payload });
  }

  // ===== Initialize =====
  async function init() {
    showView('viewLoading');
    try {
      const status = await sendMsg('GET_STATUS');
      if (!status || !status.success) { showView('viewSetup'); return; }

      // Apply theme
      applyTheme();

      if (!status.configured) {
        showView('viewSetup');
      } else if (!status.authenticated) {
        if (!status.online && status.offlineAvailable) {
          showView('viewUnlock');
          showStatus('⚡ Offline Mode — enter master password to access cached vault', 'warning');
        } else {
          showView('viewLogin');
        }
      } else if (!status.unlocked) {
        showView('viewUnlock');
        showTrustedInfo(status);
        if (!status.online) showStatus('⚡ Offline Mode — using encrypted cached vault', 'warning');
      } else {
        showView('viewVault');
        await loadVault();
        if (!status.online) showStatus('⚡ Offline — read-only mode (autofill & copy available)', 'warning');
      }

      if (status.online && status.serverUrl && !status.serverUrl.startsWith('https://') && !status.serverUrl.includes('localhost')) {
        showStatus('⚠️ Server is not using HTTPS. Your data may be at risk.', 'warning');
      }

      // Version footer
      const manifest = chrome.runtime.getManifest();
      const footer = document.getElementById('versionFooter');
      if (footer) footer.textContent = 'AMPass ' + (manifest.version_name || 'v' + manifest.version);

      checkBridgeStatus();
    } catch (e) {
      showView('viewSetup');
    }
  }

  async function applyTheme() {
    const settings = await Storage.getSettings();
    const theme = settings.theme || 'system';
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else if (theme === 'dark') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      // system
      if (window.matchMedia('(prefers-color-scheme: light)').matches) {
        document.documentElement.setAttribute('data-theme', 'light');
      }
    }
  }

  async function checkBridgeStatus() {
    const indicator = document.getElementById('bridgeIndicator');
    if (!indicator) return;
    try {
      const available = await NativeClient.isAvailable();
      if (available) {
        indicator.style.display = 'flex';
        indicator.title = 'Connected to AMPass Desktop App';
      }
    } catch (e) { /* optional */ }
  }

  // ===== Setup =====
  document.getElementById('btnSetupSave').addEventListener('click', async () => {
    const url = document.getElementById('setupUrl').value.trim();
    if (!url) return;
    await Storage.setServerUrl(url);
    showView('viewLogin');
  });

  // ===== Login =====
  document.getElementById('btnLogin').addEventListener('click', async () => {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const btnLogin = document.getElementById('btnLogin');
    const loginError = document.getElementById('loginError');
    if (!username || !password) return;

    btnLogin.disabled = true;
    btnLogin.textContent = 'Signing in...';
    loginError.style.display = 'none';

    try {
      const serverUrl = await Storage.getServerUrl();
      const trustBrowser = document.getElementById('loginTrust')?.checked || false;
      const twoFactorCode = document.getElementById('login2faCode')?.value.trim() || '';
      const result = await sendMsg('LOGIN', { serverUrl, username, password, trustBrowser, twoFactorCode });
      if (result.success) {
        document.getElementById('login2faContainer').style.display = 'none';
        document.getElementById('login2faCode').value = '';
        showView('viewUnlock');
      } else {
        if (result.code === 'TWO_FACTOR_REQUIRED') {
          document.getElementById('login2faContainer').style.display = 'block';
          document.getElementById('login2faCode').focus();
          throw new Error('2FA code required. Please enter your authenticator code.');
        }
        throw new Error(result.error || 'Login failed');
      }
    } catch (e) {
      loginError.textContent = e.message;
      loginError.style.display = 'block';
    } finally {
      btnLogin.disabled = false;
      btnLogin.textContent = 'Sign In';
      document.getElementById('loginPassword').value = '';
    }
  });

  document.getElementById('loginPassword').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btnLogin').click();
  });

  document.getElementById('btnResetConn').addEventListener('click', async () => {
    if (!confirm('This will remove trusted browser login and offline cache. Continue?')) return;
    await sendMsg('RESET_EXTENSION');
    showView('viewSetup');
  });

  // ===== Unlock =====
  document.getElementById('btnUnlockSignOut').addEventListener('click', async () => {
    await sendMsg('LOGOUT');
    showView('viewLogin');
  });
  document.getElementById('btnUnlockChangeServer').addEventListener('click', async () => {
    if (!confirm('This will sign you out and let you enter a new server URL. Continue?')) return;
    await sendMsg('RESET_EXTENSION');
    showView('viewSetup');
  });

  function showTrustedInfo(status) {
    const el = document.getElementById('unlockTrustInfo');
    if (!el) return;
    let text = '';
    if (status.serverUrl) {
      try { text = 'Server: ' + new URL(status.serverUrl).host; } catch { text = 'Server: ' + status.serverUrl; }
    }
    if (status.authenticated) text = '🔒 Trusted browser' + (text ? ' • ' + text : '');
    if (text) { el.textContent = text; el.style.display = ''; }
  }

  document.getElementById('btnUnlock').addEventListener('click', async () => {
    const password = document.getElementById('unlockPassword').value;
    const btnUnlock = document.getElementById('btnUnlock');
    const unlockError = document.getElementById('unlockError');
    if (!password) return;

    btnUnlock.disabled = true;
    btnUnlock.textContent = 'Unlocking...';
    unlockError.style.display = 'none';

    try {
      const result = await sendMsg('UNLOCK', { masterPassword: password });
      if (result.success) {
        showView('viewVault');
        await loadVault();
        if (result.offline) showStatus('⚡ Offline — read-only mode (autofill & copy available)', 'warning');
      } else {
        throw new Error(result.error || 'Invalid master password');
      }
    } catch (e) {
      if (e.message && (e.message.includes('expired') || e.message.includes('token') || e.message.includes('AUTH'))) {
        await sendMsg('RESET_EXTENSION');
        unlockError.textContent = 'Session expired. Please login again.';
        unlockError.style.display = 'block';
        setTimeout(() => showView('viewLogin'), 2000);
      } else {
        unlockError.textContent = e.message;
        unlockError.style.display = 'block';
      }
    } finally {
      btnUnlock.disabled = false;
      btnUnlock.textContent = 'Unlock';
      document.getElementById('unlockPassword').value = '';
    }
  });

  document.getElementById('unlockPassword').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btnUnlock').click();
  });

  // ===== Lock =====
  document.getElementById('btnLock').addEventListener('click', async () => {
    await sendMsg('LOCK');
    showView('viewUnlock');
  });

  // ===== Settings =====
  document.getElementById('btnSettings').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // ===== Back Button =====
  document.getElementById('btnBack').addEventListener('click', () => {
    showView('viewVault');
  });

  // ===== Vault List =====
  async function loadVault() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrl = tab?.url || '';

    const matchesSection = document.getElementById('matchesSection');
    const matchesList = document.getElementById('matchesList');
    const allItemsList = document.getElementById('allItemsList');
    const itemCount = document.getElementById('itemCount');
    const emptyState = document.getElementById('emptyState');

    isOnCurrentSite = false;

    if (currentUrl && currentUrl.startsWith('http')) {
      const matchResult = await sendMsg('GET_MATCHES', { url: currentUrl });
      if (matchResult.success && matchResult.items.length > 0) {
        isOnCurrentSite = true;
        matchesSection.style.display = 'block';
        renderItems(matchesList, matchResult.items, true);
      } else {
        matchesSection.style.display = 'none';
      }
    }

    const allResult = await sendMsg('GET_ALL_ITEMS');
    if (allResult.success) {
      itemCount.textContent = allResult.items.length;
      if (allResult.items.length > 0) {
        renderItems(allItemsList, allResult.items, false);
        emptyState.style.display = 'none';
      } else {
        allItemsList.innerHTML = '';
        emptyState.style.display = 'block';
      }
    }
  }

  function getItemIcon(itemType) {
    if (itemType === 'note' || itemType === 'secure_note') return '📝';
    if (itemType === 'credit_card') return '💳';
    if (itemType === 'identity') return '🪪';
    return '🔑';
  }

  function renderItems(container, items, showAutofill) {
    container.innerHTML = '';
    items.forEach(item => {
      const row = document.createElement('div');
      row.className = 'item';
      row.dataset.id = item.id;
      row.dataset.type = item.item_type || 'login';

      let icon = getItemIcon(item.item_type);
      if ((item.item_type === 'login' || !item.item_type) && item.url) {
        const domain = DomainUtils.getBaseDomain(item.url);
        if (domain) {
          icon = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${domain}" alt="" style="width:18px; height:18px; border-radius:3px; object-fit:contain; display:block;" onerror="this.outerHTML='🔑'">`;
        }
      }
      row.innerHTML = `
        <div class="item-icon">${icon}</div>
        <div class="item-info">
          <span class="item-title">${Security.escapeHtml(item.title)}</span>
          <span class="item-subtitle">${Security.escapeHtml(item.username || '')}</span>
        </div>
        <div class="item-actions">
          ${showAutofill && item.item_type !== 'note' && item.item_type !== 'secure_note' ? `<button class="icon-btn btn-autofill" data-id="${item.id}" title="Autofill"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg></button>` : ''}
          ${item.item_type !== 'note' && item.item_type !== 'secure_note' ? `<button class="icon-btn btn-copy-user" data-id="${item.id}" title="Copy username"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></button>
          <button class="icon-btn btn-copy-pass" data-id="${item.id}" title="Copy password"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>` : ''}
        </div>
      `;

      // Click row → detail view
      row.addEventListener('click', async (e) => {
        if (e.target.closest('.item-actions')) return;
        await openDetailView(item);
      });

      // Quick action buttons
      row.querySelectorAll('.btn-autofill').forEach(btn => {
        btn.addEventListener('click', e => { e.stopPropagation(); autofillItem(parseInt(btn.dataset.id)); });
      });
      row.querySelectorAll('.btn-copy-user').forEach(btn => {
        btn.addEventListener('click', e => { e.stopPropagation(); copyField(parseInt(btn.dataset.id), 'username'); });
      });
      row.querySelectorAll('.btn-copy-pass').forEach(btn => {
        btn.addEventListener('click', e => { e.stopPropagation(); copyField(parseInt(btn.dataset.id), 'password'); });
      });

      container.appendChild(row);
    });
  }

  // ===== Item Detail =====
  async function openDetailView(meta) {
    const result = await sendMsg('DECRYPT_ITEM', { id: meta.id });
    if (!result.success) {
      showStatus('Could not decrypt item', 'error');
      return;
    }

    currentDetailMeta = meta;
    currentDetailItem = result.item;

    const isLogin = meta.item_type === 'login' || !meta.item_type;
    const isIdentity = meta.item_type === 'identity';
    const isNote = meta.item_type === 'secure_note' || meta.item_type === 'note';

    // Populate header
    let detailIconHtml = getItemIcon(meta.item_type);
    if (isLogin && result.item.url) {
      const domain = DomainUtils.getBaseDomain(result.item.url);
      if (domain) {
        detailIconHtml = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${domain}" alt="" style="width:24px; height:24px; border-radius:4px; object-fit:contain; display:inline-block; vertical-align:middle;" onerror="this.outerHTML='🔑'">`;
      }
    }
    const detailIconEl = document.getElementById('detailIcon');
    if (detailIconHtml.startsWith('<img')) {
      detailIconEl.innerHTML = detailIconHtml;
    } else {
      detailIconEl.textContent = detailIconHtml;
    }
    document.getElementById('detailTitle').textContent = result.item.title || 'Untitled';
    document.getElementById('detailUrl').textContent = result.item.url || '';

    // Favorite button
    const favBtn = document.getElementById('btnDetailFav');
    favBtn.classList.toggle('active', !!(meta.is_favorite));

    // Username
    const usernameRow = document.getElementById('detailUsernameRow');
    const usernameEl = document.getElementById('detailUsername');
    const un = result.item.username || result.item.email || '';
    if (un && isLogin) {
      usernameEl.textContent = un;
      usernameRow.style.display = 'block';
    } else {
      usernameRow.style.display = 'none';
    }

    // Password + strength
    const passwordRow = document.getElementById('detailPasswordRow');
    const passwordEl = document.getElementById('detailPassword');
    const pw = result.item.password || '';
    if (pw && isLogin) {
      passwordEl.textContent = '••••••••';
      passwordEl.classList.add('password-dots');
      passwordEl._plaintext = pw;
      const score = CryptoClient.calculateStrength(pw);
      const fill = document.getElementById('detailStrengthFill');
      fill.style.width = score + '%';
      fill.style.background = score >= 80 ? '#22c55e' : score >= 60 ? '#84cc16' : score >= 40 ? '#f59e0b' : '#ef4444';
      passwordRow.style.display = 'block';
    } else {
      passwordRow.style.display = 'none';
    }

    // TOTP
    const totpRow = document.getElementById('detailTotpRow');
    if (result.item.totp_secret && isLogin) {
      totpRow.style.display = 'block';
      startTotpTimer(result.item.totp_secret);
    } else {
      totpRow.style.display = 'none';
    }

    // Identity Fields
    const identityGroup = document.getElementById('detailIdentityGroup');
    if (isIdentity) {
      document.getElementById('detailFirstName').textContent = result.item.first_name || '';
      document.getElementById('detailLastName').textContent = result.item.last_name || '';
      document.getElementById('detailIdentityEmail').textContent = result.item.email || '';
      document.getElementById('detailIdentityPhone').textContent = result.item.phone || '';
      document.getElementById('detailIdentityCompany').textContent = result.item.company || '';

      const addrLines = [
        result.item.address_line1,
        result.item.address_line2,
        [result.item.city, result.item.state, result.item.postcode].filter(Boolean).join(', '),
        result.item.country
      ].filter(Boolean).join('\n');
      document.getElementById('detailAddress').textContent = addrLines || '';
      document.getElementById('detailDob').textContent = result.item.date_of_birth || '';

      identityGroup.style.display = 'block';
    } else {
      identityGroup.style.display = 'none';
    }

    // Notes
    const notesRow = document.getElementById('detailNotesRow');
    const notesEl = document.getElementById('detailNotes');
    if (result.item.notes) {
      notesEl.textContent = result.item.notes;
      notesRow.style.display = 'block';
    } else {
      notesRow.style.display = 'none';
    }

    // Autofill button — only show if on a matching site (for login) or globally (for identity)
    const autofillBtn = document.getElementById('btnDetailAutofill');
    const canAutofill = isLogin ? isOnCurrentSite : isIdentity;
    autofillBtn.style.display = (canAutofill) ? 'inline-flex' : 'none';

    showView('viewDetail', { showBack: true });
  }

  // Toggle show/hide password in detail
  document.getElementById('btnTogglePass').addEventListener('click', () => {
    const el = document.getElementById('detailPassword');
    if (el.classList.contains('password-dots')) {
      el.textContent = el._plaintext || '';
      el.classList.remove('password-dots');
    } else {
      el.textContent = '••••••••';
      el.classList.add('password-dots');
    }
  });

  document.getElementById('btnCopyUsername').addEventListener('click', async () => {
    const val = document.getElementById('detailUsername').textContent;
    await copyToClipboard(val, 'username');
  });
  document.getElementById('btnCopyPassword').addEventListener('click', async () => {
    const el = document.getElementById('detailPassword');
    await copyToClipboard(el._plaintext || '', 'password');
  });
  document.getElementById('btnCopyTotp').addEventListener('click', async () => {
    const code = document.getElementById('detailTotpCode').textContent;
    if (code && code !== '------') await copyToClipboard(code, '2FA code');
  });

  // Handle generic identity sub-field copy buttons
  document.querySelectorAll('.btn-copy-child').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const targetId = btn.dataset.target;
      const el = document.getElementById(targetId);
      if (el) {
        const val = el.textContent || '';
        await copyToClipboard(val, btn.title.replace('Copy ', ''));
      }
    });
  });

  document.getElementById('btnDetailAutofill').addEventListener('click', () => {
    if (currentDetailMeta) autofillItem(currentDetailMeta.id);
  });

  document.getElementById('btnDetailFav').addEventListener('click', async () => {
    if (!currentDetailMeta) return;
    const newFav = !currentDetailMeta.is_favorite;
    const result = await sendMsg('FAVORITE_ITEM', { id: currentDetailMeta.id, isFavorite: newFav });
    if (result.success) {
      currentDetailMeta.is_favorite = newFav;
      document.getElementById('btnDetailFav').classList.toggle('active', newFav);
      showStatus(newFav ? '⭐ Added to favorites' : 'Removed from favorites', 'success');
      setTimeout(hideStatus, 1800);
    }
  });

  document.getElementById('btnDetailEdit').addEventListener('click', () => {
    if (!currentDetailItem || !currentDetailMeta) return;
    openEditForm(currentDetailMeta, currentDetailItem);
  });

  document.getElementById('btnDetailDelete').addEventListener('click', async () => {
    if (!currentDetailMeta) return;
    const title = currentDetailItem?.title || 'this item';
    if (!confirm(`Delete "${title}"? This cannot be undone.`)) return;

    const result = await sendMsg('DELETE_ITEM', { id: currentDetailMeta.id });
    if (result.success) {
      showView('viewVault');
      await loadVault();
      showStatus('Item deleted', 'success');
      setTimeout(hideStatus, 2000);
    } else {
      showStatus(result.error || 'Delete failed', 'error');
    }
  });

  // ===== TOTP Timer =====
  function startTotpTimer(secret) {
    stopTotpTimer();
    async function refresh() {
      const result = await sendMsg('GENERATE_TOTP', { secret });
      const codeEl = document.getElementById('detailTotpCode');
      const countEl = document.getElementById('totpCountdown');
      if (!codeEl) { stopTotpTimer(); return; }
      if (result.success) {
        // Format as "123 456" for readability
        const c = result.code;
        codeEl.textContent = c.slice(0, 3) + ' ' + c.slice(3);
        if (countEl) {
          countEl.textContent = result.remaining;
          countEl.classList.toggle('urgent', result.remaining <= 5);
        }
      } else {
        codeEl.textContent = 'Error';
      }
    }
    refresh();
    totpInterval = setInterval(refresh, 1000);
  }
  function stopTotpTimer() {
    if (totpInterval) { clearInterval(totpInterval); totpInterval = null; }
  }

  // ===== Add/Edit Form =====
  document.getElementById('btnAddNew').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url?.startsWith('http') ? tab.url : '';
    const title = tab?.title || '';
    openEditForm(null, { title, url, username: '', password: '', totp_secret: '', notes: '', item_type: 'login' });
  });

  document.getElementById('btnAddNote').addEventListener('click', () => {
    openEditForm(null, { title: '', url: '', username: '', password: '', totp_secret: '', notes: '', item_type: 'secure_note' });
  });

  document.getElementById('btnAddIdentity').addEventListener('click', () => {
    openEditForm(null, { title: '', notes: '', item_type: 'identity' });
  });

  function openEditForm(meta, item) {
    const isEdit = !!meta;
    document.getElementById('editItemId').value = meta ? meta.id : '';
    const itemType = (meta?.item_type || item?.item_type || 'login');
    document.getElementById('editItemType').value = itemType;

    document.getElementById('editTitle').value = item?.title || '';
    document.getElementById('editUrl').value = item?.url || '';
    document.getElementById('editUsername').value = item?.username || item?.email || '';
    document.getElementById('editPassword').value = item?.password || '';
    document.getElementById('editTotp').value = item?.totp_secret || '';
    document.getElementById('editNotes').value = item?.notes || '';

    // Show/hide fields based on type
    const isNote = itemType === 'secure_note' || itemType === 'note';
    const isIdentity = itemType === 'identity';

    document.getElementById('editUrlGroup').style.display = isNote || isIdentity ? 'none' : 'flex';
    document.getElementById('editUsernameGroup').style.display = isNote || isIdentity ? 'none' : 'flex';
    document.getElementById('editPasswordGroup').style.display = isNote || isIdentity ? 'none' : 'flex';
    document.getElementById('editTotpGroup').style.display = isNote || isIdentity ? 'none' : 'flex';
    document.getElementById('editIdentityFields').style.display = isIdentity ? 'block' : 'none';

    if (isIdentity) {
      document.getElementById('editFormTitle').textContent = isEdit ? 'Edit Identity' : 'Add Identity';
      document.getElementById('editFirstName').value = item?.first_name || '';
      document.getElementById('editLastName').value = item?.last_name || '';
      document.getElementById('editIdentityEmail').value = item?.email || '';
      document.getElementById('editIdentityPhone').value = item?.phone || '';
      document.getElementById('editIdentityCompany').value = item?.company || '';
      document.getElementById('editAddress1').value = item?.address_line1 || '';
      document.getElementById('editAddress2').value = item?.address_line2 || '';
      document.getElementById('editCity').value = item?.city || '';
      document.getElementById('editState').value = item?.state || '';
      document.getElementById('editPostcode').value = item?.postcode || '';
      document.getElementById('editCountry').value = item?.country || '';
      document.getElementById('editDob').value = item?.date_of_birth || '';
    } else {
      document.getElementById('editFormTitle').textContent = isEdit ? 'Edit Item' : (isNote ? 'Add Note' : 'Add Login');
    }

    // Update strength bar
    updateEditStrength();
    document.getElementById('editError').style.display = 'none';

    showView('viewEdit', { showBack: true });
  }

  function updateEditStrength() {
    const pw = document.getElementById('editPassword').value;
    const score = pw ? CryptoClient.calculateStrength(pw) : 0;
    const fill = document.getElementById('editStrengthFill');
    fill.style.width = score + '%';
    fill.style.background = score >= 80 ? '#22c55e' : score >= 60 ? '#84cc16' : score >= 40 ? '#f59e0b' : '#ef4444';
  }

  document.getElementById('editPassword').addEventListener('input', updateEditStrength);

  // Toggle show/hide password in edit form
  document.getElementById('btnToggleEditPass').addEventListener('click', () => {
    const pw = document.getElementById('editPassword');
    pw.type = pw.type === 'password' ? 'text' : 'password';
  });

  // Open generator from edit form
  document.getElementById('btnFillGenerate').addEventListener('click', () => {
    fromGenerator = true;
    document.getElementById('btnUsePwInEdit').style.display = 'inline-flex';
    showView('viewGenerator', { showBack: true });
    generatePassword();
  });

  document.getElementById('btnUsePwInEdit').addEventListener('click', () => {
    const pw = document.getElementById('genPassword').value;
    if (pw) {
      document.getElementById('editPassword').value = pw;
      updateEditStrength();
    }
    fromGenerator = false;
    document.getElementById('btnUsePwInEdit').style.display = 'none';
    // Go back to edit form — need to re-show it with current data
    showView('viewEdit', { showBack: true });
  });

  document.getElementById('btnSaveItem').addEventListener('click', async () => {
    const id = document.getElementById('editItemId').value;
    const itemType = document.getElementById('editItemType').value;
    const title = document.getElementById('editTitle').value.trim();
    const btn = document.getElementById('btnSaveItem');
    const errEl = document.getElementById('editError');

    if (!title) {
      errEl.textContent = 'Title is required';
      errEl.style.display = 'block';
      return;
    }

    const itemData = {
      item_type: itemType,
      title,
      notes: document.getElementById('editNotes').value.trim(),
    };

    if (itemType === 'login') {
      itemData.url = document.getElementById('editUrl').value.trim();
      itemData.username = document.getElementById('editUsername').value.trim();
      itemData.password = document.getElementById('editPassword').value;
      const totpSecret = document.getElementById('editTotp').value.trim();
      if (totpSecret) itemData.totp_secret = totpSecret;
    } else if (itemType === 'identity') {
      itemData.first_name = document.getElementById('editFirstName').value.trim();
      itemData.last_name = document.getElementById('editLastName').value.trim();
      itemData.email = document.getElementById('editIdentityEmail').value.trim();
      itemData.phone = document.getElementById('editIdentityPhone').value.trim();
      itemData.company = document.getElementById('editIdentityCompany').value.trim();
      itemData.address_line1 = document.getElementById('editAddress1').value.trim();
      itemData.address_line2 = document.getElementById('editAddress2').value.trim();
      itemData.city = document.getElementById('editCity').value.trim();
      itemData.state = document.getElementById('editState').value.trim();
      itemData.postcode = document.getElementById('editPostcode').value.trim();
      itemData.country = document.getElementById('editCountry').value.trim();
      itemData.date_of_birth = document.getElementById('editDob').value;
    }

    btn.disabled = true;
    btn.textContent = 'Saving...';
    errEl.style.display = 'none';

    try {
      let result;
      if (id) {
        result = await sendMsg('UPDATE_ITEM', { id: parseInt(id), itemData });
      } else {
        result = await sendMsg('SAVE_ITEM', { itemData });
      }

      if (result.success) {
        showView('viewVault');
        await loadVault();
        showStatus(id ? 'Item updated ✓' : 'Item saved ✓', 'success');
        setTimeout(hideStatus, 2000);
      } else {
        throw new Error(result.error || 'Save failed');
      }
    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Save';
    }
  });

  document.getElementById('btnCancelEdit').addEventListener('click', () => {
    showView('viewVault');
  });

  // ===== Autofill =====
  async function autofillItem(id) {
    const result = await sendMsg('DECRYPT_ITEM', { id });
    if (!result.success) return;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    if (result.item.item_type === 'identity') {
      chrome.tabs.sendMessage(tab.id, {
        type: 'AUTOFILL_IDENTITY',
        payload: result.item
      });
    } else {
      chrome.tabs.sendMessage(tab.id, {
        type: 'AUTOFILL',
        payload: { username: result.item.username || result.item.email || '', password: result.item.password || '' }
      });
    }

    // Log usage
    sendMsg('LOG_USAGE', { item_id: id, action: 'autofilled', client_type: 'extension' }).catch(() => {});

    window.close();
  }

  // ===== Copy =====
  async function copyToClipboard(value, label) {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    showStatus('Copied ' + label, 'success');
    setTimeout(hideStatus, 1800);

    // Auto-clear clipboard after timeout
    const settings = await Storage.getSettings();
    const clearTime = (settings.clipboardClearSeconds || 30) * 1000;
    setTimeout(async () => {
      try {
        const current = await navigator.clipboard.readText();
        if (current === value) await navigator.clipboard.writeText('');
      } catch (e) { /* cannot read clipboard */ }
    }, clearTime);
  }

  async function copyField(id, field) {
    const result = await sendMsg('DECRYPT_ITEM', { id });
    if (!result.success) return;
    const value = result.item[field] || (field === 'username' ? result.item.email : '') || '';
    await copyToClipboard(value, field);
  }

  // ===== Search =====
  let searchTimeout;
  document.getElementById('searchInput').addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
      const query = document.getElementById('searchInput').value.trim();
      if (!query) { await loadVault(); return; }
      const result = await sendMsg('SEARCH', { query });
      if (result.success) {
        document.getElementById('matchesSection').style.display = 'none';
        renderItems(document.getElementById('allItemsList'), result.items, false);
        document.getElementById('itemCount').textContent = result.items.length;
      }
    }, 250);
  });

  // ===== Generator =====
  document.getElementById('btnGenerate').addEventListener('click', () => {
    fromGenerator = false;
    document.getElementById('btnUsePwInEdit').style.display = 'none';
    showView('viewGenerator', { showBack: true });
    generatePassword();
  });

  document.getElementById('genLength').addEventListener('input', () => {
    document.getElementById('genLengthVal').textContent = document.getElementById('genLength').value;
    generatePassword();
  });

  document.getElementById('btnRegenerate').addEventListener('click', generatePassword);

  document.getElementById('btnCopyGen').addEventListener('click', async () => {
    const pw = document.getElementById('genPassword').value;
    await navigator.clipboard.writeText(pw);
    showStatus('Password copied!', 'success');
    setTimeout(hideStatus, 1800);
  });

  ['genUpper','genLower','genNumbers','genSymbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', generatePassword);
  });

  function generatePassword() {
    const pw = CryptoClient.generatePassword({
      length: parseInt(document.getElementById('genLength').value),
      uppercase: document.getElementById('genUpper').checked,
      lowercase: document.getElementById('genLower').checked,
      numbers: document.getElementById('genNumbers').checked,
      symbols: document.getElementById('genSymbols').checked
    });
    document.getElementById('genPassword').value = pw;

    const score = CryptoClient.calculateStrength(pw);
    const fill = document.getElementById('genStrength').querySelector('.strength-fill');
    fill.style.width = score + '%';
    fill.style.background = score >= 80 ? '#22c55e' : score >= 60 ? '#84cc16' : score >= 40 ? '#f59e0b' : '#ef4444';
  }

  // ===== Init =====
  init();
})();
