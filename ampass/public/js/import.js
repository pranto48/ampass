/**
 * AMPass — Password Import (Client-Side)
 * SECURITY: Parses plaintext export files in the browser.
 * Encrypts each item with vault key before sending to server.
 * Never sends plaintext passwords to the server.
 */
(function() {
  'use strict';

  let parsedItems = [];
  let selectedSource = '';
  let vaultKeyReady = false;

  // CRITICAL: Ensure vault key is available before any import operation
  async function ensureVaultKey() {
    if (vaultKeyReady) return true;
    if (typeof AMPassCrypto === 'undefined') return false;
    if (AMPassCrypto.isUnlocked()) { vaultKeyReady = true; return true; }
    // Try restoring from sessionStorage or showing inline unlock modal
    try {
      const restored = await AMPassCrypto.ensureVaultKeyUnlocked();
      vaultKeyReady = restored;
      return restored;
    } catch (e) {
      return false;
    }
  }

  // Try restoring vault key immediately
  ensureVaultKey();

  const els = {
    source: document.getElementById('importSource'),
    file: document.getElementById('importFile'),
    options: document.getElementById('importOptions'),
    confirm: document.getElementById('importConfirm'),
    acknowledge: document.getElementById('importAcknowledge'),
    btnPreview: document.getElementById('btnPreview'),
    previewCard: document.getElementById('previewCard'),
    previewCount: document.getElementById('previewCount'),
    previewBody: document.getElementById('previewBody'),
    previewWarnings: document.getElementById('previewWarnings'),
    btnSelectAll: document.getElementById('btnSelectAll'),
    btnUnselectAll: document.getElementById('btnUnselectAll'),
    checkAll: document.getElementById('checkAll'),
    btnImport: document.getElementById('btnImport'),
    btnCancel: document.getElementById('btnCancelImport'),
    progress: document.getElementById('importProgress'),
    progressBar: document.getElementById('importProgressBar'),
    progressText: document.getElementById('importProgressText'),
    resultCard: document.getElementById('resultCard'),
    resultContent: document.getElementById('resultContent')
  };

  // ===== Event Listeners =====
  els.source.addEventListener('change', () => {
    selectedSource = els.source.value;
    els.file.disabled = !selectedSource;
    els.file.value = '';
    const accept = selectedSource === 'sticky_password' ? '.txt' : '.csv';
    els.file.accept = accept;
    hidePreview();
  });

  els.file.addEventListener('change', () => {
    if (els.file.files.length > 0) {
      els.confirm.style.display = '';
      els.options.style.display = '';
      els.btnPreview.disabled = false;
    }
  });

  els.acknowledge.addEventListener('change', () => {
    els.btnPreview.disabled = !els.acknowledge.checked;
  });

  els.btnPreview.addEventListener('click', () => {
    if (!els.acknowledge.checked) return;
    const file = els.file.files[0];
    if (!file) return;

    // Detect encoding by reading first 4 bytes
    const checkReader = new FileReader();
    checkReader.onload = (e) => {
      const arr = new Uint8Array(e.target.result);
      let encoding = 'utf-8';
      
      if (arr.length >= 2) {
        if (arr[0] === 0xff && arr[1] === 0xfe) {
          encoding = 'utf-16le';
        } else if (arr[0] === 0xfe && arr[1] === 0xff) {
          encoding = 'utf-16be';
        } else if (arr.length >= 3 && arr[0] === 0xef && arr[1] === 0xbb && arr[2] === 0xbf) {
          encoding = 'utf-8';
        }
      }

      // Read entire file with detected encoding
      const textReader = new FileReader();
      textReader.onload = (evt) => {
        const text = evt.target.result;
        try {
          if (selectedSource === 'sticky_password') {
            parsedItems = parseStickyPasswordTxt(text);
          } else if (selectedSource === 'lastpass') {
            parsedItems = parseLastPassCsv(text);
          } else if (selectedSource === 'bitwarden') {
            parsedItems = parseBitwardenCsv(text);
          } else if (selectedSource === '1password') {
            parsedItems = parse1PasswordCsv(text);
          } else if (selectedSource === 'keepass') {
            parsedItems = parseKeePassCsv(text);
          } else {
            parsedItems = parseBrowserCsv(text, selectedSource);
          }
          showPreview();
        } catch (err) {
          alert('Parse error: ' + err.message);
        }
      };
      textReader.readAsText(file, encoding);
    };
    checkReader.readAsArrayBuffer(file.slice(0, 4));
  });

  els.btnSelectAll.addEventListener('click', () => { parsedItems.forEach(i => i._selected = true); renderPreview(); });
  els.btnUnselectAll.addEventListener('click', () => { parsedItems.forEach(i => i._selected = false); renderPreview(); });
  els.checkAll.addEventListener('change', () => { parsedItems.forEach(i => i._selected = els.checkAll.checked); renderPreview(); });
  els.btnCancel.addEventListener('click', () => { parsedItems = []; hidePreview(); });
  els.btnImport.addEventListener('click', doImport);

  // ===== Sticky Password TXT Parser =====
  function parseStickyPasswordTxt(text) {
    // Remove UTF-8 BOM if present in decoded string
    if (text.charCodeAt(0) === 0xFEFF) {
      text = text.substring(1);
    }

    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const items = [];
    let current = null;
    let currentLogin = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;

      const key = line.substring(0, colonIdx).trim().toLowerCase();
      let rawVal = line.substring(colonIdx + 1);
      if (rawVal.startsWith(' ')) {
        rawVal = rawVal.substring(1);
      }
      const val = rawVal.trim();

      if (key === 'account name' || key === 'account' || key === 'title' || key === 'site') {
        // Save previous credential if exists
        if (currentLogin && current) {
          items.push(buildStickyItem(current, currentLogin));
          currentLogin = null;
        }
        current = { accountName: val, link: '', description: '', logins: [] };
        currentLogin = null;
      } else if ((key === 'link' || key === 'url' || key === 'website' || key === 'web') && current) {
        current.link = val;
      } else if ((key === 'description' || key === 'notes' || key === 'note' || key === 'comment') && current) {
        current.description = val;
      } else if ((key === 'login' || key === 'username' || key === 'user' || key === 'user name' || key === 'email') && current) {
        // Save previous login if password was missing
        if (currentLogin) {
          currentLogin.warnings = currentLogin.warnings || [];
          if (!currentLogin.password) currentLogin.warnings.push('Missing password');
          items.push(buildStickyItem(current, currentLogin));
        }
        currentLogin = { username: val, password: '', warnings: [] };
      } else if ((key === 'password' || key === 'pass' || key === 'pwd') && current && currentLogin) {
        currentLogin.password = rawVal; // Preserve trailing spaces in password
        items.push(buildStickyItem(current, currentLogin));
        currentLogin = null;
      }
    }
    // Handle last item
    if (currentLogin && current) {
      if (!currentLogin.password) currentLogin.warnings = ['Missing password'];
      items.push(buildStickyItem(current, currentLogin));
    }

    return items.map((item, idx) => ({ ...item, _selected: !!item.password, _index: idx }));
  }

  function buildStickyItem(account, login) {
    let title = account.accountName || '';
    if (!title && account.link) {
      try {
        let cleanUrl = account.link;
        if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
          cleanUrl = 'https://' + cleanUrl;
        }
        title = new URL(cleanUrl).hostname;
      } catch {
        title = account.link;
      }
    }
    if (!title) title = 'Imported Login';

    const warnings = [...(login.warnings || [])];
    if (account.link && account.link.startsWith('http://')) warnings.push('HTTP URL');
    if (!login.username) warnings.push('Missing username');
    if (!login.password) warnings.push('Missing password');

    return {
      source: 'sticky_password',
      title: title,
      url: account.link || '',
      username: login.username || '',
      password: login.password || '',
      notes: account.description || '',
      warnings: warnings
    };
  }

  // ===== Browser CSV Parser =====
  function parseBrowserCsv(text, source) {
    // Remove UTF-8 BOM
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);

    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV file is empty or has no data rows');

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const items = [];

    // Column mapping
    const titleCol = findCol(headers, ['name', 'title', 'account', 'account_name', 'site']);
    const urlCol = findCol(headers, ['url', 'link', 'website', 'site_url', 'login_url', 'origin_url']);
    const userCol = findCol(headers, ['username', 'user', 'login', 'email', 'login_username']);
    const passCol = findCol(headers, ['password', 'pass', 'pwd', 'login_password']);
    const noteCol = findCol(headers, ['notes', 'note', 'description', 'comments']);

    if (passCol === -1) throw new Error('Cannot find password column in CSV. Expected: password, pass, or pwd');

    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length < 2) continue;

      const password = row[passCol] || '';
      if (!password) continue; // Skip empty passwords

      const url = urlCol >= 0 ? (row[urlCol] || '') : '';
      let title = titleCol >= 0 ? (row[titleCol] || '') : '';
      if (!title && url) {
        try { title = new URL(url).hostname; } catch { title = url; }
      }
      if (!title) title = 'Imported Login';

      const warnings = [];
      if (url && url.startsWith('http://')) warnings.push('HTTP URL');

      items.push({
        source: source,
        title: title,
        url: url,
        username: userCol >= 0 ? (row[userCol] || '') : '',
        password: password,
        notes: noteCol >= 0 ? (row[noteCol] || '') : '',
        warnings: warnings,
        _selected: true,
        _index: items.length
      });
    }

    return items;
  }

  function findCol(headers, candidates) {
    for (const c of candidates) {
      const idx = headers.indexOf(c);
      if (idx >= 0) return idx;
    }
    return -1;
  }

  // Robust CSV parser handling quoted fields
  function parseCsvRows(text) {
    const rows = [];
    let row = [];
    let field = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (i + 1 < text.length && text[i + 1] === '"') {
            field += '"'; i++;
          } else {
            inQuotes = false;
          }
        } else {
          field += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          row.push(field); field = '';
        } else if (ch === '\n') {
          row.push(field); field = '';
          if (row.some(f => f.trim())) rows.push(row);
          row = [];
        } else if (ch === '\r') {
          // skip
        } else {
          field += ch;
        }
      }
    }
    if (field || row.length > 0) { row.push(field); if (row.some(f => f.trim())) rows.push(row); }
    return rows;
  }

  // ===== Preview =====
  function showPreview() {
    els.previewCard.style.display = '';
    els.previewCount.textContent = parsedItems.length;
    renderPreview();
    els.btnImport.disabled = false;

    const warnings = parsedItems.filter(i => i.warnings && i.warnings.length > 0);
    if (warnings.length > 0) {
      els.previewWarnings.innerHTML = '<div class="alert alert-warning" style="margin-bottom:8px;font-size:0.8rem;">' + warnings.length + ' item(s) have warnings. Review before importing.</div>';
    } else {
      els.previewWarnings.innerHTML = '';
    }
  }

  function renderPreview() {
    els.previewBody.innerHTML = parsedItems.map((item, idx) => `
      <tr>
        <td><input type="checkbox" data-idx="${idx}" ${item._selected ? 'checked' : ''}></td>
        <td>${esc(item.title)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:0.8rem;">${esc(item.url)}</td>
        <td>${esc(item.username)}</td>
        <td style="color:#64748b;">••••••••</td>
        <td style="font-size:0.75rem;color:#d97706;">${item.warnings ? item.warnings.join(', ') : ''}</td>
      </tr>
    `).join('');

    // Checkbox listeners
    els.previewBody.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', () => { parsedItems[parseInt(cb.dataset.idx)]._selected = cb.checked; });
    });
  }

  function hidePreview() {
    els.previewCard.style.display = 'none';
    els.previewBody.innerHTML = '';
    els.resultCard.style.display = 'none';
  }

  // ===== Import =====
  async function doImport() {
    const selected = parsedItems.filter(i => i._selected && i.password);
    if (selected.length === 0) { alert('No items selected for import.'); return; }

    // Verify vault is unlocked
    const keyReady = await ensureVaultKey();
    if (!keyReady) {
      els.btnImport.disabled = false;
      return;
    }

    els.btnImport.disabled = true;
    els.progress.style.display = '';

    try {
      // Encrypt items in batches
      const batchSize = 50;
      let totalImported = 0;
      let totalSkipped = 0;
      let totalFailed = 0;
      let serverErrors = [];

      for (let i = 0; i < selected.length; i += batchSize) {
        const batch = selected.slice(i, i + batchSize);
        const encryptedBatch = [];

        for (const item of batch) {
          try {
            const itemData = {
              title: item.title,
              url: item.url,
              username: item.username,
              password: item.password,
              notes: item.notes || '',
              source: item.source,
              imported_at: new Date().toISOString()
            };

            const encrypted = await AMPassCrypto.encryptVaultItem(itemData);
            const searchKey = await AMPassCrypto.deriveSearchKey();
            const titleHash = await AMPassCrypto.computeSearchHash(item.title, searchKey);
            const urlHash = item.url ? await AMPassCrypto.computeSearchHash(extractDomain(item.url), searchKey) : null;
            const strength = AMPassCrypto.calculateStrength(item.password);

            encryptedBatch.push({
              item_type: 'login',
              encrypted_data: encrypted.ciphertext,
              encryption_iv: encrypted.iv,
              title_hash: titleHash,
              url_hash: urlHash,
              password_strength: strength,
              is_weak: strength < 40 ? 1 : 0,
              folder_id: document.getElementById('importFolder')?.value || null
            });
          } catch (e) {
            totalFailed++;
            serverErrors.push('Encryption failed for "' + (item.title || 'Untitled').substring(0, 40) + '": ' + (e.message || 'Unknown error'));
          }
        }

        // Send batch to server
        if (encryptedBatch.length > 0) {
          let result;
          try {
            result = await AMPassAPI.post('/api/vault/import-bulk', { items: encryptedBatch, source: selectedSource });
          } catch (err) {
            result = { success: false, error: err.message };
          }

          if (result.success) {
            totalImported += result.imported || 0;
            totalSkipped += result.skipped || 0;
            totalFailed += result.failed || 0;
            if (result.errors) {
              serverErrors = serverErrors.concat(result.errors);
            }
          } else {
            totalFailed += encryptedBatch.length;
            if (result.error) {
              serverErrors.push(result.error);
            }
          }
        }

        // Update progress
        const pct = Math.round(((i + batch.length) / selected.length) * 100);
        els.progressBar.style.width = pct + '%';
        els.progressText.textContent = `Importing... ${i + batch.length}/${selected.length}`;
      }

      let errorHtml = '';
      if (serverErrors.length > 0) {
        const uniqueErrors = Array.from(new Set(serverErrors)).slice(0, 5);
        errorHtml = `<div class="alert alert-error" style="margin-top:12px;font-size:0.8rem;text-align:left;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;padding:10px;border-radius:6px;width:100%;box-sizing:border-box;">
          <strong>Database Errors:</strong><br>
          ${uniqueErrors.map(err => esc(err)).join('<br>')}
        </div>`;
      }

      // Show result
      els.progress.style.display = 'none';
      els.previewCard.style.display = 'none';
      els.resultCard.style.display = '';
      els.resultContent.innerHTML = `
        <div class="info-grid">
          <div class="info-item"><span>Imported:</span><strong style="color:#16a34a;">${totalImported}</strong></div>
          <div class="info-item"><span>Skipped:</span><strong>${totalSkipped}</strong></div>
          <div class="info-item"><span>Failed:</span><strong style="color:${totalFailed > 0 ? '#dc2626' : 'inherit'};">${totalFailed}</strong></div>
          <div class="info-item"><span>Source:</span><strong>${esc(selectedSource)}</strong></div>
        </div>
        ${errorHtml}
      `;

      // Clear sensitive data
      parsedItems = [];

    } catch (e) {
      els.progress.style.display = 'none';
      alert('Import error: ' + e.message);
      els.btnImport.disabled = false;
    }
  }

  function extractDomain(url) {
    if (!url) return '';
    let host = url;
    try {
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }
      host = new URL(url).hostname;
    } catch {
      // Keep as is
    }
    if (host.startsWith('www.')) {
      host = host.substring(4);
    }
    return host.toLowerCase().trim();
  }

  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  // ===== LastPass CSV Parser =====
  // LastPass exports: url,username,password,totp,extra,name,grouping,fav
  function parseLastPassCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV file is empty or has no data rows');

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const urlCol = findCol(headers, ['url']);
    const userCol = findCol(headers, ['username', 'user']);
    const passCol = findCol(headers, ['password']);
    const nameCol = findCol(headers, ['name', 'title']);
    const noteCol = findCol(headers, ['extra', 'notes']);
    const groupCol = findCol(headers, ['grouping', 'folder', 'group']);
    const favCol = findCol(headers, ['fav', 'favorite']);

    if (passCol === -1) throw new Error('Cannot find password column. Expected: password');

    const items = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length < 2) continue;
      const password = row[passCol] || '';
      if (!password) continue;

      const url = urlCol >= 0 ? (row[urlCol] || '') : '';
      let title = nameCol >= 0 ? (row[nameCol] || '') : '';
      if (!title && url) { try { title = new URL(url).hostname; } catch { title = url; } }
      if (!title) title = 'Imported Login';

      // Skip LastPass "secure note" placeholder URLs
      const cleanUrl = (url === 'http://sn' || url === 'http://') ? '' : url;

      const warnings = [];
      if (cleanUrl && cleanUrl.startsWith('http://')) warnings.push('HTTP URL');

      items.push({
        source: 'lastpass',
        title, url: cleanUrl,
        username: userCol >= 0 ? (row[userCol] || '') : '',
        password,
        notes: noteCol >= 0 ? (row[noteCol] || '') : '',
        folder: groupCol >= 0 ? (row[groupCol] || '') : '',
        warnings, _selected: true, _index: items.length
      });
    }
    return items;
  }

  // ===== Bitwarden CSV Parser =====
  // Bitwarden exports: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
  function parseBitwardenCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV file is empty or has no data rows');

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const nameCol = findCol(headers, ['name']);
    const urlCol = findCol(headers, ['login_uri', 'url']);
    const userCol = findCol(headers, ['login_username', 'username']);
    const passCol = findCol(headers, ['login_password', 'password']);
    const noteCol = findCol(headers, ['notes']);
    const typeCol = findCol(headers, ['type']);
    const folderCol = findCol(headers, ['folder']);

    if (passCol === -1) throw new Error('Cannot find password column. Expected: login_password or password');

    const items = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length < 2) continue;
      const password = row[passCol] || '';
      // Bitwarden exports secure notes with no password — only import logins
      const type = typeCol >= 0 ? (row[typeCol] || '').toLowerCase() : '';
      if (type === 'note' || type === 'card' || type === 'identity') continue;
      if (!password) continue;

      const url = urlCol >= 0 ? (row[urlCol] || '') : '';
      let title = nameCol >= 0 ? (row[nameCol] || '') : '';
      if (!title && url) { try { title = new URL(url).hostname; } catch { title = url; } }
      if (!title) title = 'Imported Login';

      const warnings = [];
      if (url && url.startsWith('http://')) warnings.push('HTTP URL');

      items.push({
        source: 'bitwarden',
        title, url,
        username: userCol >= 0 ? (row[userCol] || '') : '',
        password,
        notes: noteCol >= 0 ? (row[noteCol] || '') : '',
        folder: folderCol >= 0 ? (row[folderCol] || '') : '',
        warnings, _selected: true, _index: items.length
      });
    }
    return items;
  }

  // ===== 1Password CSV Parser =====
  // 1Password exports: Title,Url,Username,Password,Notes,Type (or similar)
  function parse1PasswordCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV file is empty or has no data rows');

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const titleCol = findCol(headers, ['title', 'name']);
    const urlCol = findCol(headers, ['url', 'urls', 'website', 'login url']);
    const userCol = findCol(headers, ['username', 'user', 'login']);
    const passCol = findCol(headers, ['password', 'pass']);
    const noteCol = findCol(headers, ['notes', 'notesplain', 'extra']);

    if (passCol === -1) throw new Error('Cannot find password column. Expected: password');

    const items = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length < 2) continue;
      const password = row[passCol] || '';
      if (!password) continue;

      const url = urlCol >= 0 ? (row[urlCol] || '') : '';
      let title = titleCol >= 0 ? (row[titleCol] || '') : '';
      if (!title && url) { try { title = new URL(url).hostname; } catch { title = url; } }
      if (!title) title = 'Imported Login';

      const warnings = [];
      if (url && url.startsWith('http://')) warnings.push('HTTP URL');

      items.push({
        source: '1password',
        title, url,
        username: userCol >= 0 ? (row[userCol] || '') : '',
        password,
        notes: noteCol >= 0 ? (row[noteCol] || '') : '',
        warnings, _selected: true, _index: items.length
      });
    }
    return items;
  }

  // ===== KeePass CSV Parser =====
  // KeePass exports: "Account","Login Name","Password","Web Site","Comments" (or Title,UserName,Password,URL,Notes)
  function parseKeePassCsv(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1);
    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV file is empty or has no data rows');

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const titleCol = findCol(headers, ['title', 'account', 'group']);
    const urlCol = findCol(headers, ['url', 'web site', 'website']);
    const userCol = findCol(headers, ['username', 'user name', 'login name', 'login']);
    const passCol = findCol(headers, ['password']);
    const noteCol = findCol(headers, ['notes', 'comments']);

    if (passCol === -1) throw new Error('Cannot find password column. Expected: password');

    const items = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length < 2) continue;
      const password = row[passCol] || '';
      if (!password) continue;

      const url = urlCol >= 0 ? (row[urlCol] || '') : '';
      let title = titleCol >= 0 ? (row[titleCol] || '') : '';
      if (!title && url) { try { title = new URL(url).hostname; } catch { title = url; } }
      if (!title) title = 'Imported Login';

      const warnings = [];
      if (url && url.startsWith('http://')) warnings.push('HTTP URL');

      items.push({
        source: 'keepass',
        title, url,
        username: userCol >= 0 ? (row[userCol] || '') : '',
        password,
        notes: noteCol >= 0 ? (row[noteCol] || '') : '',
        warnings, _selected: true, _index: items.length
      });
    }
    return items;
  }
})();
