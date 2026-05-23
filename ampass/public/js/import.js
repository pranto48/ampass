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
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target.result;
      try {
        if (selectedSource === 'sticky_password') {
          parsedItems = parseStickyPasswordTxt(text);
        } else {
          parsedItems = parseBrowserCsv(text, selectedSource);
        }
        showPreview();
      } catch (err) {
        alert('Parse error: ' + err.message);
      }
    };
    reader.readAsText(file, 'UTF-8');
  });

  els.btnSelectAll.addEventListener('click', () => { parsedItems.forEach(i => i._selected = true); renderPreview(); });
  els.btnUnselectAll.addEventListener('click', () => { parsedItems.forEach(i => i._selected = false); renderPreview(); });
  els.checkAll.addEventListener('change', () => { parsedItems.forEach(i => i._selected = els.checkAll.checked); renderPreview(); });
  els.btnCancel.addEventListener('click', () => { parsedItems = []; hidePreview(); });
  els.btnImport.addEventListener('click', doImport);

  // ===== Sticky Password TXT Parser =====
  function parseStickyPasswordTxt(text) {
    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const items = [];
    let current = null;
    let currentLogin = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.startsWith('Account name:')) {
        // Save previous credential if exists
        if (currentLogin && current) {
          items.push(buildStickyItem(current, currentLogin));
          currentLogin = null;
        }
        current = { accountName: line.substring(13).trim(), link: '', description: '', logins: [] };
        currentLogin = null;
      } else if (line.startsWith('Link:') && current) {
        current.link = line.substring(5).trim();
      } else if (line.startsWith('Description:') && current) {
        current.description = line.substring(12).trim();
      } else if (line.startsWith('Logins:') && current) {
        // Just metadata, ignore count
      } else if (line.startsWith('Login:') && current) {
        // Save previous login if password was missing
        if (currentLogin) {
          currentLogin.warnings = currentLogin.warnings || [];
          if (!currentLogin.password) currentLogin.warnings.push('Missing password');
          items.push(buildStickyItem(current, currentLogin));
        }
        currentLogin = { username: line.substring(6).trim(), password: '', warnings: [] };
      } else if (line.startsWith('Password:') && current && currentLogin) {
        // Keep everything after "Password:" — only strip one optional leading space
        let raw = line.substring('Password:'.length);
        if (raw.startsWith(' ')) raw = raw.substring(1);
        currentLogin.password = raw;
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
      try { title = new URL(account.link).hostname; } catch { title = account.link; }
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

    els.btnImport.disabled = true;
    els.progress.style.display = '';

    try {
      // Encrypt items in batches
      const batchSize = 50;
      let totalImported = 0;
      let totalSkipped = 0;
      let totalFailed = 0;

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
          }
        }

        // Send batch to server
        if (encryptedBatch.length > 0) {
          const resp = await fetch(window.AMPass.baseUrl + '/api/vault/import-bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.AMPass.csrfToken },
            body: JSON.stringify({ items: encryptedBatch, source: selectedSource })
          });
          const result = await resp.json();
          if (result.success) {
            totalImported += result.imported || 0;
            totalSkipped += result.skipped || 0;
            totalFailed += result.failed || 0;
          } else {
            totalFailed += encryptedBatch.length;
          }
        }

        // Update progress
        const pct = Math.round(((i + batch.length) / selected.length) * 100);
        els.progressBar.style.width = pct + '%';
        els.progressText.textContent = `Importing... ${i + batch.length}/${selected.length}`;
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
    try { return new URL(url).hostname; } catch { return url; }
  }

  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
})();
