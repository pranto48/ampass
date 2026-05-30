/**
 * AMPass Extension - Form Detector (Content Script)
 * SECURITY: Runs in page context. Never holds vault key or decrypted data.
 * Detects login forms and communicates with service worker via messages.
 */

(function() {
  'use strict';

  // Avoid running in iframes from different origins
  if (window.self !== window.top) {
    try { window.top.location.href; } catch (e) { return; } // Cross-origin iframe, skip
  }

  const AMPASS_ATTR = 'data-ampass-detected';
  let detectedForms = [];

  /**
   * Find password fields on the page
   */
  function findPasswordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]'))
      .filter(el => !el.hasAttribute(AMPASS_ATTR) && isVisible(el) && !isHidden(el));
  }

  /**
   * Find the username/email field associated with a password field
   */
  function findUsernameField(passwordField) {
    const form = passwordField.closest('form');
    const container = form || passwordField.parentElement?.parentElement?.parentElement || document.body;

    // Look for common username field patterns
    const candidates = Array.from(container.querySelectorAll(
      'input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"], input[autocomplete="username"], input[autocomplete="email"]'
    )).filter(el => isVisible(el) && !isHidden(el));

    // Find the closest one above the password field in DOM order
    const allInputs = Array.from(container.querySelectorAll('input')).filter(el => isVisible(el));
    const pwIndex = allInputs.indexOf(passwordField);

    for (let i = pwIndex - 1; i >= 0; i--) {
      const input = allInputs[i];
      if (input.type === 'password') break; // Stop at another password field
      if (input.type === 'text' || input.type === 'email' || input.type === '' || !input.type) {
        if (candidates.includes(input) || isLikelyUsername(input)) {
          return input;
        }
      }
    }

    // Fallback: first candidate
    return candidates[0] || null;
  }

  /**
   * Check if an input is likely a username field
   */
  function isLikelyUsername(input) {
    const indicators = ['user', 'login', 'email', 'account', 'name', 'id'];
    const attrs = (input.name + ' ' + input.id + ' ' + input.placeholder + ' ' + (input.getAttribute('aria-label') || '')).toLowerCase();
    return indicators.some(ind => attrs.includes(ind));
  }

  const FIELD_PATTERNS = {
    first_name: {
      autocomplete: ['given-name'],
      attributes: [/first[_-]?name/i, /^fname$/i, /given[_-]?name/i]
    },
    last_name: {
      autocomplete: ['family-name'],
      attributes: [/last[_-]?name/i, /^lname$/i, /family[_-]?name/i, /surname/i]
    },
    full_name: {
      autocomplete: ['name'],
      attributes: [/\bname\b/i, /full[_-]?name/i]
    },
    email: {
      types: ['email'],
      autocomplete: ['email'],
      attributes: [/\bemail\b/i, /\be-mail\b/i]
    },
    phone: {
      types: ['tel'],
      autocomplete: ['tel', 'tel-national'],
      attributes: [/phone/i, /telephone/i, /^tel$/i, /mobile/i, /cell/i]
    },
    company: {
      autocomplete: ['organization'],
      attributes: [/company/i, /organization/i, /^org$/i]
    },
    address_line1: {
      autocomplete: ['address-line1', 'street-address'],
      attributes: [/address[_-]?line1/i, /street[_-]?address/i, /address1/i, /\bstreet\b/i, /addr1/i]
    },
    address_line2: {
      autocomplete: ['address-line2'],
      attributes: [/address[_-]?line2/i, /address2/i, /street2/i, /suite/i, /apt/i, /apartment/i]
    },
    city: {
      autocomplete: ['address-level2'],
      attributes: [/city/i, /town/i, /locality/i]
    },
    state: {
      autocomplete: ['address-level1'],
      attributes: [/state/i, /region/i, /province/i, /county/i]
    },
    postcode: {
      autocomplete: ['postal-code'],
      attributes: [/zip/i, /postcode/i, /postal/i, /post[_-]?code/i]
    },
    country: {
      autocomplete: ['country', 'country-name'],
      attributes: [/country/i]
    },
    date_of_birth: {
      autocomplete: ['bday'],
      attributes: [/dob/i, /birthday/i, /birth[_-]?date/i]
    }
  };

  function getLabelText(input) {
    if (input.id) {
      const label = document.querySelector(`label[for="${input.id}"]`);
      if (label) return label.textContent;
    }
    const parentLabel = input.closest('label');
    if (parentLabel) return parentLabel.textContent;
    return '';
  }

  function classifyField(input) {
    if (input.type === 'password' || isHidden(input) || !isVisible(input)) return null;

    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase().trim();
    if (autocomplete) {
      for (const [key, pattern] of Object.entries(FIELD_PATTERNS)) {
        if (pattern.autocomplete.includes(autocomplete)) {
          return key;
        }
      }
    }

    const labelText = getLabelText(input).toLowerCase();
    const attributesText = [
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('aria-label'),
      input.getAttribute('title')
    ].filter(Boolean).join(' ').toLowerCase();

    const combinedText = attributesText + ' ' + labelText;

    for (const [key, pattern] of Object.entries(FIELD_PATTERNS)) {
      if (pattern.types && pattern.types.includes(input.type)) {
        return key;
      }
      for (const regex of pattern.attributes) {
        if (regex.test(combinedText)) {
          return key;
        }
      }
    }

    return null;
  }

  window.__ampassClassifyField = classifyField;

  /**
   * Check if element is visible
   */
  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' &&
           el.offsetWidth > 0 && el.offsetHeight > 0;
  }

  /**
   * Check if element is intentionally hidden (honeypot detection)
   */
  function isHidden(el) {
    if (el.type === 'hidden') return true;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return true;
    if (el.tabIndex === -1 && el.getAttribute('aria-hidden') === 'true') return true;
    return false;
  }

  /**
   * Detect login and identity forms and notify service worker
   */
  function detectForms() {
    const passwordFields = findPasswordFields();
    
    passwordFields.forEach(pwField => {
      pwField.setAttribute(AMPASS_ATTR, 'true');
      const usernameField = findUsernameField(pwField);

      const formData = {
        type: 'login',
        passwordField: pwField,
        usernameField: usernameField,
        form: pwField.closest('form')
      };

      detectedForms.push(formData);

      // Add AMPass icon indicator to password field
      addFieldIndicator(pwField, formData);
      if (usernameField) {
        usernameField.setAttribute(AMPASS_ATTR, 'true');
      }
    });

    // Detect identity fields/forms
    detectIdentityForms();

    // Notify service worker about detected login forms
    const loginForms = detectedForms.filter(f => f.type === 'login' || !f.type);
    if (loginForms.length > 0) {
      chrome.runtime.sendMessage({
        type: 'GET_MATCHES',
        payload: { url: window.location.href }
      }).catch(() => {});
    }
  }

  /**
   * Scan page for identity and address forms
   */
  function detectIdentityForms() {
    // Find all visible input/select elements that don't have AMPASS_ATTR
    const inputs = Array.from(document.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"]), select'))
      .filter(el => !el.hasAttribute(AMPASS_ATTR) && isVisible(el) && !isHidden(el));

    // Group elements by their form or closest common section container
    const groups = new Map();
    inputs.forEach(input => {
      const container = input.closest('form') || input.closest('fieldset') || input.closest('[role="form"]') || input.closest('div') || document.body;
      if (!groups.has(container)) {
        groups.set(container, []);
      }
      groups.get(container).push(input);
    });

    // Process each group
    for (const [container, fields] of groups.entries()) {
      const classifiedFields = {};
      let fieldCount = 0;

      fields.forEach(field => {
        const fieldType = classifyField(field);
        if (fieldType) {
          classifiedFields[fieldType] = field;
          fieldCount++;
        }
      });

      // If we find 2 or more distinct identity fields, classify it as an identity form
      if (fieldCount >= 2) {
        const identityFormData = {
          type: 'identity',
          fields: classifiedFields,
          form: container
        };
        detectedForms.push(identityFormData);

        // Add indicator to the primary field or first field
        const primaryTypes = ['full_name', 'first_name', 'email'];
        let primaryField = null;
        for (const type of primaryTypes) {
          if (classifiedFields[type]) {
            primaryField = classifiedFields[type];
            break;
          }
        }
        if (!primaryField) {
          const keys = Object.keys(classifiedFields);
          primaryField = classifiedFields[keys[0]];
        }

        if (primaryField) {
          primaryField.setAttribute(AMPASS_ATTR, 'true');
          addFieldIndicator(primaryField, identityFormData);
        }

        // Mark other fields as detected too
        Object.values(classifiedFields).forEach(field => {
          field.setAttribute(AMPASS_ATTR, 'true');
        });
      }
    }
  }

  /**
   * Add a small AMPass icon overlay near a password field.
   * Uses fixed positioning to avoid CSS conflicts with the page.
   * Clicking the icon triggers autofill flow with dropdown support.
   */
  function addFieldIndicator(field, providedFormData = null) {
    if (field.hasAttribute('data-ampass-icon-added')) return;
    field.setAttribute('data-ampass-icon-added', 'true');

    // Find the associated form data for this specific field
    const formData = providedFormData || detectedForms.find(f => f.passwordField === field || (f.fields && Object.values(f.fields).includes(field))) || {
      type: 'login',
      passwordField: field,
      usernameField: findUsernameField(field),
      form: field.closest('form')
    };

    const icon = document.createElement('div');
    icon.className = 'ampass-field-icon';
    icon.title = 'AMPass - Click to autofill';
    icon.innerHTML = `<svg width="16" height="16" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>`;
    icon.style.cssText = 'position:fixed;cursor:pointer;z-index:2147483646;width:22px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:4px;opacity:0.7;transition:opacity 0.2s;pointer-events:auto;background:white;box-shadow:0 1px 4px rgba(0,0,0,0.2);padding:2px;';

    icon.addEventListener('mouseenter', () => icon.style.opacity = '1');
    icon.addEventListener('mouseleave', () => icon.style.opacity = '0.7');
    icon.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleFieldIconClick(icon, formData);
    });

    document.body.appendChild(icon);

    // Position the icon at the right edge of the field
    function positionIcon() {
      const rect = field.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        icon.style.display = 'none';
        return;
      }
      icon.style.display = 'flex';
      icon.style.top = (rect.top + (rect.height - 22) / 2) + 'px';
      icon.style.left = (rect.right - 26) + 'px';
    }

    positionIcon();

    // Reposition on scroll/resize
    let rafId = null;
    function scheduleReposition() {
      if (rafId) return;
      rafId = requestAnimationFrame(() => { positionIcon(); rafId = null; });
    }
    window.addEventListener('scroll', scheduleReposition, { passive: true });
    window.addEventListener('resize', scheduleReposition, { passive: true });

    // Show only when field is visible and focused or hovered
    field.addEventListener('focus', () => { icon.style.opacity = '0.9'; positionIcon(); });
    field.addEventListener('blur', () => { icon.style.opacity = '0.7'; });
  }

  // ================================================================
  // FIELD ICON CLICK HANDLER — autofill flow
  // ================================================================

  /**
   * Handle click on the AMPass field icon.
   * Checks vault status, gets matches, shows dropdown or fills directly.
   */
  function handleFieldIconClick(icon, formData) {
    // Remove any existing dropdown
    removeAmpassDropdown();

    // Check HTTP security
    const url = window.location.href;
    const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1|::1)/i.test(url);
    const isHttps = url.startsWith('https://');

    if (!isHttps && !isLocalhost) {
      // Check if HTTP autofill is allowed
      chrome.storage.local.get('settings', (result) => {
        const settings = result.settings || {};
        if (!settings.allowHttpAutofill) {
          showAmpassInlineMessage(icon, 'Autofill blocked on HTTP page. Enable in extension settings.', null);
          return;
        }
        // HTTP allowed — proceed
        if (formData.type === 'identity') {
          fetchIdentityMatchesAndFill(icon, formData);
        } else {
          fetchMatchesAndFill(icon, formData);
        }
      });
      return;
    }

    if (formData.type === 'identity') {
      fetchIdentityMatchesAndFill(icon, formData);
    } else {
      fetchMatchesAndFill(icon, formData);
    }
  }

  /**
   * Fetch identity matches and show dropdown or fill directly
   */
  function fetchIdentityMatchesAndFill(icon, formData) {
    chrome.runtime.sendMessage({
      type: 'GET_IDENTITIES'
    }).then(response => {
      if (!response) {
        showAmpassInlineMessage(icon, 'Could not connect to AMPass.', 'Open AMPass');
        return;
      }

      if (response.code === 'VAULT_LOCKED' || (!response.success && response.code === 'VAULT_LOCKED')) {
        showAmpassInlineMessage(icon, 'Unlock AMPass to autofill', 'Open AMPass');
        return;
      }

      if (!response.success) {
        showAmpassInlineMessage(icon, response.error || 'AMPass error', null);
        return;
      }

      const matches = response.items || [];

      if (matches.length === 0) {
        showAmpassInlineMessage(icon, 'No saved identities found', 'Open AMPass');
        return;
      }

      if (matches.length === 1) {
        fillSingleIdentityMatch(matches[0], formData);
        return;
      }

      showIdentityDropdown(icon, matches, formData);
    }).catch(() => {
      showAmpassInlineMessage(icon, 'Could not connect to AMPass.', null);
    });
  }

  /**
   * Fill a single identity profile match
   */
  function fillSingleIdentityMatch(match, formData) {
    chrome.runtime.sendMessage({
      type: 'DECRYPT_ITEM',
      payload: { id: match.id }
    }).then(response => {
      if (!response || !response.success || !response.item) {
        showAmpassToast('Could not decrypt this item', 'error');
        return;
      }

      const item = response.item;
      if (window.__ampassAutofillIdentity) {
        window.__ampassAutofillIdentity(item, formData);
        showAmpassToast('Filled by AMPass', 'success');

        chrome.runtime.sendMessage({
          type: 'LOG_USAGE',
          payload: { item_id: match.id, action: 'autofilled', client_type: 'extension' }
        }).catch(() => {});
      } else {
        showAmpassToast('Autofill script not loaded', 'error');
      }
    }).catch(() => {
      showAmpassToast('Could not decrypt this item', 'error');
    });
  }

  /**
   * Render dropdown for matching identities
   */
  function showIdentityDropdown(icon, matches, formData) {
    removeAmpassDropdown();

    const dropdown = document.createElement('div');
    dropdown.id = 'ampass-credential-dropdown';
    dropdown.style.cssText = `
      position: fixed; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 10px;
      padding: 6px 0; min-width: 260px; max-width: 340px; max-height: 280px; overflow-y: auto;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #fafafa; font-size: 13px;
    `;

    const header = document.createElement('div');
    header.style.cssText = 'padding:8px 14px 6px;font-size:11px;color:#71717a;text-transform:uppercase;letter-spacing:0.5px;';
    header.textContent = 'Choose identity (' + matches.length + ')';
    dropdown.appendChild(header);

    matches.forEach(match => {
      const item = document.createElement('div');
      item.style.cssText = 'padding:8px 14px;cursor:pointer;display:flex;flex-direction:column;gap:1px;transition:background 0.15s;';
      item.innerHTML = `
        <span style="font-weight:500;color:#fafafa;font-size:13px;">🪪 ${escHtml(match.title || 'Untitled')}</span>
        <span style="font-size:11px;color:#a1a1aa;">${escHtml(match.name || match.email || '')}</span>
      `;
      item.addEventListener('mouseenter', () => item.style.background = '#27272a');
      item.addEventListener('mouseleave', () => item.style.background = 'transparent');
      item.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        removeAmpassDropdown();
        fillSingleIdentityMatch(match, formData);
      });
      dropdown.appendChild(item);
    });

    document.body.appendChild(dropdown);

    const iconRect = icon.getBoundingClientRect();
    dropdown.style.top = (iconRect.bottom + 4) + 'px';
    dropdown.style.left = Math.max(8, iconRect.right - 280) + 'px';

    requestAnimationFrame(() => {
      const ddRect = dropdown.getBoundingClientRect();
      if (ddRect.bottom > window.innerHeight - 10) {
        dropdown.style.top = (iconRect.top - ddRect.height - 4) + 'px';
      }
      if (ddRect.right > window.innerWidth - 10) {
        dropdown.style.left = (window.innerWidth - ddRect.width - 10) + 'px';
      }
    });

    function closeHandler(e) {
      if (!dropdown.contains(e.target) && e.target !== icon) {
        removeAmpassDropdown();
        document.removeEventListener('click', closeHandler, true);
      }
    }
    setTimeout(() => {
      document.addEventListener('click', closeHandler, true);
    }, 50);
  }

  /**
   * Fetch matches from service worker and handle the result.
   */
  function fetchMatchesAndFill(icon, formData) {
    chrome.runtime.sendMessage({
      type: 'GET_MATCHES',
      payload: { url: window.location.href }
    }).then(response => {
      if (!response) {
        showAmpassInlineMessage(icon, 'Could not connect to AMPass.', 'Open AMPass');
        return;
      }

      // Vault locked
      if (response.code === 'VAULT_LOCKED' || (!response.success && response.code === 'VAULT_LOCKED')) {
        showAmpassInlineMessage(icon, 'Unlock AMPass to autofill', 'Open AMPass');
        return;
      }

      if (!response.success) {
        showAmpassInlineMessage(icon, response.error || 'AMPass error', null);
        return;
      }

      const matches = response.items || [];

      if (matches.length === 0) {
        showAmpassInlineMessage(icon, 'No saved login for this site', 'Open AMPass');
        return;
      }

      if (matches.length === 1) {
        // Single match — decrypt and fill directly
        fillSingleMatch(matches[0], formData);
        return;
      }

      // Multiple matches — show dropdown
      showCredentialDropdown(icon, matches, formData);

    }).catch(() => {
      showAmpassInlineMessage(icon, 'Could not connect to AMPass.', null);
    });
  }

  /**
   * Decrypt a single match and fill the form.
   */
  function fillSingleMatch(match, formData) {
    chrome.runtime.sendMessage({
      type: 'DECRYPT_ITEM',
      payload: { id: match.id }
    }).then(response => {
      if (!response || !response.success || !response.item) {
        showAmpassToast('Could not decrypt this item', 'error');
        return;
      }

      const item = response.item;
      const filled = window.__ampassAutofill
        ? window.__ampassAutofill({ username: item.username || item.email || '', password: item.password || '' }, formData)
        : false;

      if (filled) {
        showAmpassToast('Filled by AMPass', 'success');
        // Log usage
        chrome.runtime.sendMessage({
          type: 'LOG_USAGE',
          payload: { item_id: match.id, action: 'autofilled', client_type: 'extension' }
        }).catch(() => {});
      } else {
        showAmpassToast('Could not find login fields', 'error');
      }
    }).catch(() => {
      showAmpassToast('Could not decrypt this item', 'error');
    });
  }

  // ================================================================
  // DROPDOWN UI
  // ================================================================

  /**
   * Show a credential selection dropdown near the icon.
   */
  function showCredentialDropdown(icon, matches, formData) {
    removeAmpassDropdown();

    const dropdown = document.createElement('div');
    dropdown.id = 'ampass-credential-dropdown';
    dropdown.style.cssText = `
      position: fixed; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 10px;
      padding: 6px 0; min-width: 260px; max-width: 340px; max-height: 280px; overflow-y: auto;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #fafafa; font-size: 13px;
    `;

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'padding:8px 14px 6px;font-size:11px;color:#71717a;text-transform:uppercase;letter-spacing:0.5px;';
    header.textContent = 'Choose login (' + matches.length + ')';
    dropdown.appendChild(header);

    // Items
    matches.forEach(match => {
      const item = document.createElement('div');
      item.style.cssText = 'padding:8px 14px;cursor:pointer;display:flex;flex-direction:column;gap:1px;transition:background 0.15s;';
      item.innerHTML = `
        <span style="font-weight:500;color:#fafafa;font-size:13px;">${escHtml(match.title || 'Untitled')}</span>
        <span style="font-size:11px;color:#a1a1aa;">${escHtml(match.username || '')}</span>
      `;
      item.addEventListener('mouseenter', () => item.style.background = '#27272a');
      item.addEventListener('mouseleave', () => item.style.background = 'transparent');
      item.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        removeAmpassDropdown();
        fillSingleMatch(match, formData);
      });
      dropdown.appendChild(item);
    });

    document.body.appendChild(dropdown);

    // Position near icon
    const iconRect = icon.getBoundingClientRect();
    dropdown.style.top = (iconRect.bottom + 4) + 'px';
    dropdown.style.left = Math.max(8, iconRect.right - 280) + 'px';

    // Adjust if off-screen
    requestAnimationFrame(() => {
      const ddRect = dropdown.getBoundingClientRect();
      if (ddRect.bottom > window.innerHeight - 10) {
        dropdown.style.top = (iconRect.top - ddRect.height - 4) + 'px';
      }
      if (ddRect.right > window.innerWidth - 10) {
        dropdown.style.left = (window.innerWidth - ddRect.width - 10) + 'px';
      }
    });

    // Close on outside click or Escape
    function closeHandler(e) {
      if (!dropdown.contains(e.target) && e.target !== icon) {
        removeAmpassDropdown();
        document.removeEventListener('click', closeHandler, true);
        document.removeEventListener('keydown', escHandler, true);
      }
    }
    function escHandler(e) {
      if (e.key === 'Escape') {
        removeAmpassDropdown();
        document.removeEventListener('click', closeHandler, true);
        document.removeEventListener('keydown', escHandler, true);
      }
    }
    setTimeout(() => {
      document.addEventListener('click', closeHandler, true);
      document.addEventListener('keydown', escHandler, true);
    }, 50);
  }

  function removeAmpassDropdown() {
    const existing = document.getElementById('ampass-credential-dropdown');
    if (existing) existing.remove();
    const msg = document.getElementById('ampass-inline-message');
    if (msg) msg.remove();
  }

  // ================================================================
  // INLINE MESSAGES & TOAST
  // ================================================================

  /**
   * Show a small inline message near the icon (for locked/no-match/error states).
   */
  function showAmpassInlineMessage(icon, message, buttonText) {
    removeAmpassDropdown();

    const msg = document.createElement('div');
    msg.id = 'ampass-inline-message';
    msg.style.cssText = `
      position: fixed; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 10px;
      padding: 12px 16px; min-width: 220px; max-width: 320px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.4);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #a1a1aa; font-size: 13px; line-height: 1.4;
    `;

    let html = `<div style="display:flex;align-items:center;gap:8px;margin-bottom:${buttonText ? '10px' : '0'};">
      <svg width="16" height="16" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>
      <span>${escHtml(message)}</span>
    </div>`;

    if (buttonText) {
      html += `<button id="ampass-inline-btn" style="padding:5px 12px;border-radius:6px;border:none;background:#6366f1;color:white;cursor:pointer;font-size:12px;font-weight:500;margin-top:2px;">${escHtml(buttonText)}</button>`;
    }

    msg.innerHTML = html;
    document.body.appendChild(msg);

    // Position near icon
    const iconRect = icon.getBoundingClientRect();
    msg.style.top = (iconRect.bottom + 4) + 'px';
    msg.style.left = Math.max(8, iconRect.right - 260) + 'px';

    // Button action
    if (buttonText) {
      msg.querySelector('#ampass-inline-btn').addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Try to open desktop app unlock window via native bridge
        chrome.runtime.sendMessage({ type: 'OPEN_DESKTOP_UNLOCK', payload: { pageHost: window.location.hostname } }).then(response => {
          if (response && response.success) {
            removeAmpassDropdown();
            showAmpassToast('AMPass Desktop opened. Unlock, then click the field icon again.', 'info');
          } else {
            // Desktop bridge not available — show fallback
            removeAmpassDropdown();
            showAmpassInlineMessage(icon, 'Click the AMPass extension icon to unlock, or open AMPass Desktop.', null);
          }
        }).catch(() => {
          removeAmpassDropdown();
          showAmpassInlineMessage(icon, 'Click the AMPass extension icon to unlock.', null);
        });
      });
    }

    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      if (document.getElementById('ampass-inline-message')) {
        removeAmpassDropdown();
      }
    }, 5000);

    // Close on outside click
    setTimeout(() => {
      document.addEventListener('click', function handler(e) {
        if (!msg.contains(e.target) && e.target !== icon) {
          removeAmpassDropdown();
          document.removeEventListener('click', handler, true);
        }
      }, true);
    }, 50);
  }

  /**
   * Show a brief toast notification.
   */
  function showAmpassToast(message, type = 'success') {
    const existing = document.getElementById('ampass-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'ampass-toast';
    const bgColor = type === 'success' ? '#16a34a' : type === 'error' ? '#dc2626' : '#6366f1';
    toast.style.cssText = `
      position: fixed; bottom: 20px; right: 20px; z-index: 2147483647;
      background: ${bgColor}; color: white; padding: 10px 18px;
      border-radius: 8px; font-size: 13px; font-weight: 500;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
      animation: ampassFadeIn 0.2s ease;
    `;
    toast.textContent = message;

    if (!document.getElementById('ampass-toast-styles')) {
      const style = document.createElement('style');
      style.id = 'ampass-toast-styles';
      style.textContent = '@keyframes ampassFadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}';
      document.head.appendChild(style);
    }

    document.body.appendChild(toast);
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 3000);
  }

  /**
   * Escape HTML for safe rendering in dropdown/messages.
   */
  function escHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Get detected form data (called by autofill.js)
   */
  window.__ampassGetForms = function() {
    return detectedForms;
  };

  // ===== Run Detection =====
  // Initial detection
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(detectForms, 500));
  } else {
    setTimeout(detectForms, 300);
  }

  // Watch for dynamically added forms (SPAs)
  const observer = new MutationObserver((mutations) => {
    let hasNewInputs = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1 && (node.querySelector('input, select') || node.matches?.('input, select'))) {
            hasNewInputs = true;
            break;
          }
        }
      }
      if (hasNewInputs) break;
    }
    if (hasNewInputs) {
      setTimeout(detectForms, 300);
    }
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });

  // ===== SPA Navigation Cleanup =====
  // When a SPA navigates (pushState / replaceState / popstate), stale autofill
  // icons from the previous "page" linger because the DOM isn't fully replaced.
  // We clean them up and re-run detection after a short debounce.

  function cleanupAmpassIcons() {
    document.querySelectorAll('.ampass-field-icon').forEach(el => el.remove());
    removeAmpassDropdown();
    detectedForms = [];
    // Remove the data attribute so detectForms() will re-process fields
    document.querySelectorAll('[data-ampass-detected]').forEach(el => {
      el.removeAttribute('data-ampass-detected');
      el.removeAttribute('data-ampass-icon-added');
    });
  }

  let spaDebounceTimer = null;
  function onSpaNavigate() {
    if (spaDebounceTimer) clearTimeout(spaDebounceTimer);
    spaDebounceTimer = setTimeout(() => {
      cleanupAmpassIcons();
      setTimeout(detectForms, 400);
    }, 200);
  }

  window.addEventListener('popstate', onSpaNavigate);

  // Intercept pushState / replaceState (History API — used by React Router, Next.js, etc.)
  (function() {
    const _push = history.pushState.bind(history);
    const _replace = history.replaceState.bind(history);
    history.pushState = function(...args) { _push(...args); onSpaNavigate(); };
    history.replaceState = function(...args) { _replace(...args); onSpaNavigate(); };
  })();
})();
