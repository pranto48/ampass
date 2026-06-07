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
      'input[type="text"], input[type="email"], input:not([type]), input[name*="user"], input[name*="login"], input[name*="email"], input[autocomplete="username"], input[autocomplete="email"]'
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
        addFieldIndicator(usernameField, formData);
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

      // Auto-fill on page load: if there's exactly 1 match, fill automatically
      // This gives a LastPass-like experience where logins are pre-filled
      tryAutoFillOnLoad(loginForms[0]);
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
    icon.style.cssText = 'position:absolute;cursor:pointer;z-index:2147483646;width:22px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:4px;opacity:0.7;transition:opacity 0.2s;pointer-events:auto;background:white;box-shadow:0 1px 4px rgba(0,0,0,0.2);padding:2px;';

    icon.addEventListener('mouseenter', () => icon.style.opacity = '1');
    icon.addEventListener('mouseleave', () => icon.style.opacity = '0.7');
    icon.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleFieldIconClick(icon, formData);
    });

    document.body.appendChild(icon);

    // Focus-triggered dropdown: show credential dropdown when the field gets focus
    // This mimics LastPass/StickyPassword inline popup behavior
    field.addEventListener('focus', () => {
      // Only trigger if we haven't already auto-filled and there's no dropdown showing
      if (field.getAttribute('data-ampass-filled') === 'true') return;
      if (document.getElementById('ampass-credential-dropdown')) return;

      // Small delay to avoid interfering with click-to-fill
      clearTimeout(field.__ampassFocusTimer);
      field.__ampassFocusTimer = setTimeout(() => {
        if (document.activeElement === field && !document.getElementById('ampass-credential-dropdown')) {
          // Check if there are matches before showing the dropdown automatically
          if (formData.type === 'login') {
            chrome.runtime.sendMessage({
              type: 'GET_MATCHES',
              payload: { url: window.location.href }
            }).then(response => {
              if (response && response.success && response.items && response.items.length > 0) {
                handleFieldIconClick(icon, formData);
              }
            }).catch(() => {});
          } else if (formData.type === 'identity') {
            chrome.runtime.sendMessage({
              type: 'GET_IDENTITIES'
            }).then(response => {
              if (response && response.success && response.items && response.items.length > 0) {
                handleFieldIconClick(icon, formData);
              }
            }).catch(() => {});
          }
        }
      }, 400);
    });

    field.addEventListener('blur', () => {
      clearTimeout(field.__ampassFocusTimer);
    });

    // Position the icon at the right edge of the field
    function positionIcon() {
      const rect = field.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        icon.style.display = 'none';
        return;
      }
      const bodyRect = document.body.getBoundingClientRect();
      icon.style.display = 'flex';
      icon.style.top = (rect.top - bodyRect.top + (rect.height - 22) / 2) + 'px';
      icon.style.left = (rect.right - bodyRect.left - 26) + 'px';
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
    removeAmpassDropdown();

    // Check HTTP security
    const url = window.location.href;
    const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1|::1)/i.test(url);
    const isHttps = url.startsWith('https://');

    if (!isHttps && !isLocalhost) {
      chrome.storage.local.get('settings', (result) => {
        const settings = result.settings || {};
        if (settings.allowHttpAutofill === false) {
          showAmpassInlineMessage(icon, 'Autofill blocked on HTTP page. Enable in extension settings.', null);
          return;
        }
        processFieldIconClick(icon, formData);
      });
      return;
    }

    processFieldIconClick(icon, formData);
  }

  function processFieldIconClick(icon, formData) {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }).then(status => {
      if (!status) {
        showAmpassInlineMessage(icon, 'Could not connect to AMPass.', 'Open AMPass');
        return;
      }

      if (!status.configured) {
        showAmpassInlineMessage(icon, 'AMPass is not configured. Please click the extension icon to set up.', null);
        return;
      }

      if (!status.authenticated || !status.unlocked) {
        showAmpassAuthForm(icon, status, formData);
        return;
      }

      fetchVaultDataAndShowDropdown(icon, formData);
    }).catch(() => {
      showAmpassInlineMessage(icon, 'Could not connect to AMPass.', null);
    });
  }

  function showAmpassAuthForm(icon, status, formData) {
    removeAmpassDropdown();

    const bubble = document.createElement('div');
    bubble.id = 'ampass-credential-dropdown';
    bubble.style.cssText = `
      position: absolute; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 12px;
      padding: 16px; width: 280px;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #fafafa; font-size: 13px;
    `;

    const title = document.createElement('div');
    title.style.cssText = 'font-weight: 600; font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; color: #fafafa;';
    
    const isLoginState = !status.authenticated;
    title.innerHTML = isLoginState 
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg> Sign In to AMPass`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Unlock Vault`;
    bubble.appendChild(title);

    const form = document.createElement('form');
    form.style.cssText = 'display: flex; flex-direction: column; gap: 10px;';

    const errEl = document.createElement('div');
    errEl.style.cssText = 'color: #ef4444; font-size: 11px; display: none; word-break: break-word;';
    form.appendChild(errEl);

    if (isLoginState) {
      const usernameInput = document.createElement('input');
      usernameInput.type = 'text';
      usernameInput.placeholder = 'Username or Email';
      usernameInput.style.cssText = 'background: #27272a; border: 1px solid #3f3f46; border-radius: 6px; padding: 8px 10px; color: white; outline: none; font-size: 12px;';
      form.appendChild(usernameInput);

      const pwWrapper = document.createElement('div');
      pwWrapper.style.cssText = 'position: relative;';

      const passwordInput = document.createElement('input');
      passwordInput.type = 'password';
      passwordInput.placeholder = 'Password';
      passwordInput.style.cssText = 'background: #27272a; border: 1px solid #3f3f46; border-radius: 6px; padding: 8px 30px 8px 10px; color: white; outline: none; font-size: 12px; width: 100%; box-sizing: border-box;';
      pwWrapper.appendChild(passwordInput);

      const eyeBtn = document.createElement('span');
      eyeBtn.innerHTML = '👁️';
      eyeBtn.style.cssText = 'position: absolute; right: 8px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 12px; opacity: 0.6;';
      eyeBtn.addEventListener('click', () => {
        passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        eyeBtn.innerHTML = passwordInput.type === 'password' ? '👁️' : '🙈';
      });
      pwWrapper.appendChild(eyeBtn);
      form.appendChild(pwWrapper);

      const submitBtn = document.createElement('button');
      submitBtn.type = 'submit';
      submitBtn.textContent = 'Sign In';
      submitBtn.style.cssText = 'background: #6366f1; color: white; border: none; border-radius: 6px; padding: 8px; font-weight: 600; cursor: pointer; font-size: 12px;';
      form.appendChild(submitBtn);

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const un = usernameInput.value.trim();
        const pw = passwordInput.value;
        if (!un || !pw) return;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in...';
        errEl.style.display = 'none';

        chrome.runtime.sendMessage({
          type: 'LOGIN',
          payload: { serverUrl: status.serverUrl, username: un, password: pw, trustBrowser: true }
        }).then(loginResult => {
          if (loginResult && loginResult.success) {
            chrome.runtime.sendMessage({ type: 'GET_STATUS' }).then(newStatus => {
              showAmpassAuthForm(icon, newStatus, formData);
            });
          } else {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
            errEl.textContent = (loginResult && loginResult.error) || 'Login failed';
            errEl.style.display = 'block';
          }
        }).catch(err => {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign In';
          errEl.textContent = err.message || 'Login failed';
          errEl.style.display = 'block';
        });
      });

    } else {
      const pwWrapper = document.createElement('div');
      pwWrapper.style.cssText = 'position: relative;';

      const passwordInput = document.createElement('input');
      passwordInput.type = 'password';
      passwordInput.placeholder = 'Master Password';
      passwordInput.style.cssText = 'background: #27272a; border: 1px solid #3f3f46; border-radius: 6px; padding: 8px 30px 8px 10px; color: white; outline: none; font-size: 12px; width: 100%; box-sizing: border-box;';
      pwWrapper.appendChild(passwordInput);

      const eyeBtn = document.createElement('span');
      eyeBtn.innerHTML = '👁️';
      eyeBtn.style.cssText = 'position: absolute; right: 8px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 12px; opacity: 0.6;';
      eyeBtn.addEventListener('click', () => {
        passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        eyeBtn.innerHTML = passwordInput.type === 'password' ? '👁️' : '🙈';
      });
      pwWrapper.appendChild(eyeBtn);
      form.appendChild(pwWrapper);

      const submitBtn = document.createElement('button');
      submitBtn.type = 'submit';
      submitBtn.textContent = 'Unlock Vault';
      submitBtn.style.cssText = 'background: #6366f1; color: white; border: none; border-radius: 6px; padding: 8px; font-weight: 600; cursor: pointer; font-size: 12px;';
      form.appendChild(submitBtn);

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const pw = passwordInput.value;
        if (!pw) return;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Unlocking...';
        errEl.style.display = 'none';

        chrome.runtime.sendMessage({
          type: 'UNLOCK',
          payload: { masterPassword: pw }
        }).then(unlockResult => {
          if (unlockResult && unlockResult.success) {
            removeAmpassDropdown();
            fetchVaultDataAndShowDropdown(icon, formData);
          } else {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Unlock Vault';
            errEl.textContent = (unlockResult && unlockResult.error) || 'Invalid master password';
            errEl.style.display = 'block';
          }
        }).catch(err => {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Unlock Vault';
          errEl.textContent = err.message || 'Unlock failed';
          errEl.style.display = 'block';
        });
      });
    }

    const divider = document.createElement('div');
    divider.style.cssText = 'height: 1px; background: #27272a; margin: 12px 0;';
    form.appendChild(divider);

    const desktopBtn = document.createElement('button');
    desktopBtn.type = 'button';
    desktopBtn.textContent = 'Unlock with Desktop App';
    desktopBtn.style.cssText = 'background: #27272a; border: 1px solid #3f3f46; color: #a1a1aa; border-radius: 6px; padding: 8px; font-weight: 600; cursor: pointer; font-size: 12px;';
    desktopBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({
        type: 'OPEN_DESKTOP_UNLOCK',
        payload: { pageHost: window.location.hostname }
      }).then(response => {
        if (response && response.success) {
          removeAmpassDropdown();
          showAmpassToast('AMPass Desktop opened. Unlock, then click the field icon again.', 'info');
        } else {
          errEl.textContent = 'AMPass Desktop bridge not available.';
          errEl.style.display = 'block';
        }
      }).catch(() => {
        errEl.textContent = 'Could not contact AMPass Desktop.';
        errEl.style.display = 'block';
      });
    });
    form.appendChild(desktopBtn);

    bubble.appendChild(form);
    document.body.appendChild(bubble);

    const bodyRect = document.body.getBoundingClientRect();
    const iconRect = icon.getBoundingClientRect();
    bubble.style.top = (iconRect.bottom - bodyRect.top + 4) + 'px';
    bubble.style.left = (Math.max(8, iconRect.right - 280) - bodyRect.left) + 'px';

    requestAnimationFrame(() => {
      const ddRect = bubble.getBoundingClientRect();
      const currentBodyRect = document.body.getBoundingClientRect();
      if (ddRect.bottom > window.innerHeight - 10) {
        bubble.style.top = (iconRect.top - currentBodyRect.top - ddRect.height - 4) + 'px';
      }
      if (ddRect.right > window.innerWidth - 10) {
        bubble.style.left = (window.innerWidth - ddRect.width - 10 - currentBodyRect.left) + 'px';
      }
    });

    function closeHandler(e) {
      if (!bubble.contains(e.target) && e.target !== icon) {
        removeAmpassDropdown();
        document.removeEventListener('click', closeHandler, true);
      }
    }
    setTimeout(() => {
      document.addEventListener('click', closeHandler, true);
    }, 50);
  }

  function getPasswordFieldsInForm(formElement) {
    if (!formElement) return [];
    return Array.from(formElement.querySelectorAll('input[type="password"], input[data-ampass-original-type="password"]'));
  }

  function togglePasswordsVisibility(formElement) {
    const fields = getPasswordFieldsInForm(formElement);
    if (fields.length === 0) return false;
    const isShowing = fields[0].type === 'text';
    fields.forEach(f => {
      if (!f.hasAttribute('data-ampass-original-type')) {
        f.setAttribute('data-ampass-original-type', 'password');
      }
      f.type = isShowing ? 'password' : 'text';
    });
    return !isShowing;
  }

  function fetchVaultDataAndShowDropdown(icon, formData) {
    chrome.runtime.sendMessage({
      type: 'GET_MATCHES',
      payload: { url: window.location.href }
    }).then(loginResponse => {
      if (!loginResponse || !loginResponse.success) {
        showAmpassInlineMessage(icon, (loginResponse && loginResponse.error) || 'AMPass error', null);
        return;
      }

      const loginMatches = loginResponse.items || [];

      chrome.runtime.sendMessage({
        type: 'GET_IDENTITIES'
      }).then(identityResponse => {
        const identities = (identityResponse && identityResponse.success) ? (identityResponse.items || []) : [];
        showUnifiedDropdown(icon, loginMatches, identities, formData);
      }).catch(() => {
        showUnifiedDropdown(icon, loginMatches, [], formData);
      });
    }).catch(() => {
      showAmpassInlineMessage(icon, 'Could not connect to AMPass.', null);
    });
  }

  /**
   * Fill a single login profile match
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
      let filled = false;
      if (window.__ampassPerformIdentityAutofill) {
        window.__ampassPerformIdentityAutofill(item);
        filled = true;
      } else if (window.__ampassAutofillIdentity) {
        window.__ampassAutofillIdentity(item, formData);
        filled = true;
      }

      if (filled) {
        showAmpassToast('Identity filled by AMPass', 'success');
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
   * Render unified dropdown for logins, identities, password generation, and toggles
   */
  function showUnifiedDropdown(icon, loginMatches, identities, formData) {
    removeAmpassDropdown();

    const dropdown = document.createElement('div');
    dropdown.id = 'ampass-credential-dropdown';
    dropdown.style.cssText = `
      position: absolute; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 10px;
      padding: 6px 0; min-width: 260px; max-width: 340px; max-height: 320px; overflow-y: auto;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #fafafa; font-size: 13px;
    `;

    const headerStyle = 'padding: 8px 14px 4px; font-size: 10px; font-weight: 600; color: #818cf8; text-transform: uppercase; letter-spacing: 0.5px;';
    const itemStyle = 'padding: 8px 14px; cursor: pointer; display: flex; flex-direction: column; gap: 1px; transition: background 0.15s;';
    const actionItemStyle = 'padding: 8px 14px; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: background 0.15s; color: #fafafa; font-weight: 500;';
    const dividerStyle = 'height: 1px; background: #27272a; margin: 4px 0;';

    let hasContent = false;

    // 1. Logins Section
    if (loginMatches.length > 0) {
      hasContent = true;
      const header = document.createElement('div');
      header.style.cssText = headerStyle;
      header.textContent = 'Matching Logins';
      dropdown.appendChild(header);

      loginMatches.forEach(match => {
        const item = document.createElement('div');
        item.style.cssText = itemStyle;
        item.innerHTML = `
          <span style="font-weight:500;color:#fafafa;font-size:13px;">🔑 ${escHtml(match.title || 'Untitled')}</span>
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
    }

    // 2. Identities Section
    if (identities.length > 0) {
      if (hasContent) {
        const divider = document.createElement('div');
        divider.style.cssText = dividerStyle;
        dropdown.appendChild(divider);
      }
      hasContent = true;

      const header = document.createElement('div');
      header.style.cssText = headerStyle;
      header.textContent = 'Identities';
      dropdown.appendChild(header);

      identities.forEach(match => {
        const item = document.createElement('div');
        item.style.cssText = itemStyle;
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
    }

    // 3. Tools Section
    const activeField = document.activeElement;
    const formElement = (formData && formData.form) || (activeField && activeField.closest('form')) || document.body;
    const passwordFields = getPasswordFieldsInForm(formElement);

    if (passwordFields.length > 0 || hasContent) {
      const divider = document.createElement('div');
      divider.style.cssText = dividerStyle;
      dropdown.appendChild(divider);
    }

    const toolsHeader = document.createElement('div');
    toolsHeader.style.cssText = headerStyle;
    toolsHeader.textContent = 'Tools';
    dropdown.appendChild(toolsHeader);

    // Password Generator Option
    if (passwordFields.length > 0) {
      const genItem = document.createElement('div');
      genItem.style.cssText = actionItemStyle;
      genItem.innerHTML = `<span>✨</span><span>Generate Password</span>`;
      genItem.addEventListener('mouseenter', () => genItem.style.background = '#27272a');
      genItem.addEventListener('mouseleave', () => genItem.style.background = 'transparent');
      genItem.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        removeAmpassDropdown();
        
        // Generate secure password via service worker
        chrome.runtime.sendMessage({
          type: 'GENERATE_PASSWORD',
          payload: { length: 16 }
        }).then(response => {
          if (response && response.success && response.password) {
            const password = response.password;
            
            // Fill all password fields in the form
            passwordFields.forEach(f => {
              if (window.__ampassFillField) {
                window.__ampassFillField(f, password);
              } else {
                f.value = password;
                f.dispatchEvent(new Event('input', { bubbles: true }));
                f.dispatchEvent(new Event('change', { bubbles: true }));
              }
              f.setAttribute('data-ampass-filled', 'true');
            });

            // Reveal/show password so user can see it
            passwordFields.forEach(f => {
              f.type = 'text';
              f.setAttribute('data-ampass-original-type', 'password');
            });

            // Copy to clipboard
            navigator.clipboard.writeText(password).catch(() => {});
            showAmpassToast('Password generated and copied to clipboard!', 'success');
          }
        }).catch(() => {
          showAmpassToast('Failed to generate password', 'error');
        });
      });
      dropdown.appendChild(genItem);

      // Show/Hide passwords toggle option
      const isShowing = passwordFields[0].type === 'text';
      const toggleItem = document.createElement('div');
      toggleItem.style.cssText = actionItemStyle;
      toggleItem.innerHTML = isShowing 
        ? `<span>🙈</span><span>Hide Passwords</span>` 
        : `<span>👁️</span><span>Show Passwords</span>`;
      toggleItem.addEventListener('mouseenter', () => toggleItem.style.background = '#27272a');
      toggleItem.addEventListener('mouseleave', () => toggleItem.style.background = 'transparent');
      toggleItem.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        removeAmpassDropdown();
        
        const newStateShowing = togglePasswordsVisibility(formElement);
        showAmpassToast(newStateShowing ? 'Passwords visible' : 'Passwords hidden', 'info');
      });
      dropdown.appendChild(toggleItem);
    }

    // Open AMPass Option
    const openItem = document.createElement('div');
    openItem.style.cssText = actionItemStyle;
    openItem.innerHTML = `<span>⚙️</span><span>Open AMPass</span>`;
    openItem.addEventListener('mouseenter', () => openItem.style.background = '#27272a');
    openItem.addEventListener('mouseleave', () => openItem.style.background = 'transparent');
    openItem.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      removeAmpassDropdown();
      chrome.runtime.sendMessage({ type: 'OPEN_DESKTOP_UNLOCK', payload: { pageHost: window.location.hostname } }).then(response => {
        if (!response || !response.success) {
          showAmpassToast('Click the extension icon to open AMPass.', 'info');
        }
      }).catch(() => {
        showAmpassToast('Click the extension icon to open AMPass.', 'info');
      });
    });
    dropdown.appendChild(openItem);

    document.body.appendChild(dropdown);

    // Position near icon
    const bodyRect = document.body.getBoundingClientRect();
    const iconRect = icon.getBoundingClientRect();
    dropdown.style.top = (iconRect.bottom - bodyRect.top + 4) + 'px';
    dropdown.style.left = (Math.max(8, iconRect.right - 280) - bodyRect.left) + 'px';

    // Adjust if off-screen
    requestAnimationFrame(() => {
      const ddRect = dropdown.getBoundingClientRect();
      const currentBodyRect = document.body.getBoundingClientRect();
      if (ddRect.bottom > window.innerHeight - 10) {
        dropdown.style.top = (iconRect.top - currentBodyRect.top - ddRect.height - 4) + 'px';
      }
      if (ddRect.right > window.innerWidth - 10) {
        dropdown.style.left = (window.innerWidth - ddRect.width - 10 - currentBodyRect.left) + 'px';
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
      position: absolute; z-index: 2147483647;
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
    const bodyRect = document.body.getBoundingClientRect();
    const iconRect = icon.getBoundingClientRect();
    msg.style.top = (iconRect.bottom - bodyRect.top + 4) + 'px';
    msg.style.left = (Math.max(8, iconRect.right - 260) - bodyRect.left) + 'px';

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

  /**
   * Auto-fill on page load (like LastPass).
   * If exactly 1 match exists for this page, fill it automatically.
   * Gated by user setting (default: enabled).
   */
  function tryAutoFillOnLoad(formData) {
    // Don't auto-fill if already filled
    if (formData.passwordField && formData.passwordField.getAttribute('data-ampass-filled') === 'true') return;
    // Don't auto-fill if the password field already has a value (browser autofill)
    if (formData.passwordField && formData.passwordField.value) return;

    chrome.runtime.sendMessage({
      type: 'AUTOFILL_PAGE_LOAD',
      payload: { url: window.location.href }
    }).then(response => {
      if (!response || !response.success || !response.credentials) return;

      const { username, password } = response.credentials;
      if (!password) return;

      // Use the global autofill function
      if (window.__ampassAutofill) {
        const filled = window.__ampassAutofill({ username, password }, formData);
        if (filled) {
          // Mark as auto-filled to prevent save-detector from re-capturing
          if (formData.passwordField) formData.passwordField.setAttribute('data-ampass-filled', 'true');
          if (formData.usernameField) formData.usernameField.setAttribute('data-ampass-filled', 'true');

          showAmpassToast('Auto-filled by AMPass', 'success');

          // Log usage
          if (response.itemId) {
            chrome.runtime.sendMessage({
              type: 'LOG_USAGE',
              payload: { item_id: response.itemId, action: 'autofilled_pageload', client_type: 'extension' }
            }).catch(() => {});
          }
        }
      }
    }).catch(() => {});
  }

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
