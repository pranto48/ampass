/**
 * AMPass Extension - Autofill (Content Script)
 * SECURITY: Never holds vault key. Receives plaintext credentials from
 * service worker only during fill operation, then clears them.
 * Never autofills without user action.
 */

(function() {
  'use strict';

  /**
   * Exposed autofill function for form-detector.js to call directly.
   * SECURITY: Credentials exist in memory only during this operation.
   * @param {object} payload - { username, password }
   * @param {object|null} preferredFormData - { passwordField, usernameField } or null for auto-detect
   * @returns {boolean} true if fill succeeded
   */
  window.__ampassAutofill = function(payload, preferredFormData = null) {
    if (!payload) return false;
    const { username, password } = payload;

    if (preferredFormData && preferredFormData.passwordField) {
      // Use the specific form fields provided
      fillFieldsSequentially(preferredFormData.usernameField, username, preferredFormData.passwordField, password);
    } else {
      // Fallback: auto-detect fields
      performAutofill(payload);
    }

    // Clear sensitive data
    payload.username = null;
    payload.password = null;
    return true;
  };

  // Listen for autofill commands from popup/service worker
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'AUTOFILL') {
      // SECURITY: Verify this is a safe context for autofill
      const url = window.location.href;
      const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1|::1)/i.test(url);
      const isHttps = url.startsWith('https://');

      if (!isHttps && !isLocalhost) {
        // Check if user explicitly allowed HTTP autofill
        chrome.storage.local.get('settings', (result) => {
          const settings = result.settings || {};
          if (settings.allowHttpAutofill === false) {
            sendResponse({ success: false, error: 'Autofill blocked on HTTP page' });
            return;
          }
          performAutofill(msg.payload);
          sendResponse({ success: true });
        });
        return true; // async response
      }

      performAutofill(msg.payload);
      sendResponse({ success: true });
    } else if (msg.type === 'AUTOFILL_IDENTITY') {
      performIdentityAutofill(msg.payload);
      sendResponse({ success: true });
    }
    return false;
  });

  /**
   * Fill credentials into detected form fields
   * SECURITY: Credentials exist in memory only during this operation.
   */
  function performAutofill(payload) {
    const { username, password } = payload;
    const forms = window.__ampassGetForms ? window.__ampassGetForms() : [];

    if (forms.length === 0) {
      // Try to find fields directly
      const pwField = document.querySelector('input[type="password"]:not([data-ampass-filled])');
      if (!pwField) return;

      const form = pwField.closest('form') || document.body;
      const usernameField = form.querySelector('input[type="email"], input[type="text"], input:not([type]), input[autocomplete="username"]');

      fillFieldsSequentially(usernameField, username, pwField, password);
    } else {
      // Use detected form data
      const formData = forms[0]; // Fill first detected form
      fillFieldsSequentially(formData.usernameField, username, formData.passwordField, password);
    }

    // Clear sensitive data from local scope
    // (JavaScript GC will handle the rest, but we null the references)
    payload.username = null;
    payload.password = null;
  }

  /**
   * Scan page and perform identity autofill
   */
  function performIdentityAutofill(payload) {
    const inputs = Array.from(document.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"]), select'))
      .filter(el => {
        const style = window.getComputedStyle(el);
        const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && el.offsetWidth > 0 && el.offsetHeight > 0;
        return isVisible && el.type !== 'hidden';
      });

    const classified = {};
    inputs.forEach(input => {
      const fieldType = window.__ampassClassifyField ? window.__ampassClassifyField(input) : null;
      if (fieldType && !classified[fieldType]) {
        classified[fieldType] = input;
      }
    });

    const mockFormData = {
      type: 'identity',
      fields: classified
    };

    window.__ampassAutofillIdentity(payload, mockFormData);
  }

  /**
   * Exposed identity autofill function
   */
  window.__ampassAutofillIdentity = function(identityData, identityFormData) {
    if (!identityData || !identityFormData || !identityFormData.fields) return false;

    const fields = identityFormData.fields;

    let firstName = identityData.first_name || '';
    let lastName = identityData.last_name || '';
    let fullName = identityData.full_name || '';

    if (!fullName && firstName) {
      fullName = firstName + (lastName ? ' ' + lastName : '');
    }
    if (!firstName && fullName) {
      const parts = fullName.trim().split(/\s+/);
      firstName = parts[0] || '';
      lastName = parts.slice(1).join(' ') || '';
    }

    const mapping = {
      first_name: firstName,
      last_name: lastName,
      full_name: fullName,
      email: identityData.email || '',
      phone: identityData.phone || '',
      company: identityData.company || '',
      address_line1: identityData.address_line1 || '',
      address_line2: identityData.address_line2 || '',
      city: identityData.city || '',
      state: identityData.state || '',
      postcode: identityData.postcode || '',
      country: identityData.country || '',
      date_of_birth: identityData.date_of_birth || ''
    };

    for (const [fieldType, fieldElement] of Object.entries(fields)) {
      const val = mapping[fieldType];
      if (val && fieldElement) {
        fillField(fieldElement, val);
      }
    }

    return true;
  };

  /**
   * Fill a field and trigger proper events so websites detect the change.
   * SECURITY: Never fills hidden inputs, csrf_token fields, or AMPass-internal fields.
   * Handles React, Vue, Angular, and vanilla JS forms with proper event dispatch.
   */
  function fillField(field, value) {
    // Never fill hidden fields or CSRF tokens
    if (!field || field.type === 'hidden') return;
    if (field.name === 'csrf_token' || field.name === '_token' || field.name === '_csrf') return;
    if (field.getAttribute('data-ampass-no-fill') === 'true') return;

    // Focus the field
    field.focus();
    field.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
    field.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));

    if (field.tagName === 'SELECT') {
      const options = Array.from(field.options);
      const valLower = String(value).toLowerCase().trim();
      
      // Exact match by value or text
      let matchedOption = options.find(opt => 
        opt.value.toLowerCase().trim() === valLower || 
        opt.text.toLowerCase().trim() === valLower
      );
      
      // Country code normalization (e.g., "US" matches "United States")
      if (!matchedOption) {
        const countryMap = {
          'us': 'united states', 'usa': 'united states', 'uk': 'united kingdom', 'gb': 'united kingdom',
          'ca': 'canada', 'au': 'australia', 'de': 'germany', 'fr': 'france', 'jp': 'japan',
          'cn': 'china', 'in': 'india', 'br': 'brazil', 'mx': 'mexico', 'es': 'spain',
          'it': 'italy', 'nl': 'netherlands', 'se': 'sweden', 'no': 'norway', 'dk': 'denmark',
          'fi': 'finland', 'pl': 'poland', 'pt': 'portugal', 'at': 'austria', 'ch': 'switzerland',
          'be': 'belgium', 'ie': 'ireland', 'nz': 'new zealand', 'sg': 'singapore',
          'kr': 'south korea', 'za': 'south africa', 'ae': 'united arab emirates',
          'bd': 'bangladesh', 'pk': 'pakistan', 'ph': 'philippines', 'th': 'thailand',
          'my': 'malaysia', 'id': 'indonesia', 'vn': 'vietnam', 'tw': 'taiwan',
          'ru': 'russia', 'ua': 'ukraine', 'tr': 'turkey', 'il': 'israel', 'eg': 'egypt',
          'ar': 'argentina', 'cl': 'chile', 'co': 'colombia', 'pe': 'peru'
        };
        const mapped = countryMap[valLower];
        if (mapped) {
          matchedOption = options.find(opt => opt.text.toLowerCase().trim() === mapped);
        }
        // Also try reverse lookup (country name → code)
        if (!matchedOption) {
          for (const [code, name] of Object.entries(countryMap)) {
            if (name === valLower) {
              matchedOption = options.find(opt => opt.value.toLowerCase().trim() === code);
              break;
            }
          }
        }
      }
      
      // Partial match
      if (!matchedOption) {
        matchedOption = options.find(opt => 
          opt.text.toLowerCase().includes(valLower) || 
          valLower.includes(opt.text.toLowerCase())
        );
      }
      
      if (matchedOption) {
        field.value = matchedOption.value;
      } else {
        field.value = value;
      }
      
      field.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
      field.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
      field.dispatchEvent(new Event('blur', { bubbles: true }));
      return;
    }

    // Set value using native setter (bypasses React/Vue controlled components)
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;

    // Simulate typing: compositionstart -> input -> compositionend
    // This pattern is required by some React/Angular forms that track composition events
    field.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    
    nativeInputValueSetter.call(field, value);

    // Dispatch events in the correct order for framework compatibility
    // InputEvent is needed for React 17+ which listens to the native input event
    field.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertText', data: value }));
    field.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: value }));
    field.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
    
    // KeyboardEvent dispatch for forms that validate via keydown/keyup
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Unidentified' }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Unidentified' }));
    
    field.dispatchEvent(new Event('blur', { bubbles: true }));
  }

  /**
   * Fill username and password with a small delay between them.
   * React/Vue state updates are async — filling both simultaneously can cause race conditions.
   */
  function fillFieldsSequentially(usernameField, username, passwordField, password) {
    return new Promise(resolve => {
      if (usernameField && username) {
        fillField(usernameField, username);
      }
      // Small delay between fields to avoid React state race conditions
      setTimeout(() => {
        if (passwordField && password) {
          fillField(passwordField, password);
          passwordField.setAttribute('data-ampass-filled', 'true');
        }
        resolve(true);
      }, 50);
    });
  }

  // Expose sequential filler, identity autofill, and single field filler for form-detector
  window.__ampassFillSequential = fillFieldsSequentially;
  window.__ampassPerformIdentityAutofill = performIdentityAutofill;
  window.__ampassFillField = fillField;
})();
