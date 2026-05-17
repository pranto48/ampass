/**
 * AMPass Extension - Autofill (Content Script)
 * SECURITY: Never holds vault key. Receives plaintext credentials from
 * service worker only during fill operation, then clears them.
 * Never autofills without user action.
 */

(function() {
  'use strict';

  // Listen for autofill commands from popup/service worker
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'AUTOFILL') {
      performAutofill(msg.payload);
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
      const usernameField = form.querySelector('input[type="email"], input[type="text"], input[autocomplete="username"]');

      if (usernameField && username) {
        fillField(usernameField, username);
      }
      if (pwField && password) {
        fillField(pwField, password);
        pwField.setAttribute('data-ampass-filled', 'true');
      }
    } else {
      // Use detected form data
      const formData = forms[0]; // Fill first detected form
      if (formData.usernameField && username) {
        fillField(formData.usernameField, username);
      }
      if (formData.passwordField && password) {
        fillField(formData.passwordField, password);
        formData.passwordField.setAttribute('data-ampass-filled', 'true');
      }
    }

    // Clear sensitive data from local scope
    // (JavaScript GC will handle the rest, but we null the references)
    payload.username = null;
    payload.password = null;
  }

  /**
   * Fill a field and trigger proper events so websites detect the change
   */
  function fillField(field, value) {
    // Focus the field
    field.focus();

    // Set value using native setter (bypasses React/Vue controlled components)
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeInputValueSetter.call(field, value);

    // Dispatch events in the correct order
    field.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    field.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
    field.dispatchEvent(new Event('blur', { bubbles: true }));
  }
})();
