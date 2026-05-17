/**
 * AMPass Extension - Save Detector (Content Script)
 * SECURITY: Detects form submissions and offers to save credentials.
 * Never saves without user confirmation.
 * Captured credentials are sent to service worker for encryption.
 */

(function() {
  'use strict';

  let lastSubmittedData = null;

  /**
   * Capture form submission data
   */
  function captureSubmission(form) {
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return null;

    // Get the password value
    const passwordField = Array.from(passwordFields).find(f => f.value.length > 0);
    if (!passwordField || passwordField.value.length < 1) return null;

    // Find username field
    const usernameField = findUsernameInForm(form);
    const username = usernameField ? usernameField.value : '';

    if (!username && !passwordField.value) return null;

    return {
      url: window.location.href,
      title: document.title || window.location.hostname,
      username: username,
      password: passwordField.value,
      domain: window.location.hostname
    };
  }

  /**
   * Find username field in a form
   */
  function findUsernameInForm(form) {
    const selectors = [
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="email"]',
      'input[name*="user"]',
      'input[name*="email"]',
      'input[name*="login"]',
      'input[id*="user"]',
      'input[id*="email"]',
      'input[type="text"]'
    ];

    for (const selector of selectors) {
      const field = form.querySelector(selector);
      if (field && field.value && field.type !== 'password' && field.type !== 'hidden') {
        return field;
      }
    }
    return null;
  }

  /**
   * Handle form submit event
   */
  function onFormSubmit(e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    const data = captureSubmission(form);
    if (!data) return;

    // Don't capture if it was autofilled by us (avoid re-saving what we just filled)
    const pwField = form.querySelector('input[type="password"][data-ampass-filled]');
    if (pwField) return;

    lastSubmittedData = data;

    // Send to service worker to check if this is new or an update
    chrome.runtime.sendMessage({
      type: 'GET_MATCHES',
      payload: { url: data.url }
    }).then(response => {
      if (!response || !response.success) return;

      if (response.count > 0) {
        // Existing credential - ask to update
        showSavePrompt('update', data, response.items[0]);
      } else {
        // New credential - ask to save
        showSavePrompt('save', data);
      }
    }).catch(() => {});
  }

  /**
   * Show save/update prompt to user
   */
  function showSavePrompt(action, data, existingItem = null) {
    // Remove any existing prompt
    const existing = document.getElementById('ampass-save-prompt');
    if (existing) existing.remove();

    const prompt = document.createElement('div');
    prompt.id = 'ampass-save-prompt';
    prompt.style.cssText = `
      position: fixed; top: 12px; right: 12px; z-index: 2147483647;
      background: #18181b; border: 1px solid #27272a; border-radius: 12px;
      padding: 16px 20px; max-width: 360px; box-shadow: 0 12px 40px rgba(0,0,0,0.4);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #fafafa; font-size: 14px; line-height: 1.5;
      animation: ampassSlideIn 0.3s ease;
    `;

    const title = action === 'update' ? 'Update password?' : 'Save login?';
    const desc = action === 'update'
      ? `Update the password for <strong>${Security.escapeHtml(data.username)}</strong> on ${Security.escapeHtml(data.domain)}?`
      : `Save login for <strong>${Security.escapeHtml(data.username)}</strong> on ${Security.escapeHtml(data.domain)}?`;

    prompt.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>
        <span style="font-weight:600;font-size:15px;">${title}</span>
      </div>
      <p style="color:#a1a1aa;margin-bottom:14px;">${desc}</p>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="ampass-save-dismiss" style="padding:7px 14px;border-radius:6px;border:1px solid #27272a;background:#1f1f23;color:#a1a1aa;cursor:pointer;font-size:13px;">Not now</button>
        <button id="ampass-save-confirm" style="padding:7px 14px;border-radius:6px;border:none;background:#6366f1;color:white;cursor:pointer;font-size:13px;font-weight:500;">${action === 'update' ? 'Update' : 'Save'}</button>
      </div>
    `;

    // Add animation keyframes
    if (!document.getElementById('ampass-styles')) {
      const style = document.createElement('style');
      style.id = 'ampass-styles';
      style.textContent = '@keyframes ampassSlideIn{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}';
      document.head.appendChild(style);
    }

    document.body.appendChild(prompt);

    // Handle buttons
    prompt.querySelector('#ampass-save-dismiss').addEventListener('click', () => {
      prompt.remove();
    });

    prompt.querySelector('#ampass-save-confirm').addEventListener('click', () => {
      if (action === 'update' && existingItem) {
        chrome.runtime.sendMessage({
          type: 'UPDATE_ITEM',
          payload: {
            id: existingItem.id,
            itemData: {
              title: data.title,
              url: data.url,
              username: data.username,
              password: data.password
            }
          }
        });
      } else {
        chrome.runtime.sendMessage({
          type: 'SAVE_ITEM',
          payload: {
            itemData: {
              title: data.title,
              url: data.url,
              username: data.username,
              password: data.password
            }
          }
        });
      }
      prompt.remove();
      // Clear sensitive data
      data.password = null;
      data.username = null;
    });

    // Auto-dismiss after 15 seconds
    setTimeout(() => {
      if (document.getElementById('ampass-save-prompt')) {
        prompt.remove();
      }
    }, 15000);
  }

  // ===== Event Listeners =====

  // Listen for form submissions
  document.addEventListener('submit', onFormSubmit, true);

  // Also detect navigation-based submissions (some SPAs)
  window.addEventListener('beforeunload', () => {
    // If there's pending data, it's too late to save
    lastSubmittedData = null;
  });

  // Inject Security helper for escapeHtml
  if (typeof Security === 'undefined') {
    window.Security = {
      escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
      }
    };
  }
})();
