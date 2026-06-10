/**
 * AMPass Extension - Save Detector (Content Script)
 * SECURITY: Detects form submissions and offers to save credentials.
 * Never saves without user confirmation.
 * Captured credentials are sent to service worker for encryption.
 */

(function() {
  'use strict';

  let lastSubmittedData = null;
  let lastCaptureAt = 0;

  /**
   * Capture form submission data
   */
  function captureSubmission(form) {
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return null;

    // Never capture hidden password fields
    const passwordField = Array.from(passwordFields).find(f => 
      f.value.length > 0 && !f.hidden && f.offsetParent !== null && f.type === 'password'
    );
    if (!passwordField || passwordField.value.length < 1) return null;

    // Never save if password is empty or just whitespace
    if (!passwordField.value.trim()) return null;

    // Never capture AMPass own pages (login, unlock, register, install)
    const ampassPatterns = ['/login', '/register', '/unlock', '/install', '/admin'];
    const currentPath = window.location.pathname.toLowerCase();
    for (const pattern of ampassPatterns) {
      if (currentPath.includes(pattern) && document.querySelector('meta[name="ampass-app"]')) {
        return null;
      }
    }

    // Find username field (never capture hidden fields)
    const usernameField = findUsernameInForm(form);
    const username = usernameField ? usernameField.value : '';

    if (!username && !passwordField.value) return null;

    // Never capture CSRF tokens or hidden fields as username
    if (usernameField && usernameField.type === 'hidden') return null;

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
      'input:not([type])',
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
   * Handle form submit event.
   * Captures credentials and shows save prompt BEFORE navigation.
   * Only intercepts if the extension vault is unlocked (can actually save).
   */
  function onFormSubmit(e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    // Skip if this is our own re-submission after save prompt
    if (form.getAttribute('data-ampass-submitting') === 'true') {
      form.removeAttribute('data-ampass-submitting');
      return;
    }

    const data = captureSubmission(form);
    if (!data) return; // No password field or empty

    // Don't capture if it was autofilled by us (avoid re-saving what we just filled)
    const pwField = form.querySelector('input[type="password"][data-ampass-filled]');
    if (pwField) return;
    // Also check if any field in the form was auto-filled by page-load fill
    const anyFilled = form.querySelector('[data-ampass-filled]');
    if (anyFilled) return;

    // Store for the service worker (survives page navigation as fallback)
    lastSubmittedData = data;
    lastCaptureAt = Date.now();
    chrome.runtime.sendMessage({
      type: 'CAPTURE_SAVE_CANDIDATE',
      payload: { data }
    }).catch(() => {});

    // Prevent form submission while we check vault status and evaluate candidates
    e.preventDefault();
    e.stopPropagation();

    function continueSubmit() {
      form.setAttribute('data-ampass-submitting', 'true');
      if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
    }

    // Check if vault is unlocked before intercepting the form
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }).then(status => {
      if (status && status.success && status.unlocked) {
        // Don't intercept the AMPass server's own login/register/unlock pages
        const serverUrl = status.serverUrl || '';
        if (serverUrl && window.location.href.startsWith(serverUrl)) {
          continueSubmit();
          return;
        }
        
        // Evaluate if prompt is needed
        evaluateCredentialAction(data).then(result => {
          if (result.action === 'none') {
            // Credentials are identical, clear candidate and submit
            chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
            continueSubmit();
          } else {
            // Vault is unlocked and credentials changed/new — show save prompt
            showSavePromptWithContinue(form, data, result.action, result.existingItem);
          }
        });
      } else {
        // Vault is locked — can't save now, just submit the form
        continueSubmit();
      }
    }).catch(() => {
      // On error, just submit the form normally
      continueSubmit();
    });
  }

  /**
   * Capture and queue credentials before the page can navigate away.
   */
  function captureAndQueue(form) {
    if (!(form instanceof HTMLFormElement)) return null;

    const data = captureSubmission(form);
    if (!data) return null;

    // Don't capture if it was autofilled by us
    const pwField = form.querySelector('input[type="password"][data-ampass-filled]');
    if (pwField) return null;

    lastSubmittedData = data;
    lastCaptureAt = Date.now();

    // Queue first so the save prompt survives normal login redirects.
    chrome.runtime.sendMessage({
      type: 'CAPTURE_SAVE_CANDIDATE',
      payload: { data }
    }).catch(() => {});

    // Also try the current page for no-navigation and SPA login flows.
    setTimeout(() => processSaveCandidate(data), 250);
    return data;
  }

  /**
   * Evaluates if we should show a save or update prompt for the credential.
   * Returns a promise resolving to:
   * - { action: 'save' } if it's new
   * - { action: 'update', existingItem } if password changed
   * - { action: 'none' } if identical
   */
  function evaluateCredentialAction(data) {
    return new Promise(resolve => {
      if (!data || !data.password) {
        resolve({ action: 'none' });
        return;
      }

      chrome.runtime.sendMessage({
        type: 'GET_MATCHES',
        payload: { url: data.url }
      }).then(response => {
        if (!response || !response.success || !response.items || response.items.length === 0) {
          resolve({ action: 'save' });
          return;
        }

        const matches = response.items;
        const submittedUser = (data.username || '').trim().toLowerCase();
        const sameUserMatch = matches.find(item => 
          (item.username || '').trim().toLowerCase() === submittedUser
        );

        if (sameUserMatch) {
          chrome.runtime.sendMessage({
            type: 'DECRYPT_ITEM',
            payload: { id: sameUserMatch.id }
          }).then(decryptedResponse => {
            if (decryptedResponse && decryptedResponse.success && decryptedResponse.item) {
              const savedPassword = decryptedResponse.item.password || '';
              if (savedPassword === data.password) {
                resolve({ action: 'none' });
              } else {
                resolve({ action: 'update', existingItem: sameUserMatch });
              }
            } else {
              resolve({ action: 'update', existingItem: sameUserMatch });
            }
          }).catch(() => {
            resolve({ action: 'update', existingItem: sameUserMatch });
          });
        } else {
          resolve({ action: 'save' });
        }
      }).catch(() => {
        resolve({ action: 'none' });
      });
    });
  }

  /**
   * Check whether the captured credential is new or an update.
   */
  function processSaveCandidate(data) {
    evaluateCredentialAction(data).then(result => {
      if (result.action === 'save') {
        showSavePrompt('save', data);
      } else if (result.action === 'update') {
        showSavePrompt('update', data, result.existingItem);
      } else {
        // Clear pending save candidate since it matches exactly
        chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
      }
    });
  }

  /**
   * Find the nearest login form from a clicked/typed control.
   */
  function findFormFromEventTarget(target) {
    if (!(target instanceof HTMLElement)) return null;

    const form = target.closest('form');
    if (form) return form;

    const passwordField = target.matches('input[type="password"]')
      ? target
      : document.activeElement instanceof HTMLElement
        ? document.activeElement.closest('form')?.querySelector('input[type="password"]')
        : null;

    return passwordField ? passwordField.closest('form') : null;
  }

  /**
   * Some modern login forms submit from JS click handlers without a submit event.
   */
  function onDocumentClick(e) {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;

    const clickable = target.closest('button, input[type="submit"], input[type="button"], [role="button"]');
    if (!clickable) return;

    const form = findFormFromEventTarget(clickable);
    if (form) captureAndQueue(form);
  }

  /**
   * Capture Enter-key login submits before JavaScript navigation starts.
   */
  function onDocumentKeydown(e) {
    if (e.key !== 'Enter') return;
    const form = findFormFromEventTarget(e.target);
    if (form) captureAndQueue(form);
  }

  /**
   * Show a queued prompt after the destination page loads.
   */
  function checkPendingSave() {
    chrome.runtime.sendMessage({ type: 'CHECK_PENDING_SAVE' }).then(response => {
      if (!response || !response.success || !response.data) return;
      processSaveCandidate(response.data);
    }).catch(() => {});
  }


  /**
   * Show save prompt that pauses form submission.
   * After user decides, re-submits the form.
   */
  function showSavePromptWithContinue(form, data, action = 'save', existingItem = null) {
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

    if (!document.getElementById('ampass-styles')) {
      const style = document.createElement('style');
      style.id = 'ampass-styles';
      style.textContent = '@keyframes ampassSlideIn{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}';
      document.head.appendChild(style);
    }

    const titleText = action === 'update' ? 'Update password?' : 'Save login?';
    const actionLabel = action === 'update' ? 'Update & Continue' : 'Save & Continue';

    // Build DOM safely — no innerHTML with user data
    prompt.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>
        <span id="ampass-save-title" style="font-weight:600;font-size:15px;"></span>
      </div>
      <p id="ampass-save-desc" style="color:#a1a1aa;margin-bottom:14px;"></p>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="ampass-save-skip" style="padding:7px 14px;border-radius:6px;border:1px solid #27272a;background:#1f1f23;color:#a1a1aa;cursor:pointer;font-size:13px;">Not now</button>
        <button id="ampass-save-yes" style="padding:7px 14px;border-radius:6px;border:none;background:#6366f1;color:white;cursor:pointer;font-size:13px;font-weight:500;"></button>
      </div>
    `;
    // Populate safely using textContent
    prompt.querySelector('#ampass-save-title').textContent = titleText;
    prompt.querySelector('#ampass-save-yes').textContent = actionLabel;

    const descEl = prompt.querySelector('#ampass-save-desc');
    const strong = document.createElement('strong');
    strong.textContent = data.username || '(unknown)';
    const verb = action === 'update' ? 'Update the password for ' : 'Save login for ';
    descEl.append(verb, strong, ' on ', data.domain || window.location.hostname, '?');

    document.body.appendChild(prompt);

    function continueSubmit() {
      prompt.remove();
      // Re-submit the form programmatically
      try {
        form.setAttribute('data-ampass-submitting', 'true');
        if (form.requestSubmit) {
          form.requestSubmit();
        } else {
          form.submit();
        }
      } catch (e) {
        form.submit();
      }
    }

    prompt.querySelector('#ampass-save-skip').addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
      continueSubmit();
    });

    prompt.querySelector('#ampass-save-yes').addEventListener('click', () => {
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
        }).then(() => {
          chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
          continueSubmit();
        }).catch(() => {
          continueSubmit();
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
        }).then(() => {
          chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
          continueSubmit();
        }).catch(() => {
          continueSubmit();
        });
      }
    });

    // Auto-continue after 30 seconds if user doesn't interact
    setTimeout(() => {
      if (document.getElementById('ampass-save-prompt')) {
        chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
        continueSubmit();
      }
    }, 30000);
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

    const titleText = action === 'update' ? 'Update password?' : 'Save login?';
    const actionLabel = action === 'update' ? 'Update' : 'Save';

    // Build DOM safely — no innerHTML with user data
    prompt.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>
        <span id="ampass-prompt-title" style="font-weight:600;font-size:15px;"></span>
      </div>
      <p id="ampass-prompt-desc" style="color:#a1a1aa;margin-bottom:14px;"></p>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="ampass-save-dismiss" style="padding:7px 14px;border-radius:6px;border:1px solid #27272a;background:#1f1f23;color:#a1a1aa;cursor:pointer;font-size:13px;">Not now</button>
        <button id="ampass-save-confirm" style="padding:7px 14px;border-radius:6px;border:none;background:#6366f1;color:white;cursor:pointer;font-size:13px;font-weight:500;"></button>
      </div>
    `;
    // Populate using textContent — no XSS possible
    prompt.querySelector('#ampass-prompt-title').textContent = titleText;
    prompt.querySelector('#ampass-save-confirm').textContent = actionLabel;
    const descEl2 = prompt.querySelector('#ampass-prompt-desc');
    const strong2 = document.createElement('strong');
    strong2.textContent = data.username || '(unknown)';
    const verb = action === 'update' ? 'Update the password for ' : 'Save login for ';
    descEl2.append(verb, strong2, ' on ', data.domain || window.location.hostname, '?');

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
      chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
      prompt.remove();
    });

    prompt.querySelector('#ampass-save-confirm').addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
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

    // Auto-dismiss after 60 seconds (gives user plenty of time)
    setTimeout(() => {
      if (document.getElementById('ampass-save-prompt')) {
        chrome.runtime.sendMessage({ type: 'CLEAR_PENDING_SAVE' }).catch(() => {});
        prompt.remove();
      }
    }, 60000);
  }

  // ===== Event Listeners =====

  // Listen for form submissions
  document.addEventListener('submit', onFormSubmit, true);
  document.addEventListener('click', onDocumentClick, true);
  document.addEventListener('keydown', onDocumentKeydown, true);

  // Clear data-ampass-filled attribute if user edits the field manually
  document.addEventListener('input', (e) => {
    if (e.target && e.target.hasAttribute('data-ampass-filled')) {
      e.target.removeAttribute('data-ampass-filled');
    }
  }, true);

  // Pick up credentials queued before a normal login redirect.
  setTimeout(checkPendingSave, 500);

  // Also detect navigation-based submissions (some SPAs)
  window.addEventListener('beforeunload', () => {
    if (lastSubmittedData && Date.now() - lastCaptureAt < 5000) {
      chrome.runtime.sendMessage({
        type: 'CAPTURE_SAVE_CANDIDATE',
        payload: { data: lastSubmittedData }
      }).catch(() => {});
    }
  });

  // Inject Security helper for escapeHtml (local to IIFE, not exposed to page)
  const _escapeHtml = (function() {
    const div = document.createElement('div');
    return function(str) {
      if (!str) return '';
      div.textContent = str;
      return div.innerHTML;
    };
  })();

  // Use local reference instead of window.Security
  const Security = { escapeHtml: _escapeHtml };
})();
