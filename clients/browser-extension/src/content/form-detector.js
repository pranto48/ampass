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
   * Detect login forms and notify service worker
   */
  function detectForms() {
    const passwordFields = findPasswordFields();
    if (passwordFields.length === 0) return;

    const forms = [];

    passwordFields.forEach(pwField => {
      pwField.setAttribute(AMPASS_ATTR, 'true');
      const usernameField = findUsernameField(pwField);

      const formData = {
        passwordField: pwField,
        usernameField: usernameField,
        form: pwField.closest('form')
      };

      forms.push(formData);

      // Add AMPass icon indicator to password field
      addFieldIndicator(pwField);
      if (usernameField) {
        usernameField.setAttribute(AMPASS_ATTR, 'true');
      }
    });

    detectedForms = forms;

    // Notify service worker about detected forms
    if (forms.length > 0) {
      chrome.runtime.sendMessage({
        type: 'GET_MATCHES',
        payload: { url: window.location.href }
      }).catch(() => {});
    }
  }

  /**
   * Add a small AMPass icon to a field
   */
  function addFieldIndicator(field) {
    if (field.parentElement.querySelector('.ampass-field-icon')) return;

    const icon = document.createElement('div');
    icon.className = 'ampass-field-icon';
    icon.title = 'AMPass - Click to autofill';
    icon.innerHTML = `<svg width="16" height="16" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="6" fill="#6366f1"/><path d="M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z" fill="white" opacity="0.9"/></svg>`;

    // Position the icon inside the field
    const wrapper = field.parentElement;
    if (wrapper) {
      wrapper.style.position = wrapper.style.position || 'relative';
      icon.style.cssText = 'position:absolute;right:8px;top:50%;transform:translateY(-50%);cursor:pointer;z-index:99999;width:20px;height:20px;display:flex;align-items:center;justify-content:center;border-radius:3px;opacity:0.8;transition:opacity 0.2s;';
      icon.addEventListener('mouseenter', () => icon.style.opacity = '1');
      icon.addEventListener('mouseleave', () => icon.style.opacity = '0.8');
      icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Request autofill from popup
        chrome.runtime.sendMessage({ type: 'GET_MATCHES', payload: { url: window.location.href } });
        // Open popup
        chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
      });
      wrapper.appendChild(icon);
    }
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
          if (node.nodeType === 1 && (node.querySelector('input[type="password"]') || node.matches?.('input[type="password"]'))) {
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
})();
