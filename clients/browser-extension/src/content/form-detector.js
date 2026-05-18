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
   * Add a small AMPass icon overlay near a password field.
   * Uses fixed positioning to avoid CSS conflicts with the page.
   */
  function addFieldIndicator(field) {
    if (field.hasAttribute('data-ampass-icon-added')) return;
    field.setAttribute('data-ampass-icon-added', 'true');

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
      chrome.runtime.sendMessage({ type: 'GET_MATCHES', payload: { url: window.location.href } });
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
