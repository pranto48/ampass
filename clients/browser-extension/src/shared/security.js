/**
 * AMPass Extension - Security Utilities
 * SECURITY: Domain validation, phishing detection, HTTP warnings.
 */

const Security = {
  /**
   * Check if a URL is using HTTPS
   */
  isSecure(url) {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:';
    } catch {
      return false;
    }
  },

  /**
   * Check if URL is localhost (HTTP allowed)
   */
  isLocalhost(url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname;
      return host === 'localhost' || host === '127.0.0.1' || host === '::1';
    } catch {
      return false;
    }
  },

  /**
   * Check if autofill is safe for this URL
   */
  isAutofillSafe(url, allowHttp = false) {
    if (!url) return false;
    if (this.isLocalhost(url)) return true;
    if (this.isSecure(url)) return true;
    if (allowHttp) return true;
    return false;
  },

  /**
   * Check if URL is a suspicious/phishing page
   * Basic heuristics - not a replacement for proper phishing detection
   */
  isSuspicious(url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname;

      // IP address URLs (except localhost)
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host) && !this.isLocalhost(url)) {
        return { suspicious: true, reason: 'IP address URL - possible phishing' };
      }

      // Very long subdomains (common in phishing)
      const parts = host.split('.');
      if (parts.some(p => p.length > 30)) {
        return { suspicious: true, reason: 'Unusually long subdomain' };
      }

      // Data URLs
      if (parsed.protocol === 'data:') {
        return { suspicious: true, reason: 'Data URL - never autofill' };
      }

      return { suspicious: false };
    } catch {
      return { suspicious: true, reason: 'Invalid URL' };
    }
  },

  /**
   * Sanitize a string for safe display (prevent XSS in extension UI)
   */
  escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  /**
   * Validate that a server URL is acceptable
   */
  isValidServerUrl(url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
      if (parsed.protocol === 'http:' && !this.isLocalhost(url)) return false;
      return true;
    } catch {
      return false;
    }
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.Security = Security;
}
