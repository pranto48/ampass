/**
 * AMPass Extension - Domain Utilities
 * Handles URL normalization and domain matching for autofill.
 */

const DomainUtils = {
  /**
   * Extract the registrable domain from a URL (e.g., "mail.google.com" → "google.com")
   */
  getBaseDomain(url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();

      // Handle IP addresses
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
      if (host === 'localhost') return 'localhost';

      // Simple TLD extraction (handles most common cases)
      const parts = host.split('.');
      if (parts.length <= 2) return host;

      // Handle common multi-part TLDs
      const multiTLDs = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'org.uk'];
      const lastTwo = parts.slice(-2).join('.');
      if (multiTLDs.includes(lastTwo)) {
        return parts.slice(-3).join('.');
      }

      return parts.slice(-2).join('.');
    } catch {
      return '';
    }
  },

  /**
   * Get the full hostname from a URL
   */
  getHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  },

  /**
   * Check if two URLs share the same base domain
   */
  domainsMatch(url1, url2) {
    const d1 = this.getBaseDomain(url1);
    const d2 = this.getBaseDomain(url2);
    return d1 && d2 && d1 === d2;
  },

  /**
   * Normalize a URL for storage/comparison
   */
  normalizeUrl(url) {
    if (!url) return '';
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    try {
      const parsed = new URL(url);
      return parsed.origin + parsed.pathname.replace(/\/+$/, '');
    } catch {
      return url;
    }
  },

  /**
   * Get domain for HMAC hashing (used to match vault items by url_hash)
   */
  getDomainForHash(url) {
    return this.getBaseDomain(url);
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.DomainUtils = DomainUtils;
}
