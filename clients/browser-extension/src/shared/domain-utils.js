/**
 * AMPass Extension - Domain Utilities
 * Handles URL normalization and domain matching for autofill.
 */

const DomainUtils = {
  /**
   * Extract the registrable domain from a URL (e.g., "mail.google.com" → "google.com")
   */
  getBaseDomain(url) {
    if (!url) return '';
    let normalized = url.trim();
    if (!normalized.includes('://')) {
      normalized = 'https://' + normalized;
    }
    try {
      const parsed = new URL(normalized);
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
   * Check if an item URL matches the current page URL with subdomain, subdirectory, and port specificity.
   */
  isUrlMatch(itemUrl, currentUrl) {
    if (!itemUrl || !currentUrl) return false;

    let normItem = itemUrl.trim();
    if (!normItem.includes('://')) normItem = 'https://' + normItem;
    let normCurrent = currentUrl.trim();
    if (!normCurrent.includes('://')) normCurrent = 'https://' + normCurrent;

    try {
      const parsedItem = new URL(normItem);
      const parsedCurrent = new URL(normCurrent);

      // 1. Hostname Match (Strict Subdomain matching)
      if (parsedItem.hostname.toLowerCase() !== parsedCurrent.hostname.toLowerCase()) {
        return false;
      }

      // 2. Port Match (Strict Port matching)
      const itemPort = parsedItem.port || (parsedItem.protocol === 'https:' ? '443' : '80');
      const currentPort = parsedCurrent.port || (parsedCurrent.protocol === 'https:' ? '443' : '80');
      if (itemPort !== currentPort) {
        return false;
      }

      // 3. Path Match (Strict subdirectory/subdirectory matching)
      const itemPath = parsedItem.pathname.replace(/\/+$/, '');
      const currentPath = parsedCurrent.pathname.replace(/\/+$/, '');
      if (itemPath && itemPath !== '/') {
        if (!currentPath.startsWith(itemPath)) {
          return false;
        }
      }

      return true;
    } catch {
      return this.domainsMatch(itemUrl, currentUrl);
    }
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
