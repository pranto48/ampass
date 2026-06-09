/**
 * AMPass - Heuristic URL Parser & Segregation Engine
 * 
 * SECURITY:
 * - CSP Compliant: No dynamic code execution (eval, new Function, etc.) is used.
 * - Stringently separates credentials based on context to prevent credential leakage.
 */

export interface ParsedUrl {
  protocol: string;     // e.g., "https:"
  subdomain: string;    // e.g., "dev" or ""
  baseDomain: string;   // e.g., "company.com" or "company.co.uk" or "localhost"
  port: string;         // e.g., "8080" or ""
  exactPath: string;    // e.g., "/admin" or "/"
}

export interface SegregatedMatches {
  exactMatch: any[];
  subdomainMatches: any[];
  portVariations: any[];
  sharedBackendMatches: any[];
}

export class UrlMatcher {
  // Common multi-part public suffixes (PSL fallbacks for offline zero-latency parsing)
  private static readonly MULTI_PART_TLDS = new Set([
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au',
    'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'net.br', 'org.br',
    'co.in', 'net.in', 'org.in', 'ind.in',
    'com.sg', 'net.sg', 'org.sg',
    'co.za', 'net.za', 'org.za',
    'com.mx', 'net.mx', 'org.mx',
    'com.tw', 'net.tw', 'org.tw',
    'com.hk', 'net.hk', 'org.hk',
    'co.kr', 'ne.kr', 'or.kr',
    'com.cn', 'net.cn', 'org.cn',
    'com.tr', 'net.tr', 'org.tr',
    'co.ve', 'com.ve', 'net.ve',
  ]);

  /**
   * Safe URL decomposition into constituent components
   */
  public static parse(urlStr: string): ParsedUrl | null {
    if (!urlStr) return null;
    let cleanUrl = urlStr.trim();
    if (!cleanUrl.includes('://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    try {
      const parsed = new URL(cleanUrl);
      const protocol = parsed.protocol;
      const port = parsed.port;
      const exactPath = parsed.pathname;
      const hostname = parsed.hostname.toLowerCase();

      // Check if hostname is an IP Address (IPv4 or IPv6)
      const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$|^\[?[a-fA-F0-9:]+\]?$/;
      if (ipRegex.test(hostname)) {
        return {
          protocol,
          subdomain: '',
          baseDomain: hostname,
          port,
          exactPath
        };
      }

      // Local hostnames without dots (e.g. localhost, localdev)
      if (!hostname.includes('.')) {
        return {
          protocol,
          subdomain: '',
          baseDomain: hostname,
          port,
          exactPath
        };
      }

      const parts = hostname.split('.');
      let baseDomain = '';
      let subdomain = '';

      if (parts.length >= 3) {
        const lastTwo = parts.slice(-2).join('.');
        if (this.MULTI_PART_TLDS.has(lastTwo)) {
          baseDomain = parts.slice(-3).join('.');
          subdomain = parts.slice(0, -3).join('.');
        } else {
          baseDomain = parts.slice(-2).join('.');
          subdomain = parts.slice(0, -2).join('.');
        }
      } else {
        baseDomain = hostname;
        subdomain = '';
      }

      return {
        protocol,
        subdomain,
        baseDomain,
        port,
        exactPath
      };
    } catch {
      return null;
    }
  }
}

export class AppleQuirksManager {
  private static readonly QUIRKS_URL = 'https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/shared-credentials.json';
  
  // High-frequency shared credentials defaults (used if offline/fail to load)
  private static quirksList: Array<{ shared?: string[], from?: string[], to?: string[] }> = [
    { shared: ["apple.com", "icloud.com", "me.com", "mac.com"] },
    { shared: ["google.com", "youtube.com", "gmail.com", "blogger.com"] },
    { shared: ["facebook.com", "messenger.com", "instagram.com"] },
    { shared: ["microsoft.com", "live.com", "outlook.com", "office.com", "hotmail.com", "skype.com"] },
    { shared: ["yahoo.com", "flickr.com"] }
  ];
  
  private static isInitialized = false;

  /**
   * Initializes Apple Password Manager Quirks asynchronously
   * Fetches fresh JSON copy from GitHub with background caching
   */
  public static async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Load cached quirks if extension or browser storage is available
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const cached = await new Promise<any>((resolve) => {
          chrome.storage.local.get(['apple_quirks_cache'], resolve);
        });
        if (cached && cached.apple_quirks_cache) {
          this.quirksList = cached.apple_quirks_cache;
        }
      }

      // Fetch fresh quirks list from Apple Password Manager Resources in the background
      const response = await fetch(this.QUIRKS_URL);
      if (response.ok) {
        const data = await response.json();
        if (Array.isArray(data)) {
          this.quirksList = data;
          if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            await chrome.storage.local.set({ apple_quirks_cache: data });
          }
        }
      }
    } catch (e) {
      console.warn("Apple password manager resources failed to load. Using bundled defaults.", e);
    } finally {
      this.isInitialized = true;
    }
  }

  /**
   * Query the quirks list to find all shared backend equivalences
   */
  public static getSharedBackendEquivalents(domain: string): string[] {
    const cleanDomain = domain.toLowerCase().trim();
    const equivalents: Set<string> = new Set();
    equivalents.add(cleanDomain);

    for (const entry of this.quirksList) {
      if (entry.shared && Array.isArray(entry.shared)) {
        if (entry.shared.includes(cleanDomain)) {
          entry.shared.forEach(d => equivalents.add(d));
        }
      } else if (entry.from && entry.to && Array.isArray(entry.from) && Array.isArray(entry.to)) {
        if (entry.from.includes(cleanDomain)) {
          entry.to.forEach(d => equivalents.add(d));
        }
        if (entry.to.includes(cleanDomain)) {
          entry.from.forEach(d => equivalents.add(d));
        }
      }
    }

    return Array.from(equivalents);
  }
}

/**
 * Segregates credentials for the current URL context into distinct tiers:
 * exactMatch, subdomainMatches, portVariations, and sharedBackendMatches
 */
export function filterVaultEntries(currentContextUrl: string, entireVaultArray: any[]): SegregatedMatches {
  const currentParsed = UrlMatcher.parse(currentContextUrl);
  
  const results: SegregatedMatches = {
    exactMatch: [],
    subdomainMatches: [],
    portVariations: [],
    sharedBackendMatches: []
  };

  if (!currentParsed) return results;

  const equivalents = AppleQuirksManager.getSharedBackendEquivalents(currentParsed.baseDomain);

  for (const entry of entireVaultArray) {
    const itemUrlStr = entry.url || '';
    if (!itemUrlStr) continue;

    const itemParsed = UrlMatcher.parse(itemUrlStr);
    if (!itemParsed) continue;

    const baseDomainMatch = currentParsed.baseDomain === itemParsed.baseDomain;
    const isEquivalent = equivalents.includes(itemParsed.baseDomain);

    if (baseDomainMatch) {
      const subdomainMatch = currentParsed.subdomain === itemParsed.subdomain;
      
      const currentPort = currentParsed.port || (currentParsed.protocol === 'https:' ? '443' : '80');
      const itemPort = itemParsed.port || (itemParsed.protocol === 'https:' ? '443' : '80');
      const portMatch = currentPort === itemPort;

      const currentCleanPath = currentParsed.exactPath.replace(/\/+$/, '') || '/';
      const itemCleanPath = itemParsed.exactPath.replace(/\/+$/, '') || '/';
      const pathMatch = itemCleanPath === '/' || currentCleanPath === itemCleanPath || currentCleanPath.startsWith(itemCleanPath + '/');

      if (subdomainMatch && portMatch && pathMatch) {
        results.exactMatch.push(entry);
      } else if (!subdomainMatch && portMatch) {
        results.subdomainMatches.push(entry);
      } else if (!portMatch) {
        results.portVariations.push(entry);
      } else {
        results.subdomainMatches.push(entry);
      }
    } else if (isEquivalent) {
      results.sharedBackendMatches.push(entry);
    }
  }

  return results;
}
