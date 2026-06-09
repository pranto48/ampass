import { describe, it, expect, beforeAll, vi } from 'vitest';

// Mock fetch globally for network isolation
globalThis.fetch = vi.fn().mockImplementation(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve([
      { shared: ["apple.com", "icloud.com", "me.com", "mac.com"] },
      { shared: ["google.com", "youtube.com", "gmail.com", "blogger.com"] }
    ])
  })
);

import { UrlMatcher, AppleQuirksManager, filterVaultEntries } from '../../../shared/url-matcher/UrlMatcher.ts';

describe('UrlMatcher Tests', () => {
  it('should parse standard URLs correctly', () => {
    const result = UrlMatcher.parse('https://dev.company.com:8080/admin/dashboard');
    expect(result).not.toBeNull();
    expect(result.protocol).toBe('https:');
    expect(result.subdomain).toBe('dev');
    expect(result.baseDomain).toBe('company.com');
    expect(result.port).toBe('8080');
    expect(result.exactPath).toBe('/admin/dashboard');
  });

  it('should parse URLs without protocols (default to https)', () => {
    const result = UrlMatcher.parse('company.co.uk/index.html');
    expect(result).not.toBeNull();
    expect(result.protocol).toBe('https:');
    expect(result.subdomain).toBe('');
    expect(result.baseDomain).toBe('company.co.uk');
    expect(result.exactPath).toBe('/index.html');
  });

  it('should parse local hostnames correctly', () => {
    const result = UrlMatcher.parse('http://localhost:3000');
    expect(result).not.toBeNull();
    expect(result.protocol).toBe('http:');
    expect(result.baseDomain).toBe('localhost');
    expect(result.port).toBe('3000');
  });

  it('should parse IP addresses correctly', () => {
    const result = UrlMatcher.parse('http://192.168.1.1:8000/api');
    expect(result).not.toBeNull();
    expect(result.baseDomain).toBe('192.168.1.1');
    expect(result.port).toBe('8000');
    expect(result.exactPath).toBe('/api');
  });
});

describe('AppleQuirksManager Tests', () => {
  beforeAll(async () => {
    // Initialise quirks (will fall back to defaults if offline/in test)
    await AppleQuirksManager.initialize();
  });

  it('should return shared equivalents for default entries', () => {
    const appleEquivalents = AppleQuirksManager.getSharedBackendEquivalents('icloud.com');
    expect(appleEquivalents).toContain('apple.com');
    expect(appleEquivalents).toContain('icloud.com');

    const googleEquivalents = AppleQuirksManager.getSharedBackendEquivalents('youtube.com');
    expect(googleEquivalents).toContain('google.com');
    expect(googleEquivalents).toContain('youtube.com');
  });
});

describe('filterVaultEntries Segregation Tests', () => {
  beforeAll(async () => {
    await AppleQuirksManager.initialize();
  });

  const mockVault = [
    { id: 1, url: 'https://dev.company.com/admin', title: 'Exact Match' },
    { id: 2, url: 'https://hr.company.com/admin', title: 'Subdomain Match' },
    { id: 3, url: 'https://dev.company.com:8080/admin', title: 'Port Variation' },
    { id: 4, url: 'https://apple.com/login', title: 'Equivalent Match' }
  ];

  it('should segregate entries correctly', () => {
    const segregated = filterVaultEntries('https://dev.company.com/admin', mockVault);
    
    expect(segregated.exactMatch.map(x => x.id)).toContain(1);
    expect(segregated.subdomainMatches.map(x => x.id)).toContain(2);
    expect(segregated.portVariations.map(x => x.id)).toContain(3);
  });

  it('should detect shared backend matches correctly', () => {
    const segregated = filterVaultEntries('https://icloud.com/login', mockVault);
    expect(segregated.sharedBackendMatches.map(x => x.id)).toContain(4);
  });
});
