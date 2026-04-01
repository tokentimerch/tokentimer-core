import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('logoUtils', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('returns PNG logo path for Chrome user agent and caches it', async () => {
    Object.defineProperty(globalThis, 'navigator', {
      value: { userAgent: 'Chrome/126.0.0.0 Safari/537.36' },
      configurable: true,
    });
    const mod = await import('../../src/utils/logoUtils.js');
    const first = mod.getLogoPath();
    const second = mod.getLogoPath();
    expect(first).toBe('/Branding/logo.png');
    expect(second).toBe('/Branding/logo.png');
  });

  it('returns SVG logo path for non-Chrome user agent', async () => {
    Object.defineProperty(globalThis, 'navigator', {
      value: { userAgent: 'Firefox/123.0' },
      configurable: true,
    });
    const mod = await import('../../src/utils/logoUtils.js');
    expect(mod.getLogoPath()).toBe('/Branding/logo.svg');
  });
});
