import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveApiBaseUrl } from '../../src/utils/resolveApiBaseUrl.js';

describe('resolveApiBaseUrl', () => {
  const originalEnv = globalThis.window?.__ENV__;

  beforeEach(() => {
    delete globalThis.window.__ENV__;
  });

  afterEach(() => {
    if (originalEnv !== undefined) {
      globalThis.window.__ENV__ = originalEnv;
    } else {
      delete globalThis.window.__ENV__;
    }
  });

  it('defaults to same hostname on 127.0.0.1 when unconfigured', () => {
    Object.defineProperty(window, 'location', {
      value: {
        hostname: '127.0.0.1',
        protocol: 'http:',
      },
      configurable: true,
    });
    expect(resolveApiBaseUrl()).to.equal('http://127.0.0.1:4000');
  });

  it('rewrites configured localhost API URL to 127.0.0.1 when page is on 127.0.0.1', () => {
    Object.defineProperty(window, 'location', {
      value: {
        hostname: '127.0.0.1',
        protocol: 'http:',
      },
      configurable: true,
    });
    window.__ENV__ = { API_URL: 'http://localhost:4000' };
    expect(resolveApiBaseUrl()).to.equal('http://127.0.0.1:4000');
  });

  it('keeps configured localhost URL when page is on localhost', () => {
    Object.defineProperty(window, 'location', {
      value: {
        hostname: 'localhost',
        protocol: 'http:',
      },
      configurable: true,
    });
    window.__ENV__ = { API_URL: 'http://localhost:4000' };
    expect(resolveApiBaseUrl()).to.equal('http://localhost:4000');
  });
});
