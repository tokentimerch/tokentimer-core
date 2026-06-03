import { describe, it, expect } from 'vitest';
import {
  trackEvent,
  sanitizePosthogProperties,
  resetIdentity,
  identifyUser,
  setDefaultEventProps,
} from '../../src/utils/analytics.js';

describe('analytics stubs', () => {
  it('exposes no-op tracking helpers', () => {
    expect(trackEvent()).toBeUndefined();
    expect(resetIdentity()).toBeUndefined();
    expect(identifyUser()).toBeUndefined();
    expect(setDefaultEventProps()).toBeUndefined();
  });

  it('passes through sanitized properties unchanged', () => {
    const props = { workspaceId: 'ws-1', count: 2 };
    expect(sanitizePosthogProperties('test_event', props)).toBe(props);
  });
});
