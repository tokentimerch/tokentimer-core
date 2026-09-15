import { describe, it, expect, beforeEach } from 'vitest';
import {
  LAST_WORKSPACE_LEGACY_KEY,
  LAST_WORKSPACE_OWNER_KEY,
  accountLastWorkspaceKey,
  clearSessionLastWorkspaceId,
  pickAccessibleWorkspace,
  readLastWorkspaceId,
  writeLastWorkspaceId,
} from '../../src/utils/lastWorkspacePreference.js';

const WS_A = { id: 'ws-a', name: 'A' };
const WS_B = { id: 'ws-b', name: 'B' };
const WS_FROZEN = { id: 'ws-frozen', name: 'Frozen', is_frozen: true };

describe('pickAccessibleWorkspace', () => {
  it('prefers an explicit URL workspace when that workspace is still accessible', () => {
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: 'ws-b',
        lastWorkspaceId: 'ws-a',
        workspaces: [WS_A, WS_B],
      })
    ).toBe('ws-b');
  });

  it('falls back to the last workspace when the URL is missing', () => {
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: null,
        lastWorkspaceId: 'ws-b',
        workspaces: [WS_A, WS_B],
      })
    ).toBe('ws-b');
  });

  it('falls back to the last workspace when the URL workspace is gone or frozen', () => {
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: 'ws-gone',
        lastWorkspaceId: 'ws-a',
        workspaces: [WS_A, WS_B],
      })
    ).toBe('ws-a');
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: 'ws-frozen',
        lastWorkspaceId: 'ws-b',
        workspaces: [WS_A, WS_B, WS_FROZEN],
      })
    ).toBe('ws-b');
  });

  it('falls back to the first accessible workspace when last is gone or frozen', () => {
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: null,
        lastWorkspaceId: 'ws-gone',
        workspaces: [WS_A, WS_B],
      })
    ).toBe('ws-a');
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: null,
        lastWorkspaceId: 'ws-frozen',
        workspaces: [WS_FROZEN, WS_B],
      })
    ).toBe('ws-b');
  });

  it('returns null when nothing is accessible', () => {
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: 'ws-frozen',
        lastWorkspaceId: 'ws-frozen',
        workspaces: [WS_FROZEN],
      })
    ).toBeNull();
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: null,
        lastWorkspaceId: null,
        workspaces: [],
      })
    ).toBeNull();
  });
});

describe('account-scoped last workspace storage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('reads back the workspace written for that account', () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    expect(readLastWorkspaceId('user-a')).toBe('ws-a');
    expect(localStorage.getItem(accountLastWorkspaceKey('user-a'))).toBe(
      'ws-a'
    );
  });

  it('does not restore another account stored workspace', () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    writeLastWorkspaceId('user-b', 'ws-b');
    expect(readLastWorkspaceId('user-a')).toBe('ws-a');
    expect(readLastWorkspaceId('user-b')).toBe('ws-b');
  });

  it('does not restore from storage when the account is unknown', () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    expect(readLastWorkspaceId(null)).toBeNull();
    expect(readLastWorkspaceId('')).toBeNull();
  });

  it('keeps a session cache for the current account and clears only that on logout', () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    expect(localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY)).toBe('ws-a');
    clearSessionLastWorkspaceId();
    expect(localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY)).toBeNull();
    expect(localStorage.getItem(LAST_WORKSPACE_OWNER_KEY)).toBeNull();
    expect(readLastWorkspaceId('user-a')).toBe('ws-a');
  });

  it('claims an unscoped leftover for the first account that reads it', () => {
    localStorage.setItem(LAST_WORKSPACE_LEGACY_KEY, 'ws-ops');
    expect(readLastWorkspaceId('user-a')).toBe('ws-ops');
    expect(localStorage.getItem(accountLastWorkspaceKey('user-a'))).toBe(
      'ws-ops'
    );
    expect(localStorage.getItem(LAST_WORKSPACE_OWNER_KEY)).toBe('user-a');
  });

  it('does not let a second account claim another account session cache', () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    expect(readLastWorkspaceId('user-b')).toBeNull();
  });

  it('matches numeric and string account ids', () => {
    writeLastWorkspaceId(12, 34);
    expect(readLastWorkspaceId('12')).toBe('34');
    expect(
      pickAccessibleWorkspace({
        urlWorkspaceId: 34,
        lastWorkspaceId: '12',
        workspaces: [{ id: 34 }, { id: 12 }],
      })
    ).toBe('34');
  });
});
