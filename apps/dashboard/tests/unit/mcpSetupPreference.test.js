import { beforeEach, describe, expect, it } from 'vitest';
import {
  rememberMcpSetupPreference,
  takeMcpSetupPreference,
} from '../../src/utils/mcpSetupPreference.js';

const choice = {
  userId: 42,
  workspaceId: 'one',
  renewals: true,
  agentHealth: true,
  lifetimeDays: 7,
};
const manager = [{ id: 'one', canRequestRenewals: true }];
beforeEach(() => localStorage.clear());
describe('MCP setup preferences', () => {
  it('suggests the selected workspace and access once, without making an authorization request', () => {
    rememberMcpSetupPreference(choice);
    expect(takeMcpSetupPreference(42, manager)).toEqual({
      workspaceId: 'one',
      renewals: true,
      agentHealth: true,
      lifetimeDays: 7,
      inventoryImport: false,
      inventoryUpdate: false,
      contactCreate: false,
      webhookCreate: false,
      groupCreate: false,
      memberInvite: false,
      issuance: false,
      noExpiry: false,
    });
    expect(takeMcpSetupPreference(42, manager)).toBeNull();
  });
  it('does not apply another account’s choices or bypass a workspace role downgrade', () => {
    rememberMcpSetupPreference(choice);
    expect(takeMcpSetupPreference(43, manager)).toBeNull();
    expect(
      takeMcpSetupPreference(42, [{ id: 'one', canRequestRenewals: false }])
    ).toEqual({
      workspaceId: 'one',
      renewals: false,
      agentHealth: false,
      lifetimeDays: 7,
      inventoryImport: false,
      inventoryUpdate: false,
      contactCreate: false,
      webhookCreate: false,
      groupCreate: false,
      memberInvite: false,
      issuance: false,
      noExpiry: false,
    });
  });
  it('retains issuance only while the selected role can request it', () => {
    rememberMcpSetupPreference({ ...choice, issuance: true });
    expect(takeMcpSetupPreference(42, manager).issuance).toBe(true);
    rememberMcpSetupPreference({ ...choice, issuance: true });
    expect(takeMcpSetupPreference(42, [{ id: 'one', canRequestRenewals: false }]).issuance).toBe(false);
  });
  it('rejects expired, invalid or no-longer-accessible workspace preferences', () => {
    for (const mutation of [
      { expiresAt: 1 },
      { lifetimeDays: 999 },
      { workspaceId: 'removed' },
    ]) {
      localStorage.setItem(
        'tokentimer.mcpSetupPreference',
        JSON.stringify({
          ...choice,
          expiresAt: Date.now() + 60000,
          ...mutation,
        })
      );
      expect(takeMcpSetupPreference(42, manager)).toBeNull();
    }
    localStorage.setItem('tokentimer.mcpSetupPreference', 'broken json');
    expect(takeMcpSetupPreference(42, manager)).toBeNull();
  });
});
