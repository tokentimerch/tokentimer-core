import { describe, expect, it, vi } from 'vitest';
import {
  OperationConflictError,
  normalizeMonitorUrl,
  runIdempotent,
} from '../../src/components/onboarding/operations.js';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';

// Minimal in-memory stand-in for SessionController.
function fakeController(initial = {}) {
  let session = {
    revision: 1,
    intent: {},
    progress: {},
    operationRefs: {},
    ...initial,
  };
  return {
    get session() {
      return session;
    },
    update: vi.fn(async mutate => {
      const patch = mutate(session) || {};
      session = {
        ...session,
        ...(patch.progress ? { progress: patch.progress } : {}),
        ...(patch.operation_refs
          ? { operationRefs: patch.operation_refs }
          : {}),
        revision: session.revision + 1,
      };
      return session;
    }),
  };
}

describe('runIdempotent', () => {
  it('records the pending operation before calling the backend', async () => {
    const controller = fakeController();
    const order = [];
    controller.update.mockImplementationOnce(async mutate => {
      order.push('record-pending');
      const patch = mutate(controller.session);
      controller.session.progress = patch.progress;
    });
    const create = vi.fn(async () => {
      order.push('create');
      return { id: 'm1', url: 'https://a.example' };
    });
    await runIdempotent({
      controller,
      kind: 'monitor',
      identity: { url: 'https://a.example' },
      find: async () => null,
      create,
      record: (_refs, created) => ({ monitorUrl: created.url }),
    });
    expect(order).toEqual(['record-pending', 'create']);
  });

  it('adopts an existing item instead of creating (browser closed after success)', async () => {
    const controller = fakeController({
      progress: {
        pending: {
          id: 'op-1',
          kind: 'monitor',
          identityKey: JSON.stringify({ url: 'https://a.example' }),
        },
      },
    });
    const create = vi.fn();
    const existing = { id: 'm1', url: 'https://a.example' };
    const out = await runIdempotent({
      controller,
      kind: 'monitor',
      identity: { url: 'https://a.example' },
      find: async () => existing,
      create,
      record: (_refs, created) => ({ monitorUrl: created.url }),
    });
    expect(create).not.toHaveBeenCalled();
    expect(out.adopted).toBe(true);
    expect(controller.session.operationRefs.monitorUrl).toBe(
      'https://a.example'
    );
    // The pending marker is cleared once the result is recorded.
    expect(controller.session.progress.pending).toBeUndefined();
  });

  it('reuses the same operation id when the identity matches a retry', async () => {
    const controller = fakeController();
    const seen = [];
    const run = () =>
      runIdempotent({
        controller,
        kind: 'asset',
        identity: { name: 'Key' },
        find: async () => null,
        create: async (_i, operationId) => {
          seen.push(operationId);
          throw new Error('network down');
        },
        record: () => ({}),
      }).catch(() => {});
    await run();
    await run();
    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(seen[1]);
  });

  it('treats a conflict as success only when the existing item is the expected one', async () => {
    const controller = fakeController();
    const verified = { id: 7, name: 'Key' };
    let calls = 0;
    const out = await runIdempotent({
      controller,
      kind: 'asset',
      identity: { name: 'Key' },
      find: async () => (calls++ === 0 ? null : verified),
      create: async () => {
        throw { conflict: { id: 7 } };
      },
      record: (_r, created) => ({ tokenIds: [created.id] }),
    });
    expect(out.adopted).toBe(true);
    expect(controller.session.operationRefs.tokenIds).toEqual([7]);
  });

  it('surfaces a conflict that does not match instead of adopting it', async () => {
    const controller = fakeController();
    await expect(
      runIdempotent({
        controller,
        kind: 'asset',
        identity: { name: 'Key' },
        find: async () => null,
        create: async () => {
          throw { conflict: { id: 99, name: 'Other' } };
        },
        record: () => ({}),
      })
    ).rejects.toBeInstanceOf(OperationConflictError);
    // Nothing was recorded as done.
    expect(controller.session.operationRefs).toEqual({});
  });

  it('propagates non-conflict errors untouched', async () => {
    const controller = fakeController();
    await expect(
      runIdempotent({
        controller,
        kind: 'asset',
        identity: {},
        find: async () => null,
        create: async () => {
          throw new Error('boom');
        },
        record: () => ({}),
      })
    ).rejects.toThrow('boom');
  });
});

describe('normalizeMonitorUrl', () => {
  it('matches the server normalisation', () => {
    expect(normalizeMonitorUrl('example.com')).toBe('https://example.com');
    expect(normalizeMonitorUrl(' https://Example.com/ ')).toBe(
      'https://example.com'
    );
    expect(normalizeMonitorUrl('https://example.com/path/')).toBe(
      'https://example.com/path'
    );
  });
  it('rejects non-https and malformed input', () => {
    expect(normalizeMonitorUrl('http://example.com')).toBeNull();
    expect(normalizeMonitorUrl('')).toBeNull();
    expect(normalizeMonitorUrl('not a url')).toBeNull();
  });
  it('accepts internal single-label hosts and ports', () => {
    expect(normalizeMonitorUrl('intranet')).toBe('https://intranet');
    expect(normalizeMonitorUrl('https://localhost:8443')).toBe(
      'https://localhost:8443'
    );
  });
});

describe('evaluateVerification', () => {
  const routed = {
    alert_state: { eligibility: { eligible_channels: ['email'] } },
  };

  it('passes a monitored site with routing and SMTP', () => {
    const result = evaluateVerification({
      goal: 'monitor_https',
      monitor: { certificateExpiresAt: '2027-01-01T00:00:00Z', tokenId: 4 },
      token: routed,
      summary: { alerts: { smtpConfigured: true } },
    });
    expect(result.ok).toBe(true);
    expect(result.needsDeliverySetup).toBe(false);
  });

  it('fails when no certificate could be read', () => {
    const result = evaluateVerification({
      goal: 'monitor_https',
      monitor: { certificateExpiresAt: null, tokenId: null },
      token: null,
      summary: { alerts: { smtpConfigured: true } },
    });
    expect(result.ok).toBe(false);
    expect(result.checks.find(c => c.id === 'certificate').status).toBe('fail');
  });

  it('fails when an asset would send no alert', () => {
    const result = evaluateVerification({
      goal: 'track_asset',
      token: { alert_state: { eligibility: { eligible_channels: [] } } },
      summary: { alerts: { smtpConfigured: true } },
    });
    expect(result.ok).toBe(false);
    expect(result.checks.find(c => c.id === 'routing').status).toBe('fail');
  });

  it('treats missing SMTP as a follow-up, not a failed objective', () => {
    const result = evaluateVerification({
      goal: 'track_asset',
      token: routed,
      summary: { alerts: { smtpConfigured: false } },
    });
    expect(result.ok).toBe(true);
    expect(result.needsDeliverySetup).toBe(true);
  });

  it('does not claim success when SMTP state is unknown', () => {
    const result = evaluateVerification({
      goal: 'track_asset',
      token: routed,
      summary: { alerts: { smtpConfigured: 'unknown' } },
    });
    expect(result.ok).toBe(true);
    expect(result.checks.find(c => c.id === 'smtp').status).toBe('warn');
  });

  it('flags a read certificate that was never tracked as an asset', () => {
    const result = evaluateVerification({
      goal: 'monitor_https',
      monitor: { certificateExpiresAt: '2027-01-01', tokenId: null },
      token: null,
      summary: {},
    });
    expect(result.ok).toBe(false);
    expect(result.checks.find(c => c.id === 'asset').status).toBe('fail');
  });

  describe('AD CS goal', () => {
    const adcsSummary = adcs => ({
      alerts: { smtpConfigured: true },
      certops: {
        agents: { live: 1, items: [] },
        certificates: { total: 3 },
        adcs: {
          issuers: [{ id: 'i1', confirmed: true, safe: true }],
          profiles: 1,
          ...adcs,
        },
      },
    });

    it('keeps the follow-up warning until an enrollment is installed', () => {
      const result = evaluateVerification({
        goal: 'certops_adcs',
        token: routed,
        summary: adcsSummary({ installedEnrollments: 0 }),
      });
      const adcs = result.checks.find(c => c.id === 'adcs');
      expect(adcs.status).toBe('warn');
      expect(adcs.label).toMatch(/enrollment is not verified/);
    });

    it('passes once a certificate from the CA is installed', () => {
      const result = evaluateVerification({
        goal: 'certops_adcs',
        token: routed,
        summary: adcsSummary({ installedEnrollments: 1 }),
      });
      const adcs = result.checks.find(c => c.id === 'adcs');
      expect(adcs.status).toBe('pass');
      expect(adcs.label).toMatch(/installed/);
    });
  });
});
