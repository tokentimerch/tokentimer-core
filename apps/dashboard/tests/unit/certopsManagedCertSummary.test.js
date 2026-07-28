import { describe, it, expect } from 'vitest';

import { summarizeManagedCertificates } from '../../src/components/certops/certopsFormat';

const linked = (overrides = {}) => ({
  id: 'cert-linked',
  tokenId: 7,
  status: 'discovered',
  notAfter: '2026-09-03T00:00:00.000Z',
  ...overrides,
});

describe('summarizeManagedCertificates', () => {
  it('lists only certificates linked to a token', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'a', tokenId: 1 }),
      linked({ id: 'b', tokenId: null, status: 'provisioning' }),
    ]);

    expect(summary.highlights.map(cert => cert.id)).toEqual(['a']);
    expect(summary.linkedCount).toBe(1);
  });

  it('counts unlinked provisioning certificates separately instead of listing them', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'a', tokenId: 1 }),
      linked({ id: 'b', tokenId: null, status: 'provisioning', notAfter: null }),
      linked({ id: 'c', tokenId: null, status: 'provisioning', notAfter: null }),
    ]);

    expect(summary.provisioningCount).toBe(2);
    expect(summary.linkedCount).toBe(1);
    expect(summary.highlights.map(cert => cert.id)).toEqual(['a']);
  });

  it('reports an unlinked non-provisioning certificate rather than hiding it', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'orphan', tokenId: null, status: 'active' }),
    ]);

    expect(summary.linkedCount).toBe(0);
    expect(summary.provisioningCount).toBe(0);
    expect(summary.unlinkedCount).toBe(1);
  });

  // Silently dropping a row from both the list and every count is exactly how
  // the original inventory bug stayed invisible.
  it('never drops an active certificate from all three counts', () => {
    const certificates = [
      linked({ id: 'linked', tokenId: 1 }),
      linked({ id: 'provisioning', tokenId: null, status: 'provisioning' }),
      linked({ id: 'orphan-active', tokenId: null, status: 'active' }),
      linked({ id: 'orphan-unknown', tokenId: null, status: 'weird-state' }),
      linked({ id: 'retired', tokenId: 2, status: 'revoked' }),
    ];

    const summary = summarizeManagedCertificates(certificates);
    const accounted =
      summary.linkedCount + summary.provisioningCount + summary.unlinkedCount;
    const activeTotal = certificates.filter(
      cert => !['revoked', 'decommissioned'].includes(cert.status)
    ).length;

    expect(accounted).toBe(activeTotal);
  });

  it('excludes retired certificates from both the list and every count', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'revoked', tokenId: 1, status: 'revoked' }),
      linked({ id: 'decommissioned', tokenId: 2, status: 'decommissioned' }),
    ]);

    expect(summary.linkedCount).toBe(0);
    expect(summary.provisioningCount).toBe(0);
    expect(summary.unlinkedCount).toBe(0);
    expect(summary.highlights).toEqual([]);
  });

  it('does not count a retired certificate as provisioning or unlinked', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'a', tokenId: null, status: 'revoked' }),
    ]);

    expect(summary.provisioningCount).toBe(0);
    expect(summary.unlinkedCount).toBe(0);
  });

  it('orders highlights by soonest expiry', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'later', tokenId: 1, notAfter: '2027-01-01T00:00:00.000Z' }),
      linked({ id: 'sooner', tokenId: 2, notAfter: '2026-08-01T00:00:00.000Z' }),
    ]);

    expect(summary.highlights.map(cert => cert.id)).toEqual([
      'sooner',
      'later',
    ]);
  });

  it('sorts a missing or unparseable expiry last rather than first', () => {
    const summary = summarizeManagedCertificates([
      linked({ id: 'unparseable', tokenId: 1, notAfter: 'not-a-date' }),
      linked({ id: 'missing', tokenId: 2, notAfter: null }),
      linked({ id: 'dated', tokenId: 3, notAfter: '2026-08-01T00:00:00.000Z' }),
    ]);

    expect(summary.highlights[0].id).toBe('dated');
  });

  it('caps the highlight list without capping the count', () => {
    const many = Array.from({ length: 8 }, (_, index) =>
      linked({
        id: `cert-${index}`,
        tokenId: index + 1,
        notAfter: `2026-08-0${index + 1}T00:00:00.000Z`,
      })
    );

    const summary = summarizeManagedCertificates(many);

    expect(summary.highlights).toHaveLength(5);
    expect(summary.linkedCount).toBe(8);
  });

  it('tolerates a missing or non-array inventory', () => {
    for (const input of [undefined, null, 'nope', {}]) {
      const summary = summarizeManagedCertificates(input);
      expect(summary.linkedCount).toBe(0);
      expect(summary.provisioningCount).toBe(0);
      expect(summary.unlinkedCount).toBe(0);
      expect(summary.highlights).toEqual([]);
    }
  });
});
