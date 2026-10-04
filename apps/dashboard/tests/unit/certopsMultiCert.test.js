import { describe, it, expect } from 'vitest';
import {
  pickPrimaryCertificate,
  sortCertificatesForToken,
  resolveTokenCertificate,
} from '../../src/components/certops/certopsFormat';

function cert(overrides = {}) {
  return {
    id: 'cert-a',
    status: 'active',
    updatedAt: '2026-01-01T00:00:00.000Z',
    createdAt: '2025-12-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('sortCertificatesForToken / pickPrimaryCertificate (multi-cert)', () => {
  it('returns null / empty for missing input', () => {
    expect(pickPrimaryCertificate(undefined)).toBeNull();
    expect(pickPrimaryCertificate(null)).toBeNull();
    expect(pickPrimaryCertificate([])).toBeNull();
    expect(sortCertificatesForToken(undefined)).toEqual([]);
  });

  it('returns the only certificate when a token has a single cert', () => {
    const only = cert({ id: 'solo' });
    expect(pickPrimaryCertificate([only])).toBe(only);
  });

  it('prefers the active certificate over a retired one, regardless of recency', () => {
    const retired = cert({
      id: 'cert-retired',
      status: 'revoked',
      updatedAt: '2026-06-01T00:00:00.000Z',
    });
    const active = cert({
      id: 'cert-active',
      status: 'active',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(pickPrimaryCertificate([retired, active]).id).toBe('cert-active');
    expect(pickPrimaryCertificate([active, retired]).id).toBe('cert-active');
    expect(sortCertificatesForToken([retired, active]).map(c => c.id)).toEqual([
      'cert-active',
      'cert-retired',
    ]);
  });

  it('treats decommissioned as retired too', () => {
    const decommissioned = cert({
      id: 'cert-dec',
      status: 'decommissioned',
      updatedAt: '2026-06-01T00:00:00.000Z',
    });
    const active = cert({ id: 'cert-active' });
    expect(pickPrimaryCertificate([decommissioned, active]).id).toBe(
      'cert-active'
    );
  });

  it('picks the most recently updated among several active certificates', () => {
    const older = cert({
      id: 'cert-old',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    const newer = cert({
      id: 'cert-new',
      updatedAt: '2026-03-01T00:00:00.000Z',
    });
    expect(pickPrimaryCertificate([older, newer]).id).toBe('cert-new');
    expect(pickPrimaryCertificate([newer, older]).id).toBe('cert-new');
  });

  it('falls back to createdAt when updatedAt is missing', () => {
    const noUpdated = cert({
      id: 'cert-created-late',
      updatedAt: null,
      createdAt: '2026-05-01T00:00:00.000Z',
    });
    const updatedEarly = cert({
      id: 'cert-updated-early',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(pickPrimaryCertificate([updatedEarly, noUpdated]).id).toBe(
      'cert-created-late'
    );
  });

  it('breaks exact timestamp ties by id ascending (deterministic)', () => {
    const a = cert({ id: 'aaa', updatedAt: '2026-01-01T00:00:00.000Z' });
    const b = cert({ id: 'bbb', updatedAt: '2026-01-01T00:00:00.000Z' });
    expect(pickPrimaryCertificate([b, a]).id).toBe('aaa');
    expect(pickPrimaryCertificate([a, b]).id).toBe('aaa');
  });

  it('is stable regardless of input order (deterministic ordering)', () => {
    const certs = [
      cert({
        id: 'r1',
        status: 'revoked',
        updatedAt: '2026-06-01T00:00:00.000Z',
      }),
      cert({
        id: 'a1',
        status: 'active',
        updatedAt: '2026-02-01T00:00:00.000Z',
      }),
      cert({
        id: 'a2',
        status: 'active',
        updatedAt: '2026-04-01T00:00:00.000Z',
      }),
    ];
    const expected = ['a2', 'a1', 'r1'];
    expect(sortCertificatesForToken(certs).map(c => c.id)).toEqual(expected);
    expect(
      sortCertificatesForToken([...certs].reverse()).map(c => c.id)
    ).toEqual(expected);
  });

  it('does not mutate the input array', () => {
    const certs = [cert({ id: 'b' }), cert({ id: 'a' })];
    const snapshot = certs.map(c => c.id);
    sortCertificatesForToken(certs);
    expect(certs.map(c => c.id)).toEqual(snapshot);
  });
});

describe('resolveTokenCertificate (fingerprint scoped token contexts)', () => {
  it('does not select active B over revoked A linked to the same asset', () => {
    const A = cert({ fingerprintSha256: 'a'.repeat(64), status: 'revoked' });
    const B = cert({
      id: 'cert-b',
      fingerprintSha256: 'b'.repeat(64),
      status: 'active',
      updatedAt: '2026-03-01',
    });
    const resolution = resolveTokenCertificate([A, B]);
    expect(resolution.certificate).toBeNull();
    expect(resolution.ambiguousLink).toBe(true);
    expect(resolution.certificateCount).toBe(2);
    expect(resolution.hasManagedLinks).toBe(true);
  });

  it('normalizes the same fingerprint across sources and retains one safe representative', () => {
    const older = cert({ fingerprintSha256: 'a'.repeat(64) });
    const newer = cert({
      id: 'cert-agent',
      fingerprintSha256: 'AA:'.repeat(31) + 'AA',
      updatedAt: '2026-03-01',
    });
    expect(resolveTokenCertificate([older, newer])).toEqual({
      certificate: newer,
      certificateCount: 1,
      ambiguousLink: false,
      hasManagedLinks: true,
      allRetired: false,
    });
  });

  it('preserves aggregate retirement without selecting an ambiguous identity', () => {
    const A = cert({ fingerprintSha256: 'a'.repeat(64), status: 'revoked' });
    const B = cert({
      id: 'b',
      fingerprintSha256: 'b'.repeat(64),
      status: 'decommissioned',
    });
    expect(resolveTokenCertificate([A, B])).toMatchObject({
      ambiguousLink: true,
      certificate: null,
      allRetired: true,
    });
    expect(
      resolveTokenCertificate([A, { ...B, status: 'active' }]).allRetired
    ).toBe(false);
    expect(resolveTokenCertificate([]).allRetired).toBe(false);
  });

  it('keeps unidentified associations separate and never treats ambiguity as unmanaged', () => {
    const unknown = cert({ id: 'unknown', fingerprintSha256: null });
    expect(resolveTokenCertificate([unknown]).certificate).toBe(unknown);
    for (const linked of [
      [unknown, cert({ id: 'other-unknown' })],
      [unknown, cert({ fingerprintSha256: 'a'.repeat(64) })],
    ]) {
      expect(resolveTokenCertificate(linked).certificate).toBeNull();
      expect(resolveTokenCertificate(linked).hasManagedLinks).toBe(true);
      expect(resolveTokenCertificate(linked).ambiguousLink).toBe(true);
    }
    expect(resolveTokenCertificate([]).hasManagedLinks).toBe(false);
  });
});
