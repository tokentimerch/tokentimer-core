import { describe, it, expect } from 'vitest';
import { collapseScanSummaryByType } from '../../src/components/imports/collapseScanSummaryByType';

describe('collapseScanSummaryByType', () => {
  it('collapses duplicate Azure AD type rows and uses extracted credential counts', () => {
    const rows = collapseScanSummaryByType([
      {
        type: 'applications',
        sourceKind: 'azure-ad-client-secret',
        found: 3,
        secrets: 7,
        certificates: 0,
      },
      {
        type: 'applications',
        sourceKind: 'azure-ad-certificate',
        found: 3,
        secrets: 7,
        certificates: 0,
      },
      {
        type: 'service_principals',
        sourceKind: 'azure-ad-sp-secret',
        found: 105,
        secrets: 1,
        certificates: 2,
      },
      {
        type: 'service_principals',
        sourceKind: 'azure-ad-sp-certificate',
        found: 105,
        secrets: 1,
        certificates: 2,
      },
    ]);

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      type: 'applications',
      found: 7,
      secrets: 7,
      certificates: 0,
    });
    expect(rows[1]).toMatchObject({
      type: 'service_principals',
      found: 3,
      secrets: 1,
      certificates: 2,
    });
  });

  it('sums per-kind found when secrets and certs live on separate rows', () => {
    const rows = collapseScanSummaryByType([
      {
        type: 'applications',
        sourceKind: 'azure-ad-client-secret',
        found: 7,
        secrets: 7,
      },
      {
        type: 'applications',
        sourceKind: 'azure-ad-certificate',
        found: 0,
        certificates: 0,
      },
      {
        type: 'service_principals',
        sourceKind: 'azure-ad-sp-secret',
        found: 1,
        secrets: 1,
      },
      {
        type: 'service_principals',
        sourceKind: 'azure-ad-sp-certificate',
        found: 2,
        certificates: 2,
      },
    ]);

    expect(rows.map(r => ({ type: r.type, found: r.found }))).toEqual([
      { type: 'applications', found: 7 },
      { type: 'service_principals', found: 3 },
    ]);
  });

  it('marks a collapsed type incomplete if any sourceKind row failed', () => {
    const rows = collapseScanSummaryByType([
      {
        type: 'applications',
        sourceKind: 'azure-ad-client-secret',
        found: 1,
        secrets: 1,
        complete: true,
      },
      {
        type: 'applications',
        sourceKind: 'azure-ad-certificate',
        error: 'Graph 403',
        complete: false,
      },
    ]);

    expect(rows).toHaveLength(1);
    expect(rows[0].complete).toBe(false);
    expect(rows[0].error).toBe('Graph 403');
  });
});
