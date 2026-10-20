import { describe, expect, it } from 'vitest';
import {
  buildAssetPayload,
  categoryOf,
  emptyAsset,
  fieldsFor,
  validateAsset,
  MAX_STAGED_ASSETS,
  assetKey,
  describeAsset,
} from '../../src/components/onboarding/assetModel.js';

const base = { ...emptyAsset(), name: 'Payments API key' };
const WS = '11111111-1111-4111-8111-111111111111';

describe('asset categories', () => {
  it('uses the product category table', () => {
    expect(['cert', 'key_secret', 'license', 'general']).toEqual(
      expect.arrayContaining(['cert', 'key_secret', 'license', 'general'])
    );
    expect(categoryOf('cert').types.map(t => t.value)).toContain('ssl_cert');
    expect(categoryOf('nope')).toBe(null);
  });

  it('shows the fields of the chosen category and type', () => {
    expect(fieldsFor('cert', 'ssl_cert')).toEqual(
      expect.arrayContaining(['domains', 'issuer', 'serial_number'])
    );
    expect(fieldsFor('license', 'software_license')).toEqual(
      expect.arrayContaining(['vendor', 'cost', 'renewal_date'])
    );
    expect(fieldsFor('key_secret', 'api_key')).not.toContain('algorithm');
    expect(fieldsFor('key_secret', 'ssh_key')).toEqual(
      expect.arrayContaining(['algorithm', 'key_size'])
    );
    expect(fieldsFor('nope', 'x')).toEqual([]);
  });
});

describe('validateAsset', () => {
  it('needs only a name, category and type', () => {
    expect(validateAsset(base).ok).toBe(true);
  });

  it('does not require an expiry date', () => {
    expect(validateAsset({ ...base, expiresAt: '' }).ok).toBe(true);
    expect(validateAsset({ ...base, neverExpires: true }).ok).toBe(true);
  });

  it('rejects a past or invalid expiry only when one is given', () => {
    expect(
      validateAsset({ ...base, expiresAt: '2000-01-01' }).errors.expiresAt
    ).toMatch(/future/);
    expect(
      validateAsset({ ...base, expiresAt: 'soon' }).errors.expiresAt
    ).toMatch(/Invalid/);
    expect(
      validateAsset({ ...base, neverExpires: true, expiresAt: '2000-01-01' }).ok
    ).toBe(true);
  });

  it('checks name and type against the category', () => {
    expect(validateAsset({ ...base, name: '  ' }).errors.name).toBeTruthy();
    expect(
      validateAsset({ ...base, name: 'x'.repeat(256) }).errors.name
    ).toBeTruthy();
    expect(
      validateAsset({ ...base, category: 'cert', type: 'api_key' }).errors.type
    ).toBeTruthy();
  });

  it('validates category-specific fields as the product does', () => {
    const cert = { ...base, category: 'cert', type: 'ssl_cert' };
    expect(
      validateAsset({ ...cert, fields: { domains: ' , ' } }).errors.domains
    ).toBeTruthy();
    expect(
      validateAsset({ ...cert, fields: { domains: 'a.example.com' } }).ok
    ).toBe(true);
    const lic = { ...base, category: 'license', type: 'software_license' };
    expect(
      validateAsset({ ...lic, fields: { cost: '-5' } }).errors.cost
    ).toBeTruthy();
    expect(validateAsset({ ...lic, fields: { cost: '19.90' } }).ok).toBe(true);
    // The server rejects a cost of one trillion or more.
    expect(
      validateAsset({ ...lic, fields: { cost: '1000000000000' } }).errors.cost
    ).toBeTruthy();
    expect(
      validateAsset({ ...lic, fields: { cost: '999999999999.99' } }).ok
    ).toBe(true);
    expect(
      validateAsset({ ...base, fields: { key_size: '2048' } }).errors.key_size
    ).toBeTruthy();
    expect(
      validateAsset({ ...base, type: 'ssh_key', fields: { key_size: '4096' } })
        .ok
    ).toBe(true);
  });
});

describe('buildAssetPayload', () => {
  it('uses the never-expires date when no expiry is given', () => {
    expect(buildAssetPayload(base, WS).expiresAt).toBe('2099-12-31');
    expect(
      buildAssetPayload(
        { ...base, neverExpires: true, expiresAt: '2030-01-01' },
        WS
      ).expiresAt
    ).toBe('2099-12-31');
  });

  it('keeps a real expiry', () => {
    expect(
      buildAssetPayload({ ...base, expiresAt: '2030-06-01' }, WS).expiresAt
    ).toBe('2030-06-01');
  });

  it('sends only fields that belong to the category', () => {
    const p = buildAssetPayload(
      {
        ...base,
        fields: {
          location: 'vault/prod',
          vendor: 'Acme',
          cost: '12',
          domains: 'a.example.com',
        },
      },
      WS
    );
    expect(p.location).toBe('vault/prod');
    expect(p.vendor).toBe(null);
    expect(p.cost).toBe(null);
    expect(p.domains).toBe(null);
  });

  it('converts typed values', () => {
    const p = buildAssetPayload(
      {
        ...base,
        category: 'license',
        type: 'software_license',
        section: 'prod, billing',
        fields: { cost: '19.90', vendor: ' Acme ' },
      },
      WS
    );
    expect(p).toMatchObject({
      cost: 19.9,
      vendor: 'Acme',
      section: ['prod', 'billing'],
    });
    const cert = buildAssetPayload(
      {
        ...base,
        category: 'cert',
        type: 'ssl_cert',
        fields: { domains: 'a.example.com, b.example.com' },
      },
      WS
    );
    expect(cert.domains).toEqual(['a.example.com', 'b.example.com']);
  });

  it('carries contact groups in the same shape as the main form', () => {
    const p = buildAssetPayload({ ...base, contactGroupIds: ['g1'] }, WS);
    expect(p.contact_group_ids).toEqual(['g1']);
    expect(p.contact_group_id).toBe('g1');
    expect(buildAssetPayload(base, WS).contact_group_ids).toEqual([]);
  });

  it('never carries a secret value', () => {
    const p = buildAssetPayload(
      { ...base, fields: { location: 'vault/prod' } },
      WS
    );
    expect(Object.keys(p).join(' ')).not.toMatch(/value|secret_value|password/);
    expect(p.workspace_id).toBe(WS);
  });
});

describe('staging several assets', () => {
  const base = {
    category: 'key_secret',
    type: 'api_key',
    name: 'Payments API key',
    neverExpires: false,
    expiresAt: '2030-01-01',
  };

  it('treats the same name, kind and date as one asset, ignoring case and spaces', () => {
    expect(assetKey({ ...base, name: '  PAYMENTS api KEY ' })).toBe(
      assetKey(base)
    );
  });

  it('tells apart a different name, kind or expiry date', () => {
    const key = assetKey(base);
    expect(assetKey({ ...base, name: 'Billing API key' })).not.toBe(key);
    expect(assetKey({ ...base, type: 'password' })).not.toBe(key);
    expect(
      assetKey({ ...base, category: 'license', type: 'software_license' })
    ).not.toBe(key);
    expect(assetKey({ ...base, expiresAt: '2031-01-01' })).not.toBe(key);
  });

  it('ignores a leftover date when the asset does not expire', () => {
    expect(
      assetKey({ ...base, neverExpires: true, expiresAt: '2030-01-01' })
    ).toBe(assetKey({ ...base, neverExpires: true, expiresAt: '' }));
  });

  it('describes a draft in plain words', () => {
    expect(describeAsset(base)).toEqual({
      title: 'Payments API key',
      detail: 'Key/Secret, API Key, expires 2030-01-01',
    });
    expect(describeAsset({ ...base, neverExpires: true }).detail).toMatch(
      /no expiry date/
    );
    expect(describeAsset({ ...base, expiresAt: '' }).detail).toMatch(
      /no expiry date/
    );
  });

  it('describes an unknown category without throwing', () => {
    expect(describeAsset({ name: 'X', category: 'nope' }).detail).toBe(
      'no expiry date'
    );
  });

  it('limits a batch', () => {
    expect(MAX_STAGED_ASSETS).toBeGreaterThan(1);
  });
});
