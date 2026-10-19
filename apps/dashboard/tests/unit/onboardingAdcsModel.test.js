import { describe, expect, it } from 'vitest';
import {
  ADCS_REMAINING_STEPS,
  buildAdcsConfig,
  buildAdcsRule,
  buildCaConfig,
  namesCoveredByScopes,
} from '../../src/components/onboarding/adcsModel.js';

const good = {
  caHost: 'ca01.corp.example.com',
  caName: 'Corp Issuing CA',
  template: 'WebServer',
  dnsScopes: 'corp.example.com',
};

describe('buildCaConfig', () => {
  it('joins host and name the way the issuer must match it', () => {
    expect(buildCaConfig('ca01.corp.example.com', 'Corp Issuing CA')).toEqual({
      ok: true,
      caConfig: 'ca01.corp.example.com\\Corp Issuing CA',
    });
  });

  it('rejects a name that already has a backslash or an empty host', () => {
    expect(buildCaConfig('ca01', 'Corp\\CA').ok).toBe(false);
    expect(buildCaConfig('', 'Corp CA').ok).toBe(false);
    expect(buildCaConfig('bad host', 'Corp CA').ok).toBe(false);
  });
});

describe('buildAdcsRule', () => {
  it('produces the documented rule shape', () => {
    const r = buildAdcsRule(good);
    expect(r.ok).toBe(true);
    expect(r.rule).toEqual({
      caConfig: 'ca01.corp.example.com\\Corp Issuing CA',
      template: 'WebServer',
      dnsScopes: ['corp.example.com'],
      keyAlgorithms: ['rsa', 'ecdsa'],
    });
  });

  it('requires scopes, a template and a known key type', () => {
    expect(buildAdcsRule({ ...good, dnsScopes: '' }).ok).toBe(false);
    expect(buildAdcsRule({ ...good, template: '' }).ok).toBe(false);
    expect(buildAdcsRule({ ...good, keyAlgorithms: ['dsa'] }).ok).toBe(false);
    expect(buildAdcsRule({ ...good, keyAlgorithms: [] }).ok).toBe(false);
  });

  it('refuses wildcard scopes and tidies case and trailing dots', () => {
    expect(buildAdcsRule({ ...good, dnsScopes: '*.corp.example.com' }).ok).toBe(
      false
    );
    expect(
      buildAdcsRule({
        ...good,
        dnsScopes: 'Corp.Example.com., corp.example.com',
      }).rule.dnsScopes
    ).toEqual(['corp.example.com']);
  });
});

describe('namesCoveredByScopes', () => {
  it('matches a scope exactly or beneath it at a dot boundary', () => {
    expect(
      namesCoveredByScopes(
        ['web.corp.example.com', 'corp.example.com'],
        ['corp.example.com']
      ).ok
    ).toBe(true);
  });

  it('does not accept a look-alike domain', () => {
    const r = namesCoveredByScopes(
      ['web.evilcorp.example.com', 'evilcorp.example.com'],
      ['corp.example.com']
    );
    expect(r.ok).toBe(false);
    expect(r.missing).toHaveLength(2);
  });
});

describe('buildAdcsConfig', () => {
  it('declares the names the agent must publish, besides the rule', () => {
    const r = buildAdcsConfig({ ...good, names: ['web.corp.example.com'] });
    expect(r.ok).toBe(true);
    expect(r.config.declaredTargetSelectors).toEqual(['web.corp.example.com']);
    expect(r.config.adcs.enrollmentRules).toHaveLength(1);
    expect(r.config.execution).toEqual({ enabled: true, dryRun: true });
  });

  it('refuses a name no scope covers, which the agent would reject', () => {
    const r = buildAdcsConfig({ ...good, names: ['web.other.example.net'] });
    expect(r.ok).toBe(false);
    expect(r.problems[0]).toMatch(/not inside any DNS scope/);
  });

  it('never contains credentials', () => {
    const text = JSON.stringify(
      buildAdcsConfig({ ...good, names: ['web.corp.example.com'] })
    );
    expect(text).not.toMatch(/password|secret|token|key material/i);
  });

  it('lists what the person still has to do', () => {
    expect(ADCS_REMAINING_STEPS.length).toBeGreaterThanOrEqual(3);
    expect(ADCS_REMAINING_STEPS.join(' ')).toMatch(/issuer/i);
  });
});
