import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ADCS_CA_CONFIG_PATTERN,
  ADCS_DRY_RUN_NOTE,
  ADCS_REAL_ENROLLMENT_BLOCK,
  ADCS_TEMPLATE_PATTERN,
  buildAdcsConfig,
  buildAdcsRule,
  buildCaConfig,
  namesCoveredByScopes,
  normalizeAdcsNames,
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

  it('keeps the dry-run default and points at the step that turns it off', () => {
    const r = buildAdcsConfig({ ...good, names: ['web.corp.example.com'] });
    expect(r.config.execution.dryRun).toBe(true);
    expect(ADCS_DRY_RUN_NOTE).toMatch(/refuses real enrollment/);
    expect(ADCS_DRY_RUN_NOTE).toMatch(/Connect your Microsoft CA/);
    expect(JSON.parse(`{${ADCS_REAL_ENROLLMENT_BLOCK}}`)).toEqual({
      execution: { enabled: true, dryRun: false },
    });
  });
});

const ok = (host, name) => buildCaConfig(host, name).ok;
// Vitest runs from apps/dashboard, so the repo root is two levels up.
const repo = rel => readFileSync(resolve(process.cwd(), '../..', rel), 'utf8');

// Each row is [value, expected]. The expectation mirrors the agent patterns,
// and the cross-check below proves the model and the agent agree.
describe('CA server (DNS host)', () => {
  it.each([
    ['ca01.corp.example.com', true],
    ['ca01', true],
    ['CA-01.Corp.Example.com', true],
    ['', false],
    ['ca01..corp', false],
    ['.ca01', false],
    ['ca01.', false],
    ['-ca01.corp', false],
    ['ca_01.corp', false],
    ['bad host', false],
    [`${'a'.repeat(63)}.corp`, true],
    [`${'a'.repeat(64)}.corp`, false],
  ])('%j -> %s', (host, expected) => {
    expect(ok(host, 'Corp CA')).toBe(expected);
  });
});

describe('CA name', () => {
  it.each([
    ['Corp Issuing CA', true],
    ['Corp-CA_1 (2024).v2', true],
    ['a'.repeat(64), true],
    ['', false],
    ['a'.repeat(65), false],
    ['Corp, Inc CA', false],
    ['Corp "CA"', false],
    ['R&D CA', false],
    ["O'Brien CA", false],
    ['Corp\\CA', false],
    ['Corp/CA', false],
  ])('%j -> %s', (name, expected) => {
    expect(ok('ca01.corp.example.com', name)).toBe(expected);
  });
});

describe('template common name', () => {
  it.each([
    ['WebServer', true],
    ['Web_Server-2.0', true],
    ['a'.repeat(64), true],
    ['', false],
    ['Web Server', false],
    ['a'.repeat(65), false],
    ['Web/Server', false],
    ['Web$', false],
    ['..\\x', false],
    ['$(calc)', false],
  ])('%j -> %s', (template, expected) => {
    expect(buildAdcsRule({ ...good, template }).ok).toBe(expected);
  });

  it('explains it is the common name, not the display name, with no spaces', () => {
    const r = buildAdcsRule({ ...good, template: 'Web Server' });
    expect(r.fieldErrors.template[0]).toMatch(
      /common name, not its display name/
    );
    expect(r.fieldErrors.template[0]).toMatch(/no spaces/);
  });
});

describe('names', () => {
  const build = names => buildAdcsConfig({ ...good, names });

  it('requires at least one name', () => {
    for (const names of [[], '', '  , ']) {
      const r = build(names);
      expect(r.ok).toBe(false);
      expect(r.fieldErrors.names[0]).toMatch(/at least one name/);
    }
  });

  it('rejects wildcards with a clear message', () => {
    const r = build(['*.corp.example.com']);
    expect(r.ok).toBe(false);
    expect(r.fieldErrors.names[0]).toMatch(/wildcard/);
  });

  it('rejects malformed DNS names', () => {
    for (const bad of ['web..corp.example.com', 'web_1.corp.example.com']) {
      expect(build([bad]).ok).toBe(false);
    }
  });

  it('saves plain names in lowercase, once each', () => {
    const r = build(
      'WEB.corp.example.com, web.corp.example.com. api.corp.example.com'
    );
    expect(r.ok).toBe(true);
    expect(r.config.declaredTargetSelectors).toEqual([
      'web.corp.example.com',
      'api.corp.example.com',
    ]);
    expect(normalizeAdcsNames(['A.b', 'a.b'])).toEqual(['a.b']);
  });

  it('keeps blocking scopes that are wildcards, path-like or command-like', () => {
    for (const dnsScopes of [
      '*.corp.example.com',
      'C:\\temp',
      '$(calc)',
      '../x',
    ]) {
      expect(
        buildAdcsConfig({ ...good, dnsScopes, names: ['web.corp.example.com'] })
          .ok
      ).toBe(false);
    }
    expect(
      buildAdcsConfig({ ...good, names: ['web.other.example.net'] }).ok
    ).toBe(false);
  });

  it('reports each problem on the field it belongs to', () => {
    const r = buildAdcsConfig({
      caHost: 'ca01..corp',
      caName: 'Corp, Inc',
      template: 'Web Server',
      dnsScopes: '',
      names: [],
    });
    expect(Object.keys(r.fieldErrors).sort()).toEqual(
      ['caHost', 'caName', 'dnsScopes', 'names', 'template'].sort()
    );
  });
});

describe('agent contract', () => {
  const agentSource = repo('packages/agent/src/config/index.js');
  const pattern = name =>
    new RegExp(new RegExp(`const ${name} =\\s*/(.+)/;`).exec(agentSource)[1]);
  const schema = JSON.parse(
    repo('packages/contracts/certops/enrollment-snapshot.schema.json')
  );

  it('uses the same patterns the agent enforces at startup', () => {
    expect(ADCS_CA_CONFIG_PATTERN.source).toBe(
      pattern('ADCS_CA_CONFIG_PATTERN').source
    );
    expect(ADCS_TEMPLATE_PATTERN.source).toBe(
      pattern('ADCS_TEMPLATE_PATTERN').source
    );
  });

  it('uses the same patterns as the enrollment snapshot schema', () => {
    expect(ADCS_CA_CONFIG_PATTERN.source).toBe(
      new RegExp(schema.properties.caConfig.pattern).source
    );
    expect(ADCS_TEMPLATE_PATTERN.source).toBe(
      new RegExp(schema.properties.template.pattern).source
    );
  });

  it('generates a rule the agent would accept', () => {
    const agentCa = pattern('ADCS_CA_CONFIG_PATTERN');
    const agentTemplate = pattern('ADCS_TEMPLATE_PATTERN');
    const r = buildAdcsConfig({ ...good, names: ['web.corp.example.com'] });
    const rule = r.config.adcs.enrollmentRules[0];
    expect(agentCa.test(rule.caConfig)).toBe(true);
    expect(agentTemplate.test(rule.template)).toBe(true);
  });

  it('never accepts a CA or template the agent patterns reject', () => {
    const agentCa = pattern('ADCS_CA_CONFIG_PATTERN');
    const agentTemplate = pattern('ADCS_TEMPLATE_PATTERN');
    const hosts = [
      'ca01.corp',
      'ca01..corp',
      'bad host',
      `${'a'.repeat(64)}.x`,
    ];
    const names = ['Corp CA', 'Corp, CA', 'R&D', 'a'.repeat(65), 'x"y'];
    for (const h of hosts) {
      for (const n of names) {
        expect(ok(h, n)).toBe(agentCa.test(`${h}\\${n}`));
      }
    }
    for (const t of ['WebServer', 'Web Server', 'a'.repeat(65), 'a.b-c_d']) {
      expect(buildAdcsRule({ ...good, template: t }).ok).toBe(
        agentTemplate.test(t)
      );
    }
  });
});
