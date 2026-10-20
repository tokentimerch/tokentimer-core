// Prepares the AD CS path: the host-local enrollment rule and the values the
// issuer wizard needs. Pure. The guide cannot verify enrollment; it prepares
// exactly what the documented sequence asks for and says what is left.

const LABEL = '[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const DNS_NAME = new RegExp(`^(?=.{1,253}$)${LABEL}(\\.${LABEL})*$`);

// Copies of the patterns the agent enforces at startup, so the guide never
// accepts a value the agent would reject. Source of truth:
// packages/agent/src/config/index.js (ADCS_CA_CONFIG_PATTERN and
// ADCS_TEMPLATE_PATTERN) and the enrollment snapshot contract schema. The
// dashboard does not import the agent package; a unit test compares them.
export const ADCS_CA_CONFIG_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\[A-Za-z0-9 ._()-]{1,64}$/;
export const ADCS_TEMPLATE_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const CA_NAME = /^[A-Za-z0-9 ._()-]{1,64}$/;

export const ADCS_KEY_ALGORITHMS = ['rsa', 'ecdsa'];

function splitList(value) {
  return (Array.isArray(value) ? value : String(value || '').split(/[\s,]+/))
    .map(s => String(s).trim())
    .filter(Boolean);
}

function checkHost(host) {
  if (!host)
    return ['Enter the CA server name, for example ca01.corp.example.com.'];
  if (!DNS_NAME.test(host)) {
    return [
      'The CA server must be a DNS name: letters, digits and hyphens, no empty parts, each part up to 63 characters.',
    ];
  }
  return [];
}

function checkCaName(name) {
  if (!name) return ['Enter the CA name as shown in the CA console.'];
  if (name.includes('\\') || name.includes('/')) {
    return ['Enter only the CA name, without the server name or a backslash.'];
  }
  if (!CA_NAME.test(name)) {
    return [
      'The agent accepts only letters, digits, spaces and . _ ( ) - in the CA name, up to 64 characters.',
    ];
  }
  return [];
}

function checkTemplate(template) {
  if (!ADCS_TEMPLATE_PATTERN.test(template)) {
    return [
      'Enter the template common name, not its display name: letters, digits and . _ - only, up to 64 characters, no spaces. For example WebServer.',
    ];
  }
  return [];
}

/** "host\CA name", the form the rule and the issuer must match exactly. */
export function buildCaConfig(host, caName) {
  const h = String(host || '').trim();
  const n = String(caName || '').trim();
  const fieldErrors = {};
  const hostErrors = checkHost(h);
  const nameErrors = checkCaName(n);
  if (hostErrors.length) fieldErrors.caHost = hostErrors;
  if (nameErrors.length) fieldErrors.caName = nameErrors;
  if (hostErrors.length || nameErrors.length) {
    return {
      ok: false,
      problems: [...hostErrors, ...nameErrors],
      fieldErrors,
    };
  }
  const caConfig = `${h}\\${n}`;
  if (!ADCS_CA_CONFIG_PATTERN.test(caConfig)) {
    const problems = ['The CA server and name together are not accepted.'];
    return { ok: false, problems, fieldErrors: { caHost: problems } };
  }
  return { ok: true, caConfig };
}

function normalizeScopes(dnsScopes) {
  return splitList(dnsScopes).map(s => s.toLowerCase().replace(/\.$/, ''));
}

function checkScopes(scopes) {
  if (scopes.length === 0) {
    return ['Enter at least one DNS scope, for example corp.example.com.'];
  }
  const problems = [];
  for (const s of scopes) {
    if (s.includes('*')) {
      problems.push('Do not use a wildcard in a DNS scope.');
    } else if (!DNS_NAME.test(s)) {
      problems.push(`"${s}" is not a valid DNS scope.`);
    }
  }
  return Array.from(new Set(problems));
}

/**
 * The enrollment rule for the agent's config.json. It names the one CA and
 * template the host may contact, the DNS scopes it may request, and the key
 * types, as the AD CS guide requires.
 */
export function buildAdcsRule({
  caHost,
  caName,
  template,
  dnsScopes,
  keyAlgorithms = ['rsa', 'ecdsa'],
}) {
  const fieldErrors = {};
  const ca = buildCaConfig(caHost, caName);
  if (!ca.ok) Object.assign(fieldErrors, ca.fieldErrors);
  const tpl = String(template || '').trim();
  const templateErrors = checkTemplate(tpl);
  if (templateErrors.length) fieldErrors.template = templateErrors;
  const scopes = normalizeScopes(dnsScopes);
  const scopeErrors = checkScopes(scopes);
  if (scopeErrors.length) fieldErrors.dnsScopes = scopeErrors;
  const algos = Array.from(new Set(keyAlgorithms));
  const problems = Object.values(fieldErrors).flat();
  if (algos.length === 0 || algos.some(a => !ADCS_KEY_ALGORITHMS.includes(a)))
    problems.push('Choose RSA, ECDSA or both.');
  if (problems.length) return { ok: false, problems, fieldErrors };
  return {
    ok: true,
    rule: {
      caConfig: ca.caConfig,
      template: tpl,
      dnsScopes: Array.from(new Set(scopes)),
      keyAlgorithms: algos,
    },
  };
}

/** Every requested name must be a scope or sit under one at a dot boundary. */
export function namesCoveredByScopes(names, scopes) {
  const list = (scopes || []).map(s => String(s).toLowerCase());
  const missing = (names || [])
    .map(n => String(n).trim().toLowerCase())
    .filter(Boolean)
    .filter(n => !list.some(s => n === s || n.endsWith(`.${s}`)));
  return { ok: missing.length === 0, missing };
}

/**
 * Names the agent will publish. Plain DNS names only: the renewal profile and
 * the API reject wildcards, and the agent matches a profile's certificate
 * name against this list exactly, so names are saved in lowercase.
 */
export function normalizeAdcsNames(names) {
  const seen = new Set();
  const out = [];
  for (const raw of splitList(names)) {
    const n = raw.toLowerCase().replace(/\.$/, '');
    if (!seen.has(n)) {
      seen.add(n);
      out.push(n);
    }
  }
  return out;
}

function checkNames(names) {
  if (names.length === 0) {
    return ['Enter at least one name, for example web.corp.example.com.'];
  }
  const problems = [];
  for (const n of names) {
    if (n.includes('*')) {
      problems.push(`${n} is a wildcard. Enter the exact DNS name.`);
    } else if (!DNS_NAME.test(n)) {
      problems.push(`"${n}" is not a valid DNS name.`);
    }
  }
  return problems;
}

/** The agent config fragment: only the rule, merged by the operator. */
export function buildAdcsConfig(args) {
  const built = buildAdcsRule(args);
  const fieldErrors = built.ok ? {} : { ...built.fieldErrors };
  const problems = built.ok ? [] : [...built.problems];
  const names = normalizeAdcsNames(args.names);
  const nameErrors = checkNames(names);
  if (nameErrors.length === 0 && built.ok) {
    const covered = namesCoveredByScopes(names, built.rule.dnsScopes);
    for (const n of covered.missing) {
      nameErrors.push(
        `${n} is not inside any DNS scope, so enrollment would be refused.`
      );
    }
  }
  if (nameErrors.length) {
    fieldErrors.names = nameErrors;
    problems.push(...nameErrors);
  }
  if (problems.length) return { ok: false, problems, fieldErrors };
  return {
    ok: true,
    config: {
      // Routing reads this, not the rule: without it no job reaches the agent.
      declaredTargetSelectors: names,
      // Safe default. The CA check works in dry run; real enrollment is
      // refused until dryRun is set to false.
      execution: { enabled: true, dryRun: true },
      adcs: { enrollmentRules: [built.rule] },
    },
    rule: built.rule,
  };
}

/** Shown next to the generated config: why dryRun is true and when to change it. */
export const ADCS_DRY_RUN_NOTE =
  'This file starts in dry run (execution.dryRun is true). The CA check works, but the agent refuses real enrollment. After the issuer has passed its check, set dryRun to false and restart TokenTimerAgent. The agent authenticates as its computer account, so no credential goes in this file.';

/** What the person still has to do after the guide has prepared its part. */
export const ADCS_REMAINING_STEPS = [
  'Join the Windows server to the domain (it must not be a domain controller) and grant the computer account Enroll on the template.',
  'In Certificate Management, Renewals, open AD CS issuers and create the issuer with the same CA and template, then pin the CA certificate.',
  'Create an AD CS renewal profile for the site and attach it to the certificate.',
  'Once the issuer has passed its CA check, set "dryRun" to false under "execution" in the saved config.json and restart TokenTimerAgent. Until then the agent refuses real enrollment and only the CA check runs.',
];
