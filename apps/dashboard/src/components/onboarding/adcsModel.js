// Prepares the AD CS path: the host-local enrollment rule and the values the
// issuer wizard needs. Pure. The guide cannot verify enrollment; it prepares
// exactly what the documented sequence asks for and says what is left.

const HOST = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const CA_NAME = /^[^\\/\r\n]{1,128}$/;
const TEMPLATE = /^[A-Za-z0-9 _.-]{1,64}$/;
const DNS_SCOPE =
  /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export const ADCS_KEY_ALGORITHMS = ['rsa', 'ecdsa'];

/** "host\CA name", the form the rule and the issuer must match exactly. */
export function buildCaConfig(host, caName) {
  const h = String(host || '').trim();
  const n = String(caName || '').trim();
  const problems = [];
  if (!HOST.test(h))
    problems.push(
      'Enter the CA server name, for example ca01.corp.example.com.'
    );
  if (!CA_NAME.test(n))
    problems.push(
      'Enter the CA name as shown in the CA console, without backslashes.'
    );
  if (problems.length) return { ok: false, problems };
  return { ok: true, caConfig: `${h}\\${n}` };
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
  const problems = [];
  const ca = buildCaConfig(caHost, caName);
  if (!ca.ok) problems.push(...ca.problems);
  const tpl = String(template || '').trim();
  if (!TEMPLATE.test(tpl))
    problems.push('Enter the template common name, for example WebServer.');
  const scopes = (
    Array.isArray(dnsScopes)
      ? dnsScopes
      : String(dnsScopes || '').split(/[\s,]+/)
  )
    .map(s => String(s).trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
  if (scopes.length === 0)
    problems.push(
      'Enter at least one DNS scope, for example corp.example.com.'
    );
  for (const s of scopes) {
    if (!DNS_SCOPE.test(s)) problems.push(`"${s}" is not a valid DNS scope.`);
    if (s.startsWith('*'))
      problems.push('Do not use a wildcard in a DNS scope.');
  }
  const algos = Array.from(new Set(keyAlgorithms));
  if (algos.length === 0 || algos.some(a => !ADCS_KEY_ALGORITHMS.includes(a)))
    problems.push('Choose RSA, ECDSA or both.');
  if (problems.length) return { ok: false, problems };
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

/** The agent config fragment: only the rule, merged by the operator. */
export function buildAdcsConfig(args) {
  const built = buildAdcsRule(args);
  if (!built.ok) return built;
  const names = (args.names || []).map(n => String(n).trim()).filter(Boolean);
  const covered = namesCoveredByScopes(names, built.rule.dnsScopes);
  if (!covered.ok) {
    return {
      ok: false,
      problems: covered.missing.map(
        n => `${n} is not inside any DNS scope, so enrollment would be refused.`
      ),
    };
  }
  return {
    ok: true,
    config: {
      // Routing reads this, not the rule: without it no job reaches the agent.
      declaredTargetSelectors: names,
      execution: { enabled: true, dryRun: true },
      adcs: { enrollmentRules: [built.rule] },
    },
    rule: built.rule,
  };
}

/** What the person still has to do after the guide has prepared its part. */
export const ADCS_REMAINING_STEPS = [
  'Join the Windows server to the domain and grant the computer account Enroll on the template.',
  'In Certificate Management, Renewals, open AD CS issuers and create the issuer with the same CA and template, then pin the CA certificate.',
  'Create an AD CS renewal profile for the site and attach it to the certificate.',
];
