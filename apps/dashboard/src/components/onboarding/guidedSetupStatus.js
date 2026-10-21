// Which guided setups have been verified end to end with every option tried.
// "Not fully tested" in the setup guide is a statement about this register,
// not about whether the underlying feature is qualified.
//
// To clear a badge, set `verified: true` on its entry. Keep any remaining
// caveats in `untested`. Nothing else needs to change.
// Keys are goal ids, plus "goal:infrastructure" for the CertOps cards.
// A goal row stays marked while any of its infrastructure cards is.

const entry = (untested, hint = '') => ({ verified: false, untested, hint });
const verified = untested => ({ verified: true, untested, hint: '' });

const ADCS_HINT =
  'AD CS enrollment is qualified in 0.18.0. This guided setup has not been verified through a real enrollment yet.';

const ADCS_UNTESTED = [
  'Everything after Connect your Microsoft CA: the issuer check, the profile, a real enrollment, the binding, and the wrong template and permission errors (needs a domain-joined lab host with a route to a control plane)',
  'The walkthrough reached that step with an agent declaring adcs-enroll-v1',
];

const VAULT_UNTESTED = [
  'Creating the publish job from the UI (there is no UI path: the guide prints the API body)',
  'AppRole and Vault Agent authentication',
  'Vault namespaces',
  'HAProxy or Apache as a consumer',
  'A rollout without API-only steps',
  'The self-hosted docs for the shared-certificate and Vault Agent runbooks do not exist yet',
];

const OBSERVE_WINDOWS_UNTESTED = [
  'The install-agent.ps1 command from the setup guide and the Windows service path were never run (the development machine is not elevated)',
  'A lab Windows Server (discovery was verified with an agent run on a Windows 11 development machine only: 4 certificates from LocalMachine\\My)',
];

const AUTOMATE_LINUX_UNTESTED = [
  'DNS-01 against a real provider (Cloudflare, Route 53, Azure DNS, Google Cloud DNS and RFC 2136 only render their config)',
  "Let's Encrypt or any production ACME CA (a test ACME CA was used)",
  'A renewal triggered by the scheduler renewal window (a manual renew job was used)',
  'Multiple targets',
  'A non-WSL host',
];

const AUTOMATE_WINDOWS_UNTESTED = [
  'A real order: the setup guide flow and a signed dry run worked, but the real order failed because the development machine is not elevated and has no IIS or ACME client',
  'The certificate store and HTTPS binding on a Windows Server, TLS verification and renewal (no lab VM could reach the development API)',
];

// Verified means the guided path was run end to end for what the picker row
// promises. Keep untested to what is still not covered.
export const GUIDED_SETUP_STATUS = {
  monitor_https: verified([
    'Result pagination beyond 50 hosts',
    'The truncated and partial discovery notices',
    'A genuine server-side failure on a website batch (the earlier partial failure was injected in the browser)',
  ]),
  track_asset: verified([
    'Categories other than the three used (key/secret, license, certificate)',
    'The 25-asset limit',
  ]),
  import_file: verified(['The 1100-row file (no limit is documented)']),
  import_integration: verified([
    'Real scans for AWS, Azure Key Vault, GCP, Vault and GitHub from the setup guide (call parity with the standalone import modal was proven identical for all seven providers, and a real GitLab import worked)',
  ]),
  alerting: verified([
    'Delivery of a real email to a production SMTP server (a local Mailpit received the test email)',
    'A webhook accepted by a real receiver (loopback and private URLs are blocked unless WEBHOOK_ALLOW_PRIVATE_IPS is set)',
    'WhatsApp recipients',
  ]),
  certops_observe: entry(OBSERVE_WINDOWS_UNTESTED),
  'certops_observe:linux': verified([
    'A non-WSL Linux host',
    'A distro other than Ubuntu 24.04',
  ]),
  'certops_observe:windows': entry(OBSERVE_WINDOWS_UNTESTED),
  'certops_observe:kubernetes': verified([
    'The published 0.18.0 chart and controller image (not on ghcr yet: verified with a locally built image and the 0.17.3 chart)',
    'A real cluster',
    'ACME-issued and failing Certificates',
    'A cluster that already runs a full TokenTimer release',
  ]),
  certops_automate: entry([
    ...AUTOMATE_LINUX_UNTESTED,
    ...AUTOMATE_WINDOWS_UNTESTED,
  ]),
  'certops_automate:linux': entry(AUTOMATE_LINUX_UNTESTED),
  'certops_automate:windows': entry(AUTOMATE_WINDOWS_UNTESTED),
  certops_adcs: entry(ADCS_UNTESTED, ADCS_HINT),
  'certops_adcs:windows': entry(ADCS_UNTESTED, ADCS_HINT),
  certops_vault: entry(VAULT_UNTESTED),
  'certops_vault:linux': entry(VAULT_UNTESTED),
};

export const pickKey = (goalId, infrastructureId) =>
  infrastructureId ? `${goalId}:${infrastructureId}` : goalId;

/**
 * A pick is marked Not fully tested when its guided setup is not verified in
 * the register (or has no entry), or when the module or matrix flags it.
 */
export function isCandidatePick(key, flagged = false) {
  return Boolean(flagged) || GUIDED_SETUP_STATUS[key]?.verified !== true;
}

/** Short extra context for a pick, or an empty string. */
export function pickHint(key) {
  return GUIDED_SETUP_STATUS[key]?.hint || '';
}

export const CANDIDATE_BADGE = 'Not fully tested';

export const CANDIDATE_NOTE =
  'Marked Not fully tested: the feature itself may be fully supported, but this guided setup has not been run end to end on every option yet.';

export const CANDIDATE_REPORT_LABEL = 'Report a problem';
export const CANDIDATE_REPORT_URL =
  'https://github.com/tokentimerch/tokentimer-core/issues';

// What the badge means, for the accessible description of each marked pick.
export const CANDIDATE_EXPLANATION =
  'Not fully tested: this guided setup has not been run end to end on every option yet. The feature itself may be fully supported.';

/**
 * For a goal row built from its platform cards: which platforms are the
 * untested ones, or an empty string when every card (or none) is marked.
 * `cards` are { id, label, status } as infrastructuresFor returns them.
 */
export function untestedPlatformsNote(goalId, cards) {
  const marked = (cards || []).filter(c =>
    isCandidatePick(pickKey(goalId, c.id), c.status === 'candidate')
  );
  if (marked.length === 0 || marked.length === cards.length) return '';
  const names = marked.map(c => String(c.label).split(' ')[0]);
  return `${names.join(' and ')} not fully tested`;
}
