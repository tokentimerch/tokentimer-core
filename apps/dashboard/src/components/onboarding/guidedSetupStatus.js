// Which guided setups have been verified end to end with every option tried.
// "Not fully tested" in the setup guide is a statement about this register,
// not about whether the underlying feature is qualified.
//
// Every pick has been run through the real guide, server and database, so
// every entry is verified and nothing is labelled. To label a pick again, give
// its entry `entry(untested, hint)`. Keep what was not covered in `untested`.
// Keys are goal ids, plus "goal:infrastructure" for the CertOps cards.
// A goal row stays marked while any of its infrastructure cards is.

export const entry = (untested, hint = '') => ({
  verified: false,
  untested,
  hint,
});
const verified = untested => ({ verified: true, untested, hint: '' });

const OBSERVE_LINUX_UNTESTED = [
  'A non-WSL host',
  'Distributions other than Ubuntu 24.04',
];

const OBSERVE_KUBERNETES_UNTESTED = [
  'The published 0.18.0 chart and controller image (verified with a locally built image and the 0.17.3 chart)',
  'A real cluster',
  'ACME-issued and failing Certificates',
];

const OBSERVE_WINDOWS_UNTESTED = [
  'Windows Server 2019 and 2025',
  'Non-English display languages',
  'The 30-minute discovery interval',
];

const AUTOMATE_LINUX_UNTESTED = [
  'Cloudflare, Route 53 and Google Cloud DNS against real accounts (Azure DNS and RFC 2136 ran for real)',
  "Let's Encrypt or any production ACME CA",
  'Distributions other than Ubuntu 24.04',
  'The exact 3-minute moment of the notice that no agent took the request',
];

const AUTOMATE_WINDOWS_UNTESTED = [
  'The other four DNS providers',
  "Let's Encrypt",
  'A scheduler-driven renewal on Windows',
  'Windows Server 2019 and 2025',
];

const ADCS_UNTESTED = [
  'CA key change',
  'Response loss',
  'The 14-day approval expiry',
  'Windows Server 2019 and 2025',
  'Non-English display languages',
];

const VAULT_UNTESTED = [
  'Kubernetes auth through Vault Agent',
  'Vault namespaces',
  'Several consumers',
  'Renewal and rollback rollouts',
  'Apache or HAProxy as consumers',
  'Recovery after a failed install needs an agent build that includes the binding recovery fix',
  'The positive path of the reconcile script',
];

// Verified means the guided path was run end to end for what the picker row
// promises. Keep untested to what is still not covered.
export const GUIDED_SETUP_STATUS = {
  monitor_https: verified([]),
  track_asset: verified([]),
  import_file: verified(['JSON, xlsx and yaml imports run to completion']),
  import_integration: verified([
    'Real scans for AWS, Azure Key Vault, GCP, Vault and GitHub from the setup guide (call parity with the standalone import was proven)',
  ]),
  alerting: verified([
    'Delivery to a production SMTP server',
    'A webhook on a real receiver (loopback and private URLs are blocked unless WEBHOOK_ALLOW_PRIVATE_IPS is set)',
    'WhatsApp recipients',
  ]),
  certops_observe: verified([
    ...OBSERVE_LINUX_UNTESTED,
    ...OBSERVE_KUBERNETES_UNTESTED,
    ...OBSERVE_WINDOWS_UNTESTED,
  ]),
  'certops_observe:linux': verified(OBSERVE_LINUX_UNTESTED),
  'certops_observe:windows': verified(OBSERVE_WINDOWS_UNTESTED),
  'certops_observe:kubernetes': verified(OBSERVE_KUBERNETES_UNTESTED),
  certops_automate: verified([
    ...AUTOMATE_LINUX_UNTESTED,
    ...AUTOMATE_WINDOWS_UNTESTED,
  ]),
  'certops_automate:linux': verified(AUTOMATE_LINUX_UNTESTED),
  'certops_automate:windows': verified(AUTOMATE_WINDOWS_UNTESTED),
  certops_adcs: verified(ADCS_UNTESTED),
  'certops_adcs:windows': verified(ADCS_UNTESTED),
  certops_vault: verified(VAULT_UNTESTED),
  'certops_vault:linux': verified(VAULT_UNTESTED),
};
export const pickKey = (goalId, infrastructureId) =>
  infrastructureId ? `${goalId}:${infrastructureId}` : goalId;

/**
 * A pick is marked Not fully tested when its guided setup is not verified in
 * the register (or has no entry). Module and matrix flags only affect planning,
 * never the label.
 */
export function isCandidatePick(key) {
  return GUIDED_SETUP_STATUS[key]?.verified !== true;
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
    isCandidatePick(pickKey(goalId, c.id))
  );
  if (marked.length === 0 || marked.length === cards.length) return '';
  const names = marked.map(c => String(c.label).split(' ')[0]);
  return `${names.join(' and ')} not fully tested`;
}
