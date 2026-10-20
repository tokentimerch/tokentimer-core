// Which guided setups have been verified end to end with every option tried.
// "Candidate" in the wizard is a statement about this register, not about
// whether the underlying feature is qualified.
//
// To clear a badge, set `verified: true` on its entry. Keep any remaining
// caveats in `untested`. Nothing else needs to change.
// Keys are goal ids, plus "goal:infrastructure" for the CertOps cards.

const entry = (untested, hint = '') => ({ verified: false, untested, hint });
const verified = untested => ({ verified: true, untested, hint: '' });

const ADCS_HINT =
  'AD CS enrollment is qualified in 0.18.0. This guided setup has not been verified through a real enrollment yet.';

const ADCS_UNTESTED = [
  'Everything after installing the agent: the walkthrough on a real workspace stopped there, with no Windows agent or CA available',
  'A real enrollment against a CA: the generated rule being accepted, the issuer check and pin, attaching the profile, the first enrollment',
  'The Connect your Microsoft CA step with a live capable agent (tested with fixtures only)',
  'The generated Windows install command (checked against the script, never run)',
];

const VAULT_UNTESTED = [
  'A real publish job, rollout and consumer verification (the setup ends at Configuration prepared)',
  'AppRole authentication (the lab used plain tokens)',
  'Vault over HTTPS with a private CA, and Vault namespaces',
  'The distribution capabilities checked against a qualified agent build',
];

const LATEST_CHANGES =
  'Latest changes covered by unit tests only; re-run the browser flow';

const NO_AGENT_CLICKTHROUGH =
  'The steps clicked through in a browser with live agent state';

const AUTOMATE_LINUX_UNTESTED = [
  'Renewal (only the first issuance was run)',
  'Install into a web server and reload with the real systemctl command (the lab used nginx -s reload; Apache and HAProxy unit names are unproven)',
  'DNS-01 with a real provider (only the Pebble test provider was used)',
  'The issue step clicked in a browser (exercised through the builders and the API)',
];

// Verified means the guided path was run end to end for what the picker row
// promises. Keep untested to what is still not covered.
export const GUIDED_SETUP_STATUS = {
  monitor_https: verified([
    LATEST_CHANGES,
    'Result pagination beyond 50 discovery results',
    'Truncated and partial discovery notices',
    'Creating a new contact group',
    'A genuine server-side failure on a website batch (the partial failure was injected in the browser)',
  ]),
  track_asset: verified([
    LATEST_CHANGES,
    'Creating a new contact group',
    'Categories other than certificate (only the certificate path was submitted)',
    'The 25-asset limit',
  ]),
  import_file: entry([
    'File import was never exercised in a browser; only counts against the server were checked',
    'File import with real files',
  ]),
  import_integration: entry([
    'Only the GitHub dialog opening and closing and a simulated import were run in a browser',
    'A real GitHub or GitLab scan or sync started from the wizard (needs a token and network)',
    'The live result panel and the auto-sync form inside the wizard',
  ]),
  alerting: entry([
    'A delivered email or a webhook accepted by a real receiver (the SMTP test checks transport only)',
    'WhatsApp recipients (kept untouched when editing, never created)',
    'Changed webhook-name and threshold rules checked by unit tests and one API call, not by clicking through the wizard',
    'Accessibility scan of the group editor after the latest changes',
  ]),
  certops_observe: entry([
    'Windows and Kubernetes observe were not exercised',
    'The only real agent run was on a Windows development host, not a Linux target',
  ]),
  'certops_observe:linux': entry([
    'The only real agent run was on a Windows development host, not a Linux target',
    NO_AGENT_CLICKTHROUGH,
  ]),
  'certops_observe:windows': entry([
    'The Windows path was not exercised in a browser',
    'The generated install-agent.ps1 command (checked against the script, never run)',
  ]),
  'certops_observe:kubernetes': entry([
    'The Kubernetes path was not built beyond guidance and was never exercised',
  ]),
  certops_automate: entry([
    ...AUTOMATE_LINUX_UNTESTED,
    'Kubernetes issuance, and everything on a real Windows host',
  ]),
  'certops_automate:linux': entry(AUTOMATE_LINUX_UNTESTED),
  'certops_automate:windows': entry([
    'Everything on a real Windows host: install command and flags, the agent claiming the acme-windows job, the ACME client under the allowed path, DNS-01, the certificate store write and binding, renewal',
    'Whether the ACME client needs fixed leading arguments on Windows',
  ]),
  certops_adcs: entry(ADCS_UNTESTED, ADCS_HINT),
  'certops_adcs:windows': entry(ADCS_UNTESTED, ADCS_HINT),
  certops_vault: entry(VAULT_UNTESTED),
  'certops_vault:linux': entry(VAULT_UNTESTED),
};
export const pickKey = (goalId, infrastructureId) =>
  infrastructureId ? `${goalId}:${infrastructureId}` : goalId;

/**
 * A pick is a Candidate when its guided setup is not verified in the register
 * (or has no entry), or when the module or matrix flags it on its own.
 */
export function isCandidatePick(key, flagged = false) {
  return Boolean(flagged) || GUIDED_SETUP_STATUS[key]?.verified !== true;
}

/** Short extra context for a pick, or an empty string. */
export function pickHint(key) {
  return GUIDED_SETUP_STATUS[key]?.hint || '';
}

export const CANDIDATE_BADGE = 'Candidate';

export const CANDIDATE_NOTE =
  'Options marked Candidate have not been fully tested end to end yet. Tell us what you find.';

// What Candidate means, for the accessible description of each marked pick.
export const CANDIDATE_EXPLANATION =
  'Candidate: this guided setup has not been fully tested end to end yet. The feature itself may be fully supported.';
