// Registry of everything the wizard can set up. A goal is a user-facing
// objective; a module is one unit of work that can satisfy part of it.
//
// Modules declare which capability they need, which step ids they contribute
// and how to tell from verified reality that they are done. The planner only
// reads this table, so adding a module never changes the planner.

// A step's title is also its page header, so the rail and the page match.
export const STEP_DEFS = {
  goal: { title: 'What do you want to do first?', kind: 'ui' },
  monitor: { title: 'Add the websites to monitor', kind: 'ui' },
  asset: { title: 'Add your assets', kind: 'ui' },
  file_import: { title: 'Import assets from a file', kind: 'ui' },
  integration: { title: 'Connect a service', kind: 'ui' },
  recipients: { title: 'Choose who gets alerted', kind: 'ui' },
  notifications: { title: 'Set up notifications', kind: 'ui' },
  smtp: { title: 'Email delivery', kind: 'ui' },
  verify: { title: 'Check that it is working', kind: 'verify' },
  // CertOps
  certops_objective: { title: 'Where will the certificates live?', kind: 'ui' },
  certops_agent: { title: 'Install the agent', kind: 'runbook' },
  certops_config: { title: 'Prepare the agent configuration', kind: 'runbook' },
  certops_execution: { title: 'Turn on execution safely', kind: 'verify' },
  certops_first: { title: 'See your first certificate', kind: 'verify' },
  certops_adcs: { title: 'Connect your Microsoft CA', kind: 'ui' },
  certops_vault: {
    title: 'Share a certificate through Vault',
    kind: 'runbook',
  },
};

export const INTEGRATIONS = {
  github: { label: 'GitHub', hint: 'Secrets and keys in your repositories' },
  gitlab: { label: 'GitLab', hint: 'Access tokens and keys' },
  vault: { label: 'HashiCorp Vault', hint: 'KV secrets and PKI certificates' },
  aws: { label: 'AWS', hint: 'Secrets Manager, ACM and IAM keys' },
  azure: { label: 'Azure Key Vault', hint: 'Secrets, keys and certificates' },
  'azure-ad': {
    label: 'Microsoft Entra ID',
    hint: 'App secrets and certificates',
  },
  gcp: { label: 'Google Cloud', hint: 'Secret Manager and certificates' },
};

// Each goal lists the steps it needs in order. "verify" is always last.
// `time` and `needs` are shown in the goal picker; `doneUnverified` makes the
// final card say the setup is finished but not verified.
export const GOALS = {
  monitor_https: {
    doneText:
      'The website certificate is monitored and alerts have somewhere to go.',
    label: 'Monitor a website certificate',
    description:
      'Track the HTTPS certificate of a site and get alerted before it expires.',
    time: 'About 2 min',
    steps: ['monitor', 'recipients', 'verify'],
    requires: ['monitoring.endpoint', 'alerts.contact_groups'],
    area: 'assets',
  },
  track_asset: {
    doneText: 'Your asset is tracked and alerts have somewhere to go.',
    label: 'Track an API key, secret or license',
    description: 'Record one asset by hand and get alerted before it expires.',
    time: 'About 2 min',
    steps: ['asset', 'recipients', 'verify'],
    requires: ['assets.manual', 'alerts.contact_groups'],
    area: 'assets',
  },
  import_file: {
    doneText: 'Your assets are imported and alerts have somewhere to go.',
    // Shown when the import dialog replaces the guided steps.
    doneTextModal:
      'Review your assets in the asset inventory and check who gets alerted in Alert Preferences.',
    label: 'Import many assets from a file',
    description: 'Bring in a CSV, spreadsheet, JSON or YAML inventory.',
    time: 'About 2 min',
    steps: ['file_import', 'recipients', 'verify'],
    requires: ['assets.file_import', 'alerts.contact_groups'],
    area: 'assets',
  },
  import_integration: {
    doneText: 'Your assets are imported and alerts have somewhere to go.',
    doneTextModal:
      'Review your assets in the asset inventory and check who gets alerted in Alert Preferences.',
    label: 'Import from GitHub, Vault, AWS or another service',
    description: 'Scan a connected service and choose which assets to import.',
    time: 'About 2 min',
    steps: ['integration', 'recipients', 'verify'],
    requires: ['assets.file_import', 'alerts.contact_groups'],
    area: 'assets',
    needsProvider: true,
  },
  alerting: {
    doneText: 'Alert notifications are set up.',
    label: 'Set up alert notifications',
    description:
      'Choose recipients, thresholds and make sure email delivery works.',
    time: 'About 2 min',
    steps: ['recipients', 'notifications', 'smtp', 'verify'],
    requires: ['alerts.contact_groups'],
    area: 'alerts',
  },
  certops_observe: {
    doneText: 'An agent is connected and reporting certificates.',
    label: 'Discover certificates on my servers',
    description:
      'Install an agent that finds certificates and reports them, without changing anything.',
    time: 'Needs a server, about 20 min',
    // The prepared configuration comes first: the installer keeps an existing
    // config.json, and replacing it after registration would drop the agent's
    // identity.
    steps: [
      'certops_objective',
      'certops_config',
      'certops_agent',
      'certops_execution',
      'certops_first',
      'recipients',
      'verify',
    ],
    requires: ['certops.core', 'alerts.contact_groups'],
    area: 'certops',
    certopsObjective: 'observe',
    // The Kubernetes controller has no agent configuration file and no
    // execution switch; its Helm values are in the install step.
    variants: {
      kubernetes: {
        omit: ['certops_config', 'certops_execution'],
        titles: { certops_agent: 'Install the Kubernetes controller' },
      },
    },
  },
  certops_automate: {
    doneText: 'Your agent issued a staging certificate.',
    doneTextWindows:
      'Your agent requested a staging certificate and bound it to an HTTPS listener (IIS).',
    label: 'Issue and renew certificates automatically',
    description:
      'Use an agent to request, install and renew certificates (ACME).',
    needs:
      "a domain you control, a DNS provider API token and a web server. The first certificate comes from the Let's Encrypt staging CA, so browsers do not trust it.",
    time: 'Needs a server, about 20 min',
    // Command profiles are only reported when the agent registers, so the
    // configuration comes first.
    steps: [
      'certops_objective',
      'certops_config',
      'certops_agent',
      'certops_execution',
      'certops_first',
      'recipients',
      'verify',
    ],
    requires: ['certops.core', 'alerts.contact_groups'],
    area: 'certops',
    certopsObjective: 'automate',
  },
  certops_adcs: {
    doneText:
      'Your agent is ready to enroll from your Microsoft CA. Enrollment itself is not verified by this guide.',
    // The body hedges, so the final card must not say the setup is verified.
    doneUnverified: true,
    label: 'Issue certificates from my Microsoft CA (AD CS)',
    description:
      'A domain-joined Windows agent enrolls certificates for an HTTPS listener (IIS) from your private CA.',
    needs:
      'a domain-joined Windows Server (not a domain controller), Enroll rights on the certificate template and a network route to your CA.',
    time: 'Needs a server, about 20 min',
    // The rule must exist before the agent registers, as for ACME profiles.
    steps: [
      'certops_objective',
      'certops_config',
      'certops_agent',
      'certops_adcs',
      'recipients',
      'verify',
    ],
    requires: ['certops.core', 'certops.adcs'],
    area: 'certops',
    certopsObjective: 'adcs',
    candidate: true,
  },
  certops_vault: {
    doneText:
      'Your Vault distribution is set up. It is not verified until a rollout is: the verify step shows the rollout state, and Certificate Management, Renewals lists each host.',
    label: 'Share one certificate across servers with Vault',
    doneUnverified: true,
    description:
      'Publish an issued certificate to your Vault and deploy it to several hosts.',
    time: 'Needs a server, about 20 min',
    steps: [
      'certops_objective',
      'certops_config',
      'certops_agent',
      'certops_vault',
      'certops_execution',
      'recipients',
      'verify',
    ],
    requires: ['certops.core', 'certops.vault_distribution'],
    area: 'certops',
    certopsObjective: 'vault',
  },
};

export const GOAL_AREAS = [
  { id: 'assets', label: 'Track assets' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'certops', label: 'Certificate management' },
];
