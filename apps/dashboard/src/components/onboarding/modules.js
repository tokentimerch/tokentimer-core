// Registry of everything the wizard can set up. A goal is a user-facing
// objective; a module is one unit of work that can satisfy part of it.
//
// Modules declare which capability they need, which step ids they contribute
// and how to tell from verified reality that they are done. The planner only
// reads this table, so adding a module never changes the planner.

export const STEP_DEFS = {
  goal: { title: 'What do you want to track?', kind: 'ui' },
  monitor: { title: 'Add the website to monitor', kind: 'ui' },
  asset: { title: 'Add your first asset', kind: 'ui' },
  file_import: { title: 'Import assets from a file', kind: 'ui' },
  integration: { title: 'Import from an integration', kind: 'ui' },
  recipients: { title: 'Choose who gets alerted', kind: 'ui' },
  notifications: { title: 'Set up notifications', kind: 'ui' },
  smtp: { title: 'Email delivery', kind: 'ui' },
  verify: { title: 'Check that it is working', kind: 'verify' },
  // CertOps
  certops_objective: { title: 'Pick a certificate objective', kind: 'ui' },
  certops_agent: { title: 'Install an agent', kind: 'runbook' },
  certops_config: { title: 'Prepare the agent configuration', kind: 'runbook' },
  certops_execution: { title: 'Enable execution safely', kind: 'verify' },
  certops_first: { title: 'See your first certificate', kind: 'verify' },
  certops_vault: { title: 'Distribute through Vault', kind: 'runbook' },
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
export const GOALS = {
  monitor_https: {
    label: 'Monitor a website certificate',
    description:
      'Track the HTTPS certificate of a site and get alerted before it expires.',
    steps: ['monitor', 'recipients', 'verify'],
    requires: ['monitoring.endpoint', 'alerts.contact_groups'],
    area: 'assets',
  },
  track_asset: {
    label: 'Track an API key, secret or license',
    description: 'Record one asset by hand and get alerted before it expires.',
    steps: ['asset', 'recipients', 'verify'],
    requires: ['assets.manual', 'alerts.contact_groups'],
    area: 'assets',
  },
  import_file: {
    label: 'Import many assets from a file',
    description: 'Bring in a CSV, spreadsheet, JSON or YAML inventory.',
    steps: ['file_import', 'recipients', 'verify'],
    requires: ['assets.file_import', 'alerts.contact_groups'],
    area: 'assets',
  },
  import_integration: {
    label: 'Import from GitHub, Vault, AWS or another service',
    description: 'Scan a connected service and choose which assets to import.',
    steps: ['integration', 'recipients', 'verify'],
    requires: ['assets.file_import', 'alerts.contact_groups'],
    area: 'assets',
    needsProvider: true,
  },
  alerting: {
    label: 'Set up alert notifications',
    description:
      'Choose recipients, thresholds and make sure email delivery works.',
    steps: ['recipients', 'notifications', 'smtp', 'verify'],
    requires: ['alerts.contact_groups'],
    area: 'alerts',
  },
  certops_observe: {
    label: 'Discover certificates on my servers',
    description:
      'Install an agent that finds certificates and reports them, without changing anything.',
    steps: [
      'certops_objective',
      'certops_agent',
      'certops_config',
      'certops_execution',
      'certops_first',
      'recipients',
      'verify',
    ],
    requires: ['certops.core', 'alerts.contact_groups'],
    area: 'certops',
    certopsObjective: 'observe',
  },
  certops_automate: {
    label: 'Issue and renew certificates automatically',
    description:
      'Use an agent to request, install and renew certificates (ACME).',
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
  certops_vault: {
    label: 'Share one certificate across servers with Vault',
    description:
      'Publish an issued certificate to your Vault and deploy it to several hosts.',
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
    candidate: true,
  },
};

export const GOAL_AREAS = [
  { id: 'assets', label: 'Track assets' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'certops', label: 'Certificate management' },
];
