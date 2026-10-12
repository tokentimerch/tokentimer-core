export const SELF_HOSTED_DOCS_BASE = 'https://tokentimer.ch/docs/self-hosted';

// Anchors match docs/certops/agent/adcs.md. The hosted page is published from that file.
const ADCS_DOCS_PAGE = `${SELF_HOSTED_DOCS_BASE}/certops/adcs`;

export const ADCS_DOCS = {
  template: `${ADCS_DOCS_PAGE}#certificate-template`,
  caConfig: `${ADCS_DOCS_PAGE}#ca-config`,
  enrollmentRules: `${ADCS_DOCS_PAGE}#enrollment-rules`,
  renewalProfile: `${ADCS_DOCS_PAGE}#renewal-profile`,
};

export const IMPORT_DOCS = {
  file: `${SELF_HOSTED_DOCS_BASE}/tokens/import-file`,
  integrations: `${SELF_HOSTED_DOCS_BASE}/integrations`,
  github: `${SELF_HOSTED_DOCS_BASE}/integrations/github`,
  gitlab: `${SELF_HOSTED_DOCS_BASE}/integrations/gitlab`,
  vault: `${SELF_HOSTED_DOCS_BASE}/integrations/vault`,
  aws: `${SELF_HOSTED_DOCS_BASE}/integrations/aws`,
  azureKeyVault: `${SELF_HOSTED_DOCS_BASE}/integrations/azure-key-vault`,
  entraId: `${SELF_HOSTED_DOCS_BASE}/integrations/entra-id`,
  gcp: `${SELF_HOSTED_DOCS_BASE}/integrations/gcp`,
};
