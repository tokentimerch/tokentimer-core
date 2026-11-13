export const distributionDiagnostics = {
  CERTOPS_AGENT_OFFLINE:
    'Bring the registered agent online and confirm its next heartbeat before retrying.',
  CERTOPS_AGENT_CAPABILITY_UNAVAILABLE:
    'Use an agent build with fresh, qualified connector capabilities; check its release readiness.',
  CERTOPS_PINNED_VERSION_UNAVAILABLE:
    'Select an unexpired published version and confirm that exact version exists in the customer store.',
  CERTOPS_ACTIVATION_CONNECTOR_UNSUPPORTED:
    'Choose a supported activation method or complete the required connector qualification.',
  CERTOPS_LOCAL_RECONCILIATION_REQUIRED:
    'Inspect and reconcile the customer-local deployment journal. Preserve live locks and retry the original signed job.',
  CERTOPS_ACTIVATION_WINDOW_UNAVAILABLE:
    'Review allowed windows, blackouts and authorization expiry before the deployed certificate expires.',
  CERTOPS_CUSTOMER_LOCAL_PREFLIGHT_REQUIRED:
    'Run customer-local preflight to check store access, exact material, local policy, permissions, service configuration and probes.',
};
export const diagnosticExplanation = code =>
  distributionDiagnostics[code] ||
  'Inspect the signed job evidence and review customer-local configuration before retrying.';
