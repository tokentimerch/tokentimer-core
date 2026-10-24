// What the agents list returns for a real 0.18.0 agent: the fields the API
// summary projects from the row, with the capability set the shipped agent
// re-declares on every check-in (packages/agent, qualified manifest).
const COMMON = [
  'evidence-claim-binding-v1',
  'job-log-stream-v1',
  'trust-anchor-deploy-v1',
  'agent-id-binding-v1',
];

export const WINDOWS_0_18_0 = [
  ...COMMON,
  'windows-cert-store-v1',
  'iis-binding-v1',
  'adcs-enroll-v1',
];

export const LINUX_0_18_0 = [
  ...COMMON,
  'material-store-vault-kv2-v1',
  'certificate-publication-v1',
  'deploy-from-store-v1',
];

export function realAgent(platform, extra = {}) {
  const windows = platform === 'win32';
  return {
    id: 'a1b2c3d4-0000-4000-8000-000000000001',
    wireAgentId: 'agent-1',
    name: windows ? 'WIN-CA01' : 'edge-01',
    hostname: windows ? 'WIN-CA01' : 'edge-01',
    platform,
    agentVersion: '0.18.0',
    livenessState: 'live',
    lastSeenAt: new Date().toISOString(),
    compatibilityState: 'compatible',
    clockDriftState: 'ok',
    ntpSynced: true,
    declaredCapabilities: windows ? WINDOWS_0_18_0 : LINUX_0_18_0,
    supportedOperations: ['discover'],
    targetSelectors: [],
    commandProfiles: [],
    ...extra,
  };
}
