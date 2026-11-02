import { vi } from 'vitest';
export const WS = '11111111-1111-4111-8111-111111111111';
export const GROUP = '22222222-2222-4222-8222-222222222222';
export const VERSION = '33333333-3333-4333-8333-333333333333';
export const ISSUER = '44444444-4444-4444-8444-444444444444';
export const CONSUMER = '55555555-5555-4555-8555-555555555555';
export function materialContext(provider = 'vault-kv2') {
  const setup = {
    provider,
    issuerAgentId: ISSUER,
    materialStoreRef: 'customer',
    issuanceProfileRef: 'wildcard',
    profileRevision: 1,
    groupId: GROUP,
  };
  const capabilities = [
    'material-store-vault-kv2-v1',
    'material-store-openbao-kv2-v1',
    'material-store-azure-key-vault-v1',
    'certificate-publication-v1',
    'deploy-from-store-v1',
    'evidence-claim-binding-v1',
  ];
  const agent = {
    platform: 'linux',
    declaredCapabilities: capabilities,
    claimEvidenceFresh: true,
    livenessState: 'live',
    commandProfiles: ['certbot'],
    supportedOperations: ['issue', 'deploy-from-store'],
  };
  const ctx = {
    workspaceId: WS,
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    apiUrl: 'https://tokentimer.example.test',
    session: {
      intent: { goal: 'certops_vault' },
      progress: {
        certops: {
          objective: 'vault',
          materialSetup: setup,
          names: 'web.example.test',
          zone: 'example.test',
          vaultDryRunJobIds: { [ISSUER]: 'noop' },
        },
      },
    },
    capabilities: {
      viewer: { workspaceRole: 'workspace_manager' },
      items: [
        ...['certops.core', 'certops.vault_distribution'].map(id => ({
          id,
          qualified: true,
          authorized: true,
          state: 'ready',
        })),
        ...['vault_kv2', 'openbao_kv2', 'azure_key_vault'].map(p => ({
          id: `certops.material_store_${p}`,
          qualified: p !== 'azure_key_vault',
          authorized: true,
          state: p === 'azure_key_vault' ? 'candidate' : 'ready',
        })),
        {
          id: 'certops.windows_material_iis',
          qualified: false,
          authorized: true,
          state: 'candidate',
        },
      ],
    },
    summary: {
      certops: {
        agents: {
          items: [
            {
              ...agent,
              id: ISSUER,
              wireAgentId: 'issuer-wire',
              name: 'Issuer',
            },
            {
              ...agent,
              id: CONSUMER,
              wireAgentId: 'consumer-wire',
              name: 'Consumer',
            },
          ],
        },
        distribution: {
          items: [
            {
              id: GROUP,
              ...setup,
              active: true,
              completed: false,
              verified: false,
              publication: {
                materialVersionId: VERSION,
                publishedAt: new Date().toISOString(),
                validTo: new Date(Date.now() + 86400000).toISOString(),
              },
            },
          ],
        },
      },
    },
  };
  ctx.controller = {
    update: vi.fn(async mutate =>
      Object.assign(ctx.session, mutate(ctx.session))
    ),
  };
  return ctx;
}
