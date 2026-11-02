import { buildVaultConfigs, SENSITIVE_PATTERN } from './certopsConfig.js';

export const MATERIAL_PROVIDERS = {
  'vault-kv2': {
    label: 'HashiCorp Vault KV v2',
    capability: 'certops.material_store_vault_kv2',
  },
  'openbao-kv2': {
    label: 'OpenBao KV v2',
    capability: 'certops.material_store_openbao_kv2',
  },
  'azure-key-vault': {
    label: 'Azure Key Vault Secrets',
    capability: 'certops.material_store_azure_key_vault',
  },
};
export const materialAgents = ctx => ctx.summary?.certops?.agents?.items || [];
export const materialProvider = id =>
  Object.hasOwn(MATERIAL_PROVIDERS, id) ? MATERIAL_PROVIDERS[id] : null;
export const canManageMaterial = ctx =>
  ['admin', 'workspace_manager'].includes(
    ctx.capabilities?.viewer?.workspaceRole
  );
export function featureReady(capabilities, id) {
  const item = capabilities?.items?.find(c => c.id === id);
  return (
    item?.state === 'ready' &&
    item.qualified === true &&
    item.authorized === true
  );
}
export function materialProviderReady(ctx, provider) {
  return [
    'certops.core',
    'certops.vault_distribution',
    materialProvider(provider)?.capability,
  ].every(id => Boolean(id) && featureReady(ctx.capabilities, id));
}
export function materialSetup(saved = {}) {
  return (
    saved.materialSetup || {
      provider: 'vault-kv2',
      issuerAgentId: saved.vaultIssuerAgentId || saved.chosenAgentId || '',
      materialStoreRef: 'customer',
      issuanceProfileRef: 'wildcard',
      profileRevision: 1,
      groupId: saved.chosenDistributionId || saved.groupId || '',
    }
  );
}
export function materialCertificateInput(saved) {
  const input = saved.materialPublicationRequest || saved;
  return {
    names: Array.isArray(input.names)
      ? input.names.filter(name => typeof name === 'string')
      : (input.names || '').split(/[\s,]+/).filter(Boolean),
    zone: input.zone,
    dnsProvider: input.dnsProvider || 'cloudflare',
    caEndpoint: input.caEndpoint || undefined,
  };
}
export function setupErrors(setup) {
  const errors = [];
  if (!materialProvider(setup.provider))
    errors.push('Choose a supported material provider.');
  if (!setup.issuerAgentId) errors.push('Choose an issuing agent.');
  for (const field of ['materialStoreRef', 'issuanceProfileRef']) {
    if (
      !/^[A-Za-z0-9_-]{1,64}$/.test(setup[field] || '') ||
      SENSITIVE_PATTERN.test(setup[field])
    )
      errors.push(
        `Use a public configuration reference for ${field}, never a credential.`
      );
  }
  if (
    !Number.isInteger(setup.profileRevision) ||
    setup.profileRevision < 1 ||
    setup.profileRevision > 2147483647
  )
    errors.push('Profile revision must be a positive integer.');
  return errors;
}
export function materialSetupPatch(saved, next) {
  const before = materialSetup(saved);
  const changed = [
    'groupId',
    'provider',
    'issuerAgentId',
    'materialStoreRef',
    'issuanceProfileRef',
    'profileRevision',
  ].some(key => before[key] !== next[key]);
  return {
    ...(changed
      ? {
          vaultConsumers: [],
          vaultConsumerAgentId: '',
          vaultBindingId: '',
          vaultMaterialVersionId: '',
          vaultRolloutJobId: '',
          vaultRolloutRequestKey: '',
          materialVerification: null,
          materialIisRollout: null,
          materialIisBinding: null,
        }
      : {}),
    materialSetup: next,
    groupId: next.groupId,
    chosenDistributionId: '',
    chosenDistributionConfirmed: '',
  };
}
export function agentRequirements(
  agent,
  provider,
  role = 'issuer',
  { allowStoppedIssuer = false } = {}
) {
  if (!agent) return ['Register and select an agent in this workspace.'];
  const required = [
    `material-store-${provider}-v1`,
    'evidence-claim-binding-v1',
    role === 'issuer' ? 'certificate-publication-v1' : 'deploy-from-store-v1',
  ];
  if (role === 'consumer' && agent.platform === 'win32')
    required.push(
      'windows-material-iis-v1',
      'windows-cert-store-v1',
      'iis-binding-v1'
    );
  const errors = required
    .filter(
      cap =>
        !Array.isArray(agent.declaredCapabilities) ||
        !agent.declaredCapabilities.includes(cap)
    )
    .map(cap => `Missing capability: ${cap}`);
  const preparingStoppedIssuer = role === 'issuer' && allowStoppedIssuer;
  if (!preparingStoppedIssuer && agent.livenessState !== 'live')
    errors.push('Wait for a live agent check-in.');
  if (!preparingStoppedIssuer && agent.claimEvidenceFresh !== true)
    errors.push(
      'Refresh the agent capability declaration; signed claim evidence is missing or stale.'
    );
  if (
    role === 'issuer' &&
    (agent.platform !== 'linux' || !agent.commandProfiles?.includes('certbot'))
  )
    errors.push(
      'Use a Linux issuer with the registered certbot command profile.'
    );
  if (role === 'consumer' && !['linux', 'win32'].includes(agent.platform))
    errors.push('Only Linux endpoint and Windows/IIS consumers are supported.');
  if (
    !Array.isArray(agent.supportedOperations) ||
    !agent.supportedOperations.includes(
      role === 'issuer' ? 'renew' : 'deploy-from-store'
    )
  )
    errors.push(
      'Enable the required execution operation locally, then restart/check in.'
    );
  return errors;
}
export function selectedMaterialGroup(summary, saved) {
  const setup = materialSetup(saved);
  return (
    summary?.certops?.distribution?.items?.find(g => g.id === setup.groupId) ||
    null
  );
}
export function materialStoreSatisfied(summary, saved, now = Date.now()) {
  const setup = materialSetup(saved),
    group = selectedMaterialGroup(summary, saved);
  return Boolean(
    !setupErrors(setup).length &&
    group?.active === true &&
    group.provider === setup.provider &&
    group.materialStoreRef === setup.materialStoreRef &&
    group.issuerAgentId === setup.issuerAgentId &&
    group.issuanceProfileRef === setup.issuanceProfileRef &&
    group.profileRevision === setup.profileRevision &&
    group.publication?.materialVersionId &&
    Date.parse(group.publication.validTo) > now
  );
}
export function materialConsumersSatisfied(summary, saved) {
  const group = selectedMaterialGroup(summary, saved);
  return (
    materialStoreSatisfied(summary, saved) &&
    (group?.completed === true || group?.verified === true)
  );
}

// Host-local configuration only. Endpoint/CA values never enter session writes
// or job payloads. Credentials are deliberately absent; only sink paths appear.
export function materialConfigs({
  setup,
  address,
  mount = 'secret',
  ...input
}) {
  if (!materialProvider(setup.provider) || setupErrors(setup).length)
    return { ok: false, problems: setupErrors(setup) };
  let endpoint;
  try {
    endpoint = new URL(address);
  } catch {
    return {
      ok: false,
      problems: ['Enter the customer-local HTTPS material store address.'],
    };
  }
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.pathname !== '/'
  )
    return {
      ok: false,
      problems: [
        'Use an HTTPS origin without credentials, paths, query parameters or fragments.',
      ],
    };
  if (
    setup.provider === 'azure-key-vault' &&
    (Boolean(endpoint.port) ||
      !/^[a-z0-9-]+\.vault\.azure\.net$/.test(endpoint.hostname))
  )
    return {
      ok: false,
      problems: [
        'Use a public-cloud <name>.vault.azure.net Key Vault Secrets endpoint.',
      ],
    };
  if (!/^[A-Za-z0-9_-]+$/.test(mount))
    return {
      ok: false,
      problems: ['Use the KV v2 mount name, without a path.'],
    };
  const configs = buildVaultConfigs({
    ...input,
    vaultAddress: endpoint.origin,
    mount,
    provider: setup.provider,
    materialStoreRef: setup.materialStoreRef,
    issuanceProfileRef: setup.issuanceProfileRef,
    issuerProfileRevision: setup.profileRevision,
  });
  if (configs.ok && setup.provider === 'azure-key-vault') {
    for (const role of ['issuer', 'consumer']) {
      const store = configs[role].materialStores[setup.materialStoreRef];
      delete store.mount;
      delete store.tokenFile;
      store.auth = { type: 'managed-identity' };
    }
  }
  return configs;
}
