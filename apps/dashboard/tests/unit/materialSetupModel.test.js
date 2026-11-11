import { describe, expect, it } from 'vitest';
import {
  agentRequirements,
  featureReady,
  materialConfigs,
  materialStoreSatisfied,
  materialConsumersSatisfied,
  materialSetupPatch,
} from '../../src/components/onboarding/materialSetupModel.js';
import { materialContext, GROUP, WS } from './materialOnboardingFixtures.js';
import {
  isStepSatisfied,
  planJourney,
  stepsForGoal,
} from '../../src/components/onboarding/journeyPlanner.js';
import { observedDoneStep } from '../../src/components/onboarding/heldSteps.js';
import { resolveNavigation } from '../../src/components/onboarding/stepNavigation.js';

describe('material onboarding evidence and planner', () => {
  it('accepts the real issuer wire declaration and still requires renewal execution', () => {
    const issuer = {
      ...materialContext('openbao-kv2').summary.certops.agents.items[0],
      supportedOperations: ['noop', 'renew'],
    };
    expect(agentRequirements(issuer, 'openbao-kv2')).toEqual([]);
    expect(
      agentRequirements(
        { ...issuer, supportedOperations: ['noop'] },
        'openbao-kv2'
      )
    ).toContain(
      'Enable the required execution operation locally, then restart/check in.'
    );
    expect(agentRequirements(issuer, 'openbao-kv2', 'consumer')).toContain(
      'Enable the required execution operation locally, then restart/check in.'
    );
  });
  it('adds both steps to the existing goal and holds an observed completion until Continue', () => {
    expect(stepsForGoal('certops_vault')).toContain('certops_material_store');
    expect(stepsForGoal('certops_vault')).toContain('certops_consumers');
    const ctx = materialContext();
    const plan = planJourney({
      intent: ctx.session.intent,
      progress: ctx.session.progress,
      reality: ctx.summary,
    });
    expect(plan.steps.find(s => s.id === 'certops_material_store').status).toBe(
      'done'
    );
    expect(
      observedDoneStep(
        { id: 'certops_material_store', key: 'vault' },
        { key: 'vault', plan, session: ctx.session }
      )
    ).toBe('certops_material_store');
    const navigation = resolveNavigation(
      {
        steps: [
          { id: 'goal', status: 'done' },
          { id: 'certops_material_store', status: 'done' },
          { id: 'certops_consumers', status: 'current' },
        ],
        currentStepId: 'certops_consumers',
      },
      'certops_material_store'
    );
    expect(navigation.shownId).toBe('certops_material_store');
    expect(navigation.returnId).toBe('certops_consumers');
  });
  it('requires accepted, current publication metadata matching every selected authority field', () => {
    for (const patch of [
      { active: false },
      { provider: 'openbao-kv2' },
      { issuerAgentId: 'foreign' },
      { materialStoreRef: 'other' },
      { issuanceProfileRef: 'other' },
      { profileRevision: 2 },
      { publication: null },
      { publication: { materialVersionId: 'old', validTo: '2020-01-01' } },
    ]) {
      const ctx = materialContext();
      Object.assign(ctx.summary.certops.distribution.items[0], patch);
      expect(
        materialStoreSatisfied(ctx.summary, ctx.session.progress.certops)
      ).toBe(false);
    }
  });
  it('ignores UI completion flags, a successful job and unrelated groups, and reopens after restart', () => {
    const ctx = materialContext();
    const saved = ctx.session.progress.certops;
    saved.materialComplete = true;
    ctx.summary.certops.distribution.items[0].publication = null;
    ctx.summary.certops.issueJob = { status: 'succeeded', mode: 'real' };
    expect(
      isStepSatisfied('certops_material_store', {
        reality: ctx.summary,
        progress: ctx.session.progress,
        objective: 'vault',
      })
    ).toBe(false);
    expect(
      materialStoreSatisfied(ctx.summary, {
        ...saved,
        materialSetup: { ...saved.materialSetup, groupId: 'unrelated' },
      })
    ).toBe(false);
    expect(materialStoreSatisfied(ctx.summary, {})).toBe(false);
  });
  it('resumes from server evidence and requires real consumer convergence independently of publication', () => {
    const ctx = materialContext(),
      saved = JSON.parse(JSON.stringify(ctx.session.progress.certops));
    expect(materialStoreSatisfied(ctx.summary, saved)).toBe(true);
    expect(materialConsumersSatisfied(ctx.summary, saved)).toBe(false);
    ctx.summary.certops.distribution.items[0].completed = true;
    expect(
      isStepSatisfied('certops_consumers', {
        reality: ctx.summary,
        progress: { certops: saved },
        objective: 'vault',
      })
    ).toBe(true);
    ctx.summary.certops.distribution.items[0].completed = false;
    expect(materialConsumersSatisfied(ctx.summary, saved)).toBe(false);
  });
  it('preserves a selected legacy Vault publication without trusting its UI acknowledgement', () => {
    const ctx = materialContext();
    expect(
      materialStoreSatisfied(ctx.summary, {
        groupId: GROUP,
        vaultIssuerAgentId:
          ctx.session.progress.certops.materialSetup.issuerAgentId,
      })
    ).toBe(true);
  });
  it('resets only guide references when switching groups, preserving backend jobs and saved proof as external facts', () => {
    const ctx = materialContext(),
      saved = ctx.session.progress.certops;
    saved.vaultConsumers = [{ bindingId: 'old-binding' }];
    saved.vaultRolloutJobId = 'old-job';
    const patch = materialSetupPatch(saved, {
      ...saved.materialSetup,
      groupId: 'another-group',
    });
    expect(patch.vaultConsumers).toEqual([]);
    expect(patch.vaultRolloutJobId).toBe('');
    expect(patch.materialVerification).toBeNull();
    expect(saved.vaultRolloutJobId).toBe('old-job');
    expect(materialSetupPatch(saved, saved.materialSetup)).not.toHaveProperty(
      'vaultConsumers'
    );
  });
  it('does not treat an advertised capability as production qualification or accept stale declarations', () => {
    const ctx = materialContext('azure-key-vault');
    expect(
      featureReady(ctx.capabilities, 'certops.material_store_azure_key_vault')
    ).toBe(false);
    expect(featureReady(null, 'certops.material_store_vault_kv2')).toBe(false);
    expect(
      agentRequirements(
        { ...ctx.summary.certops.agents.items[0], claimEvidenceFresh: false },
        'vault-kv2'
      )
    ).toContain(
      'Refresh the agent capability declaration; signed claim evidence is missing or stale.'
    );
  });
});

describe('customer-local material configuration', () => {
  it('accepts the existing backend reference alphabet for reused local policies', () => {
    const ctx = materialContext();
    const setup = {
      ...ctx.session.progress.certops.materialSetup,
      materialStoreRef: '_customer',
      issuanceProfileRef: '-shared',
    };
    const config = materialConfigs({
      setup,
      address: 'https://store.example.test',
      workspaceId: WS,
      groupId: GROUP,
      names: ['web.example.test'],
      zone: 'example.test',
      dnsProvider: 'cloudflare',
      consumerDeliveryMode: 'files',
    });
    expect(config.ok).toBe(true);
    expect(
      config.issuer.materialStores._customer.groups[GROUP].issuanceProfileRef
    ).toBe('-shared');
  });
  const input = provider => ({
    setup: materialContext(provider).session.progress.certops.materialSetup,
    address: 'https://store.example.test',
    workspaceId: WS,
    groupId: GROUP,
    names: ['web.example.test'],
    zone: 'example.test',
    dnsProvider: 'cloudflare',
    consumerDeliveryMode: 'files',
  });
  it.each(['vault-kv2', 'openbao-kv2'])(
    'keeps exact refs and complete installed-only configuration for %s',
    provider => {
      const config = materialConfigs(input(provider));
      expect(config.ok).toBe(true);
      expect(
        config.consumer.materialStores.customer.provider || 'vault-kv2'
      ).toBe(provider);
      expect(
        config.consumer.materialBindings.REPLACE_WITH_BINDING_ID
      ).toMatchObject({ verificationPolicy: 'installed', probes: [] });
      expect(
        config.consumer.materialBindings.REPLACE_WITH_BINDING_ID.reloadService
      ).toBeUndefined();
      expect(config.issuer.execution.dryRun).toBe(true);
    }
  );
  it('shows Azure identity configuration without Vault fields or embedded credentials', () => {
    const config = materialConfigs({
      ...input('azure-key-vault'),
      address: 'https://customer.vault.azure.net',
    });
    expect(config.issuer.materialStores.customer.auth).toEqual({
      type: 'managed-identity',
    });
    expect(config.issuer.materialStores.customer).not.toHaveProperty(
      'tokenFile'
    );
    expect(config.issuer.materialStores.customer).not.toHaveProperty('mount');
  });
  it.each([
    'http://store.example.test',
    'https://user:password@store.example.test',
    'https://store.example.test?token=never',
    'https://store.example.test/secret',
  ])('rejects unsafe endpoint %s', address => {
    expect(materialConfigs({ ...input('vault-kv2'), address }).ok).toBe(false);
  });
  it('rejects unknown providers and non-Azure authorities', () => {
    for (const provider of ['unknown', '__proto__', 'constructor', 'toString'])
      expect(materialConfigs(input(provider)).ok).toBe(false);
    expect(materialConfigs(input('azure-key-vault')).ok).toBe(false);
  });
});
