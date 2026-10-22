import { describe, expect, it } from 'vitest';
import { vaultOutcome } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import { executionStage } from '../../src/components/onboarding/certopsExecutionStep.jsx';
import { describeAgent } from '../../src/components/onboarding/certopsAgentStep.jsx';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import {
  installerOptionsFor,
  installerOptionsKey,
} from '../../src/components/onboarding/certopsConfig.js';

const VAULT_CAPS = [
  'material-store-vault-kv2-v1',
  'certificate-publication-v1',
  'deploy-from-store-v1',
];

describe('vaultOutcome never overclaims', () => {
  it('generated files alone are only "prepared"', () => {
    expect(
      vaultOutcome({ declaredByAgents: [], distribution: { groups: 0 } }).level
    ).toBe('prepared');
    expect(
      vaultOutcome({
        declaredByAgents: VAULT_CAPS,
        distribution: { groups: 0 },
      }).level
    ).toBe('prepared');
  });

  it('lists exactly the capabilities no agent declares', () => {
    const out = vaultOutcome({
      declaredByAgents: ['certificate-publication-v1'],
      distribution: { groups: 1 },
    });
    expect(out.level).toBe('prepared');
    expect(out.missing).toEqual([
      'material-store-vault-kv2-v1',
      'deploy-from-store-v1',
    ]);
  });

  it('is ready to roll out only with capabilities and a distribution group', () => {
    expect(
      vaultOutcome({
        declaredByAgents: VAULT_CAPS,
        distribution: { groups: 1, verified: false },
      }).level
    ).toBe('ready_to_roll_out');
  });

  it('is verified only when the control plane recorded a verified rollout', () => {
    expect(
      vaultOutcome({
        declaredByAgents: [],
        distribution: { groups: 1, verified: true },
      }).level
    ).toBe('verified');
    // A group with every capability but no verified rollout is not verified.
    expect(
      vaultOutcome({
        declaredByAgents: VAULT_CAPS,
        distribution: { groups: 2, verified: false },
      }).level
    ).not.toBe('verified');
  });
});

describe('executionStage follows observed state', () => {
  const live = { live: 1, executionEnabled: false };

  it('is none until an agent is live', () => {
    expect(executionStage({ agents: { live: 0 } }).stage).toBe('none');
    expect(executionStage({ agents: undefined }).stage).toBe('none');
  });

  it('advances only as each thing is observed', () => {
    expect(executionStage({ agents: live }).done).toEqual(['observe']);
    expect(
      executionStage({ agents: { ...live, executionEnabled: true } }).done
    ).toEqual(['observe', 'enabled']);
    expect(
      executionStage({
        agents: { ...live, executionEnabled: true },
        dryRunJob: { status: 'dry_run_complete' },
      }).done
    ).toEqual(['observe', 'enabled', 'dryrun']);
  });

  it('does not accept succeeded as a passed dry run', () => {
    expect(
      executionStage({
        agents: { ...live, executionEnabled: true },
        dryRunJob: { status: 'succeeded' },
      }).done
    ).not.toContain('dryrun');
  });
});

describe('describeAgent', () => {
  const ok = {
    livenessState: 'live',
    compatibilityState: 'compatible',
    clockDriftState: 'ok',
  };

  it('is healthy only with no problems', () => {
    expect(describeAgent(ok).healthy).toBe(true);
  });

  it('explains each problem in plain language', () => {
    const stale = describeAgent({ ...ok, livenessState: 'stale' });
    expect(stale.healthy).toBe(false);
    expect(stale.problems.join(' ')).toMatch(/not checked in/);
    expect(
      describeAgent({ ...ok, compatibilityState: 'outdated' }).problems.join(
        ' '
      )
    ).toMatch(/Upgrade/);
    expect(
      describeAgent({ ...ok, clockDriftState: 'alert' }).problems.join(' ')
    ).toMatch(/NTP/);
    expect(describeAgent(ok, ['iis-binding-v1']).problems.join(' ')).toMatch(
      /iis-binding-v1/
    );
  });
});

describe('CertOps journey', () => {
  const caps = {
    items: [
      { id: 'certops.core', state: 'ready' },
      { id: 'alerts.contact_groups', state: 'ready' },
    ],
  };

  it('puts configuration before agent registration for automation', () => {
    const plan = planJourney({
      intent: { goal: 'certops_automate' },
      progress: { certops: { objective: 'automate' } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 0 } },
      },
    });
    const ids = plan.steps.map(s => s.id);
    expect(ids.indexOf('certops_config')).toBeLessThan(
      ids.indexOf('certops_agent')
    );
    expect(plan.currentStepId).toBe('certops_config');
  });

  it('does not treat the agent step as done until an agent is live', () => {
    const base = {
      intent: { goal: 'certops_observe' },
      progress: { certops: { objective: 'observe', configReviewed: true } },
      capabilities: caps,
    };
    const without = planJourney({
      ...base,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 0 } },
      },
    });
    expect(without.currentStepId).toBe('certops_agent');
    const withAgent = planJourney({
      ...base,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 1 }, certificates: { total: 0 } },
      },
    });
    expect(withAgent.steps.find(s => s.id === 'certops_agent').status).toBe(
      'done'
    );
  });

  it('treats a reporting Kubernetes controller as the installed component', () => {
    const base = {
      intent: { goal: 'certops_observe' },
      capabilities: caps,
    };
    const progress = {
      certops: {
        objective: 'observe',
        infrastructure: 'kubernetes',
        clusterId: 'wiz-k8s',
      },
    };
    const reality = clusters => ({
      alerts: { smtpConfigured: true },
      certops: {
        agents: { live: 0 },
        controllers: { clusters },
        certificates: { observed: 1, total: 1 },
      },
    });
    const waiting = planJourney({
      ...base,
      progress,
      reality: reality([]),
    });
    const status = plan =>
      Object.fromEntries(plan.steps.map(s => [s.id, s.status]));
    // The controller has no agent configuration or execution switch: those
    // two steps are not part of its journey at all.
    expect(waiting.steps.map(s => s.id)).toEqual([
      'goal',
      'certops_objective',
      'certops_agent',
      'certops_first',
      'recipients',
      'verify',
    ]);
    expect(waiting.currentStepId).toBe('certops_agent');
    const other = planJourney({
      ...base,
      progress,
      reality: reality([{ clusterId: 'elsewhere' }]),
    });
    expect(other.currentStepId).toBe('certops_agent');
    const reporting = planJourney({
      ...base,
      progress,
      reality: reality([{ clusterId: 'wiz-k8s' }]),
    });
    expect(status(reporting).certops_agent).toBe('done');
    expect(status(reporting).certops_first).toBe('done');
  });

  it('reopens the agent step when the goal needs installer options the agent was installed without', () => {
    const certops = {
      objective: 'automate',
      infrastructure: 'linux',
      configReviewed: true,
      certPath: '/etc/ssl/tokentimer/a.pem',
      reloadService: 'apache',
    };
    const reality = {
      alerts: { smtpConfigured: true },
      certops: {
        agents: {
          live: 1,
          items: [{ livenessState: 'live', commandProfiles: ['certbot'] }],
        },
      },
    };
    const agentStatus = progress =>
      planJourney({
        intent: { goal: 'certops_automate' },
        progress: { certops: progress },
        capabilities: caps,
        reality,
      }).steps.find(s => s.id === 'certops_agent').status;
    // Registered for another goal: the installer has to run again.
    expect(agentStatus(certops)).toBe('current');
    // The operator confirmed the run for these exact options.
    const key = installerOptionsKey(
      installerOptionsFor({ ...certops, certPath: certops.certPath })
    );
    expect(agentStatus({ ...certops, installerKey: key })).toBe('done');
    // A later change of server or folder asks again.
    expect(
      agentStatus({ ...certops, installerKey: key, reloadService: 'haproxy' })
    ).toBe('current');
    // Without a reload or a folder to grant, nothing needs re-running.
    expect(
      agentStatus({ ...certops, certPath: 'relative.pem', reloadService: '' })
    ).toBe('done');
  });

  it('reopens the agent step if the agent disappears', () => {
    const plan = planJourney({
      intent: { goal: 'certops_observe' },
      progress: { certops: { objective: 'observe', configReviewed: true } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 0 } },
      },
    });
    expect(plan.steps.find(s => s.id === 'certops_agent').status).toBe(
      'current'
    );
  });

  it('requires the server to report dry_run_complete', () => {
    const progress = {
      certops: {
        objective: 'automate',
        configReviewed: true,
        executionAcknowledged: false,
      },
    };
    const reality = status => ({
      alerts: { smtpConfigured: true },
      certops: {
        agents: { live: 1, executionEnabled: true },
        dryRun: status ? { status } : null,
        certificates: { total: 0 },
      },
    });
    const run = status =>
      planJourney({
        intent: { goal: 'certops_automate' },
        progress,
        capabilities: caps,
        reality: reality(status),
      }).steps.find(s => s.id === 'certops_execution').status;
    expect(run('dry_run_complete')).toBe('done');
    expect(run('succeeded')).not.toBe('done');
    expect(run(null)).not.toBe('done');
  });

  it('labels the Vault goal a candidate but still plannable', () => {
    const plan = planJourney({
      intent: { goal: 'certops_vault' },
      capabilities: {
        items: [
          { id: 'certops.core', state: 'ready' },
          {
            id: 'certops.vault_distribution',
            state: 'candidate',
            blockers: [{ code: 'FEATURE_NOT_QUALIFIED' }],
          },
        ],
      },
      reality: { alerts: { smtpConfigured: true } },
    });
    expect(plan.blocked).toBeNull();
    expect(plan.steps.map(s => s.id)).toContain('certops_vault');
  });
});
