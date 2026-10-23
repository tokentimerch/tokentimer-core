// What CertOps combinations the wizard may offer. Only qualified paths are
// offered as normal choices; everything else is not listed, so the wizard
// never presents an unsupported combination.

export const OBJECTIVES = {
  observe: {
    label: 'Discover and observe existing certificates',
    description:
      'An agent finds certificates on a server and reports them. It never changes anything.',
  },
  automate: {
    label: 'Issue and renew certificates automatically',
    description:
      'The agent requests a certificate through ACME (DNS-01), installs it and renews it.',
  },
  adcs: {
    label: 'Issue certificates from my Microsoft CA (AD CS)',
    description:
      'A domain-joined Windows agent enrolls certificates for an HTTPS listener (IIS) from your private CA.',
  },
  vault: {
    label: 'Share one certificate across servers with Vault',
    description:
      'Publish a certificate to your Vault and deploy it to other agents.',
  },
};

// status: qualified | candidate. Anything unsupported is simply absent.
// The Not fully tested label comes from guidedSetupStatus.js only.
export const INFRASTRUCTURES = {
  linux: {
    label: 'Linux server',
    detail: 'systemd, Node.js 22 or 24, nginx / Apache / HAProxy',
    platform: 'linux',
    objectives: {
      observe: 'qualified',
      automate: 'qualified',
      vault: 'qualified',
    },
  },
  windows: {
    label: 'Windows Server',
    detail: 'Server 2016 or later (build 14393+), PowerShell 5.1',
    // AD CS was qualified on Server 2019, 2022 and 2025; 2016 and earlier are
    // outside its qualified scope.
    goalBase: {
      adcs: 'Server 2019 or later (build 17763+), PowerShell 5.1',
    },
    // Appended per goal: IIS only matters once a certificate is deployed.
    goalDetail: {
      observe:
        'Discover certificates in the machine certificate store and HTTPS bindings. No IIS needed.',
      automate:
        'Install the certificate in the machine store and bind it to an HTTPS listener, typically an IIS site.',
      adcs: 'Use a domain-joined member server, not a domain controller. Install the certificate in the machine store and bind it to an HTTPS listener, typically an IIS site.',
    },
    platform: 'win32',
    objectives: {
      observe: 'qualified',
      automate: 'candidate',
      adcs: 'candidate',
    },
  },
  kubernetes: {
    label: 'Kubernetes with cert-manager',
    detail: 'Installed with Helm; reports the cert-manager certificates',
    platform: null,
    objectives: { observe: 'qualified' },
  },
};

export function infrastructuresFor(objective) {
  return Object.entries(INFRASTRUCTURES)
    .filter(([, infra]) => infra.objectives[objective])
    .map(([id, { goalDetail, goalBase, ...infra }]) => ({
      id,
      ...infra,
      detail: [goalBase?.[objective] || infra.detail, goalDetail?.[objective]]
        .filter(Boolean)
        .join('. '),
      status: infra.objectives[objective],
    }));
}

export function isSupported(objective, infrastructure) {
  return Boolean(INFRASTRUCTURES[infrastructure]?.objectives[objective]);
}

// Operations that only exist once execution is switched on in the agent.
const EXECUTION_OPERATIONS = ['issue', 'renew', 'deploy', 'reload', 'revoke'];

/** Name of the Windows ACME client profile the job and the policy share. */
export const WINDOWS_ACME_PROFILE = 'acme-windows';

/**
 * The command profile an agent must have declared at registration to claim
 * this goal's issuance orders, or null when none is needed. Profiles are only
 * reported at registration, so a missing one means a different agent setup.
 */
export function commandProfileFor(objective, infrastructure) {
  if (objective !== 'automate' && objective !== 'vault') return null;
  if (infrastructure === 'windows') {
    return objective === 'automate' ? WINDOWS_ACME_PROFILE : null;
  }
  return 'certbot';
}

/**
 * The agent a guide step sends its jobs to, among the agents on the platform
 * this setup runs on (an agent of another platform is never "the agent" for
 * it). One that serves the setup comes first, preferring an agent enrolled by
 * this guide (or one the operator chose to reuse); with several agents (for
 * example an issuer and a Vault consumer) the newest is not necessarily the
 * one that can place orders, so a live agent with the goal's command profile
 * follows.
 */
export function pickGoalAgent(items, objective, infrastructure, reusedId) {
  const list = (items || []).filter(a => agentOnPlatform(a, infrastructure));
  const serves = a => agentServesSetup(a, objective, infrastructure);
  const served =
    list.find(a => serves(a) && agentUsable(a, reusedId)) || list.find(serves);
  if (served) return served;
  const profile = commandProfileFor(objective, infrastructure);
  if (profile) {
    const has = a => (a.commandProfiles || []).includes(profile);
    const match =
      list.find(a => a.livenessState === 'live' && has(a)) || list.find(has);
    if (match) return match;
  }
  return list.find(a => a.livenessState === 'live') || list[0];
}

/**
 * Certificates an agent or the Kubernetes controller of this setup can have
 * reported. The summary counts every observed certificate in the workspace,
 * website monitors included, so a certificate only counts as reported once
 * there is a live agent (or a reporting controller) to have sent it.
 */
export function reportedCertificates(
  certops,
  { infrastructure, clusterId } = {}
) {
  const observed =
    certops?.certificates?.observed ?? certops?.certificates?.total ?? 0;
  if (!(observed > 0)) return 0;
  if (infrastructure === 'kubernetes') {
    const clusters = certops?.controllers?.clusters || [];
    return clusters.some(c => !clusterId || c.clusterId === clusterId)
      ? observed
      : 0;
  }
  // Only a live agent on this setup's system counts, never one that runs
  // somewhere else in the workspace.
  return (scopeAgents(certops?.agents, infrastructure)?.live || 0) > 0
    ? observed
    : 0;
}

/** The system a pick runs on when the operator has not chosen one yet. */
export function effectiveInfrastructure(objective, infrastructure) {
  return infrastructure || (objective === 'adcs' ? 'windows' : 'linux');
}

/**
 * The workspace agent summary as one pick sees it: only agents on the pick's
 * system, with the live count and execution flag recomputed from them. The
 * Kubernetes controller is not an agent, so that pick sees none. A summary
 * without the agent list cannot be narrowed and is returned as it is.
 */
export function scopeAgents(agents, infrastructure) {
  if (!agents || !Array.isArray(agents.items)) return agents;
  const items = agents.items.filter(a => agentOnPlatform(a, infrastructure));
  const live = items.filter(a => a.livenessState === 'live');
  return {
    ...agents,
    items,
    total: items.length,
    live: live.length,
    executionEnabled: live.some(a =>
      (a.supportedOperations || []).some(op =>
        EXECUTION_OPERATIONS.includes(op)
      )
    ),
  };
}

/**
 * An agent that was already in the workspace when this guide session started.
 * Summaries from an API that does not say so are read as new, as before.
 */
export function agentExistedBefore(agent) {
  return agent?.existedBeforeSession === true;
}

// Enrolled by this guide, or an older agent the operator chose to reuse.
function agentUsable(agent, reusedId) {
  return (
    !agentExistedBefore(agent) || (Boolean(reusedId) && agent.id === reusedId)
  );
}

/** Capabilities an agent must declare for this combination. */
export function requiredCapabilities(objective, infrastructure) {
  if (objective === 'observe') return [];
  if (objective === 'automate') {
    return infrastructure === 'windows'
      ? ['windows-cert-store-v1', 'iis-binding-v1']
      : [];
  }
  if (objective === 'adcs') {
    return ['windows-cert-store-v1', 'iis-binding-v1', 'adcs-enroll-v1'];
  }
  if (objective === 'vault') {
    return [
      'material-store-vault-kv2-v1',
      'certificate-publication-v1',
      'deploy-from-store-v1',
    ];
  }
  return [];
}

/**
 * Compares what the agent declared with what the goal needs. Returns the
 * missing capabilities so the wizard can say exactly what is wrong.
 */
export function capabilityGap(objective, infrastructure, declared = []) {
  const have = new Set(declared);
  return requiredCapabilities(objective, infrastructure).filter(
    c => !have.has(c)
  );
}

/**
 * The workspace agent counts as seen by one chosen agent: execution is
 * "enabled" when that agent can run jobs, not when any other agent can (a
 * Linux agent set up earlier must not switch on a Windows setup's stage).
 * Summaries whose agent rows carry no operation list keep the workspace flag.
 */
export function agentsFor(agents, agent) {
  if (!agents) return agents;
  if (!agent) return { ...agents, live: 0, executionEnabled: false };
  const ops = agent.supportedOperations;
  return {
    ...agents,
    // The chosen agent is the only one this step is about.
    live: agent.livenessState === 'live' ? 1 : 0,
    executionEnabled: Array.isArray(ops)
      ? ops.some(op => EXECUTION_OPERATIONS.includes(op))
      : agents.executionEnabled === true,
  };
}

/**
 * Whether a goal needs anything from an agent beyond checking in. Observe
 * goals do not, so a live agent in the count is enough for them.
 */
export function needsAgentFacts(objective, infrastructure) {
  return (
    Boolean(commandProfileFor(objective, infrastructure)) ||
    requiredCapabilities(objective, infrastructure).length > 0
  );
}

/**
 * Whether an agent runs on the system this setup targets: its reported
 * platform must be exactly the pick's. The Kubernetes controller is not an
 * agent, and an agent that never reported a platform cannot be vouched for.
 */
export function agentOnPlatform(agent, infrastructure) {
  const platform = INFRASTRUCTURES[infrastructure]?.platform;
  return Boolean(platform) && agent?.platform === platform;
}

/**
 * Whether one agent row can serve this setup: checking in, on the right
 * system, with the command profile and every capability the goal needs. The
 * planner, the poll loop and the status card all use this one rule so they
 * cannot disagree. Other agents of the workspace never block it.
 */
export function agentServesSetup(agent, objective, infrastructure) {
  if (!agent || agent.livenessState !== 'live') return false;
  if (!agentOnPlatform(agent, infrastructure)) return false;
  const profile = commandProfileFor(objective, infrastructure);
  if (profile && !(agent.commandProfiles || []).includes(profile)) {
    return false;
  }
  return (
    capabilityGap(objective, infrastructure, agent.declaredCapabilities)
      .length === 0
  );
}

/**
 * Whether the workspace has an agent for this setup: one live agent that
 * serves it and is either new to this guide session or one the operator chose
 * to reuse. An agent that was in the workspace before the session only counts
 * once `reusedAgentId` names it, so the guide never moves past the install
 * step on an agent the operator did not see. A summary without the agent list
 * can only say how many are live, which settles goals that ask nothing of the
 * agent. `acceptReused` ignores the reuse choice, to know whether the
 * operator could be offered an existing agent at all.
 */
export function setupAgentReady(
  agents,
  objective,
  infrastructure,
  { reusedAgentId, acceptReused = false } = {}
) {
  if ((agents?.live || 0) === 0) return false;
  if (!Array.isArray(agents.items)) {
    return !needsAgentFacts(objective, infrastructure);
  }
  return agents.items.some(
    a =>
      agentServesSetup(a, objective, infrastructure) &&
      (acceptReused || agentUsable(a, reusedAgentId))
  );
}

/**
 * The agent the status card describes: one that serves the setup (new, or the
 * one chosen for reuse, first), else a live one on the right system (so its
 * gap is what gets explained), else any. Agents of another system are never
 * returned.
 */
export function pickSetupAgent(items, objective, infrastructure, reusedId) {
  const onPlatform = (items || []).filter(a =>
    agentOnPlatform(a, infrastructure)
  );
  const serves = a => agentServesSetup(a, objective, infrastructure);
  return (
    onPlatform.find(a => serves(a) && agentUsable(a, reusedId)) ||
    onPlatform.find(serves) ||
    onPlatform.find(a => a.livenessState === 'live') ||
    onPlatform[0]
  );
}

/**
 * Live agents of this workspace that cannot serve the setup because they run
 * on another system, for the neutral hint that says where to install.
 */
export function otherSystemAgents(items, infrastructure) {
  return (items || []).filter(
    a => a.livenessState === 'live' && !agentOnPlatform(a, infrastructure)
  );
}
