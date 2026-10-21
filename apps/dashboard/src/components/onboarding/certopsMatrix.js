// What CertOps combinations the wizard may offer. Only qualified paths are
// offered as normal choices; candidates are labelled; everything else is not
// listed, so the wizard never presents an unsupported combination.

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
// The wizard also marks a pick Candidate from guidedSetupStatus.js.
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
    // The guided Windows ACME and AD CS setups are flagged here as well as in
    // the guided setup register.
    objectives: {
      observe: 'qualified',
      automate: 'candidate',
      adcs: 'candidate',
    },
  },
  kubernetes: {
    label: 'Kubernetes with cert-manager',
    detail: 'Installed with Helm; observe or provision mode',
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
 * The agent a guide step sends its jobs to. With several agents in the
 * workspace (for example an issuer and a Vault consumer) the newest one is not
 * necessarily the one that can place orders, so prefer a live agent that
 * declared the goal's command profile.
 */
export function pickGoalAgent(items, objective, infrastructure) {
  const list = items || [];
  const profile = commandProfileFor(objective, infrastructure);
  if (profile) {
    const has = a => (a.commandProfiles || []).includes(profile);
    const match =
      list.find(a => a.livenessState === 'live' && has(a)) || list.find(has);
    if (match) return match;
  }
  return list[0];
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
