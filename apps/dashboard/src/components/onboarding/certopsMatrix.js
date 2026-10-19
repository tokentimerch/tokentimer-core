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
      'A domain-joined Windows agent enrolls IIS certificates from your private CA. Candidate: the guide prepares it but cannot verify enrollment.',
  },
  vault: {
    label: 'Share one certificate across servers with Vault',
    description: 'Candidate: not yet production-qualified.',
  },
};

// status: qualified | candidate. Anything unsupported is simply absent.
export const INFRASTRUCTURES = {
  linux: {
    label: 'Linux server',
    detail: 'systemd, Node.js 22 or 24, nginx / Apache / HAProxy',
    platform: 'linux',
    objectives: {
      observe: 'qualified',
      automate: 'qualified',
      vault: 'candidate',
    },
  },
  windows: {
    label: 'Windows Server with IIS',
    detail: 'Server 2016 or later (build 14393+), PowerShell 5.1',
    platform: 'win32',
    // The Windows ACME and AD CS paths are built in the guide but have not
    // been verified on a real host, so they are labelled as candidates.
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
    .map(([id, infra]) => ({
      id,
      ...infra,
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
