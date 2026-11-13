import { Box, Text, VStack } from '@chakra-ui/react';

// Project only public review fields. Never render an arbitrary job payload or
// spread a nested object: future execution fields may contain local-only data.
function fields(value, labels) {
  return Object.fromEntries(
    labels.map(([key, label]) => {
      const item = value?.[key];
      return [
        label,
        item === null || ['string', 'number', 'boolean'].includes(typeof item)
          ? item
          : undefined,
      ];
    })
  );
}

function retention(policy) {
  return fields(policy, [
    ['minimumSeconds', 'Minimum age (seconds)'],
    ['minimumVersions', 'Minimum retained versions'],
    ['rollbackSeconds', 'Rollback protection (seconds)'],
    ['cleanupEnabled', 'Cleanup enabled'],
    ['reportOnly', 'Report only'],
    ['requiresApproval', 'Independent approval required'],
  ]);
}

function activation(binding) {
  const policy = binding.activationPolicy;
  if (!policy)
    return {
      Method:
        binding.activationClass ||
        (binding.verificationPolicy === 'installed' ? 'none' : 'reload'),
      Calendar: 'No additional calendar configured',
      'Preparation before activation window': false,
    };
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return {
    ...fields(policy, [
      ['method', 'Method'],
      ['disruptive', 'Disruptive'],
      ['requiresApproval', 'Explicit approval required'],
      ['timezone', 'Time zone'],
      ['validUntil', 'Authorization expires'],
    ]),
    'Preparation before activation window': policy.independentStaging === true,
    ...(policy.independentStaging === true
      ? {
          'Preparation scope':
            'Copies protected material to the consumer before the activation window. It does not establish installation, service use or trust.',
        }
      : {}),
    'Maintenance windows': Object.fromEntries(
      (policy.windows || []).map((window, index) => [
        `Window ${index + 1}`,
        `${window.days.map(day => days[day]).join(', ')}: ${window.start}–${window.end}`,
      ])
    ),
    Blackouts: Object.fromEntries(
      (policy.blackouts || []).map((blackout, index) => [
        `Blackout ${index + 1}`,
        `${blackout.start} – ${blackout.end}`,
      ])
    ),
    'Emergency exception': policy.emergency
      ? fields(policy.emergency, [
          ['start', 'Start'],
          ['end', 'End'],
          ['reference', 'Audit reference'],
        ])
      : null,
  };
}

function consumers(bindings) {
  return Object.fromEntries(
    (bindings || []).map((binding, index) => [
      `Consumer ${index + 1}`,
      {
        ...fields(binding, [
          ['bindingId', 'Binding ID'],
          ['agentId', 'Agent ID'],
          ['profileRef', 'Local deployment profile'],
          ['profileRevision', 'Local profile revision'],
          ['authorizationRevision', 'Authorization revision'],
          ['required', 'Required consumer'],
          ['wave', 'Wave'],
          ['verificationPolicy', 'Verification assurance'],
          ['freshnessSeconds', 'Proof freshness (seconds)'],
        ]),
        Activation: activation(binding),
      },
    ])
  );
}

function policyScope(policy) {
  return {
    ...fields(policy, [
      ['mode', 'Mode'],
      ['maxParallel', 'Maximum parallel consumers'],
      ['authorizationExpiresAt', 'Authorization expires'],
    ]),
    Verification: fields(policy?.verification, [
      ['enabled', 'Enabled'],
      ['intervalSeconds', 'Interval (seconds)'],
      ['maxBackoffSeconds', 'Maximum backoff (seconds)'],
      ['staleJobSeconds', 'Stale job (seconds)'],
      ['failureThreshold', 'Failure threshold'],
    ]),
    Alerts: {
      ...fields(policy?.alerts, [
        ['enabled', 'Enabled'],
        ['offlineSeconds', 'Offline threshold (seconds)'],
        ['stuckSeconds', 'Stuck threshold (seconds)'],
        ['convergenceSeconds', 'Convergence threshold (seconds)'],
        ['expiryWarningDays', 'Expiry warning (days)'],
        ['repeatSeconds', 'Repeat interval (seconds)'],
      ]),
      'Contact groups': Array.isArray(policy?.alerts?.contactGroupIds)
        ? policy.alerts.contactGroupIds
            .filter(id => typeof id === 'string')
            .join(', ') || 'None'
        : undefined,
    },
    Retention: retention(policy?.retention),
  };
}

export function cleanupScopeAvailable(job) {
  if (job?.operation !== 'cleanup-from-store') return true;
  const intent = job.payload?.materialCleanup;
  return (
    !!intent &&
    [
      'materialVersionId',
      'provider',
      'providerVersion',
      'materialStoreRef',
      'profileRevision',
      'policyRevision',
      'scopeHash',
      'expiresAt',
    ].every(key => intent[key] !== undefined && intent[key] !== null)
  );
}

function reviewScope(job) {
  const payload = job?.payload;
  if (payload?.materialReconciliation) {
    const scope = payload.materialReconciliation;
    return {
      Operation: 'Read-only reconciliation of an original deployment',
      ...fields(scope, [
        ['originalJobId', 'Original job'],
        ['assignedAgentId', 'Assigned agent'],
        ['workspaceAuthorizationRevision', 'Workspace authority revision'],
      ]),
      'Original deployment': fields(scope.intent, [
        ['groupId', 'Distribution group'],
        ['bindingId', 'Consumer binding'],
        ['rolloutId', 'Original rollout'],
        ['materialVersionId', 'Material version'],
        ['provider', 'Provider'],
        ['materialStoreRef', 'Customer store alias'],
        ['providerVersion', 'Provider version'],
        ['fingerprintSha256', 'Certificate SHA-256'],
        ['generation', 'Generation'],
        ['deploymentProfileRef', 'Local deployment profile'],
        ['profileRevision', 'Local profile revision'],
        ['authorizationRevision', 'Authorization revision'],
        ['verificationPolicy', 'Verification policy'],
        ['verificationOnly', 'Verification only'],
        ['preparationOnly', 'Preparation only'],
      ]),
      'Execution boundary':
        'Inspect the original deployment only. Do not install material, reload services or substitute newer deployment evidence.',
    };
  }
  if (payload?.materialCleanup) {
    const intent = payload.materialCleanup;
    return {
      Operation: 'Soft delete one store version',
      ...fields(intent, [
        ['groupId', 'Distribution group'],
        ['managementPeriodId', 'Management period'],
        ['materialVersionId', 'Material version'],
        ['provider', 'Provider'],
        ['materialStoreRef', 'Customer store alias'],
        ['providerVersion', 'Provider version'],
        ['profileRevision', 'Local profile revision'],
        ['policyRevision', 'Policy revision'],
        ['scopeHash', 'Scope hash'],
        ['expiresAt', 'Approval expires'],
      ]),
      Retention: retention(intent.retentionPolicy),
    };
  }
  if (payload?.distributionRollout) {
    const intent = payload.distributionRollout;
    return {
      Operation: intent.verificationOnly
        ? 'Verification only'
        : 'Deploy exact version',
      ...fields(intent, [
        ['workspaceId', 'Workspace'],
        ['workspaceAuthorizationRevision', 'Workspace authority revision'],
        ['groupId', 'Distribution group'],
        ['managementPeriodId', 'Management period'],
        ['materialVersionId', 'Material version'],
        ['materialStoreRef', 'Customer store alias'],
        ['providerVersion', 'Provider version'],
        ['fingerprintSha256', 'Certificate SHA-256'],
        ['issuanceProfileRevision', 'Issuer profile revision'],
        ['generation', 'Generation'],
        ['maxParallel', 'Maximum parallel consumers'],
      ]),
      Provider: intent.provider || 'vault-kv2',
      Consumers: consumers(intent.bindings),
    };
  }
  if (payload?.distributionPolicyApproval) {
    const intent = payload.distributionPolicyApproval;
    const { scope } = intent;
    return {
      Operation: 'Standing distribution authorization',
      ...fields(intent, [
        ['groupId', 'Distribution group'],
        ['revision', 'Policy revision'],
        ['scopeHash', 'Scope hash'],
        ['expiresAt', 'Approval expires'],
      ]),
      'Source authority': fields(scope, [
        ['workspaceId', 'Workspace'],
        ['managementPeriodId', 'Management period'],
        ['materialStoreRef', 'Customer store alias'],
        ['issuerAgentId', 'Issuer agent ID'],
        ['issuanceProfileRef', 'Local issuance profile'],
        ['profileRevision', 'Issuer profile revision'],
        ['workspaceAuthorizationRevision', 'Workspace authorization revision'],
        ['workspaceRequiresApproval', 'Workspace requires approval'],
        ['workspaceOwner', 'Workspace owner user ID'],
      ]),
      Reviewers: Object.fromEntries(
        (scope?.reviewers || []).map((reviewer, index) => [
          `Reviewer ${index + 1}`,
          fields(reviewer, [
            ['user_id', 'User ID'],
            ['role', 'Role'],
          ]),
        ])
      ),
      Policy: policyScope(scope?.policy),
      'Rollout behavior': fields(scope?.rolloutBehavior, [
        ['requiredFailure', 'Required consumer failure'],
        ['optionalFailure', 'Optional consumer failure'],
        ['waveOrder', 'Wave order'],
        ['rollback', 'Rollback'],
        ['verificationBeforeNextWave', 'Verify before next wave'],
      ]),
      Consumers: consumers(scope?.bindings),
    };
  }
  return null;
}

function ScopeFields({ values }) {
  const entries = Object.entries(values).filter(
    ([, value]) => value !== undefined
  );
  if (!entries.length) return <Text fontSize='sm'>None</Text>;
  return (
    <VStack as='dl' align='stretch' spacing={2}>
      {entries.map(([label, value]) => (
        <Box key={label}>
          <Text as='dt' fontSize='xs' fontWeight='semibold'>
            {label}
          </Text>
          <Box as='dd' ml={typeof value === 'object' && value !== null ? 3 : 0}>
            {typeof value === 'object' && value !== null ? (
              <ScopeFields values={value} />
            ) : (
              <Text fontSize='sm' overflowWrap='anywhere'>
                {value === null
                  ? 'None'
                  : typeof value === 'boolean'
                    ? value
                      ? 'Yes'
                      : 'No'
                    : value}
              </Text>
            )}
          </Box>
        </Box>
      ))}
    </VStack>
  );
}

export default function JobApprovalScope({ job }) {
  const scope = reviewScope(job);
  if (!scope && job?.operation !== 'cleanup-from-store') return null;
  return (
    <Box
      as='section'
      aria-label='Immutable approval scope'
      borderWidth='1px'
      borderRadius='md'
      p={3}
    >
      <Text fontWeight='semibold' mb={2}>
        Immutable approval scope
      </Text>
      {!cleanupScopeAvailable(job) ? (
        <Text role='alert' fontSize='sm'>
          Exact cleanup scope is unavailable. Refresh Jobs before approving.
        </Text>
      ) : null}
      {scope ? <ScopeFields values={scope} /> : null}
    </Box>
  );
}
