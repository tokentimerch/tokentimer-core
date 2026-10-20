export const deploymentStates = {
  verified: { label: 'Verified and current', scheme: 'green' },
  partial: { label: 'Partially verified', scheme: 'orange' },
  failed: { label: 'Deployment failed', scheme: 'red' },
  uncertain: { label: 'Deployment outcome uncertain', scheme: 'orange' },
  stale: { label: 'Verification outdated', scheme: 'orange' },
  pending: { label: 'Pending verification', scheme: 'blue' },
  not_deployed: { label: 'Not deployed', scheme: 'gray' },
  inactive: { label: 'Management ended', scheme: 'gray' },
  not_distributed: { label: 'Not distributed', scheme: 'gray' },
  unavailable: { label: 'Verification needs refresh', scheme: 'orange' },
};

export function combineDeploymentSummaries(groups) {
  if (!groups.length)
    return { status: 'not_distributed', total: 0, verified: 0 };
  const counts = groups.reduce(
    (result, group) => {
      for (const key of Object.keys(result))
        result[key] += Number(group.summary?.[key] || 0);
      return result;
    },
    {
      total: 0,
      verified: 0,
      failed: 0,
      uncertain: 0,
      stale: 0,
      pending: 0,
      not_deployed: 0,
    }
  );
  const status = counts.uncertain
    ? 'uncertain'
    : counts.failed
      ? 'failed'
      : counts.stale
        ? 'stale'
        : counts.total && counts.verified === counts.total
          ? 'verified'
          : counts.verified
            ? 'partial'
            : !counts.total || counts.not_deployed === counts.total
              ? 'not_deployed'
              : 'pending';
  return { ...counts, status };
}

export function distributionKey(certificate) {
  return certificate.identityId
    ? `identity:${certificate.identityId}`
    : `managed:${certificate.managedCertificateId || certificate.id}`;
}

export function verificationDeadline(consumer) {
  const freshness = freshnessDeadline(consumer);
  const expiry = Date.parse(consumer.observed_valid_to);
  return freshness !== null && Number.isFinite(expiry)
    ? Math.min(freshness, expiry)
    : null;
}

export function freshnessDeadline(consumer) {
  const observed = Date.parse(consumer.observed_at);
  const seconds = Number(consumer.freshness_seconds);
  return Number.isFinite(observed) && Number.isFinite(seconds) && seconds > 0
    ? observed + seconds * 1000
    : null;
}

export function formatFreshnessDuration(value) {
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds <= 0) return 'Unavailable';
  return [
    [Math.floor(seconds / 3600), 'hour'],
    [Math.floor((seconds % 3600) / 60), 'minute'],
    [seconds % 60, 'second'],
  ]
    .filter(([amount]) => amount > 0)
    .map(([amount, unit]) => `${amount} ${unit}${amount === 1 ? '' : 's'}`)
    .join(' ');
}

export function consumerDeploymentStatus(consumer, now = Date.now()) {
  if (consumer.binding_state !== 'active') return 'inactive';
  if (consumer.latest_deployment?.stage === 'orphaned_unknown_effect')
    return 'uncertain';
  if (consumer.latest_deployment?.stage === 'failed') return 'failed';
  const deadline = verificationDeadline(consumer);
  if (deadline !== null && now >= deadline && consumer.observed_at)
    return 'stale';
  if (consumer.converged === true) return 'verified';
  if (consumer.stale) return 'stale';
  return consumer.desired_material_version_id ? 'pending' : 'not_deployed';
}

export const verificationStages = {
  served_verified: 'Certificate served successfully',
  trust_validated: 'Certificate and TLS trust validated',
  orphaned_unknown_effect: 'Deployment outcome uncertain',
  failed: 'Deployment failed',
  pending: 'Deployment requested',
  fetched: 'Certificate material fetched',
  installed: 'Certificate material installed',
  bound: 'Certificate bound to service',
};

export const verificationMethods = {
  served: 'Certificate served and fingerprint verified',
  trust: 'Certificate and TLS trust verified',
};

export function consumerVersionComparison(consumer, status) {
  if (status === 'uncertain') return 'Unknown';
  if (!consumer.desired_material_version_id) return '—';
  if (!consumer.observed_material_version_id) return 'Not confirmed';
  // Compare immutable TokenTimer material IDs, never provider revisions or rollout generations.
  return consumer.desired_material_version_id ===
    consumer.observed_material_version_id
    ? 'Matches expected'
    : 'Different version';
}
