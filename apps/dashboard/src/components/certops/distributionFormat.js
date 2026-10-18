export const deploymentStates = {
  verified: { label: 'Verified and current', scheme: 'green' },
  partial: { label: 'Partially verified', scheme: 'orange' },
  failed: { label: 'Deployment failed', scheme: 'red' },
  uncertain: { label: 'Execution uncertain', scheme: 'orange' },
  stale: { label: 'Verification outdated', scheme: 'orange' },
  pending: { label: 'Pending verification', scheme: 'blue' },
  not_deployed: { label: 'Not deployed', scheme: 'gray' },
  inactive: { label: 'Management ended', scheme: 'gray' },
  not_distributed: { label: 'Not distributed', scheme: 'gray' },
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

export function consumerDeploymentStatus(consumer) {
  if (consumer.binding_state !== 'active') return 'inactive';
  if (consumer.latest_deployment?.stage === 'orphaned_unknown_effect')
    return 'uncertain';
  if (consumer.latest_deployment?.stage === 'failed') return 'failed';
  if (consumer.converged === true) return 'verified';
  if (consumer.stale) return 'stale';
  return consumer.desired_material_version_id ? 'pending' : 'not_deployed';
}
