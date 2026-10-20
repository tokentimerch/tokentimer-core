import { useCallback, useMemo } from 'react';
import apiClient from '../../utils/apiClient';
import {
  combineDeploymentSummaries,
  distributionKey,
} from './distributionFormat.js';
import useDistributionRead, {
  DISTRIBUTION_POLL_MS,
  serverClockOffset,
} from './useDistributionRead.js';

export default function useDistributionSummaries(
  workspaceId,
  certificates = []
) {
  const managedIds = [
    ...new Set(
      certificates
        .filter(c => !c.identityId)
        .map(c => c.managedCertificateId || c.id)
        .filter(Boolean)
    ),
  ]
    .sort()
    .join(',');
  const identityIds = [
    ...new Set(certificates.map(c => c.identityId).filter(Boolean)),
  ]
    .sort()
    .join(',');
  const scope =
    workspaceId && (managedIds || identityIds)
      ? `${workspaceId}/${managedIds}/${identityIds}`
      : null;
  const read = useCallback(
    async (signal, startedAt) => {
      const managed = managedIds ? managedIds.split(',') : [];
      const identities = identityIds ? identityIds.split(',') : [];
      const requests = [];
      for (
        let index = 0;
        index < Math.max(managed.length, identities.length);
        index += 200
      ) {
        requests.push(
          apiClient.get(
            `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups`,
            {
              params: {
                summaries: true,
                managedCertificateIds:
                  managed.slice(index, index + 200).join(',') || undefined,
                identityIds:
                  identities.slice(index, index + 200).join(',') || undefined,
              },
              signal,
            }
          )
        );
      }
      const responses = await Promise.all(requests);
      const groups = new Map();
      for (const { data } of responses) {
        const offset = serverClockOffset(data, startedAt);
        for (const group of data.groups || [])
          groups.set(group.id, {
            ...group,
            offset,
            fallbackExpiry: startedAt + DISTRIBUTION_POLL_MS,
          });
      }
      const index = new Map();
      for (const group of groups.values()) {
        for (const key of [
          `identity:${group.current_identity_id}`,
          `managed:${group.managed_certificate_id}`,
        ]) {
          if (!index.has(key)) index.set(key, []);
          index.get(key).push(group);
        }
      }
      return {
        index,
        deadlines: [...groups.values()].flatMap(group =>
          Array.isArray(group.summary?.verification_expirations)
            ? group.summary.verification_expirations.map(
                time => time + group.offset
              )
            : [group.fallbackExpiry]
        ),
      };
    },
    [workspaceId, managedIds, identityIds]
  );
  const state = useDistributionRead(scope, read);
  const summaries = useMemo(() => {
    const result = new Map();
    for (const [key, groups] of state.data?.index || []) {
      result.set(
        key,
        groups.map(group => {
          const summary = group.summary || {};
          const expirations = summary.verification_expirations;
          if (Array.isArray(expirations)) {
            const expired = expirations.filter(
              time => time + group.offset <= state.now
            ).length;
            return {
              ...group,
              summary: {
                ...summary,
                verified: Math.max(0, summary.verified - expired),
                stale: (summary.stale || 0) + expired,
              },
            };
          }
          // Older servers cannot supply exact freshness boundaries. Fail closed after one poll window.
          return state.now >= group.fallbackExpiry && summary.verified
            ? { ...group, freshnessUnknown: true }
            : group;
        })
      );
    }
    return result;
  }, [state.data, state.now]);
  return {
    ...state,
    getSummary(certificate) {
      if (!state.data) return null;
      const groups = (summaries.get(distributionKey(certificate)) || []).filter(
        group =>
          !certificate.expectedIdentityId ||
          certificate.expectedIdentityId === group.current_identity_id
      );
      const summary = combineDeploymentSummaries(groups);
      return {
        ...summary,
        staleData: Boolean(state.error),
        ...(groups.some(group => group.freshnessUnknown)
          ? { status: 'unavailable' }
          : {}),
      };
    },
  };
}
