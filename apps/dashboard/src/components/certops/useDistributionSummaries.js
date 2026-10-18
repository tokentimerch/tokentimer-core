import { useEffect, useState } from 'react';
import apiClient from '../../utils/apiClient';
import {
  combineDeploymentSummaries,
  distributionKey,
} from './distributionFormat.js';

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
  const scope = `${workspaceId || ''}/${managedIds}/${identityIds}`;
  const [state, setState] = useState({
    scope: '',
    groups: [],
    loading: false,
    error: '',
  });
  useEffect(() => {
    if (!workspaceId || (!managedIds && !identityIds)) return undefined;
    let active = true;
    const controller = new AbortController();
    let sequence = 0;
    const load = () => {
      const request = ++sequence;
      setState({ scope, groups: [], loading: true, error: '' });
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
              signal: controller.signal,
            }
          )
        );
      }
      Promise.all(requests)
        .then(results => {
          if (active && request === sequence)
            setState({
              scope,
              groups: [
                ...new Map(
                  results
                    .flatMap(({ data }) => data.groups || [])
                    .map(group => [group.id, group])
                ).values(),
              ],
              loading: false,
              error: '',
            });
        })
        .catch(() => {
          if (active && request === sequence)
            setState({
              scope,
              groups: [],
              loading: false,
              error: 'Deployment status unavailable',
            });
        });
    };
    load();
    const timer = setInterval(load, 30_000);
    return () => {
      active = false;
      controller.abort();
      clearInterval(timer);
    };
  }, [workspaceId, managedIds, identityIds, scope]);
  const current = state.scope === scope;
  return {
    loading: !current || state.loading,
    error: current ? state.error : '',
    getSummary(certificate) {
      if (!current || state.loading || state.error) return null;
      const key = distributionKey(certificate);
      return combineDeploymentSummaries(
        state.groups.filter(
          group =>
            (!certificate.expectedIdentityId ||
              certificate.expectedIdentityId === group.current_identity_id) &&
            (key === `identity:${group.current_identity_id}` ||
              key === `managed:${group.managed_certificate_id}`)
        )
      );
    },
  };
}
