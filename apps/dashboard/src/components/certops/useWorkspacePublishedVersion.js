import { useEffect, useState } from 'react';
import apiClient from '../../utils/apiClient';

function hasPublishedVersion(group) {
  if (!group) return false;
  // The group list reports publication fields from the newest version only.
  // latest_material_version_id stays on the last version that was published.
  if (group.latest_material_version_id) return true;
  if (group.published_at || group.publication_state === 'published') return true;
  return (group.versions || []).some(
    version => version && version.state === 'published'
  );
}

/** True only after this workspace has at least one published material version. */
export default function useWorkspacePublishedVersion(workspaceId) {
  const [published, setPublished] = useState(false);

  useEffect(() => {
    if (!workspaceId) {
      setPublished(false);
      return undefined;
    }
    let cancelled = false;
    const controller = new AbortController();
    apiClient
      .get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups`,
        { signal: controller.signal }
      )
      .then(({ data }) => {
        if (!cancelled)
          setPublished((data?.groups || []).some(hasPublishedVersion));
      })
      .catch(() => {
        if (!cancelled) setPublished(false);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId]);

  return published;
}
