/**
 * Workspace-scoped deep links for CertOps resources referenced from jobs.
 * Detail UIs are modal/tab based, so links land on the owning page with a
 * query param the destination page resolves into a details view.
 */

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isCertOpsResourceId(value) {
  return typeof value === 'string' && UUID_RE.test(value.trim());
}

/**
 * @returns {string|null} relative path under the dashboard router
 */
export function jobSubjectHref(subjectType, subjectId) {
  if (!isCertOpsResourceId(subjectId)) return null;
  const id = subjectId.trim();
  switch (String(subjectType || '')) {
    case 'managed_certificate':
      return `/certops/certificates?certificateId=${encodeURIComponent(id)}`;
    case 'trust_anchor':
      return `/certops/agents?trustAnchorId=${encodeURIComponent(id)}`;
    default:
      return null;
  }
}

export function jobAgentHref(agentId) {
  if (!isCertOpsResourceId(agentId)) return null;
  return `/certops/agents?agentId=${encodeURIComponent(agentId.trim())}`;
}
