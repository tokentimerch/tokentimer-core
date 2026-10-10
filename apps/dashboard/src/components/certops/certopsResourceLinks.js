/**
 * Workspace-scoped deep links for CertOps resources referenced from jobs.
 *
 * Destinations:
 * - managed_certificate → Certificates page opens CertificateIdentityDetailModal
 * - trust_anchor → Agents page expands and highlights the trust-anchor row
 * - agent → Agents page scrolls to and highlights the fleet row
 *
 * There is no dedicated agent/trust-anchor details modal; list focus is the
 * information surface for those types.
 */

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isCertOpsResourceId(value) {
  return typeof value === 'string' && UUID_RE.test(value.trim());
}

export function matchesCertOpsFocusId(focusId, ...candidates) {
  if (!focusId) return false;
  const needle = String(focusId);
  return candidates.some(
    candidate => candidate != null && String(candidate) === needle
  );
}

/**
 * Scroll a focused list row into view once it exists in the DOM.
 * Retries briefly because fleet/trust-anchor lists load asynchronously.
 */
export function scrollCertOpsFocusedNode(selector) {
  if (!selector || typeof document === 'undefined') return () => {};
  let cancelled = false;
  let attempts = 0;
  const maxAttempts = 40;

  const tick = () => {
    if (cancelled) return;
    const node = document.querySelector(selector);
    if (node) {
      node.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
      if (typeof node.focus === 'function') {
        try {
          node.focus({ preventScroll: true });
        } catch {
          node.focus();
        }
      }
      return;
    }
    attempts += 1;
    if (attempts < maxAttempts) {
      window.setTimeout(tick, 50);
    }
  };

  tick();
  return () => {
    cancelled = true;
  };
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
