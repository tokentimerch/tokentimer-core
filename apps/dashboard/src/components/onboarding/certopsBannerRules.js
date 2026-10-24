// When to invite someone to the CertOps quickstart from the Certificate
// Management pages. Conservative on purpose: only a workspace with no agents,
// no managed certificates and no issuers, for someone who can act on it, and
// never once they asked to stop seeing it.

/** Its own flow, so hiding this banner never affects the dashboard prompt. */
export const CERTOPS_FLOW = 'certops';

/**
 * @param {{
 *   enabled?: boolean|null,
 *   paused?: boolean,
 *   canManage?: boolean,
 *   summary?: object|null,
 *   session?: object|null,
 * }} input
 * @returns {boolean}
 */
export function shouldShowCertopsBanner({
  enabled,
  paused,
  canManage,
  summary,
  session,
}) {
  // Unknown is not "empty": wait for each answer before speaking up.
  if (enabled !== true || !canManage || !session) return false;
  if (session.status === 'dismissed' || session.status === 'completed') {
    return false;
  }
  // The paused warning already owns this space.
  if (paused) return false;
  const certops = summary?.certops;
  if (!certops || certops === 'unknown') return false;
  const agents = certops.agents?.total;
  const certificates = certops.certificates?.total;
  if (!Number.isInteger(agents) || !Number.isInteger(certificates)) {
    return false;
  }
  const issuers = certops.adcs?.issuers;
  if (!Array.isArray(issuers)) return false;
  return agents === 0 && certificates === 0 && issuers.length === 0;
}
