// What the standing "CertOps quickstart" button does. The wizard keeps all its
// progress in the shared setup guide session, not in the banner's own flow, so
// the answer comes from that session.

import { GOALS } from './modules.js';

/** The session the wizard page reads and writes. */
export const WIZARD_FLOW = 'mega';

export const QUICKSTART_PATH = '/onboarding?area=certops';

/** Keep the active workspace when opening the CertOps area of the guide. */
export function quickstartPath(workspaceId) {
  if (workspaceId == null || workspaceId === '') return QUICKSTART_PATH;
  return `${QUICKSTART_PATH}&workspace=${encodeURIComponent(workspaceId)}`;
}

/**
 * - `continue`: a certificate goal is under way; reopen it where it stopped.
 * - `restart`: the guide was finished or dismissed; start from a clean session.
 * - `switch`: another goal is under way; keep its facts but drop the goal so
 *   the certificate goals show.
 * - `start`: nothing chosen yet.
 *
 * @param {{status?: string, intent?: {goal?: string}}|null|undefined} session
 * @returns {'continue'|'restart'|'switch'|'start'}
 */
export function quickstartMode(session) {
  if (!session) return 'start';
  if (session.status === 'completed' || session.status === 'dismissed') {
    return 'restart';
  }
  const goal = session.intent?.goal;
  if (!goal) return 'start';
  return GOALS[goal]?.area === 'certops' ? 'continue' : 'switch';
}

export function quickstartLabel(session) {
  return quickstartMode(session) === 'continue'
    ? 'Continue the CertOps quickstart'
    : 'Start the CertOps quickstart';
}
