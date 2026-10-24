// When to invite someone to the setup guide. Deliberately conservative: it
// only speaks up for a workspace with nothing in it, and never for someone who
// asked to stop seeing it.

/**
 * What to show, if anything: the one-time `modal`, a quiet `banner` that stays
 * on the dashboard, or nothing. Closing the modal by accident must not remove
 * the way back, so the banner takes over once the modal has been offered.
 *
 * @param {{session?: object, summary?: object, isViewer?: boolean, modalShown?: boolean}} input
 * @returns {'modal'|'banner'|null}
 */
export function inviteKind({ session, summary, isViewer, modalShown = false }) {
  if (isViewer || !session || !summary) return null;
  if (session.status === 'dismissed' || session.status === 'completed') {
    return null;
  }
  const assets = summary.assets?.total;
  const monitors = summary.monitors?.total;
  // Unknown counts must not read as "empty".
  if (!Number.isInteger(assets) || !Number.isInteger(monitors)) return null;
  if (assets !== 0 || monitors !== 0) return null;
  // Someone who already picked a goal knows the guide, but may have left it.
  if (session.intent?.goal) return 'banner';
  return modalShown ? 'banner' : 'modal';
}

/** True when the one-time modal should open. */
export function shouldNudge(input) {
  return inviteKind({ ...input, modalShown: false }) === 'modal';
}

const checkedKey = workspaceId => `tt_setup_nudge_checked:${workspaceId}`;
const modalKey = workspaceId => `tt_setup_nudge_modal:${workspaceId}`;

function read(key, storage) {
  try {
    return storage?.getItem(key) === '1';
  } catch (_) {
    return false;
  }
}

function write(key, storage) {
  try {
    storage?.setItem(key, '1');
  } catch (_) {
    /* private mode: the check simply runs again */
  }
}

/** True once there was nothing to show in this browser session, so it costs one request. */
export function wasChecked(workspaceId, storage = globalThis.sessionStorage) {
  return read(checkedKey(workspaceId), storage);
}

export function markChecked(workspaceId, storage = globalThis.sessionStorage) {
  write(checkedKey(workspaceId), storage);
}

/** True once the modal was offered in this browser session. */
export function wasModalShown(
  workspaceId,
  storage = globalThis.sessionStorage
) {
  return read(modalKey(workspaceId), storage);
}

export function markModalShown(
  workspaceId,
  storage = globalThis.sessionStorage
) {
  write(modalKey(workspaceId), storage);
}
