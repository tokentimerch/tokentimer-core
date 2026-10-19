// When to invite someone to the setup guide. Deliberately conservative: it
// only speaks up for a workspace with nothing in it, once, for someone who has
// not started the guide and has not asked to stop seeing it.

/**
 * @param {{session?: object, summary?: object, isViewer?: boolean}} input
 */
export function shouldNudge({ session, summary, isViewer }) {
  if (isViewer || !session || !summary) return false;
  if (session.status === 'dismissed' || session.status === 'completed') {
    return false;
  }
  // Someone who already picked a goal knows where the guide is.
  if (session.intent?.goal) return false;
  const assets = summary.assets?.total;
  const monitors = summary.monitors?.total;
  // Unknown counts must not read as "empty".
  if (!Number.isInteger(assets) || !Number.isInteger(monitors)) return false;
  return assets === 0 && monitors === 0;
}

const seenKey = workspaceId => `tt_setup_nudge_checked:${workspaceId}`;

/** True once the check ran in this browser session, so it costs one request. */
export function wasChecked(workspaceId, storage = globalThis.sessionStorage) {
  try {
    return storage?.getItem(seenKey(workspaceId)) === '1';
  } catch (_) {
    return false;
  }
}

export function markChecked(workspaceId, storage = globalThis.sessionStorage) {
  try {
    storage?.setItem(seenKey(workspaceId), '1');
  } catch (_) {
    /* private mode: the check simply runs again */
  }
}
