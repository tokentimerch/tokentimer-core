// Closes operations that were started but never recorded (for example the
// browser closed after the backend call succeeded). Runs against verified
// reality, so it only ever adopts something that really exists.

function parseIdentity(pending) {
  try {
    return JSON.parse(pending.identityKey);
  } catch (_) {
    return null;
  }
}

/**
 * @returns {object|null} a SessionController.update() patch, or null when
 *   there is nothing to reconcile.
 */
export function reconcilePending({ session, summary }) {
  const pending = session?.progress?.pending;
  if (!pending || !summary) return null;
  const identity = parseIdentity(pending);
  const clear = () => {
    const { pending: _drop, ...rest } = session.progress || {};
    return rest;
  };

  if (pending.kind === 'monitor' && identity?.url) {
    const monitor = (summary.monitors?.items || []).find(
      m => m.url?.toLowerCase() === identity.url.toLowerCase()
    );
    if (!monitor) return null;
    const refs = session.operationRefs || {};
    return {
      progress: clear(),
      operation_refs: {
        ...refs,
        monitorUrl: identity.url,
        monitorIds: Array.from(
          new Set([...(refs.monitorIds || []), monitor.id].filter(Boolean))
        ),
        tokenIds: Array.from(
          new Set([...(refs.tokenIds || []), monitor.tokenId].filter(Boolean))
        ),
      },
    };
  }

  if (pending.kind === 'contact_group') {
    if (!summary.alerts?.contactGroups?.defaultHasEmailRecipient) return null;
    return {
      progress: clear(),
      operation_refs: {
        ...(session.operationRefs || {}),
        ...(identity?.groupId ? { contactGroupId: identity.groupId } : {}),
      },
    };
  }

  // Assets cannot be verified from the summary alone; the asset step
  // reconciles by identity when the user submits it again.
  return null;
}
