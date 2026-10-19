// What each provider can do, and how to describe the two ways of using it.
// "Import once" scans and brings in a chosen set a single time. "Keep in sync"
// saves a connection that rescans on a schedule. Support for the second comes
// from the deployment's capabilities, not from a list in the screen, so a
// hosted edition that adds providers needs no change here.

const ACTIVE = new Set(['ready', 'unknown']);

function capability(capabilities, id) {
  return (capabilities?.items || []).find(c => c.id === id) || null;
}

function blockerOf(cap) {
  if (!cap || ACTIVE.has(cap.state)) return null;
  return {
    code: cap.blockers?.[0]?.code || String(cap.state).toUpperCase(),
    remediation: cap.blockers?.[0]?.remediation || null,
  };
}

/**
 * @returns {{once: object, sync: object|null}} for one provider
 * `sync` is null when the deployment has no auto-sync for that provider.
 */
export function providerModes(capabilities, providerId) {
  const importCap = capability(capabilities, `integrations.${providerId}`);
  const syncCap = capability(capabilities, `autosync.${providerId}`);
  return {
    once: { available: !blockerOf(importCap), blocker: blockerOf(importCap) },
    sync: syncCap
      ? { available: !blockerOf(syncCap), blocker: blockerOf(syncCap) }
      : null,
  };
}

export const MODE_COPY = {
  once: {
    label: 'Import once',
    summary:
      'Scan, choose what to bring in, and import it a single time. Nothing is kept afterwards: no credentials are saved and nothing changes on its own.',
    needs: 'A token with read access, used for this scan only.',
  },
  sync: {
    label: 'Keep in sync',
    summary:
      'Save the connection and rescan on a schedule. New items are added, changed ones updated, and you can choose to remove items that disappeared.',
    needs:
      'A token with read access, stored encrypted so scheduled scans can run.',
  },
};

/** Which mode a provider should be offered first. */
export function defaultMode(modes) {
  if (modes.sync?.available) return 'sync';
  return 'once';
}

/**
 * Describes one auto-sync connection for display. Takes the summary item;
 * never reads credentials, which the summary does not carry.
 */
export function describeSync(item) {
  if (!item) return null;
  if (item.running) {
    return { tone: 'blue', label: 'Scanning now', detail: null };
  }
  if (!item.enabled) {
    return { tone: 'gray', label: 'Paused', detail: 'Turned off.' };
  }
  const status = item.lastStatus;
  if (!status || !item.lastSyncAt) {
    return {
      tone: 'gray',
      label: 'Waiting for the first run',
      detail: `Scheduled ${item.frequency || 'daily'}.`,
    };
  }
  if (status === 'success') {
    return {
      tone: 'green',
      label: 'Last run succeeded',
      detail: `${item.lastItems ?? 0} items seen.`,
    };
  }
  if (status === 'partial') {
    return {
      tone: 'orange',
      label: 'Last run partly succeeded',
      detail:
        'Some items could not be imported. Open the connection to see why.',
    };
  }
  return {
    tone: 'red',
    label: 'Last run failed',
    detail:
      item.failures > 1
        ? `Failed ${item.failures} times in a row.`
        : 'Check the token and its permissions.',
  };
}

/** Connections for one provider, newest first as the summary returns them. */
export function syncFor(summary, providerId) {
  return (summary?.autoSync?.items || []).filter(
    c => c.provider === providerId
  );
}

/**
 * What changed between two summaries, so the screen can say what the modal
 * actually did. Counts come from the server on both sides.
 */
export function diffImport(before, after) {
  const assets = Math.max(
    0,
    (after?.assets?.total ?? 0) - (before?.assets?.total ?? 0)
  );
  const beforeIds = new Set((before?.autoSync?.items || []).map(c => c.id));
  const newConnections = (after?.autoSync?.items || []).filter(
    c => !beforeIds.has(c.id)
  );
  const beforeById = new Map(
    (before?.autoSync?.items || []).map(c => [c.id, c])
  );
  const ranSince = (after?.autoSync?.items || []).filter(c => {
    const prev = beforeById.get(c.id);
    return prev && c.lastSyncAt && c.lastSyncAt !== prev.lastSyncAt;
  });
  return { assets, newConnections, ranSince };
}
