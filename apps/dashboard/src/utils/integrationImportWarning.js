const CLEANUP_MESSAGES = new Map([
  ['partial', 'Cleanup ran only for complete scan scopes.'],
  ['skipped_import_errors', 'Obsolete-item cleanup was skipped.'],
  [
    'skipped_incomplete',
    'Cleanup was skipped because no scan scope was complete.',
  ],
  [
    'skipped_unavailable',
    'Cleanup was skipped because the scan is unavailable. Run a new scan before retrying.',
  ],
  ['failed', 'Cleanup failed. Run a new scan before retrying.'],
]);

export function integrationImportWarning(result, cleanupRequested = false) {
  const failed = result?.error_count ?? 0;
  const status =
    result?.cleanup_status ??
    (failed > 0 && cleanupRequested ? 'skipped_import_errors' : undefined);
  const cleanup = CLEANUP_MESSAGES.get(status);
  if (!failed && !cleanup) return null;

  const details = [
    `Created ${result.created_count ?? 0}. Updated ${result.updated_count ?? 0}.`,
  ];
  if (result.deleted_count > 0)
    details.push(`Removed ${result.deleted_count}.`);
  const first = result.errors?.[0];
  if (typeof first?.error === 'string') {
    const item = typeof first.item === 'string' ? first.item.slice(0, 80) : '';
    details.push([item, first.error.slice(0, 180)].filter(Boolean).join(' · '));
  }
  if (cleanup) details.push(cleanup);
  return {
    title: failed
      ? `${failed} item${failed === 1 ? '' : 's'} failed to import`
      : 'Obsolete-item cleanup needs attention',
    description: details.join(' '),
  };
}
