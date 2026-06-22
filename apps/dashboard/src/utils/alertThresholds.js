export const MIN_ALERT_THRESHOLD_DAYS = -365;
export const MAX_ALERT_THRESHOLD_DAYS = 730;
export const DEFAULT_ALERT_THRESHOLDS = [30, 14, 7, 1, 0];

function parseThresholdValues(input) {
  if (Array.isArray(input)) {
    return input
      .map(value =>
        typeof value === 'number' ? value : String(value ?? '').trim()
      )
      .filter(value => value !== '' && value !== null && value !== undefined);
  }

  if (typeof input === 'string') {
    return input
      .split(',')
      .map(part => part.trim())
      .filter(Boolean);
  }

  return [];
}

export function normalizeThresholds(input) {
  const seen = new Set();

  return parseThresholdValues(input)
    .map(value => (typeof value === 'number' ? value : Number(value)))
    .filter(
      value =>
        Number.isInteger(value) &&
        value >= MIN_ALERT_THRESHOLD_DAYS &&
        value <= MAX_ALERT_THRESHOLD_DAYS
    )
    .filter(value => {
      if (seen.has(value)) return false;
      seen.add(value);
      return true;
    })
    .sort((a, b) => b - a);
}

export function thresholdsToCsv(input) {
  return normalizeThresholds(input).join(',');
}

export function thresholdsEqual(left, right) {
  const a = normalizeThresholds(left);
  const b = normalizeThresholds(right);
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

export function groupEffectiveThresholds(groupThresholds, workspaceThresholds) {
  const workspace = normalizeThresholds(workspaceThresholds);
  const group = normalizeThresholds(groupThresholds);
  if (group.length === 0 || thresholdsEqual(group, workspace)) {
    return workspace;
  }
  return group;
}

export function groupHasThresholdOverride(
  groupThresholds,
  workspaceThresholds
) {
  const group = normalizeThresholds(groupThresholds);
  if (group.length === 0) return false;
  return !thresholdsEqual(group, workspaceThresholds);
}

export function groupThresholdsCsvForEditor(
  groupThresholds,
  workspaceThresholds
) {
  return thresholdsToCsv(
    groupEffectiveThresholds(groupThresholds, workspaceThresholds)
  );
}

export function groupThresholdsOverrideForSave(groupCsv, workspaceCsv) {
  const cur = normalizeThresholds(groupCsv);
  const def = normalizeThresholds(workspaceCsv);
  if (cur.length === 0 || thresholdsEqual(cur, def)) {
    return null;
  }
  return cur;
}

export function getThresholdDraftError() {
  return `Use a whole number from ${MIN_ALERT_THRESHOLD_DAYS} to ${MAX_ALERT_THRESHOLD_DAYS}.`;
}

export function getGroupThresholdInheritHint(groupCsv, workspaceCsv) {
  if (groupThresholdsOverrideForSave(groupCsv, workspaceCsv) !== null) {
    return 'Differs from workspace defaults. Saving stores a group override.';
  }
  return 'Matches workspace defaults. Saving without changes keeps inheritance.';
}

export function parseThresholdDraft(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return null;

  const value = Number(trimmed);
  if (!Number.isInteger(value)) return null;
  if (value < MIN_ALERT_THRESHOLD_DAYS || value > MAX_ALERT_THRESHOLD_DAYS) {
    return null;
  }
  return value;
}

export function validateAlertThresholds(input) {
  const list = normalizeThresholds(input);
  if (list.length === 0) {
    return {
      ok: false,
      list: [],
      error: `Please provide at least one valid threshold between ${MIN_ALERT_THRESHOLD_DAYS} and ${MAX_ALERT_THRESHOLD_DAYS}.`,
    };
  }

  return { ok: true, list, error: '' };
}

export function formatThresholdLabel(days) {
  if (days === 0) return 'On expiry';
  if (days < 0) {
    const abs = Math.abs(days);
    return abs === 1 ? '1 day after expiry' : `${abs} days after expiry`;
  }
  return days === 1 ? '1 day before expiry' : `${days} days before expiry`;
}

export function formatThresholdChipLabel(days) {
  if (days === 0) return 'On expiry';
  if (days < 0) return `${Math.abs(days)}d after`;
  return `${days}d before`;
}
