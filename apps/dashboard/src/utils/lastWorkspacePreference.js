export const LAST_WORKSPACE_LEGACY_KEY = 'tt_last_workspace_id';
export const LAST_WORKSPACE_ACCOUNT_PREFIX = 'tt_last_workspace:';
export const LAST_WORKSPACE_OWNER_KEY = 'tt_last_workspace_account';

export function accountLastWorkspaceKey(accountId) {
  return `${LAST_WORKSPACE_ACCOUNT_PREFIX}${accountId}`;
}

export function isWorkspaceAccessible(workspace) {
  if (!workspace || workspace.id == null || workspace.id === '') {
    return false;
  }
  return workspace.is_frozen !== true;
}

export function pickAccessibleWorkspace({
  urlWorkspaceId = null,
  lastWorkspaceId = null,
  workspaces = [],
} = {}) {
  const accessible = workspaces.filter(isWorkspaceAccessible);
  const ids = new Set(accessible.map(workspace => String(workspace.id)));
  const url =
    urlWorkspaceId != null && urlWorkspaceId !== ''
      ? String(urlWorkspaceId)
      : '';
  const last =
    lastWorkspaceId != null && lastWorkspaceId !== ''
      ? String(lastWorkspaceId)
      : '';

  if (url && ids.has(url)) return url;
  if (last && ids.has(last)) return last;
  const first = accessible[0];
  return first && first.id != null ? String(first.id) : null;
}

export function readLastWorkspaceId(accountId) {
  if (accountId == null || accountId === '') return null;
  try {
    const scoped = localStorage.getItem(accountLastWorkspaceKey(accountId));
    if (scoped) return scoped;

    const legacy = localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY);
    if (!legacy) return null;

    const owner = localStorage.getItem(LAST_WORKSPACE_OWNER_KEY);
    if (owner == null || owner === '') {
      localStorage.setItem(accountLastWorkspaceKey(accountId), legacy);
      localStorage.setItem(LAST_WORKSPACE_OWNER_KEY, String(accountId));
      return legacy;
    }
    if (String(owner) === String(accountId)) return legacy;
    return null;
  } catch (_) {
    return null;
  }
}

export function writeLastWorkspaceId(accountId, workspaceId) {
  if (workspaceId == null || workspaceId === '') return;
  const value = String(workspaceId);
  try {
    if (accountId != null && accountId !== '') {
      localStorage.setItem(accountLastWorkspaceKey(accountId), value);
      localStorage.setItem(LAST_WORKSPACE_OWNER_KEY, String(accountId));
    }
    localStorage.setItem(LAST_WORKSPACE_LEGACY_KEY, value);
  } catch (_) {}
}

export function readSessionLastWorkspaceId() {
  try {
    return localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY);
  } catch (_) {
    return null;
  }
}

export function clearSessionLastWorkspaceId() {
  try {
    localStorage.removeItem(LAST_WORKSPACE_LEGACY_KEY);
    localStorage.removeItem(LAST_WORKSPACE_OWNER_KEY);
  } catch (_) {}
}

export function dashboardHrefAfterLogin({ firstLogin = false } = {}) {
  return firstLogin ? '/dashboard?first_login=true' : '/dashboard';
}
