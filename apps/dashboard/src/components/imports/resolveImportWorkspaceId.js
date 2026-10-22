// Order: the workspace the setup guide is configuring, then the URL so a deep
// link behaves as before, then the dashboard's active workspace.
export function resolveImportWorkspaceId({
  embeddedWorkspaceId = null,
  contextWorkspaceId = null,
  search = typeof window !== 'undefined' ? window.location.search : '',
} = {}) {
  const fromUrl = new URLSearchParams(search).get('workspace');
  const candidates = [embeddedWorkspaceId, fromUrl, contextWorkspaceId];
  const found = candidates.find(id => id != null && id !== '');
  return found == null ? null : String(found);
}
