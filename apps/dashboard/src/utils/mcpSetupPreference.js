// A short-lived form preference, never a credential or an authorization grant.
const KEY = 'tokentimer.mcpSetupPreference';
const LIFETIME_MS = 10 * 60 * 1000;

export function rememberMcpSetupPreference(input) {
  if (!input.userId || !input.workspaceId) return;
  try {
    localStorage.setItem(
      KEY,
      JSON.stringify({ ...input, expiresAt: Date.now() + LIFETIME_MS })
    );
  } catch {
    // Sign-in still works when browser storage is unavailable.
  }
}

export function takeMcpSetupPreference(userId, workspaces) {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (String(value.userId) !== String(userId)) return null;
    localStorage.removeItem(KEY);
    const workspace = workspaces.find(item => item.id === value.workspaceId);
    if (
      !workspace ||
      !Number.isFinite(value.expiresAt) ||
      value.expiresAt <= Date.now() ||
      value.expiresAt > Date.now() + LIFETIME_MS ||
      (value.noExpiry === true
        ? value.lifetimeDays !== null
        : ![1, 7, 30, 90, 180, 365].includes(value.lifetimeDays))
    )
      return null;
    const canRequest = workspace.canRequestRenewals === true;
    return {
      workspaceId: workspace.id,
      renewals: canRequest && value.renewals === true,
      agentHealth:
        canRequest && (value.agentHealth === true || value.renewals === true),
      inventoryImport: canRequest && value.inventoryImport === true,
      inventoryUpdate: canRequest && value.inventoryUpdate === true,
      contactCreate: canRequest && value.contactCreate === true,
      webhookCreate: canRequest && value.webhookCreate === true,
      groupCreate: canRequest && value.groupCreate === true,
      memberInvite: canRequest && value.memberInvite === true,
      issuance: canRequest && value.issuance === true,
      lifetimeDays: value.lifetimeDays,
      noExpiry: value.noExpiry === true,
    };
  } catch {
    return null;
  }
}
