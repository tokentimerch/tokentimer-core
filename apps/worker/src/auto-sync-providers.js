/**
 * Core auto-sync provider allowlist.
 *
 * Hardcoded to github/gitlab. Enterprise replaces this file via
 * src/worker/auto-sync-providers.js in tokentimer-enterprise.
 */

export const CORE_AUTO_SYNC_PROVIDERS = ["github", "gitlab"];

export function isAutoSyncProviderAllowed(provider) {
  return CORE_AUTO_SYNC_PROVIDERS.includes(provider);
}
