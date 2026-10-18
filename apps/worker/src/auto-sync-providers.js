/**
 * Core auto-sync provider allowlist.
 *
 * Core supports github/gitlab. A downstream composition may replace this
 * module to extend its provider allowlist.
 */

export const CORE_AUTO_SYNC_PROVIDERS = ["github", "gitlab"];

export function isAutoSyncProviderAllowed(provider) {
  return CORE_AUTO_SYNC_PROVIDERS.includes(provider);
}
