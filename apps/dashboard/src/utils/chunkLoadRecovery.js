const RECOVERY_KEY = 'tokentimer:chunk-recovery';
const RECOVERY_WINDOW_MS = 60_000;

// Match browser/Vite loader failures, not generic network or application errors.
export function isChunkLoadError(error) {
  const message = error?.message;
  if (typeof message !== 'string') return false;
  return (
    /^Failed to fetch dynamically imported module(?::|$)/i.test(message) ||
    /^error loading dynamically imported module(?::|$)/i.test(message) ||
    /^Importing a module script failed\.?$/i.test(message) ||
    /^Unable to preload CSS for /i.test(message)
  );
}

export function hasRecentChunkRecovery() {
  try {
    const timestamp = Number(window.sessionStorage.getItem(RECOVERY_KEY));
    const age = Date.now() - timestamp;
    return timestamp > 0 && age >= 0 && age < RECOVERY_WINDOW_MS;
  } catch {
    return false;
  }
}

export function refreshAfterChunkFailure() {
  try {
    window.sessionStorage.setItem(RECOVERY_KEY, String(Date.now()));
  } catch {
    // Recovery is always user initiated, so unavailable storage cannot loop.
  }
  window.location.reload();
}
