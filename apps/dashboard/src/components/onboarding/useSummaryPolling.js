import { useEffect } from 'react';
import { CHECK_STATUS } from './verification.js';

export const SUMMARY_POLL_MS = 15000;
// Steps that wait for something to show up (a certificate, an attachment).
export const WAIT_POLL_MS = 10000;

/**
 * Re-reads the onboarding summary on an interval while `active` is true and
 * stops on unmount or when it turns false. A hidden tab skips its turn and
 * reads once as soon as it is visible again.
 */
export function useSummaryPolling(
  refresh,
  active,
  intervalMs = SUMMARY_POLL_MS
) {
  useEffect(() => {
    if (!active || typeof refresh !== 'function') return undefined;
    const hidden = () => typeof document !== 'undefined' && document.hidden;
    const read = () => {
      Promise.resolve(refresh()).catch(() => {});
    };
    const timer = setInterval(() => {
      if (!hidden()) read();
    }, intervalMs);
    const onVisible = () => {
      if (!hidden()) read();
    };
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisible);
    }
    return () => {
      clearInterval(timer);
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisible);
      }
    };
  }, [active, refresh, intervalMs]);
}

/**
 * A Vault rollout moves on the server without any click here: keep reading
 * while a worker warning is showing, a publish job is still moving, or a
 * group exists that no rollout has verified yet.
 */
export function vaultNeedsPolling({
  backlogMessage,
  distribution,
  publishActive,
}) {
  if (backlogMessage || publishActive) return true;
  return (distribution?.groups || 0) > 0 && distribution?.verified !== true;
}

/**
 * The final check is read once on mount. It keeps re-reading while it shows
 * a worker warning or an unverified distribution, since both clear without
 * any action on this page.
 */
export function verifyNeedsPolling(result) {
  return (result?.checks || []).some(
    c =>
      c.id === 'worker' ||
      (c.id === 'distribution' && c.status === CHECK_STATUS.WARN) ||
      // A website the server has not read yet is rechecked on its side.
      (c.status === CHECK_STATUS.WARN && String(c.id).startsWith('certificate'))
  );
}
