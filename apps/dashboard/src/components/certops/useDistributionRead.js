import { useCallback, useEffect, useRef, useState } from 'react';

export const DISTRIBUTION_POLL_MS = 30_000;

/** One in-flight read per scope. Keep the last successful snapshot during revalidation. */
export default function useDistributionRead(scope, read, { poll = true } = {}) {
  const [state, setState] = useState({ scope: null, data: null });
  const [now, setNow] = useState(Date.now);
  const requestRef = useRef(null);
  const refresh = useCallback(() => requestRef.current?.(), []);

  useEffect(() => {
    if (!scope) return undefined;
    let active = true;
    let inFlight;
    let timer;
    let lastReadAt = 0;
    const controller = new AbortController();
    const load = () => {
      if (!active || inFlight) return inFlight;
      clearTimeout(timer);
      const startedAt = Date.now();
      lastReadAt = startedAt;
      setState(previous => ({
        ...(previous.scope === scope ? previous : { scope, data: null }),
        refreshing: true,
      }));
      inFlight = Promise.resolve()
        .then(() => (active ? read(controller.signal, startedAt) : null))
        .then(data => {
          if (active) {
            setState({ scope, data, refreshing: false, error: '' });
            setNow(Date.now());
          }
        })
        .catch(error => {
          if (active)
            setState(previous => ({
              ...previous,
              // Cached metadata is not an authorization grant after access is revoked.
              data: [401, 403, 404].includes(error?.response?.status)
                ? null
                : previous.data,
              refreshing: false,
              error: 'Deployment status unavailable',
            }));
        })
        .finally(() => {
          inFlight = null;
          if (active && poll)
            timer = setTimeout(() => {
              if (document.visibilityState !== 'hidden') load();
            }, DISTRIBUTION_POLL_MS);
        });
      return inFlight;
    };
    const onVisible = () => {
      setNow(Date.now());
      if (
        document.visibilityState !== 'hidden' &&
        Date.now() - lastReadAt >= DISTRIBUTION_POLL_MS
      )
        load();
    };
    requestRef.current = load;
    load();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
      requestRef.current = null;
    };
  }, [scope, read, poll]);

  // Wake only at an evidence deadline, not once per second for every inventory row.
  const current = Boolean(scope) && state.scope === scope;
  useEffect(() => {
    if (!current || !state.data) return undefined;
    const upcoming = state.data.deadlines?.filter(time => time > now) || [];
    if (!upcoming.length) return undefined;
    const next = Math.min(...upcoming);
    const timer = setTimeout(
      () => setNow(Date.now()),
      Math.min(2_147_483_647, Math.max(0, next - Date.now()))
    );
    return () => clearTimeout(timer);
  }, [current, state.data, now]);
  return {
    data: current ? state.data : null,
    loading:
      Boolean(scope) &&
      (!current || (!state.data && state.refreshing !== false)),
    refreshing: current && Boolean(state.refreshing),
    error: current ? state.error || '' : '',
    now,
    refresh,
  };
}

// Anchor server deadlines at request start, conservatively accounting for latency and clock skew.
export function serverClockOffset(data, startedAt) {
  const evaluatedAt = Date.parse(data?.evaluated_at);
  return Number.isFinite(evaluatedAt) ? startedAt - evaluatedAt : 0;
}
