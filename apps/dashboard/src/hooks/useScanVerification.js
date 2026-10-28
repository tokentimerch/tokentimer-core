import React from 'react';

// Approval belongs to one completed attempt for one exact scan context.
// Identities can contain credentials: keep them in refs, never in logs or storage.
export function useScanVerification({
  identity,
  provider,
  onScanSuccess,
  onScanInvalidated,
}) {
  const serialized = JSON.stringify(identity);
  const current = React.useRef({
    identity: serialized,
    attempt: 0,
    mounted: true,
  });
  const callbacks = React.useRef({ onScanSuccess, onScanInvalidated });
  React.useLayoutEffect(() => {
    callbacks.current = { onScanSuccess, onScanInvalidated };
    if (current.current.identity !== serialized) {
      current.current.identity = serialized;
      current.current.attempt += 1;
      callbacks.current.onScanInvalidated?.();
    }
  });
  React.useLayoutEffect(() => {
    const state = current.current;
    state.mounted = true;
    return () => {
      state.mounted = false;
      state.attempt += 1;
    };
  }, []);
  const beginScanVerification = () => {
    current.current.attempt += 1;
    callbacks.current.onScanInvalidated?.();
    return {
      identity: current.current.identity,
      attempt: current.current.attempt,
    };
  };
  const completeScanVerification = ticket => {
    if (
      current.current.mounted &&
      ticket.identity === current.current.identity &&
      ticket.attempt === current.current.attempt
    ) {
      callbacks.current.onScanSuccess?.(provider);
    }
  };
  return { beginScanVerification, completeScanVerification };
}
