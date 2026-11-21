import {
  createContext,
  useContext,
  useLayoutEffect,
  useMemo,
  useSyncExternalStore,
} from 'react';

const AttemptsContext = createContext(null);
const emptySubscribe = () => () => {};

function createAttempts(accountId) {
  const attempts = new Map();
  const listeners = new Set();
  const hasStatus = status => {
    for (const attempt of attempts.values()) {
      if (attempt.status === status) return true;
    }
    return false;
  };
  const hasUnresolved = () => hasStatus('pending') || hasStatus('unknown');
  return {
    accountId,
    get: workspaceId => attempts.get(workspaceId),
    set(workspaceId, attempt) {
      if (attempt) attempts.set(workspaceId, attempt);
      else attempts.delete(workspaceId);
      listeners.forEach(listener => listener());
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    hasUnresolved,
    confirmSignOut() {
      return (
        !hasUnresolved() ||
        window.confirm(
          'An AD CS request may already have reached the server. Signing out clears the retry details in this tab. Check job history before submitting another request. Sign out?'
        )
      );
    },
    cancelInFlight() {
      for (const attempt of attempts.values()) attempt.controller?.abort();
    },
  };
}

export function useAdcsStoreIssueAttemptStore(accountId) {
  return useMemo(() => createAttempts(accountId), [accountId]);
}

export function AdcsStoreIssueAttemptsProvider({ attempts, children }) {
  const hasUnresolved = useSyncExternalStore(
    attempts.subscribe,
    attempts.hasUnresolved
  );
  useLayoutEffect(() => () => attempts.cancelInFlight(), [attempts]);
  useLayoutEffect(() => {
    if (!hasUnresolved) return undefined;
    const warn = event => {
      event.preventDefault();
      event.returnValue = true;
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [hasUnresolved]);
  return (
    <AttemptsContext.Provider value={attempts}>
      {children}
    </AttemptsContext.Provider>
  );
}

export function useAdcsStoreIssueAttempts(workspaceId) {
  const attempts = useContext(AttemptsContext);
  const attempt = useSyncExternalStore(
    attempts?.subscribe ?? emptySubscribe,
    () => attempts?.get(workspaceId)
  );
  return { attempts, attempt };
}
