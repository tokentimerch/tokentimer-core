import { useCallback, useEffect, useState } from 'react';

/**
 * Persist a small UI preference in localStorage (no backend).
 *
 * These are intentionally client-only for now; server-side persistence can be
 * layered on later without changing call sites.
 *
 * @template T
 * @param {string} key localStorage key (prefer the `tt_pref_*` convention)
 * @param {T} defaultValue value used when nothing is stored / storage fails
 * @returns {[T, (next: T | ((prev: T) => T)) => void]}
 */
export function useLocalPreference(key, defaultValue) {
  const [value, setValue] = useState(() => {
    try {
      const raw = window.localStorage.getItem(key);
      if (raw == null) return defaultValue;
      return JSON.parse(raw);
    } catch (_) {
      return defaultValue;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (_) {}
  }, [key, value]);

  // Keep multiple tabs / components in sync.
  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const handleStorage = event => {
      if (event.key !== key) return;
      try {
        setValue(
          event.newValue == null ? defaultValue : JSON.parse(event.newValue)
        );
      } catch (_) {
        setValue(defaultValue);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [key, defaultValue]);

  const update = useCallback(next => {
    setValue(prev => (typeof next === 'function' ? next(prev) : next));
  }, []);

  return [value, update];
}
