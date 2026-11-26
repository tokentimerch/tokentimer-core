import { useSyncExternalStore } from 'react';

export const TIMELINE_ORDER_KEY = 'tt_certops_timeline_order';
export const OLDEST_FIRST = 'oldest-first';
export const NEWEST_FIRST = 'newest-first';

let sessionOrder;

export function readTimelineOrder() {
  if (sessionOrder) return sessionOrder;
  try {
    if (window.localStorage.getItem(TIMELINE_ORDER_KEY) === NEWEST_FIRST) {
      return NEWEST_FIRST;
    }
  } catch {
    // Storage can be unavailable in private or restricted browsing.
  }
  return OLDEST_FIRST;
}

export function subscribeToTimelineOrder(notify) {
  const onStorage = event => {
    if (event.key === TIMELINE_ORDER_KEY || event.key === null) notify();
  };
  window.addEventListener('storage', onStorage);
  window.addEventListener(TIMELINE_ORDER_KEY, notify);
  return () => {
    window.removeEventListener('storage', onStorage);
    window.removeEventListener(TIMELINE_ORDER_KEY, notify);
  };
}

export function setTimelineOrder(order) {
  try {
    if (order === NEWEST_FIRST) {
      window.localStorage.setItem(TIMELINE_ORDER_KEY, order);
    } else {
      window.localStorage.removeItem(TIMELINE_ORDER_KEY);
    }
    sessionOrder = undefined;
  } catch {
    sessionOrder = order;
  }
  window.dispatchEvent(new Event(TIMELINE_ORDER_KEY));
}

export function useTimelineOrder() {
  return useSyncExternalStore(
    subscribeToTimelineOrder,
    readTimelineOrder,
    () => OLDEST_FIRST
  );
}
