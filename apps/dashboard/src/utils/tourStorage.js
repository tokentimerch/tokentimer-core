// Single source of truth for product tour storage keys. ProductTour always
// used `tt_tour_<type>`, while the welcome skip and "Restart tour" used a
// `_v1` suffix, so neither actually affected the tour. The legacy key is
// still cleared so old browsers do not keep a dead flag.

const LEGACY_DASHBOARD_TOUR_KEY = 'tt_tour_dashboard_v1';

export function tourCompletedKey(tourType = 'dashboard') {
  return `tt_tour_${tourType}`;
}

function storage() {
  try {
    return typeof window !== 'undefined' ? window.localStorage : null;
  } catch (_) {
    return null;
  }
}

export function isTourCompleted(tourType = 'dashboard') {
  const store = storage();
  if (!store) return false;
  try {
    return store.getItem(tourCompletedKey(tourType)) === 'true';
  } catch (_) {
    return false;
  }
}

export function markTourCompleted(tourType = 'dashboard') {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(tourCompletedKey(tourType), 'true');
  } catch (_) {}
}

export function resetTourCompleted(tourType = 'dashboard') {
  const store = storage();
  if (!store) return;
  try {
    store.removeItem(tourCompletedKey(tourType));
    if (tourType === 'dashboard') store.removeItem(LEGACY_DASHBOARD_TOUR_KEY);
  } catch (_) {}
}
