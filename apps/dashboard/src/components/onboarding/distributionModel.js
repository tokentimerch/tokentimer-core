// Session-scoped Vault distribution facts. A group that was already verified
// before the session began never marks the Vault step done unless the operator
// ticks "My Vault distribution is already set up" and confirms with Continue.

/** A distribution group that was already in the workspace when the session began. */
export function distributionExistedBefore(item) {
  return item?.existedBeforeSession === true;
}

/**
 * The distributions a guide may use. Reusing an existing verified distribution
 * is the operator's explicit choice (`chosenId`). Without it only groups with
 * work from this session count. Summaries from an API that does not say so
 * read every group as new.
 */
export function candidateDistributions(items, chosenId) {
  const list = Array.isArray(items) ? items : [];
  if (chosenId) return list.filter(i => i.id === chosenId);
  return list.filter(i => !distributionExistedBefore(i));
}

/**
 * The distribution summary as one session sees it. An older server with no
 * `items` keeps the workspace aggregates unchanged.
 */
export function scopeDistribution(distribution, chosenId) {
  if (!distribution) return distribution;
  if (!Array.isArray(distribution.items)) return distribution;
  const items = candidateDistributions(distribution.items, chosenId);
  return {
    ...distribution,
    items,
    groups: items.length,
    verified: items.some(i => i.verified === true),
  };
}
