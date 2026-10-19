// Back/forward navigation over a derived journey. The planner decides which
// step is current from server state; this only decides which step is shown.
// A step the user has not reached yet is never reachable, and a reviewed step
// never changes what is recorded as done.

/**
 * @param {{steps: Array<{id: string, status: string}>, currentStepId: string, complete: boolean}} plan
 * @param {string|null} viewStepId step the user asked to look at, if any
 */
export function resolveNavigation(plan, viewStepId) {
  const steps = plan?.steps || [];
  const ids = steps.map(s => s.id);
  const currentId = plan?.complete ? null : plan?.currentStepId || null;
  const reachable = new Set(
    steps.filter(s => s.status !== 'upcoming').map(s => s.id)
  );
  const viewing =
    viewStepId && reachable.has(viewStepId) && viewStepId !== currentId
      ? viewStepId
      : null;
  const shownId = viewing || currentId;
  // A finished journey sits after its last step.
  const index = shownId ? ids.indexOf(shownId) : ids.length;
  const previousId = index > 0 ? ids[index - 1] : null;
  let nextId = null;
  if (viewing) {
    const candidate = ids[index + 1];
    nextId =
      candidate && reachable.has(candidate) && candidate !== currentId
        ? candidate
        : null;
  }
  return { viewing, shownId, previousId, nextId, returnId: currentId };
}
