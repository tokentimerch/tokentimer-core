// Serialises writes to one onboarding session and survives concurrent tabs.
// The server owns the revision; on a conflict this adopts the server copy and
// replays the caller's change on top of it so no step progress is lost and
// nothing is created twice.

const MAX_CONFLICT_RETRIES = 3;

const goalOf = session => session?.intent?.goal || '';

/**
 * The server copy lost a goal this client was working on, and nobody asked
 * for that: the row still exists and carries no explicit "cleared" mark. A
 * deleted row (reset) and a deliberate clear in another tab are respected.
 */
function lostGoalByAccident(previous, incoming) {
  return (
    Boolean(goalOf(previous)) &&
    !goalOf(incoming) &&
    incoming?.exists !== false &&
    incoming?.intent?.goalCleared !== true
  );
}

// Clearing on purpose is recorded in the intent so other tabs can tell it
// from a copy that merely lacks the goal. Choosing a goal removes the mark.
function markGoalChange(intent, base) {
  if (!intent) return intent;
  // A write replaces the whole intent, so leaving the goal out would drop it.
  const full = 'goal' in intent ? intent : { ...intent, goal: goalOf(base) };
  const { goalCleared: _old, ...rest } = full;
  if (goalOf({ intent: full })) return rest;
  return goalOf(base) ? { ...rest, goalCleared: true } : full;
}

export class SessionController {
  constructor({ api, workspaceId, flow, onChange = () => {} }) {
    this.api = api;
    this.workspaceId = workspaceId;
    this.flow = flow;
    this.onChange = onChange;
    this.session = null;
    this.queue = Promise.resolve();
  }

  async load() {
    this.session = await this.api.getSession(this.workspaceId, this.flow);
    this.onChange(this.session);
    return this.session;
  }

  /**
   * `mutate(current)` returns the sections to replace
   * ({ intent, progress, operation_refs, status }). It is re-run against the
   * latest server copy after a conflict, so it must be a pure function of
   * its input.
   */
  update(mutate) {
    const run = async () => {
      if (!this.session) await this.load();
      let restore = null;
      for (let attempt = 0; ; attempt += 1) {
        const base = this.session;
        const patch = mutate(base) || {};
        if (patch.intent) {
          patch.intent = markGoalChange(patch.intent, base);
        } else if (restore) {
          // The server copy lost the goal, so a progress-only write would
          // leave it lost. Put it back with this write.
          patch.intent = restore.intent;
        }
        try {
          this.session = await this.api.putSession(
            this.workspaceId,
            this.flow,
            { ...patch, expectedRevision: this.session.revision }
          );
          this.onChange(this.session);
          return this.session;
        } catch (e) {
          if (e?.name !== 'RevisionConflictError' || !e.current) throw e;
          if (attempt >= MAX_CONFLICT_RETRIES) throw e;
          // Never let a conflict silently reset a goal the user chose.
          restore = lostGoalByAccident(base, e.current)
            ? {
                ...e.current,
                intent: { ...e.current.intent, goal: goalOf(base) },
              }
            : null;
          this.session = restore || e.current;
          // The repaired copy is not shown until the write lands, so the
          // goal picker does not flash while the change is replayed.
          if (!restore) this.onChange(this.session);
        }
      }
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => {});
    return next;
  }
}
