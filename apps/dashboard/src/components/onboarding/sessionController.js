// Serialises writes to one onboarding session and survives concurrent tabs.
// The server owns the revision; on a conflict this adopts the server copy and
// replays the caller's change on top of it so no step progress is lost and
// nothing is created twice.

const MAX_CONFLICT_RETRIES = 3;

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
      for (let attempt = 0; ; attempt += 1) {
        const patch = mutate(this.session) || {};
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
          this.session = e.current;
          this.onChange(this.session);
        }
      }
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => {});
    return next;
  }
}
