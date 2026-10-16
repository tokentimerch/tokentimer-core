# Public retirement of an idle installed Windows agent

The existing production API exposes agent retirement, not a generic certificate-job cancellation endpoint. This source exercises the real public retirement route for the already installed healthy LocalSystem agent with no actively leased jobs. It does not force-retire in-flight work or claim cancellation of a CA request.

An anonymous request must return 401; the owned viewer actor must receive the specific role refusal. The same actor restored to workspace manager must publicly retire the exact registered agent. PostgreSQL must show the same actor attribution, one append-only retirement audit, `force=false` and zero leased jobs. A repeated public request must preserve the terminal row without a second audit.

The source then requires a new native host log retirement86 message, clean SCM exit0, original host/Node absence and a real monotonic observation window of at least five seconds without respawn. Original protected CNG custody, HTTP.sys binding, trusted served TLS, local configuration/credential/pin and certificate job claims must remain unchanged. This is a bounded idle-control observation, not an atomic process-tree containment guarantee or all recovery-policy timing qualification.

A sticky original-file ownership receipt precedes public mutation. Any unresolved request/native outcome preserves that guard and blocks parent cleanup. Temporary role changes affect only the owned fixture actor and are restored independently. Source, parent lifecycle and mandatory bounded report checks are wired for all five Windows key profiles on both Server versions. Supporting offline controls pass; native Windows execution remains pending.
