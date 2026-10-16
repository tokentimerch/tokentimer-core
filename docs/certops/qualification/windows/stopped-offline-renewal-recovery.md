# Installed service stop during an ACME renewal

This separate Windows Server qualification is being implemented. It is not a
passed native qualification and is not part of the existing Windows journey's
successful report merely because these supporting modules are present.

The intended fixture stops the actual installed agent while an owned public
manual renewal is held at its real DNS operation, after the signed claim and
native CNG journal exist. An owned transport barrier can hold that job's result
before forwarding it. This is a fixture transport boundary, not a production
retry or a fabricated result.

The stopped case uses the actual persisted 900-second lease and the actual
600-second offline threshold. It invokes the production reaper with its normal
clock and policy, after both observed deadlines have passed. The one-hour default
alive-agent grace stays unchanged, but this case does **not** claim that the
alive-agent grace elapsed or that a deployed worker loop invoked the reaper.
Restart follows actual terminalization; a fresh public renewal must then install
a new leaf and protected key and pass independently trusted TLS verification.
The original job remains `orphaned_unknown_effect` with operator reconciliation
required after that success. A fresh operation does not automatically recover
the original operation or resolve its possible side effects.

The initial journal and CNG key must actually exist at the held DNS boundary.
Graceful local completion can replace that journal with a durable queued
outcome before API acceptance. Such an outcome must remain independently bound
to the original job, claim and dispatch; it cannot be substituted with invented
fixture data. The source must distinguish this from an unresolved journal left
by a host timeout. Later key absence is observed independently and does not,
by itself, attribute the deletion to startup recovery.

The read-only observer pins query/synchronize handles for the identified service
host and its observed descendants before announcing readiness. It neither sends
signals nor terminates processes. The receipt is accepted only after those
handles signal exit, fresh inventory checks pass, all native handles close and
the observer's retained child process closes. New observed descendants, changed
ownership, a timeout or an incomplete receipt preserve the fixture's ownership
state and prevent certificate, key, service-root and database cleanup.

This observation is not atomic process-tree containment. A periodic inventory
cannot exclude an unobserved short-lived fork or reparenting race. Actual command
executor completion and the fixture's captured native process facts remain
separate required observations. A host timeout fallback must be reported as a
fallback; it must never be labelled graceful in-flight shutdown.

The existing mock-process Go regression exercises actual Windows SIGBREAK
delivery and delayed shutdown without installing a service. It does not qualify
SCM session 0, a full agent renewal, native CNG custody or this recovery journey.

The manual `certops-windows-stop-offline.yml` lane uses disposable hosted Windows
Server 2022 and 2025 machines with RSA-2048. It requires no Azure resources. The
separate mandatory report requires closed measured facts, original candidate/source
identities, actual LocalSystem/native Server observations and completed owned
cleanup. The ordinary ten-profile Windows journey remains separate. Native
execution is pending; pure checks validate contracts and report refusal only.

PostgreSQL setup exclusively creates a nonce-owned cluster and publishes cleanup
authority only after exact native process/listener/argument and SQL data-directory
observations. Unknown startup or changed ownership preserves the cluster. Cleanup
requests an owned graceful stop while retaining its original process handle and
keeps private files on the disposable runner; no foreign cluster is adopted.

The PostgreSQL PID receipt is checked while locked, then unlocked immediately
before the ordinary stop request so PostgreSQL can update its shutdown status
and remove that file. The original native process object stays retained through
exit. These checks confine cleanup to the exclusively owned fixture; they do not
claim an atomic machine-wide transaction against a privileged actor racing the
last path check. Actual PostgreSQL shutdown compatibility remains unexecuted.
