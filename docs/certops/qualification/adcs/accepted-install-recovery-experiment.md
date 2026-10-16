# Accepted certificate before IIS cutover

The optional `accepted-before-bind` journal-phase experiment observes the supported
recovery boundary after real `certreq -accept` and before IIS switches certificates.
It remains explicitly **experimental / not qualified**, excluded from release cells.
Source implementation and synthetic proof controls do not demonstrate native execution.

The independent PowerShell observer accepts only the run-owned SYSTEM SCM host,
agent process, protected configuration and frozen enrollment receipt. It observes
the real durable `installing / bind` journal, stops only the verified service tree,
and requires every captured native child to disappear. The complete tree is captured
and checked before termination; a later unexpected descendant causes preservation
and failure rather than adoption through a potentially reused parent PID. It then independently checks the exact
accepted leaf in LocalMachine/My, its RSA machine CNG container, Software KSP,
nonexportability and key size, and the unchanged outgoing IIS SNI binding. A missed
window, already-completed cutover, changed journal or unproven process drain fails.
No journal, database date, CSR, CA result or production callback is fabricated.

The fixture also checks old independently trusted TLS and HTTP.sys binding state.
It waits actual persisted lease expiry plus the fixed worker grace, with a reviewed
fifteen-minute upper bound derived from the database's real measurement. Public
acknowledged recovery must preserve RequestId, leaf, CSR, public key and container,
finish native IIS/TLS installation, retain the original unknown-effect job, create
the recovery audit, and leave the actual CA request count unchanged. Acceptance
receipt identity remains the same; its normal acceptance timestamp may advance.

The parent owns enrollment, certificate and site cleanup. An observer failure keeps
its native-drain guard active even after the observer exits, preventing parent
native cleanup from treating an unproven process tree as absent. No automatic SCM
recovery configuration is changed. The observer must drain before its exact receipt
can be removed or a stopped owned service can be restarted.

This phase uses the existing manual disposable-forest experiment lane and bounded
experimental report verifier. A successful observed run still does not qualify
other journal windows, arbitrary crash timing, worker timer intervals or a 24-hour
qualification run. Full native execution remains pending.
