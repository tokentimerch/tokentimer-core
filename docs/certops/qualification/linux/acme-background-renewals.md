# Actual Linux ACME renewals from the production worker's default cron

This separate journey source runs the unmodified `apps/worker/src/runner.js certops`
CLI. It omits cron, interval, startup and one-shot overrides. The real production
default is `*/1 * * * *`; it is a minute cron schedule, not a shortened polling
interval or a direct scheduler-service invocation.

The existing owned Pebble certificate must be naturally due, with its unchanged
stored profile and active management period. Exactly one global profile and no
active certificate job are allowed before startup. Both subsequent renewals must
be created automatically by actual cron ticks, claimed and executed by the real
agent, and produce distinct actual CA serials, SPKIs and advancing expiries.
Independent protected private-file checks and trusted served TLS bind each leaf.
Claim-bound verification evidence must contain that exact fingerprint/expiry and
the production automatic-creation audit must identify the renewal scheduler.
The worker's bounded local log observer counts real cron starts, completed
maintenance summaries and graceful shutdown; it never supplies results or calls
a sweep. Raw logs, credentials and private keys are excluded from its proof.

A retained Linux controller starts in a fresh process group. Its direct child
stops before exec; the controller pins a pidfd before authorizing the production
runner to start. Actual executable, parent, session/group and `/proc` birth
identity are checked before graceful SIGTERM through that retained pidfd. Unknown descendants, a changed birth identity or missing close leave an
exclusive ownership marker, preventing parent database and private-file cleanup.
The real child must be reaped and its pidfd closed before the wrapper closes.
No PID-only kill fallback is used. Two successful automatic admissions and exact
group absence are required; direct scheduler controls remain separately labelled.

The source and pure observer/proof checks do not establish native execution.
Both supported ACME clients require their own real disposable execution. Hosted
CI, real CA actions and end-to-end native qualification remain pending.
