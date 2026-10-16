# Production interval worker and native AD CS renewals

The full disposable domain qualification starts the unmodified worker CLI,
`node apps/worker/src/runner.js certops`, after the existing native renewal
controls and before later pending enrollments. The supported interval selector
uses the production default of 60 seconds and no startup run. No clock,
worker definition, maintenance service or renewal dispatcher is replaced.

The fixture refuses additional global profiles, active jobs or scheduled
continuations. Both renewals must be created by actual interval ticks against
the naturally due six-day certificate and unchanged stored profile. It verifies
independent CA requests, fresh protected machine keys, journal and claim-bound
verification evidence, native IIS/HTTP.sys cutovers and trusted SNI TLS. Existing
job rows must remain unchanged and exactly two new jobs may appear.

An allowlisted environment supplies only required database/signing/runtime
settings. The candidate root `.env` must be absent. Raw worker logs, officer
credentials and environment values are never persisted. The controller retains
only bounded lifecycle counts; malformed or failing output prevents qualification.

A test-only preload forwards one nonce-bound IPC request to the actual production
SIGTERM handler. This demonstrates graceful requested shutdown and timer/pool
drainage; it does not qualify delivery of a native operating-system signal.
The controller starts suspended inside a retained Windows Job Object before it
can launch the worker. Failure cleanup uses that exact retained handle and requires
an empty job plus exact process absence. It never kills a numeric PID.

A separate primary-store receipt is registered before the worker can admit a
job. New enrollment IDs are recorded as soon as they are observed. Unknown
acceptance or incomplete worker/native cleanup preserves journals, keys and the
owned root. Public certificates are removed only with exact durable ownership,
before exact key cleanup. This is separate from elapsed certificate-retention
qualification and from the supporting directly invoked scheduler controls.

Pure proof/environment regressions and PowerShell parsing can run locally. The
actual worker, installed service, CA, CNG, IIS and TLS journey remains pending
execution in the protected disposable Windows domain lane.
