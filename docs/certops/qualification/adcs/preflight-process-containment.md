# Native preflight process containment

The protected disposable AD CS lab runs isolated candidate CLI processes for
additional genuine preflight checks. Each process starts suspended inside a
retained Windows Job Object. The parent independently checks the native root
identity and SYSTEM SID before allowing the original candidate CLI to execute.
Bootstrap credentials pass only through the private inherited environment.

The shared test-only contained-process driver also supports owned temporary
supporting processes. Such checks establish process mechanics only; they do not
qualify AD CS, certificate operations, installed services, or Windows Server.

Closing a cohort requires measured zero active job members, the original root's
native exit, closure of retained native and protocol handles, and the actual
wrapper process close. Unknown drainage preserves the cohort workspace and
protected state. Numeric PID process-tree termination is not a cleanup fallback.
The private protocol directory contains launch arguments and local ownership
receipts; it must never be uploaded as an artifact.

The original per-workspace dispatch budget remains 18 actual preflight requests.
A real monotonic launch age of 45 minutes also rolls an idle cohort before its
one-hour containment deadline. Rule changes drain the prior native job before rewriting the isolated config and
launching the next candidate process. Full native qualification remains pending
execution in the protected disposable forest.
