# Certificate result delivery after an agent restart

The existing Ubuntu24 certbot/noEAB journey requires a genuine successful
certificate renewal whose result cannot initially reach the API. Source and
supporting checks are implemented; native Node24, agent, CA and trusted-TLS
execution remains pending. No additional host, provider or Azure lab is used.

An owned loopback HTTP gateway preserves the original protocol requests and
signed bytes. The real command barrier pauses the current public renewal
before certbot executes, allowing an independent database read to bind its
actual current claim. Only that job/claim's terminal result receives HTTP 503;
evidence shares the same route and continues unchanged. New claim polling is
refused during the outage. Foreign result identities fail closed. No successful
API acknowledgement, evidence, signed result, client output or CA response is
manufactured.

The production agent must persist an actual succeeded outbox entry before
fixture termination. Independent observations require a genuinely changed
CA leaf, matching local private key, trusted served TLS and DNS cleanup while
the public job remains nonterminal. The current key-reuse policy is preserved;
this case does not claim a new SPKI or a job cancellation. The exact signed
nonce, claim and first attempt are independently observed.

A narrow external controller opens a Linux pidfd before independently checking
the original agent's parent, birth ticks, executable, full argv and absence of
children. Only this retained kernel descriptor can receive the explicit
restart SIGTERM. There is no numeric PID/PGID signal, tree-kill fallback or
atomic process-tree claim. The case requires native root exit, the real owning
Node ChildProcess close, controller close0, and a closed receipt before restart.
Unknown consumers, attachment failure or incomplete drainage preserve the
private root and public database ownership records.

The same configuration, credential and signing pin restart without another
bootstrap token. The unmodified production outbox retry loop uses actual time;
no retry timestamp is rewritten or fast-forwarded. Its ordinary first-send
failure and later backoff paths may legitimately produce different retry waits.
The original job must reach public success under its original claim and single
attempt, with one persisted claim-bound verification fact, no dead letter,
unchanged deployed bytes/key/trusted TLS and no additional CA order after the
restart. Original receipt identities and bytes must match before guard release.

Strict Node and Python projections accept only the bounded public facts and
cross-bind the prior bulk/adoption generations and distinct jobs. Private
state, credentials, signatures and result envelopes never enter the report.
The API gateway remains retained until parent agent/process/socket drainage;
any uncertain native ownership blocks database and private-file cleanup.

Supporting checks use offline contract fixtures, actual benign loopback HTTP
servers and an owned idle Node child in an offline, capability-free nonroot
container. They do not execute the actual agent, CA, certificate client,
services or a qualification workflow and cannot substitute for a native report.
