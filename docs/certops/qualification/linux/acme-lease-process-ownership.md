# ACME lease-loss process ownership

The native ACME journey already holds a genuine production-launched command
before its ACME client starts, then retires the owning agent through the public
API. The production lease-abort path must terminate that command while the arm
remains present. Certificate/key bytes, trusted serving TLS and owned DNS state
must remain unchanged.

The native journey's retained-process adapter pins
the existing blocked command with a Linux pidfd, then independently checks its
birth, parent, process group, Node executable, exact wrapper arguments and
original arm/receipt file identities. It never replaces the production launch.
The initial group must contain only the blocked root. Emergency cleanup signals
only the retained root descriptor; it never signals a numeric PID or PGID.

A successful natural-exit receipt requires the native process descriptor to
become readable, the group to become empty, the original public ownership files
to remain unchanged and the controller to close with code zero. The adapter
separately records emergency signaling: that result cannot qualify genuine
production lease cancellation. Unknown descendants, failed attachment, missing
receipts or unconfirmed controller closure preserve the ownership guard.
This is not an atomic process-tree containment claim.

Three pure protocol checks reject missing/false observations, identity splicing,
extra fields and nonboolean signal facts. A separate actual benign supporting
control ran the real barrier and pidfd adapter in an offline cached Node22 Linux
container as UID/GID65534 with no capabilities, a read-only repository and a
temporary filesystem. It observed retained-descriptor termination, an empty
group, actual controller closure, actual original-child closure and owned-file
cleanup; the harmless client never started. It used no API, agent, certificate,
CA, service or network operation. This supporting control is not Node24 or
native certificate qualification. The source is wired into the existing Linux
and Alpine journeys; native certificate qualification remains pending.

A second actual benign control deleted the public process receipt after
attachment. Even after the original child closed, the controller refused a
successful drainage receipt, sticky ownership remained and destructive cleanup
was refused. The in-memory guard does not disappear with its filesystem marker.
The real parent's cleanup also requires its original agent ChildProcess `close`
event before deleting database ownership records or private fixture files.
