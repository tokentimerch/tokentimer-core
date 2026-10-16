# Installed Linux agent reapplication qualification

The manual Ubuntu 22.04/24.04 systemd workflow now requires a separate `linux-systemd-reapply` report. Its three named cases run inside the already owned installed-agent journey after real crash recovery and before retirement. They use the actual candidate installer and existing non-root service, not a reconstructed or transient unit.

The fixture stops its own service, writes supported operator polling/heartbeat and execution settings, and records the exact config, credential and candidate-runtime drop-in bytes. It reruns the same candidate installer with the existing write-path grant and a newly created spare bootstrap token. Independent file hashes must prove that installed package files match the candidate while the operator config, stored credential and drop-in remain unchanged. Config/credential ownership and private modes, effective writable paths and absence of staging/previous application trees are also mandatory.

A fresh installed service PID must scrub the spare bootstrap file without creating or replacing any API agent registration. After another actual systemd restart, the native process environment must contain no bootstrap token, a real authenticated heartbeat must advance, and the spare token must remain unconsumed in PostgreSQL. Checking the environment after this second restart avoids confusing initial process environment memory with the agent's in-process token scrubbing.

Cleanup restores the exact original configuration, restarts the owned service, and revokes only the unused fixture token. An unexpected bootstrap file is never deleted. Failures remain failures and the parent journey/workflow retains its independent receipt-bound installer teardown. Artifacts contain only public boolean/PID facts and source hashes; credentials, bootstrap tokens and config contents stay on the disposable host.

The installed journey has a ten-minute native test deadline within its twelve-minute producer bound; the workflow remains limited to twenty-five minutes, with independent teardown still mandatory.

This is same-candidate installer reapplication, not an old-release-to-candidate upgrade, archive-package upgrade, ARM64 qualification or rollback test. Source wiring, syntax and portable negative-proof checks passed. No native installer, systemd or host mutation was executed during implementation; actual protected-host qualification remains pending.
