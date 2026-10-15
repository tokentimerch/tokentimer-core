# Installed default retention timer qualification

This separate manual domain campaign observes the production installed Windows
agent's immediate retention sweep and its first genuine default timer sweep.
The agent configuration omits both `windows.sweepIntervalMs` and
`windows.supersededRetentionHours`. The resolved defaults are six hours and 168
hours. The production polling loop waits with 20% jitter **after** each sweep
completes, so its timer delay is 4.8–7.2 hours.

A successful preparation performs two real public AD CS enrollments on a fresh
SYSTEM service, verifies the replacement through trusted IIS SNI TLS, and drains
the service. The resulting production predecessor ledger must still be pending.
A separate read-only SYSTEM observer takes ownership of that exact ledger before
preparation restarts SCM once. It observes the immediate pending-to-deferred
atomic replacement, records the installed host and Node creation identities,
boot, configuration digest and native protected-key custody, and then watches the
same process for the actual timer rewrite of the same deferred ledger bytes.

The observer never calls the collector, edits the ledger, supplies a clock, or
uses log messages as proof. Stable native file identities distinguish atomic
replacement from an in-place change. Actual wall and monotonic intervals must
agree within five seconds. A five-minute margin bounds native sweep completion
and observation work around the jitter window; it is not a measurement of the
otherwise unobservable polling callback return instant. Unexpected early writes,
changed lineage, process restarts, boot changes, changed configuration, unknown
native operation children, expired ownership or missing timer activity fail the
campaign.

The same fresh disposable fixture must have no other active jobs or renewal
profiles. The controller independently seals that state. All three original VMs remain
running conservatively, including the API required for healthy agent polling.
The observer independently checks the pinned API TLS leaf and actual /health
response during each periodic and final native inspection. This limits the authorized ledger writers in this owned
fixture; it does not claim kernel-level attribution against a malicious
privileged actor. Both predecessor and replacement certificates and protected
keys remain present, and the actual predecessor expiry must extend beyond the
original sixteen-hour lease plus one hour.

The ordinary initial lease lasts four hours. Only an independently authenticated,
immutable original preparation artifact and fresh exact-VM/task readback permit
handoff to the original sixteen-hour hard deadline. Repeated handoffs cannot
renew it. The unattended cleanup queue and independent expiry janitor must remain
available while protected preparation awaits approval. Azure or Actions outages
can delay actual deletion; the lease is an authorization limit, not a billing
cutoff guarantee. Final qualification requires current native and trusted TLS
readback, exact observer completion/drain, and independently verified owned Azure
resource absence.

This campaign qualifies the installed **deferral timer** only. It does not
qualify certificate deletion, the full 168-hour retention period, the 720-hour
maximum, power loss, or the separate stopped-agent real-day collector campaign.
The source and offline contract tests are supporting checks. Native execution
and full CI qualification remain pending until the protected workflow actually
runs and produces the authenticated report.
