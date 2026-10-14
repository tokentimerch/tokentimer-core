# Default24h AD CS release evidence

The `windows-domain-adcs-default-ttl24h` suite has one explicit Server2022,
en-US, LocalSystem, x64 release cell. It is separate from the native24h retention
collector: this journey tests the default preflight freshness and deferred
validation deadline. Native execution remains pending on the protected workflows.

Preparation creates genuine AD CS enrollments and captures their original public
CA, journal, cache and protected native-key identities. One resident process on
the same VM observes an actual monotonic day without changing dates or journals.
Post-day source requires real stale local cache refusals, public profile attachment
and `waiting_for_fresh_preflight`, a naturally due production default-clock sweep
with zero dispatch, and a genuine signed continuation reaching the original
validation deadline. The unaccepted key must disappear while the accepted
predecessor and trusted TLS remain intact. Fresh public preflight then permits a
separate default-clock sweep and actual native renewal.

The five mandatory scenarios require real-host evidence. The shared reviewed
inventory in `scripts/certops-adcs-ttl24h-sources.js` binds preparation, resident,
post-day execution, native helper, API admission and maintenance, controller,
workflow and collection sources. Source hashes detect drift; they establish no
native outcome by themselves.

A native-only stage deliberately lacks the independent CA request counters and
control-plane scheduler-isolation facts. It cannot satisfy the full proof or this
release cell. Collection additionally authenticates both immutable original
prepare artifacts and their owner run/attempt, preserving the original candidate
when a later trusted-main finalizer runs. Qualification requires independently
verified resource-group absence and passed cleanup. Synthetic tests and partial
preparation or timing receipts are supporting checks only.

See the [resident source guide](resident-default-ttl24h.md) for the local custody
and default-timeout boundary. This cell does not qualify OCSP/HTTP distribution
faults, subordinate-CA TTL variants or all certificate features.
