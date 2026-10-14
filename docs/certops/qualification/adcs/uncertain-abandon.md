# Native uncertain submission and abandonment

The protected disposable AD CS forest runs three mandatory scenarios against
the installed LocalSystem agent. The test blocks only native `certreq.exe`
outbound traffic to the isolated CA address, then interrupts the verified owned
agent process tree after observing its durable `submitting` journal. A missed
phase fails the test. Independent native CA database observations must find zero
requests for the unique fixture name at every checkpoint. The transport rule
is removed while the agent is still stopped, before recovery; a zero count
after recovery therefore proves no resubmission with working CA connectivity.
The configured issuing CA hostname must resolve to one IPv4 address matching
the provisioned `domain-ca` VM inside the isolated lab subnet. Both root and
subordinate configurations use that VM; the separate offline root is refused
as a transport-fault destination.

Recovery waits for actual lease expiry and the worker's ordinary unknown-effect
classification. It uses the public recovery API with explicit acknowledgement,
preserves the original orphaned job, and proves that reconciliation reaches
`submission_uncertain` without resubmission. Original CSR bytes, frozen identity,
and an independent hash of the actual machine CNG key's public blob must match.
The owned key must remain non-exportable throughout recovery.
The wait budget comes from the persisted lease and actual database measurement,
plus the sixty-second hard grace and thirty seconds for observation. A required
budget above fifteen minutes fails prerequisites. The report retains bounded
remaining lease, wait budget and actual monotonic elapsed time; no special
shortened experiment lease is assumed.

The public abandon API then schedules the ordinary terminal cleanup operation.
The test observes its audit event, final journal and enrollment state, absence
of the exact unaccepted key, no installed fixture certificate, and zero CA
requests. It never edits journals, enrollment states, job leases, database time,
or native CA outcomes. Its manually created service must have no automatic SCM
failure actions; that policy remains unchanged. Owned firewall rules and the
observer target receipt are removed even on failure, and the service restarts.
The exact owned observer must exit and drain its output before receipt cleanup
can complete. A drain failure fails qualification.

Mandatory scenarios:

- `adcs-real-uncertain-zero-request-owned-termination`
- `adcs-real-uncertain-zero-request-acknowledged-recovery`
- `adcs-real-uncertain-zero-request-public-abandon-cleans-key`

This is separate from the existing known-pending abandon refusal and from
experimental crash reports. Supporting proof tests do not qualify native
execution. Native execution remains pending until the protected lab workflow
runs. Accepted-certificate and foreign-reference deletion refusal are covered
by the separate certificate-store survivor qualifications.
