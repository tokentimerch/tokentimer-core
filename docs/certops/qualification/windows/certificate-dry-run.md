# Installed Windows certificate dry-run

Two mandatory scenarios run against the real installed LocalSystem agent after
the parent journey's genuine ACME issuance has installed its non-exportable CNG
key, local certificate and IIS/HTTP.sys binding. A successful claim-bound real
issuance job, persisted evidence, independently trusted TLS and an exercised
owned DNS proxy establish that the fixture can perform native mutations.

- `windows-certificate-deploy-dry-run` requires the real signed deploy operation
  to finish as `dry_run_complete` with three persisted authenticated plan steps.
- `windows-certificate-renew-dry-run` requires the real signed renewal operation
  to finish as `dry_run_complete` with six persisted authenticated plan steps,
  using the actual stored renewal profile and the same installed agent.

The generic public job route does not expose a selectable execution mode. These
cases explicitly call production `createCertificateJob` with `mode: "dry_run"`;
normal signing, dispatch, claim, lease, evidence and result handling remain in
use. No job result, enrollment journal, key identity or clock is fabricated.

Before and after each operation, independent observations compare the local
machine My certificate inventory, machine CNG key-file metadata, exact protected
key identity and export policy, native HTTP.sys binding, trusted served leaf,
configuration, credential and signing pin. The owned DNS proxy request count
must remain unchanged. Key-file contents are never read or hashed. Global
inventories remain private in memory and are never included in artifacts.

This covers native state and traffic through the owned DNS proxy. It does not
claim that arbitrary child processes never ran, that direct CA traffic was
observed, or that transient effects were traced by ETW. Existing real issuance
and subsequent genuine unattended renewals provide the parent journey's
separate mutation controls; they are not converted into dry-run successes.

The helper creates no additional native resource. The parent owns the installed
service, certificates, keys, endpoint, API jobs and final cleanup. Failed dry-run
assertions fail the journey and still reach that cleanup. The public report
contains only bounded proof fields and source hashes. Supporting pure proof
tests do not qualify native execution; the hosted Windows lanes remain unrun.
