# Live machine Enroll permission restoration

This disposable-forest source journey changes only the current member machine's
Enroll permission on the already confirmed `TTQualificationRSAShort` template.
It complements the existing static `TTQualificationNoEnroll` native denial and
unsafe-template preflight cases.

The controller verifies the actual member computer SID, template GUID, OID,
schema and revision. A fixed mutex and private receipt belong to the exact
template GUID. The receipt is created before the LDAP commit. The native script
adds a noninherited Enroll extended-right deny for that machine SID, restarts the
owned CA service to refresh its template cache, and requires an actual CA ping.
It preserves the template's other permissions, owner, group, SACL and publication.

An ordinary public enrollment using the original confirmed issuer must fail with
`0x80094012`. Independent native observations require the rejected key absent,
the genuine denied journal retained, and the preceding certificate, key custody,
IIS/HTTP.sys binding and trusted TLS unchanged. The CA may allocate zero or one
denied request; the test measures the difference and verifies any allocated row.
It does not manufacture a request identifier or claim that denial precedes CA
submission.

Restoration requires the exact private owner token and current DACL to match
either the owned mutation or the original DACL. The script restores only the
original DACL, verifies it, refreshes the CA again, and requires a new successful
public enrollment with a distinct actual leaf, serial, SPKI and nonexportable
machine key. The accepted store, native IIS/SNI binding, trusted replacement TLS,
CA-issued request and job evidence are independently checked.
The real CA RequestId is mandatory in the independent native observation.
Immediate issued CMC responses may omit it from the API and journal; those
fields are compared when present and are never populated by the fixture.

The parent must register both returned enrollment IDs immediately and retain a
My-store cleanup receipt before admission. Its cleanup must refuse while
`machineAclPendingVerification` is true or the owned guard remains. A failed
restoration, timeout or unknown acceptance preserves the owned state. Directory
permission restoration alone never authorizes certificate/key cleanup.

Both full root and hierarchy AD CS suites require these two scenarios and the
closed `nativeLiveEnrollAcl` report. The installed fixture runs the journey after
its default-worker renewals, reusing their exact registered My-store ownership.
Source hashes cover the native mutation, production disposition/journal/store
paths, and strict public projection. Missing or false required facts cannot fill
a release cell. The private original DACL receipt remains on the CA until
whole-lab teardown; it is never an artifact.

The helper, parent and report controls are implemented source pending protected
native execution. They do not qualify signed CMC renewal requests or an
unsafe-template preflight refusal.
