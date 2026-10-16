# Native AD CS per-issuer capacity

This source extends public capacity admission into actual Windows enrollment.
It has not executed against the disposable forest. Pure proof refusals establish
the report contract only; native qualification remains pending.

`tests/e2e/helpers/certops-adcs-capacity.js` creates one fresh issuer through the
real public API, executes native preflight, confirms the observed CA key and
executes a fresh post-confirmation preflight. Both dispatches must be counted in
the parent workspace's existing native preflight budget. It uses the unchanged
production capacity of five, with no environment, clock or successful-result
substitution.

## Genuine pending admission and native positive controls

The fixture snapshots the public workspace approval setting and temporarily
requires approval. Six concurrent real public enrollments use six distinct,
exactly declared subjects and owned IIS sites against the same newly confirmed
issuer. Five persisted enrollment/jobs must remain `pending_approval`; one public
response must be HTTP409 `CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED`.

Before approval, independent CA queries must find no exact-subject requests.
The five registered enrollment containers and execution journals must be absent,
and a metadata-only native KSP inventory digest must remain unchanged. That
inventory is kept only in memory and is never reported. For the refused subject,
independent SQL requires no enrollment, job or outbox intent, and the machine
store must contain no matching public certificate.

A separately authenticated manager, distinct from the requester, approves one
job through the actual approval route. The agent must complete genuine native
issuance and installation with a real CA RequestId, a protected non-exportable
machine CNG key, the expected IIS/HTTP.sys SNI coordinate, authenticated TLS and
claim-bound verification evidence. That successful terminal job must free one
slot. The originally refused subject then enters through the same public
enrollment route and receives its own independent approval and actual issuance.
Both requests, leaves, enrollment IDs and jobs must be distinct.

The remaining four requests are publicly rejected without CA submission.
Finally the exact original approval boolean is restored through the public
settings route, even if rejection cleanup fails. Unresolved native jobs or
custody remain the parent's cleanup responsibility and must fail the run.

This proves per-issuer admission and successful-job capacity release. It does
not claim a background scheduler interval, pending-CA continuation occupancy,
cross-issuer physical-CA throttling or a signed CMC renewal protocol.

## Parent integration contract

The helper requires the normal genuine registered LocalSystem AD CS fixture,
its authenticated requester/API/PostgreSQL clients, `jobFinished`, trusted TLS
authority resolver and exact native command oracles. It exports four
`REQUIRED_SCENARIOS`, its critical source list, `domains(run)` and `verifyProof`.
Integration must add all six exported domains to the agent's declared selectors
before starting the service. Invoke before CA rollover with the published
`TTQualificationRSAShort` template available.

`reservePrimaryPreflights(2)` must account for both actual dispatches against the
existing primary workspace budget. A budget overflow must fail or use an
explicitly designed supported cohort; skipping a preflight is not allowed.

`registerOwnedStoreCertificate({store: "My", domain, certificateId})` is mandatory
before any enrollment POST. It must return a guarded parent-owned receipt with
the same coordinates and empty `enrollmentIds`/`thumbprints` arrays. Returned
enrollment IDs are appended immediately before native waits. Cleanup must bind
any partially accepted public certificate to that exact enrollment's durable
issued-container/store/certificate/key association after exact service and child
drainage. Unknown association or unresolved native state preserves the fixture.

The helper creates an independent real API approver fixture and records it in
`ownedApiFixtures` before adding its narrowly scoped `workspace_manager`
membership prerequisite. Decisions remain public; no approval or result row is
written directly. The parent cleans these additional API fixtures after deleting
its main owned workspace, so approval/audit references cannot strand users.
Ephemeral credentials stay in memory and must not enter evidence or artifacts.

The comprehensive root-CA and hierarchy native sources invoke this helper. Both
mandatory inventories require its four cases, with current critical source
fingerprints and strict public collector/release proof validation. Source and
focused pure/API-route checks are implemented; forest execution is still pending.
