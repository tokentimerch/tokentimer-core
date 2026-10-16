# Browser RequestId reconciliation on real native ambiguity

This source exercises the existing dashboard's supported RequestId form. It does
not invent a browser action for acknowledged orphan recovery: that separate
recovery step remains a genuine public API operation in the native fixture.
The source has not executed against the disposable forest or Chromium.

The existing native ambiguity fixture first creates actual zero-request
uncertainty, preserves its genuine CSR and machine key, and deliberately submits
that same CSR twice as the owned SYSTEM requester. It independently verifies both
actual CA RequestIds/DER/SPKI and proves automatic recovery refuses ambiguity.
These deliberately operator-created requests do not establish deterministic
lost-submit-response timing.

The optional browser actor logs in as the same genuine fixture manager through
the real trusted dashboard. It selects only the exact enrollment's accessible
`RequestId for <short ID>` input and `Reconcile <short ID>` button. Entering zero
must show the real form validation error without any CertOps write. All CertOps
POST/PUT/PATCH/DELETE requests are counted, including other actions/workspaces. The
actor then enters the independently selected actual owned RequestId. Exactly one
same-origin public POST must target that enrollment's `/reconcile` endpoint with
only the numeric RequestId, and the real server must acknowledge HTTP204.
Responses and enrollment state are never mocked.

The shared owned Chromium session validates the candidate, Playwright pin and
bootstrap digest. Its browser process and temporary public API trust receipt
must drain before action completion. No screenshot, trace, storage state,
credential, private configuration or raw request body is published. A released
session owner cannot remove another session's later reused trust receipt.

Afterward the original native fixture runs its normal default-clock signed
continuation and requires the selected actual leaf, unchanged protected CNG key,
exact IIS/SNI binding, trusted TLS, claim-bound verification and one matching
public-action audit. It independently verifies the unused leaf was never accepted
anywhere in LocalMachine before revoking only its owned CA request. The original
unknown-effect job and its reconciliation requirement remain intact.

Only the fully verified native ambiguity proof, after owned fault restoration,
can complete the browser proof. Native execution remains pending. The actor
exports two mandatory scenarios in each comprehensive root and hierarchy suite.
The parent invokes the actor, and both collection and release verification bind
its RequestIds, enrollment, selected fingerprint and continuation job to the
complete native ambiguity proof. All ten full-suite matrix cells fingerprint
the critical sources. Pending-hour and retention lanes remain separate.

The integration point is the actual public RequestId proposal in
`certops-adcs-uncertain-operator-ambiguity.js`, through an optional
`reconcileActor.reconcileEnrollment(enrollmentId, selectedRequestId)` callback.
The wrapper invokes `observeNativeCompletion` only after the existing native
fixture has verified its full proof, restored its faults and preserved custody.
The API-only default path remains available for source consumers that do not
supply the browser actor.
