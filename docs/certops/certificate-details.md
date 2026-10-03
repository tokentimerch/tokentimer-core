# Certificate details: locations and management

CertOps shows one certificate per SHA-256 fingerprint in a workspace. A
certificate can appear at several locations and be registered through several
integrations without creating separate certificate entries.

## Observed locations

This section answers **“Where has this certificate been seen?”** Each endpoint,
file path, certificate-store slot, or service binding is a separate location.
A stored copy does not establish service use. Failed checks, disconnected
agents, deleted monitoring, and stale evidence mean uncertain presence, not removal.
The table explains why: **Monitoring ended**, **Not checked recently**, or
**Needs verification**. An **Observed** badge requires fresh presence evidence.

Deleting and recreating an endpoint monitor does not create another location.
The default view shows one row per endpoint URL, preferring its current monitor.
**Show previous observations** reveals older monitor records; these are history,
not extra current locations. Up to 20 locations and 20 previous observations per
location are returned, with full counts. File paths on different hosts and
separate service bindings remain distinct. Unknown visibility at a genuinely
unmonitored location is still shown and still matters for decommissioning.
Seeing a certificate does not by itself configure automatic renewal.

## Certificate management

This section answers **“Through which registrations does CertOps track or
renew this certificate?”** A registration may be a manual import, an endpoint
checker, an agent, or an integration. Tracking and automatic renewal are
separate: **No automatic renewal** means no renewal profile is assigned to
that management period. It does not mean that the certificate is absent.

**Stop managing** ends the selected registration's current management period
and cancels unclaimed automation. An already-running operation may finish.
It does not delete the certificate, remove installed copies, revoke it, or
stop independent location observations. Remove an endpoint monitor separately
if you want its checks to stop.

**Start managing again** opens a new period for the same registration and
certificate identity. Choose **Track without automatic renewal** or explicitly
select a renewal profile; old jobs and settings are not restored. The prior
period remains in the audit history. This is another management period, not
another certificate. A deleted endpoint must be recreated through endpoint
monitoring rather than restarted from its historical registration.

The default table shows current registrations and the latest stopped
registrations that can be restarted. **Show ended periods** reveals older
periods, deleted registrations, and previous certificate associations. Their
history is preserved even when hidden. A registration that has rotated to a
different fingerprint cannot restart the old certificate from this view.

## Lifecycle is separate

Marking revoked or decommissioned applies to the certificate fingerprint and
does not close management periods or release their quota. Recording revocation
in CertOps does not contact the CA. Fresh evidence of TLS or bound service use
blocks decommissioning. Stored copies and uncertain visibility require a
reason and acknowledgment. Rediscovery preserves lifecycle and can display
**Revoked · Still observed** or **Decommissioned · Still observed**.

## Retained certificate details

Stopping management keeps the certificate's linked token details and Notes.
The details view uses public fields saved for that exact fingerprint; a source
rotating to another certificate cannot replace those historical fields. If the
original token is deleted, transferred to another workspace, or now describes a
different certificate, the retained details are read-only. Historical fields
that cannot be verified during upgrade are shown as unavailable rather than
guessed from the current source.

When enrollment reaches its managed-certificate limit, valid agent observations
are retained as unmanaged certificates with their separate locations. Replayed
evidence does not refresh presence. Later enrollment joins the same identity.

## CSR action

**Add new CSR** starts the operator-supplied public CSR workflow for a
certificate. It does not generate a private key or a CSR in the browser.
Cloud uses this same single action as Core and Enterprise; there is no second
**New CSR** button. TokenTimer never accepts private-key material.
