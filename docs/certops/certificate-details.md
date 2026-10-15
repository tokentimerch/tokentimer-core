# Certificate details: locations and management

CertOps shows one certificate per SHA-256 fingerprint in a workspace. A
certificate can appear at several locations and be registered through several
integrations without creating separate certificate entries.

## Inventory filters and search

The inventory search matches public properties across all management sources:
certificate and identity IDs, names, SANs, issuers, serial numbers, algorithms,
validity dates, key modes, source types and references, and token/profile IDs.
Source filters include observed locations as well as management provenance.
The default **All (except retired)** view excludes revoked and decommissioned certificates. Select
**Revoked** or **Decommissioned** to view them; fresh presence evidence adds
**Still observed** to their lifecycle label. They never count as active.
**Show unmanaged** includes identities without an open management period and
remains available while its count loads or cannot be retrieved.
Key references and deployment paths are searchable only for roles allowed to
read them. Workspace viewers cannot infer those values through search results.

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

## Renewal identities and the linked token

The linked token is the asset row used for expiry alerts, Notes, and contact
routing. The certificate identity is the exact public certificate, identified
by its SHA-256 fingerprint. A renewal creates a new fingerprint even when the
name or private key stays the same.

For example, an agent renews certificate A to B. Its management source moves
to B, and the linked token receives B's expiry and public certificate details
while retaining its Notes and contact routing. A remains in certificate and
management history. Those historical identities alone do not create extra
current sources. However, another linked import or discovery source may still
point to A; the token can then reference several different fingerprints.

The token has one expiry date. Check each certificate's own validity and
locations in Certificate Management when different fingerprints share it.

## Retiring a certificate from a shared token

1. Open **Retire** on the token in the asset inventory. When different
   fingerprints are linked, choose **Certificate to retire** using its expiry
   and fingerprint. Sources with the same fingerprint appear as one choice.
2. Choose **Mark revoked** or **Decommission** and enter a reason. Decommission
   also requires the visibility acknowledgment; confirmed service use still
   blocks it.
3. Verify the selected certificate's lifecycle in Certificate Management.
   Other fingerprints keep their status. The token remains active, with expiry
   alerts enabled, while another linked fingerprint is independently active.
   Retiring the final active fingerprint updates the token's lifecycle and
   suppresses its expiry alerts.

**Earlier versions:** if the token action is disabled or reports multiple
certificate identities, open Certificate Management, select the exact
fingerprint, and use **Change lifecycle** there. Token details never choose a
different fingerprint automatically.

Ordinary renewal of a revoked or decommissioned fingerprint is blocked.
Rediscovery of that same fingerprint preserves retirement. A replacement
certificate with a new fingerprint can be accepted for the same source and
update the same token to active with its replacement details; later renewals
update it again. The retired fingerprint stays retired in history.

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
