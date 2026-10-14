# Two native AD CS scheduler renewal cycles

The disposable forest fixture extends an already observed and managed RSA-2048
certificate through two further automatic renewals. It reuses the safe
`TTQualificationRSAShort` template's actual six-day validity and the unchanged
stored profile's thirty-day renewal window. Each actual new certificate therefore
remains naturally due under the production SQL `NOW()` selection query.

The fixture invokes two production default scheduler sweeps. It supplies no
custom job creator, scheduler clock, selected certificate payload or direct
renewal-service call. The existing public profile creation and source-management
adoption establish authority; native jobs are created with `source=automation`
and `mode=real`. This qualifies scheduler selection and complete unattended agent
execution after a sweep. It does not qualify the background worker's interval
timer. The report records that invocation scope explicitly.

Production deduplicates by managed certificate and actual expiry, excludes open
enrollments and nonterminal renewal jobs, and requires a fresh safe AD CS check.
The fixture waits for real discovery of each resulting fingerprint and expiry,
then uses the next natural generation. A short actual monotonic wait crosses
the CA's second-granular issuance boundary. No profile, expiry, database clock,
journal or successful result is rewritten. An unchanged actual expiry or an
already used generation fails instead of bypassing deduplication.

For all three generations, independent CA database lookup binds the actual
trusted TLS leaf fingerprint to its request ID, disposition and serial. CA
request counts must advance by exactly one per cycle. Leaf fingerprints, serials,
SPKIs, enrollment container names and native KSP unique names must differ.
The actual machine keys remain non-exportable in Microsoft Software KSP.
Native IIS binding coordinates, SNI flags, HTTP.sys certificate hashes and
independently trusted hostname-checked TLS must match each cutover. Both jobs
require claim-bound verification evidence and scheduler audit events.

The stored profile and active management period remain unchanged. Final public
inventory must match the latest observed leaf. Both predecessors' certificates,
keys and accepted ownership receipts remain intact. New enrollment IDs and
certificate thumbprints are registered with the parent before dependent waits;
the parent performs its existing bounded owned cleanup. The journey does not
claim elapsed retention cleanup or a full twenty-four-hour qualification window.

Mandatory scenario IDs:

- `adcs-real-two-unattended-natural-generations`
- `adcs-real-two-unattended-native-key-cutovers`
- `adcs-real-two-unattended-profile-and-custody-preservation`

ADR-0014 requires a fresh key and CSR for every new enrollment. This supported
renewal behavior does not implement signed CMC same-key renewal requests.
Supporting proof tests validate evidence refusal paths; actual native forest
execution remains pending.
