# Real Linux ACME key reuse

The Linux filesystem executor supports `keyRotation=false`: it retains the
existing agent-local private key and creates a new CSR. Both supported clients,
certbot (`--csr`) and acme.sh (`--signcsr`), sign that externally generated CSR.
This is certificate-key reuse, separate from ACME account-key persistence.

`tests/e2e/helpers/certops-acme-key-reuse.js` is an additional real journey control.
Run it after the existing positive key-rotation generations and before the
lease-loss control retires the owning agent. The parent supplies its existing
disposable agent/API/database/Pebble, trusted TLS listener and exact owned paths.
The helper does not start a second service or access a live public CA.

The operator session changes only the existing profile's rotation policy through
the public profile PATCH endpoint. A manual renewal and a production scheduler
sweep then execute through the real signed-agent dispatch pipeline. The automatic
cycle requires genuine SQL `NOW()` eligibility and a previously unused expiry
idempotency key. Real wall-clock waits allow the CA's second-resolution expiry to
advance; certificate dates, database clocks, journals and capabilities are never
fabricated. The sweep is invoked directly; this does not qualify background worker
timer intervals or a continuous 24-hour run.

For the starting leaf and both renewed generations, the oracle checks unchanged
private-file bytes and restrictive file ownership/mode, unchanged SPKI, private-key
matching, exact SANs, independently trusted served TLS, advancing real expiry,
distinct leaf DER and CA serials, and no residual authoritative DNS challenges.
Both jobs must succeed in real mode with `keyRotation=false`, `keyRotated=false`
and claim-bound `validation.passed` evidence. The source profile ID, timestamp and
public metadata stay unchanged across both renewals; the bounded report includes
a fingerprint of that complete stable source snapshot. Private material remains
local and is absent from the proof.

Each admitted job is immediately registered in the parent's cleanup list, including
admissions committed by a sweep that later reports an error. The parent retains
ownership of agent shutdown, DNS, database rows, sockets and local private files.
No unsupported cleanup claim is emitted by this helper.

The focused proof tests validate strict public report shape and refusal cases;
they do not prove real issuance. Source implementation and pure checks must remain
distinguished from pending disposable Linux execution for each client and matrix
surface. This fixture makes no Windows CNG key-reuse claim.

The Windows policy boundary remains separate: `renewalProfile.js` currently maps
`rotateOnRenew=false` to the agent payload even for `windows-iis`, while the native
ACME executor in `packages/agent/src/index.js` unconditionally creates an enrollment
CSR/container through `generateCsrViaCng`. This accepted flag does not establish
native reuse support. Explicit refusal or truthful policy handling and its native
regression coverage remain pending; this Linux fixture does not change that product
contract or add a Windows feature.
