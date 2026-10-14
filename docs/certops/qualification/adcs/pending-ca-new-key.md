# Pending request across CA rekey

The separate native helper prepares a genuine pending request before the lab's
existing single CA new-key rekey. It verifies the original CSR, snapshot, native
non-exportable CNG signature, CA RequestId and request count before allowing the
rekey callback. Signed continuation must refuse `ADCS_CA_KEY_CHANGED`, retain
the frozen request identity, remove its exact invalid-terminal key and preserve
the serving predecessor's custody, IIS/HTTP.sys coordinates and trusted TLS.

Only the independently owned pending CA request is denied by the lab officer.
The same issuer then receives one real native preflight and public confirmation
of the new CA key. A fresh enrollment must use a new snapshot, CSR, CNG key and
RequestId. Actual pending approval and signed continuation must install the new
CA-signed leaf with independently verified key association, native endpoint,
trusted TLS and claim-bound evidence. The rejected original is never repinned.

The existing registered My cleanup receipt is guarded before public enrollment.
Uncertain response, acceptance or process ownership preserves recovery state.
Scheduler eligibility uses the supported explicit `now` input; CA and native
clocks remain actual. This does not qualify the background worker interval.

The root-domain cohort needs one additional primary preflight: its reviewed
maximum becomes 18, plus two existing browser checks, within the unchanged
20-request workspace limit. The subordinate lane does not run root-CA rekey.
The two scenarios and strict closed proof are mandatory in the root-domain
release matrix. Native execution remains pending; pure proof checks do not
establish CA execution or release qualification.
