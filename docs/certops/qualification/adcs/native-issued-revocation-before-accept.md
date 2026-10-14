# Actual revoked AD CS leaf refused before acceptance

This mandatory root/hierarchy source is wired into the parent, suite inventory,
matrix and strict release reports. It has not executed against a disposable
forest. It covers an actual issued leaf revoked
before the installed agent retrieves and validates it. The existing separate
case revokes an already installed certificate and checks native chain behavior.

The control reuses the pending-cancel site's genuine successfully installed
certificate and its exact matching registered journal, issuer and template.
The cancelled original enrollment is never treated as an installed control.
A new ownership receipt is registered before public enrollment dispatch.

After actual pending submission, the existing safe officer approves only the
owned request. Independent inspection checks its actual CA signature, matching
RequestId, original CSR SPKI, template, CN and authorized DNS SAN. An independent
native online chain build must succeed without unknown/offline revocation.
The officer then revokes that exact request and publishes the real CRL. The
CA database must show disposition21, and a new independent chain must report
actual `Revoked`, without unknown/offline status, before continuation dispatch.
Immediately before approval and again before the owned manual dispatch, actual
public state must remain pending with unchanged future scheduler eligibility,
exactly the one original `awaiting_issuer` job, an unchanged native pending
journal and no retrieved material. The predecessor remains independently served
and the new leaf is absent from both target stores. Any automatic early
continuation or acceptance fails the scenario and retains unresolved ownership.

The existing parent-owned disposable revocation-cache fixture must be supplied
as `invalidateOwnedRevocationCache`; it retains its existing snapshot and final
restoration. This helper introduces no additional global cache or registry
mutation. Continuation scheduling uses the supported explicit scheduler `now`
input at the unchanged `next_poll_at` plus one second. It does not qualify
background/default-clock scheduler timing; native host, certificate and CA clocks
remain actual. No response, certificate, journal or CA observation is fabricated.

The production signed continuation must retrieve the exact revoked leaf and
fail with the native helper's `certificate is revoked` detail plus
`rejected_invalid` / `ADCS_CERTIFICATE_INVALID`. A generic failure or a CA
retrieval refusal cannot satisfy the proof: the production journal must contain
the same real leaf. No copy may be accepted into My or WebHosting, the exact
unaccepted key must be gone, and the original rejected request/journal identity
must remain observable. Independent predecessor CNG/binding/TLS observations
remain unchanged, and the CA request count must not increase.

Cleanup reuses the exact unaccepted-enrollment registry and machine-wide
survivor guard. Unknown acceptance or unresolved native cleanup preserves public
ownership records and local state. The scenario adds no new preflight and no
new officer primitive. Protected forest execution is still required to establish
actual certreq retrieval, cache propagation and installed-agent behavior.
