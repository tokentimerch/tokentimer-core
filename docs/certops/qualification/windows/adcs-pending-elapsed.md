# Actual elapsed AD CS pending timeout

Run **CertOps / Enterprise AD CS actual one-hour pending expiry** manually on
`main` after the candidate source is merged. The protected `certops-adcs-lab`
environment supplies its dedicated Azure OIDC identity. The workflow creates a
fresh Server 2022 / en-US domain lab with a four-hour resource expiry, a
180-minute job limit, unconditional owned-resource teardown and the independent
lab janitor. No permanent runner or domain is required.

This is a separate, cost-bounded qualification scope. It runs native language
verification, actual installed SYSTEM-agent registration, one real RSA-2048
issuance/IIS deployment, the elapsed pending case and owned cleanup. It does not
produce a successful comprehensive AD CS baseline report or replace the nine
Windows Server/language slots.

The case creates a held CA request through the public API with the supported
frozen `pendingTimeout: 3600` and `pollInterval: 60`. It waits at least one hour
according to both monotonic host duration and actual PostgreSQL time. Every
scheduler call uses its default real clock; no database dates, journal phases,
CA clocks or host clocks are rewritten. A real service restart must preserve
the original registration credential, CSR, request ID, snapshot and protected
CNG key. Before the actual deadline the key must remain present.

After expiry, the production scheduler and signed continuation must remove the
exact unaccepted key without accepting a certificate, changing the outgoing
trusted IIS certificate or resubmitting to the CA. The officer then approves
that same genuine request. Public reconciliation must refuse the terminal
enrollment, repeated real-clock scheduler sweeps must not revive it, and the
unused late-issued certificate is revoked using its native CA serial number.

The dedicated report is
`qualification-results/enterprise-adcs-elapsed-pending-real.json`. Both the
mandatory suite verifier and `scripts/certops-adcs-pending-elapsed-report.js`
must pass. The latter rejects shortened waits, injected clock evidence, missing
custody/cleanup guarantees, wrong environment and mismatched helper source
bytes. Only bounded public timing, IDs, hashes and boolean observations are
recorded; no CSR private key, service credential or officer credential is an
artifact.

The native test has an 80-minute limit so it fits Azure Action RunCommand's
90-minute execution ceiling. Failure to finish the actual hour and cleanup in
that budget fails qualification. This proves the supported configured
one-hour policy; it does **not** prove that the default fourteen-day timeout was
observed for fourteen days. The faster baseline timeout case separately tests
the supported scheduler eligibility input. Native execution of this new lane
remains pending until its protected workflow runs.
