# Hosted standalone AD CS feasibility

`certops-standalone-adcs-smoke.yml` is an experimental trusted manual workflow on disposable Windows Server 2022. It requires a genuinely elevated token, refuses an existing CA and rejects installation that requests a reboot. It installs AD CS and IIS without assuming this is supported on every hosted image.

Three native cases must execute: standalone pending request observation, real officer resubmission/retrieval/acceptance with a non-exportable machine CNG key, and installation of that issued leaf on a unique IIS SNI binding with an independent trusted TLS fingerprint check. The request includes its public DNS SAN and server-authentication purpose. No TokenTimer AD CS capability is enabled.

Cleanup removes only the owned site/binding, leaf certificate/key, uniquely named CA certificates and authority, and roles installed by this run. Existing IIS roles and sites are preserved. The report records candidate SHA, current source digest, measured native Windows version/build, identity, CA type, named execution and cleanup. The independent verifier rejects empty, duplicate, missing, failed or stale cases and any attempt to label this experimental result qualified.

Promotion to a stable standalone host gate requires at least three consecutive successful runs of the same candidate on the selected hosted image, each within the workflow's 25-minute bound, with no reboot, no unexpected skips, all three named cases and completed cleanup. Repeat this evidence after changes to the Windows image or fixture tooling. A failure or missed prerequisite keeps the lane experimental; a green command without valid execution evidence does not count.

Successful standalone evidence covers only these native feasibility operations. Enterprise domain membership, actual computer-account Kerberos enrollment, template permissions, asynchronous product continuations, renewal, revocation outage, CA-key changes, localization and the full release matrix require the separate domain-backed qualification lab. The release collector deliberately excludes this workflow.

Implementation has PowerShell syntax checks and four passing focused verifier regressions. Actual hosted feasibility has not yet been executed.
