# CertOps qualification guides

Start with the [qualification overview](../e2e-qualification.md). These runbooks distinguish implemented source, focused local checks and required native execution; a source mapping does not mean a scenario has qualified.

For setup, follow [Azure-free first qualification](reporting/first-qualification.md). Azure lab identities are optional domain-backed AD CS prerequisites, not normal Windows or cross-platform setup.

Machine-readable specifications retain their stable locations: [scenario catalog](../e2e-scenario-catalog.json), [mandatory suite inventory](../qualification-suites.json), [release environment matrix](../release-qualification-matrix.json) and [skip mappings](../skip-qualification.generated.json).

- [Browser approval and rejection of native AD CS jobs](adcs/browser-job-approval.md)
- [Supported AD CS manager/viewer admin boundary](adcs/browser-admin-role-boundary.md)

## API, inventory and worker behavior

- [Native certificate dry-run and independent side-effect controls](api/native-certificate-dry-run.md)
- [Fleet execution-log quotas](api/fleet-log-quota.md)
- [Actual elapsed log abandonment and worker retention](api/log-maintenance.md)

- [Issuance admission and workspace pause qualification](api/admission-and-pause-qualification.md)
- [Certificate audit history qualification](api/audit-history-qualification.md)
- [Certificate audit filtering and attribution in Chromium](api/browser-certificate-audit.md)
- [Decommission acknowledgement and factual rediscovery](api/decommission-lifecycle.md)
- [Certificate workspace transfer and CSR lineage](api/certificate-transfer-qualification.md)
- [Browser console authorization and reconnects](api/browser-console.md)
- [Retired certificate filters and factual browser details](api/browser-retirement-visibility.md)
- [Mixed eligible bulk renewal admission](api/bulk-eligible-qualification.md)
- [Public CA capacity admission qualification](api/ca-capacity-qualification.md)
- [CSR observation qualification](api/csr-observation-qualification.md)
- [Shared CSR ownership and truthful installation evidence](api/csr-provisional-qualification.md)
- [Certificate import metadata preservation](api/import-metadata-qualification.md)
- [Retirement through fresh and concurrent TLS observations](api/retired-observation.md)
- [Public certificate import and private container refusal](api/public-import-qualification.md)
- [Certificate-producing integration source qualification](api/integration-source-qualification.md)
- [Public renewal issuer switch policy](api/issuer-switch-qualification.md)
- [Multi-target filesystem deployment qualification](api/multi-target-deployment-qualification.md)
- [Queued renewal profile snapshot qualification](api/queued-profile-snapshot-qualification.md)
- [Renewal outbox and SMTP qualification](api/renewal-alert-qualification.md)
- [Renewal path topology qualification](api/renewal-health-qualification.md)
- [Scheduler and public admission capacity](api/scheduler-capacity-qualification.md)
- [Renewal public-key metadata correctness](api/renewal-key-facts.md)
- [Terminal certificate renewal admission](api/terminal-renewal-admission.md)
- [Authoritative retirement and automatic renewal](api/retired-scheduler-admission.md)
- [Retirement, approval and dispatch races](api/retirement-approval-qualification.md)
- [Native signing key rotation qualification](api/signing-rotation-qualification.md)
- [Unmanaged discovery qualification](api/unmanaged-discovery-qualification.md)

## Windows and AD CS

- [Native preflight process containment](adcs/preflight-process-containment.md)
- [Cancelled-request late approval with an installed successor](adcs/cancelled-late-approval.md)


- [Temporary file response barriers (supporting controls)](adcs/response-delivery-barrier-support.md)

- [AD CS algorithm/template negatives with actual positive issuance controls](adcs/algorithm-template-boundaries.md)
- [Native CA-signed response decoder signature tamper controls](adcs/signed-response-signature-tamper.md)
- [Windows 11 ARM64 native CNG runtime and strict desktop scope](windows/arm64-native-cng-runtime.md)
- [Installed certificate dry-run native state and DNS observation](windows/certificate-dry-run.md)
- [Native CNG export refusal and operational key custody](windows/cng-export-refusal-qualification.md)
- [Native certificate KeyUsage and CNG signing permission](windows/native-key-usage.md)
- [IIS SNI isolation between sites sharing one port](windows/shared-port-sni-qualification.md)
- [Native store and HTTP.sys discovery selectors](windows/native-discovery-qualification.md)
- [Canonical-root unmodified Windows installer lifecycle](windows/canonical-root-lifecycle.md)
- [Full installer CLI second-rename refusal and guarded cleanup](windows/installer-cli-second-rename.md)
- [Literal installer paths and junction refusal controls](windows/installer-path-controls.md)
- [Installed Windows adoption and predecessor retention qualification](windows/windows-adoption-qualification.md)
- [Installed Windows agent qualification](windows/windows-real-journey.md)
- [Explicit installed Windows service state handoff](windows/installed-state-handoff.md)
- [Installer native helper preactivation checks](windows/installer-pe-preflight.md)
- [Installer first-rename refusal and preserved service](windows/installer-first-rename-refusal.md)
- [Activation-function second-rename restoration](windows/installer-second-rename-restoration.md)
- [Two successful unattended Windows renewal generations](windows/two-unattended-renewals.md)
- [Retention-ledger atomic replacement refusal](windows/retention-ledger-atomic-replace.md)
- [Native retention reference protection and configuration boundaries](windows/retention-reference-guards.md)
- [Native AD CS journal read/list ACL refusals](windows/journal-read-refusals.md)
- [Native retention ledger read/list ACL refusals](windows/retention-ledger-access-refusal.md)
- [Native configuration, credential and signing-pin read-access refusals](windows/state-read-refusals.md)
- [Retention replacement lineage, cross-store key survivors and protected cleanup](windows/retention-replacement-lineage.md)
- [Two-cutover retention with actual expiry grace and interruption recovery](windows/retention-two-cutover-expiry-grace.md)
- [Default and maximum retention policies with actual expiry-grace cleanup](windows/native-retention-policy-expiry.md)
- [Optional AD CS installed-service default retention timer](windows/installed-default-retention-timer.md)
- [Linux ACME renewals from the production worker default cron](linux/acme-background-renewals.md)
- [ACME certificate key binding before Windows acceptance](windows/acme-csr-key-binding.md)
- [Hosted standalone AD CS feasibility](windows/standalone-adcs-feasibility.md)
- [Domain-backed AD CS lab, native safety matrix and cleanup](../../../infra/certops-adcs/README.md)
- [AD CS operator guide](../agent/adcs.md)
- [Native uncertain submission, acknowledged recovery and safe abandonment](adcs/uncertain-abandon.md)
- [Browser confirmation of uncertain AD CS abandonment](adcs/browser-uncertain-abandon.md)
- [Browser RequestId reconciliation of owned AD CS ambiguity](adcs/browser-requestid-reconcile.md)
- [Native issued unauthorized SAN refusal](adcs/native-issued-san-refusal.md)
- [Native revoked leaf refused before acceptance](adcs/native-issued-revocation-before-accept.md)
- [Browser cancellation of a never-approved AD CS renewal](adcs/browser-requested-cancel.md)
- [AD CS renewal, discovery and retention coordinates in WebHosting](adcs/webhosting-renewal.md)
- [Native AD CS per-issuer capacity and genuine approval release](adcs/native-issuer-capacity.md)
- [Two native AD CS renewal generations through default scheduler sweeps](adcs/two-unattended-renewals.md)
- [Production interval worker and native AD CS renewals](adcs/background-worker-renewals.md)
- [Live same-template machine Enroll permission denial and restoration](adcs/live-machine-enroll-acl.md)
- [Hierarchy HTTP intermediate CRL fault and native recovery](adcs/http-intermediate-crl-fault.md)
- [HTTP-only leaf CRL endpoint availability and restored-publication renewal](adcs/http-only-leaf-crl.md): real installed renewals and independent native chain probes; signed-agent fault continuation and OCSP remain separate.
- [Native Microsoft OCSP responder](adcs/native-ocsp-responder.md): existing disposable CA, delegated signer, OCSP-only renewal, independent signed-good/native endpoint probes and guarded active-resource drainage; native execution remains pending.
- [AD CS native result outbox and SCM restart](adcs/native-result-outbox-restart.md): real installation before result-delivery failure, actual durable retry timing, retained original process drainage and same-claim delivery after restart; native execution remains pending.
- [Manual hierarchy Windows and display-language environments](adcs/hierarchy-environments.md)
- [Experimental accepted-certificate crash recovery before IIS cutover](adcs/accepted-install-recovery-experiment.md)
- [Experimental new IIS binding before durable completion](adcs/bound-install-recovery-experiment.md)
- [Browser-driven issuer, profile and native AD CS enrollment](adcs/browser-native-journey.md)
- [Exact local CA/template permission boundaries](adcs/local-ca-template-boundaries.md)
- [Other-enrollment native CA candidate SPKI refusal](adcs/foreign-spki-candidate.md)
- [Native fault observer ownership and drainage](adcs/fault-observer-lifecycle.md)

## Linux agents and deployment

- [Native certificate filesystem qualification](linux/filesystem-qualification.md)
- [Same-process concurrent filesystem rotations](linux/filesystem-concurrent-rotation.md)
- [Native backup-directory alias refusal](linux/filesystem-backup-directory-alias.md)
- [Native destination-scoped backup retention](linux/filesystem-backup-retention.md)
- [Independent native trust ownership](linux/trust-independent-roots.md)
- [Native consuming-daemon coordinator rollback](linux/daemon-coordinator-rollback.md)
- [Real Linux ACME qualification](linux/linux-acme-qualification.md)
- [Manual and scheduled Linux ACME key reuse](linux/acme-key-reuse.md)
- [Retained-process ownership during Linux ACME lease loss](linux/acme-lease-process-ownership.md)
- [Installed Linux agent qualification](linux/linux-systemd-qualification.md)
- [Installed Linux file discovery and guarded restoration](linux/installed-file-discovery.md)
- [Same-candidate Linux installer reapplication](linux/linux-systemd-reapply-qualification.md)
- [Published Linux package upgrade and preserved service state](linux/linux-published-upgrade-qualification.md)
- [Native nonroot filesystem backup permission refusal](linux/filesystem-backup-dac.md)
- [Native Linux trust-store qualification](linux/linux-trust-qualification.md)
- [Native Linux agent fault qualification](linux/native-agent-qualification.md)
- [Native Linux consuming-server certificate reload qualification](linux/nginx-qualification.md)

## DNS providers and ACME

- [DNS provider error qualification](dns-acme/dns-provider-errors-qualification.md)
- [Real DNS provider qualification](dns-acme/dns-provider-qualification.md)
- [Real DNS-hook routing qualification](dns-acme/dns-routing-qualification.md)
- [Two configured DNS resolver views](dns-acme/dns-resolver-views.md)
- [Native ACME browser issue and renewal lifecycle](linux/acme-browser-job-lifecycle.md)
- [Unprivileged native file discovery refusals](linux/native-file-discovery-refusals.md)
- [Real agent/API/ACME filesystem qualification](dns-acme/real-acme-qualification.md)
- [ACME stage transport refusal](dns-acme/stage-transport-refusal.md)
- [Actual native ACME browser console](linux/acme-native-browser-console.md)

## Kubernetes and cert-manager

- [External HTTP-01 controller qualification](kubernetes/kubernetes-http01-qualification.md)
- [Disposable Kubernetes qualification](kubernetes/kubernetes-qualification.md)
- [Native Kubernetes public Secret fallback](kubernetes/kubernetes-secret-fallback-qualification.md)

## Downstream extensions

- [Edition qualification stays tied to its composition](editions/downstream-qualification.md)

## Reports, skips and release qualification

- [Finding a qualification harness](reporting/harness-layout.md)
- [Selecting affected CI lanes and focused reruns](reporting/ci-selection.md)

- [Certificate release qualification](reporting/release-qualification.md)
- [Skip qualification ownership](reporting/skip-qualification.md)
- [Supporting CertOps integration qualification](reporting/supporting-integration-qualification.md)

- [Completed-console authority withdrawal](api/browser-completed-console.md)

The [operator-created uncertain ambiguity journey](adcs/operator-created-uncertain-ambiguity.md) exercises public ambiguous-candidate refusal and explicit RequestId recovery after a real zero-request interruption. Its two real operator submissions are distinct from the nonqualified lost-response experiment.

The [resident domain retention journey](windows/resident-domain-retention24h.md) separates short CI jobs from a genuine same-process Windows day, with independently attested lease handoff and bounded cleanup. Preparation and timing-only receipts cannot qualify its native slot.

The [retention controller lifecycle](windows/retention24h-controller-lifecycle.md) documents immutable artifact readback, the bounded resource lease, independent finalization and cleanup.

The [Windows ACME key rotation policy](windows/acme-key-rotation-policy.md) requires fresh CNG keys; its public refusal journey preserves existing native custody and trusted TLS.

The [HTTP.sys client-certificate policy fixture](windows/http-sys-client-policy.md) measures native revocation and usage settings across real cutover and rollback without claiming a client-auth handshake.

The [packaged chain runtime fixture](windows/packaged-chain-runtime.md) separates actual candidate path/protocol behavior from lab-built CMC and reference Go verifier qualification.

- [Native ARM64 candidate packaged service-host mock-child lifecycle](windows/arm64-packaged-scm.md)

- [Pending request across same-key root CA renewal](adcs/pending-same-key-ca-renewal.md): actual pending custody and same-request continuation; native execution pending.
- [Pending request across CA new-key rekey](adcs/pending-ca-new-key.md): signed frozen-request refusal and same-issuer fresh confirmation/approval/installation; native execution pending.
- [Public unrelated-SPKI RequestId refusal](adcs/public-foreign-spki.md): actual same-SAN/template issuance, signed candidate refusal, guarded revocation and matching recovery; native execution pending.
- [Required template attributes](adcs/required-template-attributes.md): actual zero minimum/missing name flag, native/public refusal and exact fresh-safe restoration; native execution pending.

- [ARM64 installed agent/API](windows/arm64-installed-agent-api.md): original canonical installer, real signed jobs, file-plan/discovery scope and explicit pinned x64-emulated PostgreSQL; native execution pending.

The separate [default24h AD CS release contract](adcs/default24h-release-contract.md) requires a genuine same-VM day, original stale caches, production-deadline cleanup and fresh native renewal. Its timing-only and native-stage receipts cannot qualify the new slot; protected execution remains pending.

- [Native orphan reconciliation and open enrollment protection](windows/native-orphan-journal-protection.md): supporting CNG/journal controls with explicit installed-service, CA and age-policy exclusions.

- [Installed public IIS refusal](windows/installed-public-iis-refusal.md): real public deploy admission, installed-agent signed refusal, claim-bound failure audit and two protected CNG/IIS/TLS endpoints. All ten hosted Windows/key-profile cells remain unexecuted.

- [IPv6 SNI shadow and rollback](windows/ipv6-sni-shadow-rollback.md): concrete IPv6 native failure/recovery with a separate preserved IPv4 sibling; native execution pending.

- [IPv6 wildcard shadow and rollback](windows/ipv6-wildcard-shadow-rollback.md): separate [::] native scope and both-stack isolation prerequisites; native execution pending.

- [Installed Unicode paths](windows/installed-unicode-paths.md): exact native SCM/Node/config paths with spaces, Unicode and literal brackets, actual public signed issuance and CNG/IIS/trusted TLS. Historical migration runs first in a separate ASCII supporting root. Native execution remains pending.

- [Installed crash ownership](windows/installed-crash-ownership.md): exact native handles, fail-closed fixture preservation and explicit shortened-lease recovery scope; native execution pending.

The [real-day interrupted deletion case](windows/resident-retention24h-interrupted-delete.md) requires actual delstore interruption, retained-key/incomplete-ledger observations and ordinary recovery within the same genuine resident campaign. Native execution remains pending.

- [Native IPv4 wildcard HTTP.sys shadow and rollback](windows/ipv4-wildcard-shadow.md).

- [Installed Windows SCM control contract](windows/installed-service-controls.md).

- [Native prepared CNG key with unreadable enrollment journal](windows/native-cng-unreadable-journal.md): actual OS access denial, production orphan deferral and exact ACL restoration; native execution pending.

- [Installed Windows configuration encoding refusals](windows/configuration-encoding-refusals.md).

- [Public idle installed Windows retirement](windows/public-idle-retirement.md) — authorization, idempotent audit, clean native exit and preserved custody.

- [Same-certificate renewal after cancellation and late approval](adcs/same-certificate-cancelled-late-approval.md): distinct real pending requests of one discovered managed identity, actual successor installation and guarded unused late issuance. Native execution pending.

- [Installed retention configuration refusals](windows/retention-configuration-refusals.md) — real startup validation boundaries with native custody preservation.

- [Installed credential startup refusals](windows/credential-startup-refusals.md) — real protected-reader failures, preserved identity/custody and exact repair.

- [WebHosting expiry-based certificate and key reclamation](windows/webhosting-expiry-reclamation.md) — separate manual hosted Windows lane, without Azure or a full-window timer claim.

- [Installed service controls during an actual certificate phase](windows/active-certificate-service-controls.md) — held real DNS operation, unchanged claim/journal/CNG and trusted serving leaf; no interruption or default-grace claim.

- [Native daemon served-leaf mismatch and paired rollback](linux/daemon-served-leaf-mismatch.md)

- [Public Windows multi-target admission refusal](windows/multi-target-admission-refusal.md) — immutable profile/edit and manual override rejection, without a signed multi-target execution claim.

- [Public bulk renewal with two genuine native ACME completions](linux/public-bulk-native-renewal.md)
- [Public native renewal setup](linux/public-native-renewal-setup.md)
- [Certificate result outbox and native agent restart](linux/certificate-result-outbox-restart.md)

- [Installed service stop with real lease expiry and offline reconciliation](windows/stopped-offline-renewal-recovery.md) — separate manual hosted Windows lane; no alive-agent grace or original-operation recovery claim.

The [installed public renewal verification/rollback journey](windows/installed-public-verify-rollback.md) requires real signed current-claim failure evidence, accepted native custody, restored trusted TLS and a fresh public retry in the existing Windows profile cells. Native execution remains pending; transient binding observation and AppID preservation are not qualified.

- [Installed corrupt signing-pin startup refusals](windows/installed-signing-pin-refusal.md): two actual production reader failures with exact pin repair and preserved registered/native state; native execution remains pending.

- [Readable public credential with weak native ACL](windows/native-credential-weak-acl.md): production-reader refusal and exact retained-handle repair, supporting host scope only; native execution remains pending.

- [Native manual renewal under a disabled automatic profile](linux/disabled-profile-native-manual-renewal.md)

- [Alive installed agent with genuine default lease and hard-grace classification](windows/alive-agent-default-hard-grace.md) — separate manual Azure-free two-Server lane, actual 75-minute boundary; no worker-loop or automatic recovery claim.

- [Native IIS public-only certificate association refusal](windows/native-iis-public-only-association.md) — exact public My copy, absent original key, actual refusal/rollback and trusted sibling preservation; no installed signed-job claim.

- [Installed public renewal with failed rollback](windows/installed-failed-rollback.md) — separate manual Azure-free Server 2022/2025 lane, actual signed failure/native absent predecessor, retained original association restoration and distinct public retry; native execution pending.

## Distribution

PR #329's fixtures and enrolled-agent journey are integrated with strict reports.
See [distribution qualification](distribution/README.md),
[feature coverage](distribution/coverage-matrix.md) and
[actual execution](distribution/execution.md). Source-mounted evidence remains
experimental and cannot qualify production agent capabilities.
