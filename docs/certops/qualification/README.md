# CertOps qualification guides

Start with the [qualification overview](../e2e-qualification.md). These runbooks distinguish implemented source, focused local checks and required native execution; a source mapping does not mean a scenario has qualified.

Machine-readable specifications retain their stable locations: [scenario catalog](../e2e-scenario-catalog.json), [mandatory suite inventory](../qualification-suites.json), [release environment matrix](../release-qualification-matrix.json) and [skip mappings](../skip-qualification.generated.json).

## API, inventory and worker behavior

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

- [Native CNG export refusal and operational key custody](windows/cng-export-refusal-qualification.md)
- [IIS SNI isolation between sites sharing one port](windows/shared-port-sni-qualification.md)
- [Native store and HTTP.sys discovery selectors](windows/native-discovery-qualification.md)
- [Canonical-root unmodified Windows installer lifecycle](windows/canonical-root-lifecycle.md)
- [Installed Windows adoption and predecessor retention qualification](windows/windows-adoption-qualification.md)
- [Installed Windows agent qualification](windows/windows-real-journey.md)
- [Installer first-rename refusal and preserved service](windows/installer-first-rename-refusal.md)
- [Activation-function second-rename restoration](windows/installer-second-rename-restoration.md)
- [Two successful unattended Windows renewal generations](windows/two-unattended-renewals.md)
- [Retention-ledger atomic replacement refusal](windows/retention-ledger-atomic-replace.md)
- [Retention replacement lineage, cross-store key survivors and protected cleanup](windows/retention-replacement-lineage.md)
- [Two-cutover retention with actual expiry grace and interruption recovery](windows/retention-two-cutover-expiry-grace.md)
- [ACME certificate key binding before Windows acceptance](windows/acme-csr-key-binding.md)
- [Hosted standalone AD CS feasibility](windows/standalone-adcs-feasibility.md)
- [Domain-backed AD CS lab, native safety matrix and cleanup](../../../infra/certops-adcs/README.md)
- [AD CS operator guide](../agent/adcs.md)
- [Native uncertain submission, acknowledged recovery and safe abandonment](adcs/uncertain-abandon.md)

## Linux agents and deployment

- [Native certificate filesystem qualification](linux/filesystem-qualification.md)
- [Real Linux ACME qualification](linux/linux-acme-qualification.md)
- [Installed Linux agent qualification](linux/linux-systemd-qualification.md)
- [Same-candidate Linux installer reapplication](linux/linux-systemd-reapply-qualification.md)
- [Published Linux package upgrade and preserved service state](linux/linux-published-upgrade-qualification.md)
- [Native Linux trust-store qualification](linux/linux-trust-qualification.md)
- [Native Linux agent fault qualification](linux/native-agent-qualification.md)
- [Native Linux consuming-server certificate reload qualification](linux/nginx-qualification.md)

## DNS providers and ACME

- [DNS provider error qualification](dns-acme/dns-provider-errors-qualification.md)
- [Real DNS provider qualification](dns-acme/dns-provider-qualification.md)
- [Real DNS-hook routing qualification](dns-acme/dns-routing-qualification.md)
- [Real agent/API/ACME filesystem qualification](dns-acme/real-acme-qualification.md)

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
