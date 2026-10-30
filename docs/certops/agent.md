# TokenTimer Agent

The agent runs on the host that holds certificate keys. TokenTimer plans and audits work; the agent enforces local policy and executes allowed jobs. It connects outbound to the control plane over HTTPS and does not accept inbound connections. Agent-local private keys stay on that host. Explicitly configured Vault publication transfers a certificate/key bundle to your own Vault and consumer hosts, while keeping it outside TokenTimer's control plane.

## Start here

1. Enable CLM on the control plane and prepare a workspace bootstrap token.
2. Open the [setup guide](setup-guide.md) and select the result you need. Prepare [local policy](agent/configuration.md) before allowing certificate work.
3. Follow [Linux](agent/install-linux.md) or [Windows](agent/install-windows.md) installation when the guide requests it, verify signed dispatch with a no-op, then opt into the selected operation.

An agent with `execution.enabled: false` registers, heartbeats, and can report configured certificate discovery; it does not poll for or claim jobs. To test signed jobs, set `execution.enabled: true` and keep `execution.dryRun: true`, then restart and request a job with `mode: "dry_run"`. Real mutating jobs are refused while that safety switch is on. AD CS preflight is a separate real read-only check and can run with local dry-run protection enabled; signed preflight `mode: "dry_run"` is blocked. A no-op proves dispatch/reporting, not the permissions or success of later issuance. Enabling execution does not bypass local policy.

## Task guides

- [DNS and ACME](agent/dns-and-acme.md): provider credentials, zone routing, DNS-01, and the external HTTP-01 workflow.
- [Microsoft AD CS](agent/adcs.md): domain-joined Windows enrollment from an enterprise CA. The agent contacts a CA only when a local enrollment rule names that CA and template. Linux and non-domain hosts do not enroll over DCOM. Use a domain-joined Windows agent, or an ACME gateway.
- [Vault publication and distribution](vault-first-distribution.md): publish once, approve two consumers and verify each listener.
- [Verify the live certificate](verify-live-service.md): compare the actual served identity after installation or renewal.
- [Windows configuration maintenance](windows-maintenance.md): preserve enrolled identity, protected state and private-CA trust.
- [Trust and signing-key rotation](agent/trust-and-key-rotation.md): CA distribution/revocation and signing-key changes.
- [Operations](agent/operations.md): upgrades, troubleshooting, compatibility, and retirement.

## Advanced reference

- [Protocol and job contracts](../../.github/maintainers/certops/agent/protocol.md).
- [Execution and crash recovery](agent/execution.md).
- [Security model](agent/security.md).
- [Windows runtime](agent/windows-runtime.md): CNG, stores, IIS bindings, and retention.

## Previous reference sections

<a id="2-install-and-run"></a>
<a id="installer-script-linux-systemd"></a>
<a id="installer-flags"></a>

See [Install an agent on Linux](agent/install-linux.md).

<a id="config-directory"></a>
<a id="first-run-registration"></a>
<a id="encrypted-registration-recovery"></a>
<a id="config-reference-configjson"></a>

See [Agent configuration reference](agent/configuration.md).

<a id="3-protocol"></a>
<a id="protocol-validation-parity"></a>
<a id="which-agent-gets-a-job-exclusivity-vs-assignment"></a>
<a id="dry-run-and-reconciliation-statuses"></a>
<a id="7-contract-status-and-forward-compatible-fields"></a>

See [Agent protocol and job contracts](../../.github/maintainers/certops/agent/protocol.md).

<a id="4-job-security-model"></a>
<a id="ed25519-signature-verification-with-tofu-pinning"></a>
<a id="canonical-payload"></a>
<a id="replay-cache"></a>
<a id="clock-drift-window-checks"></a>
<a id="agent-local-policy"></a>
<a id="6-zero-custody-guarantees"></a>

See [Agent security model](agent/security.md).

<a id="signing-key-rotation-lifecycle"></a>
<a id="trust-anchor-distribution-and-revocation"></a>

See [Trust distribution and signing-key rotation](agent/trust-and-key-rotation.md).

<a id="5-renewal-execution-chain"></a>
<a id="fail-closed-lease-start"></a>
<a id="lease-renew-endpoint"></a>
<a id="side-effect-journal-and-crash-recovery"></a>

See [Job execution and crash recovery](agent/execution.md).

<a id="dns-01-providers"></a>

See [DNS and ACME configuration](agent/dns-and-acme.md).

<a id="8-windows-notes"></a>

See [Windows runtime reference](agent/windows-runtime.md).

<a id="9-troubleshooting"></a>
<a id="fleet-compatibility-clock-drift-and-liveness-control-plane"></a>
<a id="forced-agent-retirement-and-in-flight-work"></a>
<a id="clean-exit-on-retirement-exit-code-86"></a>
<a id="supported-platform--tool-version-matrix"></a>
<a id="wire-contract-compatibility-upgrade-ordering"></a>

See [Agent operations and troubleshooting](agent/operations.md).

<a id="1-what-the-agent-is"></a>

The agent uses observe-only mode until execution is enabled. See [Configuration](agent/configuration.md) and [Security](agent/security.md).
