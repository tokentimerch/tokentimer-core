# TokenTimer Agent

The agent runs on the host that holds certificate keys. TokenTimer plans and audits work; the agent enforces local policy and executes allowed jobs. It connects outbound to the control plane over HTTPS and does not accept inbound connections. Private keys stay on the host.

## Start here

1. Enable CertOps on the control plane and prepare a workspace bootstrap token.
2. Follow [Install on Linux](agent/install-linux.md) or [Install on Windows](agent/install-windows.md).
3. Prepare [local policy and configuration](agent/configuration.md), verify a signed dry-run, then opt into real execution.

An agent with `execution.enabled: false` registers, heartbeats, and can report configured certificate discovery; it does not poll for or claim jobs. To test signed jobs, set `execution.enabled: true` and keep `execution.dryRun: true`, then restart and request a job with `mode: "dry_run"`. Real jobs are refused while that local safety switch is on. Enabling execution does not bypass local policy.

## Task guides

- [DNS and ACME](agent/dns-and-acme.md): provider credentials, zone routing, DNS-01, and the external HTTP-01 workflow.
- [Trust and signing-key rotation](agent/trust-and-key-rotation.md): CA distribution/revocation and signing-key changes.
- [Operations](agent/operations.md): upgrades, troubleshooting, compatibility, and retirement.

## Advanced reference

- [Protocol and job contracts](agent/protocol.md).
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

See [Agent protocol and job contracts](agent/protocol.md).

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
