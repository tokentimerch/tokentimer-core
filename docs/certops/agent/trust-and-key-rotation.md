# Trust distribution and signing-key rotation

Use this reference when changing trust stores or the control-plane signing key. These are separate operations: CA anchors establish host trust; the signing key authenticates jobs. Configure only the command profiles needed for the operation.

<a id="signing-key-rotation-lifecycle"></a>

### Signing-key rotation lifecycle

The control plane supports an overlapping old/new signing-key rotation so a
fleet does not lose the ability to accept jobs the moment a key is retired:

1. `beginSigningKeyRotation()` creates a new Ed25519 key as `active` and
   moves the previous key to `retiring` (still accepted for verification
   until fully retired).
2. Heartbeat responses include a `signingKeyRotation` field when the calling
   agent's pinned key is not yet the new active key:

   ```json
   {
     "signingKeyRotation": {
       "pendingSigningKeyId": "ttsk_<new>",
       "pendingPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
       "supersedesSigningKeyId": "ttsk_<old>",
       "status": "pending_ack"
     }
   }
   ```

   `signingKeyRotation` is `null` once the agent has already pinned the
   active key.
3. The agent adopts the pending key (TOFU update) and acknowledges on its
   next heartbeat by echoing `pinnedSigningKeyId` equal to
   `pendingSigningKeyId`. The server records the acknowledgement in
   `certops_signing_key_acks`.
4. `completeSigningKeyRotation()` retires the `retiring` key only once every
   `active` agent has acknowledged, or when an operator forces incomplete
   rotation (`force: true`, reason logged on the key row) to bound how long a
   single unresponsive agent can block retirement of a compromised key.

Rotation is deliberately operator-initiated, never automatic or
time-based: nothing calls `beginSigningKeyRotation()` on its own. The
operator entry point is the `certops-rotate-signing-key` CLI, run from the
API image or a repo checkout with the same env as the API process:

```bash
pnpm certops:rotate-signing-key status
pnpm certops:rotate-signing-key begin
pnpm certops:rotate-signing-key complete
pnpm certops:rotate-signing-key complete --force --reason "agent-07 decommissioned"
```

`status` reports the active key, any `retiring` key, and the
acknowledgement count against the active-agent count, so an operator can see
whether `complete` would succeed before running it. `--force` requires
`--reason` (recorded on the key row and in the audit event). Both `begin` and
`complete` write `CERTOPS_SIGNING_KEY_ROTATION_STARTED` /
`CERTOPS_SIGNING_KEY_ROTATION_COMPLETED` audit events.

There is deliberately **no HTTP route** for this: `certops_signing_keys` is
deployment-global (no `workspace_id`, single active key per deployment), so a
workspace-scoped route would be the wrong authorization boundary. On managed
Cloud, rotation is an operator action, not a tenant action.

<a id="trust-anchor-distribution-and-revocation"></a>

### Trust-anchor distribution and revocation

`distribute-trust`/`revoke-trust` (`executeTrustJob` in `src/index.js`,
executor in `src/trust-store/index.js`) install or remove one CA certificate
in the host's machine trust store on behalf of the control plane. Each job
carries `trustAnchorId`, `anchorType` (`root` or `intermediate`),
`fingerprintSha256`, and (for `distribute-trust` only) the anchor's `pem`.
Unlike `renew`/`deploy`, there is no per-target policy path check: the target
is the platform's own trust store, resolved from `anchorType` and the
detected OS family, never re-derived from the certificate's own
basicConstraints/issuer at run time.

Platform resolution is a hard gate before anything else runs: Windows targets
`LocalMachine\Root` (root anchors) or `LocalMachine\CA` (intermediates) via
`certutil`; Debian-family hosts write to
`/usr/local/share/ca-certificates` and run `update-ca-certificates`;
RHEL-family hosts write to `/etc/pki/ca-trust/source/anchors` and run
`update-ca-trust extract`. A host that is neither Windows nor a detected
Debian/RHEL-family trust store reports `blocked`, never a silent no-op.

On Linux the hardened unit also has to be allowed to write those
directories. `install-agent.sh` grants that automatically on Ubuntu
22.04/24.04/26.04 and AlmaLinux 9 when the family update command exists
(pass `--no-trust-store` to skip). Without that grant, distribute fails
with `EROFS` on the anchors directory even though the agent advertised
`trust-anchor-deploy-v1`; as of 0.14.2 that failure is a tagged
`trust_store_not_writable` result rather than a thrown error that
surfaces as a generic job-execution failure. Do not chown the system CA
store. Windows needs no extra grant: LocalSystem already writes
`LocalMachine\Root` / `LocalMachine\CA`.

AlmaLinux 9 (and other RHEL-family hosts) get the same recursive ACL grant,
but the grant is necessary, not sufficient: `update-ca-trust extract`'s
underlying `p11-kit` step calls `chmod(2)` on the extracted
directory-hash bundle directory, an operation that requires ownership no
POSIX ACL can confer. That `chmod` can fail (non-zero exit) even while the
consolidated trust bundle is genuinely regenerated and the certificate is
genuinely trusted. Before 0.14.2 this was reported as a false-negative
`os_mutation_failed`, and a later `revoke-trust` on the same target would
then refuse permanently with `receipt_pending_install` (there was no
agent-side path to recover a target stuck this way; it required manual
root intervention). As of 0.14.2, `distribute-trust` re-observes the real
anchors-directory state before trusting that exit code: if the certificate
is genuinely present it reports `installed` with the non-zero exit's output
carried as a non-fatal warning, and `revoke-trust` can additionally unwind
a `pending_install` receipt it finds already stranded from an older agent,
as long as the anchor is still observably present.

Debian-family revoke has a related but separate gap: plain
`update-ca-certificates` reports "0 added, 0 removed" and does not prune a
just-removed anchor's dangling `/etc/ssl/certs` symlink - only
`update-ca-certificates --fresh` does. As of 0.14.2, `revoke-trust` prefers
a policy-supplied `--fresh` argv under the
`trust-store:update-ca-certificates-fresh` profile (see the config
reference above) when the operator has configured it, and otherwise falls
back to the pre-0.14.2 behaviour with a non-fatal `debian_fresh_command_ref_missing`
warning on the result rather than silently leaving the symlink.

The hardened unit's `PrivateTmp=true` (shipped in
`packages/agent/scripts/tokentimer-agent.service`) matters specifically
here: `update-ca-certificates`/`update-ca-trust extract` both call
`mktemp` internally, and without `PrivateTmp=true`, `ProtectSystem=strict`
leaves the real `/tmp` read-only, so the update command fails at `mktemp`
before it ever touches the anchors directory - a failure mode easy to
mistake for the anchors-directory grant itself being missing. A manually
written unit (bypassing `install-agent.sh`) that omits `PrivateTmp=true`
will reproduce this even with every other grant correctly in place.

On every platform the update command/executable is gated through the same
`policyEngine.checkCommandRef` allowlist as ACME/reload commands, under the
`trust-store:update-ca-certificates` / `trust-store:update-ca-trust` /
`trust-store:certutil` profile names (see the [configuration reference](configuration.md)): on
Debian/RHEL this gates the full update-command argv (executable plus fixed
args); on Windows it gates the `certutil` executable itself, since the rest
of that platform's argv (`-addstore`/`-delstore`, store name, staging path)
is built from validated agent-local inputs rather than an operator-supplied
template. Either way, an agent whose policy omits the profile for its own
platform refuses the job with `command_not_allowlisted` before attempting
any mutation, so a renew-only agent (no `allowedCommands` profiles at all)
cannot be made to run `distribute-trust`/`revoke-trust` on any platform.

Ownership is proven locally, not just server-side: before mutating the store,
the agent writes an intent record to `<configDir>/trust-receipts/`, keyed by
`(store, fingerprintSha256)` (see the [state-directory table](configuration.md#config-directory)), and fsyncs it
**before** attempting the OS-level mutation; the receipt is finalized only
after the mutation completes. `revoke-trust` refuses to remove anything for a
`(store, fingerprintSha256)` pair with no readable, `installed` receipt:
a missing or corrupt receipt fails closed, never treated as license to
proceed. Every result reports one of four outcomes (`preexisting`,
`installed`, `already_absent`, `removed`) plus the observed pre/post
fingerprint at the store, restricted per action: `distribute-trust` may only
ever report `preexisting`, `installed`, or `already_absent` (its own
failure-fallback outcome; `already_absent` on a `distribute-trust` result
always means the install attempt failed before or during the mutation, never
that nothing needed doing), and `revoke-trust` may only ever report
`already_absent`, `removed`, or `installed` (its own failure-fallback
outcome, meaning the removal attempt failed and the material is still
there). The control plane rejects any result whose `agentId`, `store`,
`fingerprintSha256`, or `transitionGeneration` does not match the signed job
it claims to answer (`CERTOPS_TRUST_RESULT_MISMATCH`), and separately
rejects a result naming its own action's failure-fallback outcome on a job
already classified succeeded (`CERTOPS_TRUST_RESULT_INVALID`), since that
combination is self-contradictory.
A crashed `pending_install` receipt from an earlier attempt is reclaimed
automatically by a later `distribute-trust` job for the same key once the
agent has confirmed the fingerprint is genuinely absent from the OS store,
rather than permanently blocking that key until an operator deletes the
receipt file by hand. If instead the OS mutation itself succeeds but the
agent's own local receipt-finalize write fails, the control plane still
settles the installation row on the observed outcome (`installed`/`removed`)
rather than unwinding it, and records `receipt_finalize_conflict` in the
row's `last_error`; a later `revoke-trust` on that same target can then fail
with the agent's own `receipt_pending_install`. As of 0.14.2 there are two
ways to recover that: re-run `distribute-trust` for the same target, which
retries the finalize write and clears the stale receipt state, or simply
re-run `revoke-trust` directly - it now re-observes the real anchors-
directory state before refusing, and unwinds (finalizes, then removes) a
`pending_install` receipt it finds stranded whenever the anchor is still
observably present, only falling back to the original refusal when it
genuinely is not. See ADR-0012 decisions 6 and (d) (twelfth amendment)
for the full ownership-reference and crash-recovery contract.

Dry-run mode behaves identically to the renewal chain above: `mode: "dry_run"`
reports the platform/command gates as `policy.checked` evidence and returns
`dry_run_complete` with no filesystem or exec side effects, including no
receipt write.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
