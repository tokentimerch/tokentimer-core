# Public signed Linux trust lifecycle composition

The dedicated manual source lane is implemented; actual native execution remains pending.
Existing API trust tests create and retire metadata; the Linux trust host
qualifier calls the executor directly. Neither proves the complete public
admission, signed dispatch, native mutation and authenticated result path.

## Reachable existing contract

An authenticated workspace administrator creates public CA material through
`POST /api/v1/workspaces/{id}/certops/trust-anchors`. The existing manual jobs
route accepts `distribute-trust` and `revoke-trust` with `subjectType` equal to
`trust_anchor`, the anchor's `subjectId`, the registered agent's `agentId`, an
explicit owner and the normal idempotency key. Its dedicated creator updates
the installation row transactionally with admission. Managers must receive 403.

The real agent requires its embedded `trust-anchor-deploy-v1` declaration and
the local `trust-store:update-ca-certificates` command reference. Configure its argv explicitly as
`["/usr/sbin/update-ca-certificates", "--fresh"]` for this isolated fixture,
so signed install and revoke both refresh derived links. The signed executor
does not currently forward the native direct-call fresh-profile seam; merely
listing a separate fresh command profile would not change its behavior. Never
silently rewrite an operator's existing profile. Inspect the
actual candidate artifact; do not change a release capability manifest to make
this fixture pass. The current checked-in build input already includes that
capability. The executor uses its configured state directory's trust receipts,
emits `trust.distributed` or `trust.revoked` evidence, and submits structured
trust results through ordinary authenticated result delivery.

## Disposable native lane

The workflow uses a separate explicit Ubuntu 24 runner with root authority, the existing
isolated API/PostgreSQL fixture, and one genuinely registered foreground agent.
Do not elevate or broaden the ordinary nonroot ACME lane. No DNS provider,
Azure, external CA or certificate distribution service is needed.

Generate one owned root, an intermediate issued by it, a leaf requiring that
intermediate and a separate leaf issued directly by the root. Keep all private
material inside an original mode-0700 directory with mode-0600 files. Register
sticky ownership before the first API/native mutation.

1. Independently require both leaves to fail default OS verification before
   installation. Invoke OpenSSL with `-purpose sslserver` and the exact hostname;
   provide no CA file or chain file that could bypass the actual OS inventory.
2. Admit root distribution through the public route; require a genuine signed
   current claim, consumed nonce, succeeded result, finalized native receipt,
   installation row and current-claim evidence. Verify the direct leaf through
   default OS-derived trust.
3. Admit intermediate distribution the same way. Verify the intermediate leaf
   without supplying its missing intermediate to the oracle. Require native
   source and derived-link identities independently of the job status.
4. Revoke only the owned intermediate through the public route. Require actual
   removal evidence and receipt transition. The intermediate leaf must fail;
   the direct leaf and root source/receipt identities must remain unchanged.
5. Revoke the root through the public route. Both leaves must fail, both owned
   source entries and derived references must be absent, and installation rows
   must match actual authenticated results before releasing native ownership.

Bind all four jobs to distinct actual claims, one dispatch each, the original
agent/workspace, exact anchor fingerprints and their typed root/intermediate
intent. Public responses or persisted status alone cannot qualify a step.
Capture real production receipt/result field names before implementing the
closed proof projection; this design deliberately defines no invented schema.

## Cleanup and implementation boundary

Drain the retained agent process before any private or database cleanup. On a
failed step, remove only a verified original receipt-owned source through the
existing native ownership rules and refresh the OS store. A missing, replaced,
corrupt or ambiguous receipt must preserve the fixture and fail cleanup.
Independent failed trust verification and absence of owned references are
required before deleting recovery files or public rows. Host disposal is a
separate operational boundary, not a measured cleanup success.

The producer is `scripts/certops-linux-signed-trust.js`; invoke only through the
trusted-main manual `certops-linux-signed-trust.yml` workflow on its disposable
Ubuntu24 host. It fails if root, Node24, embedded capability, local command or
isolated API prerequisites are absent. No released manifest is modified.
The separate report is `qualification-results/linux-signed-trust.json`. The
workflow verifies that report with the strict scenario verifier and both closed
proofs before upload. The closed Node/Python proof is also mandatory in the one
declared Ubuntu24 matrix cell. This lane does not claim native qualification.
Supporting tests validate actual route authorization/creator selection, native
job binding, strict proof/source adversaries and real directory replacement;
they are not native execution evidence. No native trust operation, service
action or workflow dispatch has been executed locally.

If any mutation or ownership check is uncertain, the runner drains retained
agent resources but preserves the original root, receipts and public rows. The
workflow refuses database-volume teardown without a passed cleanup report.
No automated recovery or installed-service/background reconciliation claim is
made. Hosted VM disposal remains an operational boundary rather than a measured
fixture recovery.
