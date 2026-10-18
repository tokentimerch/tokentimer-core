"use strict";
// Public API actions and external TLS probes only. No service imports, SQL or
// agent result fabrication. Customer controls alter only this disposable host.
const assert = require("node:assert/strict");
const tls = require("node:tls");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createHostGate } = require("../../../packages/agent/scripts/host-gate");
const SOURCE = "tests/wildcard-vault/ux-lab/journey.cjs";
const PHASES = [
  "setup",
  "publish",
  "bindings",
  "validation",
  "scanner",
  "rejection",
  "authorization",
  "recovery",
  "deployment-recovery",
  "qualification",
  "security",
  "runtime-controls",
  "browser",
  "privacy",
  "transfer",
];
const SUITE = "distribution-agent-lab";
function createGate({ root, candidateSha, mode }) {
  const metadata = require("../../../docs/certops/qualification-suites.json");
  const gate = createHostGate({
    suite: SUITE,
    strict: true,
    evidenceLevel: "e2e",
    candidateSha,
    reportPath: path.join(root, "qualification.json"),
    fixtureSource: {
      file: SOURCE,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(__dirname, "journey.cjs")))
        .digest("hex"),
    },
    requiredCapabilities: metadata.requiredCapabilities[SUITE],
    probeCapabilities: async () => ({
      "fresh-owned-lab": {
        available: !fs.existsSync(path.join(root, "journey-state.json")),
      },
      "explicit-candidate": {
        available: /^[a-f0-9]{40}$/.test(candidateSha || ""),
      },
      "browser-runtime": {
        available: fs.existsSync(
          require("playwright").chromium.executablePath(),
        ),
      },
    }),
  });
  // Source mounts and the lab-only capability manifest are explicit. The release
  // collector MUST reject this report even if every functional case passes.
  Object.assign(gate.report, {
    supportingRunId: path.basename(root),
    experimental: true,
    qualificationStatus: "not-qualified",
    databaseInjection: false,
    qualificationScope: process.env.TT_UX_PACKAGE_ACCEPTANCE === "1" ? "packaged-enrolled-agent-lab" : "source-mounted-enrolled-agent-lab",
    allFeaturesQualified: false,
  });
  gate.report.qualificationEnvironment.certificateMode = mode;
  gate.report.fixtureSources =
    require("../../../docs/certops/qualification-suites.json")
      .slots.find((s) => s.suite === SUITE)
      .requiredSources.map((file) => ({
        file,
        sha256: crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.resolve(__dirname, "../../..", file)))
          .digest("hex"),
      }));
  return gate;
}
const fingerprint = (value) => String(value).replaceAll(":", "").toLowerCase();
async function served(port, sni, ca) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: "127.0.0.1",
      port,
      servername: sni,
      ca,
      rejectUnauthorized: true,
    });
    socket.setTimeout(5000, () =>
      socket.destroy(new Error("TLS probe timeout")),
    );
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      const leaf = socket.getPeerCertificate();
      socket.end();
      resolve(fingerprint(leaf.fingerprint256));
    });
  });
}
async function extend(c) {
  const {
    state,
    owner,
    approver,
    api,
    group,
    versions,
    matrix,
    rollout,
    approve,
    terminal,
    job,
    customer,
    wait,
    converge,
    check,
    save,
  } = c;
  const initial = (await versions()).find((v) => v.id === state.versionId);
  const current = (await versions()).find(
    (v) => v.id === state.renewedVersionId,
  );
  assert.equal(initial.state, "published");
  assert.equal(current.state, "published");
  const immutable = (value) => [
    value.id,
    value.provider_version,
    value.fingerprint_sha256,
    value.valid_to,
  ];
  const historical = immutable(initial);
  const beforeOrders = (await customer("facts", "issuer")).orders.length;
  const browser = (label) =>
    require("./browser.cjs").inspect({
      state,
      owner,
      base: "http://127.0.0.1:" + (process.env.TT_UX_WEB_PORT || 58801),
      matrix,
      root: c.root,
      label,
    });
  const externalProof = async (version) => {
    const ca = (await customer("facts", "issuer")).publicTrustCaPem;
    const expected = fingerprint(version.fingerprint_sha256);
    for (const [name, port] of [
      ["nginx", Number(process.env.TT_UX_NGINX_PORT || 58843)],
      ["haproxy", Number(process.env.TT_UX_HAPROXY_PORT || 58943)],
    ]) {
      const sni =
        state.certificateMode === "ordinary"
          ? "nginx.wildcard.test"
          : name + ".wildcard.test";
      const installed = await customer("facts", name);
      assert.equal(fingerprint(installed.certificate.fingerprint256), expected);
      assert.equal(
        await served(port, sni, ca),
        expected,
        "independent external TLS leaf must match immutable version",
      );
    }
  };
  await externalProof(current);
  // Change membership through the actual admin route; the same authenticated
  // manager session must immediately lose mutation/approval rights as a viewer.
  const session = await approver.request("/api/session");
  const member =
    "/api/v1/workspaces/" + state.workspaceId + "/members/" + session.user.id;
  await owner.request(member, "PATCH", { role: "viewer" });
  try {
    await approver.request(group() + "/versions", "GET", undefined, 403);
    await approver.request(
      group() + "/consumers/" + state.bindings[0].id,
      "PUT",
      state.bindings[0].body,
      403,
    );
    await approver.request(
      group() + "/rollouts",
      "POST",
      { materialVersionId: current.id, maxParallel: 1 },
      403,
    );
    await approver.request(
      api() + "/distribution-jobs/" + state.recoveredDeploymentJobId + "/retry",
      "POST",
      {},
      403,
    );
  } finally {
    await owner.request(member, "PATCH", { role: "workspace_manager" });
  }
  check(
    "viewer cannot read operator distribution versions, mutate bindings, request rollouts or retry jobs; admin restores manager rights",
  );
  // Real same-key retries concurrently resolve one approval and frozen intent.
  const concurrent = await Promise.all(
    Array.from({ length: 4 }, () =>
      rollout("qualified-concurrent", current.id, { maxParallel: 2 }),
    ),
  );
  assert.equal(new Set(concurrent.map((r) => r.id)).size, 1);
  await owner.request(
    api() + "/jobs/" + concurrent[0].id + "/approve",
    "POST",
    { reason: "self approval must fail" },
    [403, 409],
  );
  await approve(concurrent[0].id);
  await terminal(concurrent[0].id);
  await converge();
  check(
    "concurrent rollout requests serialize one frozen approval; self approval is refused",
  );

  // Offline required canary prevents later-wave dispatch. Control-plane approval
  // success cannot count as consumer success. Pause and resume use real routes.
  await customer("stop", "nginx");
  await customer("stop", "haproxy");
  const r = await rollout("qualified-canary", current.id);
  await approve(r.id);
  const approved = await terminal(r.id);
  assert.equal(approved.status, "succeeded");
  const pending = await wait("real first wave queued", async () => {
    const rows = await matrix();
    const id = rows.find((x) => x.binding_id === state.bindings[0].id)
      ?.latest_deployment?.jobId;
    return id &&
      (await job(id)).payload.materialDeployment.generation ===
        approved.payload.distributionRollout.generation
      ? rows
      : false;
  });
  const first = pending.find((x) => x.binding_id === state.bindings[0].id);
  const next = pending.find((x) => x.binding_id === state.bindings[1].id);
  assert.equal(
    next.latest_deployment?.jobId || null,
    null,
    "later wave cannot be queued before required canary verification",
  );
  assert.ok(
    pending.every((x) => !x.converged),
    "successful approval job cannot imply deployment",
  );
  await browser("pending-canary");
  const canaryJob = await job(first.latest_deployment.jobId);
  const pinned = canaryJob.payload.materialDeployment;
  assert.equal(pinned.materialVersionId, current.id);
  assert.equal(pinned.authorizationRevision, 2);
  const control = group() + "/rollouts/" + pinned.rolloutId + "/state";
  await owner.request(control, "POST", { state: "paused" });
  await customer("start", "nginx");
  await new Promise((resolve) => setTimeout(resolve, 4500));
  assert.notEqual((await job(canaryJob.id)).status, "succeeded");
  await owner.request(control, "POST", { state: "deploying" });
  await terminal(canaryJob.id);
  const waveOne = await wait("verified canary releases next wave", async () => {
    const rows = await matrix();
    return rows.find((x) => x.binding_id === state.bindings[1].id)
      ?.latest_deployment?.jobId
      ? rows
      : false;
  });
  assert.equal(
    waveOne.find((x) => x.binding_id === state.bindings[0].id).converged,
    true,
  );
  assert.equal(
    waveOne.find((x) => x.binding_id === state.bindings[1].id).converged,
    false,
  );
  await customer("start", "haproxy");
  await converge();
  check(
    "offline canary, frozen version/revision, pause/resume and wave ordering verified through real agents",
  );

  // Optional consumer failure preserves the successful required deployment.
  // Both bindings share wave zero here so maxParallel=2 can admit both jobs.
  const optional = state.bindings[1];
  const optionalRow = await owner.request(
    group() + "/consumers/" + optional.id,
    "PUT",
    { ...optional.body, required: false, wave: 0 },
  );
  await customer("configure", "haproxy", {
    workspaceId: state.workspaceId,
    groupId: state.groupId,
    bindingId: optional.id,
    authorizationRevision: optionalRow.authorization_revision,
  });
  await customer("fail-reload", "haproxy");
  await customer("start", "haproxy");
  const partial = await rollout("qualified-partial", current.id, {
    maxParallel: 2,
  });
  await approve(partial.id);
  await terminal(partial.id);
  const failed = await wait(
    "optional real reload fails independently",
    async () => {
      const rows = await matrix(),
        row = rows.find((x) => x.binding_id === optional.id);
      return row?.latest_deployment?.stage === "orphaned_unknown_effect" &&
        rows.find((x) => x.binding_id === state.bindings[0].id)?.converged
        ? job(row.latest_deployment.jobId)
        : false;
    },
  );
  assert.equal(
    (await matrix()).find((x) => x.binding_id === optional.id).converged,
    false,
  );
  await browser("optional-failure");
  await customer("repair-reload", "haproxy");
  assert.equal(
    (await customer("reconcile-binding", "haproxy", { bindingId: optional.id }))
      .reconciled,
    true,
  );
  assert.equal((await job(failed.id)).needsOperatorReconciliation, true);
  await owner.request(
    api() + "/distribution-jobs/" + failed.id + "/retry",
    "POST",
    {},
  );
  await owner.request(
    group() +
      "/rollouts/" +
      failed.payload.materialDeployment.rolloutId +
      "/state",
    "POST",
    { state: "deploying" },
  );
  await customer("start", "haproxy");
  await terminal(failed.id);
  await converge();
  const restored = await owner.request(
    group() + "/consumers/" + optional.id,
    "PUT",
    optional.body,
  );
  await customer("configure", "haproxy", {
    workspaceId: state.workspaceId,
    groupId: state.groupId,
    bindingId: optional.id,
    authorizationRevision: restored.authorization_revision,
  });
  await customer("start", "haproxy");
  check(
    "optional native reload failure preserves required consumer proof and requires real reconciliation before retry",
  );

  // New approval explicitly pins the older immutable version. No ACME call.
  const rollback = await rollout("qualified-rollback", initial.id);
  assert.equal((await job(rollback.id)).status, "pending_approval");
  await approve(rollback.id);
  await terminal(rollback.id);
  await converge();
  await externalProof(initial);
  assert.deepEqual(
    immutable((await versions()).find((v) => v.id === initial.id)),
    historical,
  );
  const restore = await rollout("qualified-restore", current.id);
  await approve(restore.id);
  await terminal(restore.id);
  await converge();
  await externalProof(current);
  // Verification-only mismatch observes drift; it must not install or reload.
  const drift = await rollout("qualified-drift", initial.id, {
    verificationOnly: true,
  });
  await approve(drift.id);
  await terminal(drift.id);
  await wait("actual verification-only mismatch", async () =>
    (await matrix()).some((x) => x.latest_deployment?.stage === "failed"),
  );
  await browser("verification-drift");
  await externalProof(current);
  const verify = await rollout("qualified-verify", current.id, {
    verificationOnly: true,
    maxParallel: 2,
  });
  await approve(verify.id);
  await terminal(verify.id);
  await converge();
  await externalProof(current);
  assert.equal((await customer("facts", "issuer")).orders.length, beforeOrders);
  check(
    "approved rollback and restore, drift refusal and verification-only recovery use retained immutable versions without ACME",
  );

  // Retirement is the supported rollout cancellation operation. Retire while
  // unclaimed and prove that starting both genuine agents cannot deploy it.
  await customer("stop", "nginx");
  await customer("stop", "haproxy");
  const cancel = await rollout("qualified-cancel", initial.id);
  await approve(cancel.id);
  const cancellation = await terminal(cancel.id);
  const unstarted = await wait("unstarted cancellation target", async () => {
    const row = (await matrix()).find(
      (x) => x.binding_id === state.bindings[0].id,
    );
    const j = row?.latest_deployment?.jobId
      ? await job(row.latest_deployment.jobId)
      : null;
    return j?.payload.materialDeployment.generation ===
      cancellation.payload.distributionRollout.generation
      ? j
      : false;
  });
  await owner.request(
    group() +
      "/rollouts/" +
      unstarted.payload.materialDeployment.rolloutId +
      "/state",
    "POST",
    { state: "retired" },
  );
  await customer("start", "nginx");
  await customer("start", "haproxy");
  await new Promise((resolve) => setTimeout(resolve, 4500));
  assert.notEqual((await job(unstarted.id)).status, "succeeded");
  await externalProof(current);
  // A fresh explicit verification restores convergence after retired intent.
  const final = await rollout("qualified-final", current.id, {
    verificationOnly: true,
  });
  await approve(final.id);
  await terminal(final.id);
  await converge();
  assert.equal((await customer("facts", "issuer")).orders.length, beforeOrders);
  state.qualificationProof = {
    initialVersion: initial.id,
    currentVersion: current.id,
    independentTls: true,
    acmeOrders: beforeOrders,
  };
  save();
  check(
    "retired unstarted rollout cannot replace current leaf or rewrite publication history",
  );
}
module.exports = { createGate, extend, served, fingerprint, PHASES, SUITE };
