"use strict";
// All Core interactions use authenticated HTTP. Customer controls operate only
// the owned host; no SQL, fake receipt, re-signing or replay-ledger edits.
const assert = require("node:assert/strict");
const { served, fingerprint } = require("./qualification.cjs");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const starts = facts => facts.reloadEvents.filter(x => x.event === "start").length;
async function leaf(c, name, expected) {
  const facts = await c.customer("facts", name);
  const sni = c.state.certificateMode === "ordinary" ? "nginx.wildcard.test" : name + ".wildcard.test";
  const port = Number(process.env[name === "nginx" ? "TT_UX_NGINX_PORT" : "TT_UX_HAPROXY_PORT"] || (name === "nginx" ? 58843 : 58943));
  assert.equal(fingerprint(facts.certificate.fingerprint256), fingerprint(expected));
  assert.equal(await served(port, sni, facts.publicTrustCaPem), fingerprint(expected));
  return facts;
}
async function security(c) {
  const { state, owner, customer, matrix, job, wait, rollout, approve, terminal, converge, api, group, check } = c;
  const current = (await c.versions()).find(x => x.id === state.renewedVersionId);
  const browser = require("./browser.cjs");
  const base = "http://127.0.0.1:" + (process.env.TT_UX_WEB_PORT || 58801);
  await browser.inspect({ state, owner: c.approver, base, matrix, root: c.root, label: "manager" });
  const manager = (await c.approver.request("/api/session")).user.id;
  const member = "/api/v1/workspaces/" + state.workspaceId + "/members/" + manager;
  await owner.request(member, "PATCH", { role: "viewer" });
  try { await browser.viewerRefused({ state, viewer: c.approver, base }); }
  finally { await owner.request(member, "PATCH", { role: "workspace_manager" }); }
  check("real browser allows workspace manager distribution and denies the same session after viewer demotion; admin reads remain covered");
  // Authenticate and retrieve with the real agent using a genuinely revoked
  // read-only Vault token. A verification-only job must fail before mutation.
  await customer("stop", "nginx");
  const before = await leaf(c, "nginx", current.fingerprint_sha256);
  await customer("revoke-material-token", "nginx");
  const denied = await rollout("security-revoked-consumer", current.id, { verificationOnly: true });
  await approve(denied.id); await terminal(denied.id);
  await customer("start", "nginx");
  const failed = await wait("revoked consumer credential fails genuine fetch", async () => {
    const row = (await matrix()).find(x => x.binding_id === state.bindings[0].id);
    if (!["failed", "orphaned_unknown_effect"].includes(row?.latest_deployment?.stage)) return false;
    const result = await job(row.latest_deployment.jobId);
    return result.payload.materialDeployment.materialVersionId === current.id ? result : false;
  });
  if (failed.status === "orphaned_unknown_effect") assert.equal(failed.needsOperatorReconciliation, true);
  assert.equal((await matrix()).find(x => x.binding_id === state.bindings[0].id).converged, false);
  const unchanged = await leaf(c, "nginx", current.fingerprint_sha256);
  assert.equal(unchanged.certificate.modifiedAt, before.certificate.modifiedAt);
  assert.equal(starts(unchanged), starts(before));
  await customer("stop", "nginx");
  await customer("rotate-material-token", "nginx");
  await owner.request(api() + "/distribution-jobs/" + failed.id + "/retry", "POST", {});
  await owner.request(group() + "/rollouts/" + failed.payload.materialDeployment.rolloutId + "/state", "POST", { state: "deploying" });
  await customer("start", "nginx");
  const recovered = await terminal(failed.id); await converge();
  assert.equal(recovered.needsOperatorReconciliation, false, "only a validated current receipt resolves the server fence");
  check("revoked consumer Vault token blocks real retrieval without mutation; rotated credential recovers the original pinned job");

  const history = (await matrix()).filter(row => state.bindings.some(binding => binding.id === row.binding_id));
  const successful = await Promise.all(history.map(row => job(row.latest_deployment.jobId)));
  assert.ok(successful.every(value => value.status === "succeeded" && value.completedAt));
  for (const mode of ["signature", "payload", "foreign-agent", "replay"]) {
    const prior = await customer("facts", "nginx");
    const metric = mode === "foreign-agent" ? "foreignAgentRejected" : mode === "replay" ? "replayRejected" : "signatureRejected";
    const armed = await customer("transport-fault", "nginx", { mode });
    await wait("real agent rejects " + mode + " dispatch", async () => {
      const facts = await customer("facts", "nginx");
      return facts.transport.injected > armed.injected && facts.security[metric] > prior.security[metric];
    }, 20000);
    const after = await leaf(c, "nginx", current.fingerprint_sha256);
    assert.equal(after.certificate.modifiedAt, prior.certificate.modifiedAt);
    assert.equal(starts(after), starts(prior));
    for (const original of successful) {
      const now = await job(original.id);
      assert.equal(now.status, "succeeded", "attack cannot rewrite the original successful outcome");
      assert.equal(now.completedAt, original.completedAt);
    }
    assert.ok((await matrix()).filter(row => state.bindings.some(binding => binding.id === row.binding_id)).every(row => row.converged));
  }
  check("real CLI rejects corrupted signatures, modified version pins, foreign-agent delivery and genuine signed replays without reload or history rewrite");
}
async function runtimeControls(c) {
  const { state, owner, approver, customer, matrix, job, wait, rollout, approve, terminal, converge, api, group, check } = c;
  const current = (await c.versions()).find(x => x.id === state.renewedVersionId);
  const old = (await c.versions()).find(x => x.id === state.versionId);
  const orders = (await customer("facts", "issuer")).orders.length;
  // A manager cannot flip the workspace incident control. Existing work is
  // claimed only after the real admin clears pause, even after approval.
  await approver.request(api() + "/settings", "PUT", { certOpsPaused: true }, 403);
  await customer("stop", "nginx"); await customer("stop", "haproxy");
  const paused = await rollout("workspace-pause", current.id, { verificationOnly: true });
  await approve(paused.id); await terminal(paused.id);
  const pending = await wait("queued work before workspace pause", async () => {
    const row = (await matrix()).find(x => x.binding_id === state.bindings[0].id);
    const value = row?.latest_deployment?.jobId ? await job(row.latest_deployment.jobId) : null;
    return value?.payload.materialDeployment.materialVersionId === current.id && value.status === "pending" ? value : false;
  });
  const control = group() + "/rollouts/" + pending.payload.materialDeployment.rolloutId + "/state";
  await owner.request(api() + "/settings", "PUT", { certOpsPaused: true, reason: "Isolated qualification containment" });
  try {
    await owner.request(control, "POST", { state: "paused" });
    await owner.request(control, "POST", { state: "deploying" }, [403, 409]);
    await owner.request(group() + "/rollouts", "POST", { materialVersionId: current.id, maxParallel: 1 }, [403, 409]);
    await customer("start", "nginx"); await customer("start", "haproxy");
    await sleep(4500);
    assert.equal((await job(pending.id)).status, "pending");
    assert.equal((await matrix()).find(x => x.binding_id === state.bindings[0].id).converged, false);
    await leaf(c, "nginx", current.fingerprint_sha256);
    await require("./browser.cjs").inspect({ state, owner, base: "http://127.0.0.1:" + (process.env.TT_UX_WEB_PORT || 58801), matrix, root: c.root, label: "workspace-paused" });
  } finally {
    await owner.request(api() + "/settings", "PUT", { certOpsPaused: false, reason: "Owned qualification resume" });
  }
  await owner.request(control, "POST", { state: "deploying" });
  await converge();
  check("workspace admin pause fences actual claims while allowing containment; managers cannot bypass it; explicit resume recovers pending work");

  // Put both required consumers in the same wave, then hold real service-hook
  // processes to establish serialization/overlap independently of API receipts.
  const binding = state.bindings[1];
  const changed = await owner.request(group() + "/consumers/" + binding.id, "PUT", { ...binding.body, wave: 0 });
  await customer("configure", "haproxy", { workspaceId: state.workspaceId, groupId: state.groupId, bindingId: binding.id, authorizationRevision: changed.authorization_revision });
  await customer("start", "haproxy");
  for (const maxParallel of [1, 2]) {
    const baseline = {};
    for (const name of ["nginx", "haproxy"]) {
      baseline[name] = starts(await customer("facts", name));
      await customer("hold-reload", name);
    }
    try {
      const request = await rollout("real-concurrency-" + maxParallel, current.id, { maxParallel });
      await approve(request.id); await terminal(request.id);
      await wait("real reload barrier admission", async () => {
        const facts = await Promise.all(["nginx", "haproxy"].map(name => customer("facts", name)));
        const admitted = facts.filter((value, index) => starts(value) > baseline[["nginx", "haproxy"][index]]).length;
        return admitted === maxParallel;
      }, 15000);
      if (maxParallel === 1) {
        await sleep(3000);
        const facts = await Promise.all(["nginx", "haproxy"].map(name => customer("facts", name)));
        assert.equal(facts.reduce((sum, value, index) => sum + starts(value) - baseline[["nginx", "haproxy"][index]], 0), 1);
      } else {
        const facts = await Promise.all(["nginx", "haproxy"].map(name => customer("facts", name)));
        for (const value of facts) assert.equal(value.reloadEvents.at(-1).event, "start", "both real hooks must overlap before release");
      }
    } finally {
      await customer("release-reload", "nginx"); await customer("release-reload", "haproxy");
    }
    await converge();
  }
  check("maxParallel one serializes actual reload hooks; maxParallel two admits overlapping NGINX and HAProxy hooks");
  const restored = await owner.request(group() + "/consumers/" + binding.id, "PUT", binding.body);
  await customer("configure", "haproxy", { workspaceId: state.workspaceId, groupId: state.groupId, bindingId: binding.id, authorizationRevision: restored.authorization_revision });
  await customer("start", "haproxy");

  // Replace the installed pair outside the agent, reload the genuine service,
  // and ask for CURRENT verification. Drift must fail and remain physically
  // visible until a separately approved mutating rollout repairs it.
  await customer("replace-local-material", "nginx", { materialVersionId: old.id });
  const drifted = await leaf(c, "nginx", old.fingerprint_sha256);
  const verify = await rollout("filesystem-drift", current.id, { verificationOnly: true });
  await approve(verify.id); await terminal(verify.id);
  await customer("start", "nginx");
  await wait("actual filesystem drift is rejected", async () => {
    const row = (await matrix()).find(x => x.binding_id === state.bindings[0].id);
    return row?.latest_deployment?.stage === "failed" && !row.converged;
  });
  const stillDrifted = await leaf(c, "nginx", old.fingerprint_sha256);
  assert.equal(stillDrifted.certificate.modifiedAt, drifted.certificate.modifiedAt);
  assert.equal(starts(stillDrifted), starts(drifted));
  const repair = await rollout("filesystem-drift-repair", current.id);
  await approve(repair.id); await terminal(repair.id); await converge();
  await leaf(c, "nginx", current.fingerprint_sha256); await leaf(c, "haproxy", current.fingerprint_sha256);
  assert.equal((await customer("facts", "issuer")).orders.length, orders);
  check("physical old-version drift fails verification without mutation; explicitly approved repair restores current TLS without a new ACME order");
}
module.exports = { security, runtimeControls };
