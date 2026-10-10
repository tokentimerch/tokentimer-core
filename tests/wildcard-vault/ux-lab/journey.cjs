"use strict";
// Every product read/write goes through HTTP. No pg, SQL, internal service
// imports, fabricated agent receipts, clock manipulation or state-row updates.
const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const root = path.resolve(
  process.env.TT_WILDCARD_UX_OUTPUT ||
    path.resolve(__dirname, "../../../.scratch/wildcard-ux"),
);
fs.mkdirSync(root, { recursive: true });
const file = root + "/journey-state.json",
  state = fs.existsSync(file)
    ? JSON.parse(fs.readFileSync(file))
    : { runId: crypto.randomUUID(), completed: [], checks: [] };
const base = "http://127.0.0.1:" + (process.env.TT_UX_WEB_PORT || "58801"),
  controlBase = "http://127.0.0.1:" + (process.env.TT_UX_CONTROL_PORT || "58805"),
  mailBase = "http://127.0.0.1:" + (process.env.TT_UX_MAIL_PORT || "58803"),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
state.certificateMode ||= process.env.TT_UX_CERTIFICATE_MODE || "san";
state.coreCommit ||= process.env.TT_UX_CORE_COMMIT || null;
const certificateSans = state.certificateMode === "wildcard"
  ? ["*.wildcard.test", "wildcard.test"]
  : ["nginx.wildcard.test", "haproxy.wildcard.test"];
const save = () =>
  fs.writeFileSync(file, JSON.stringify(state, null, 2) + "\n", {
    mode: 0o600,
  });
function check(name, details = {}) {
  if (!state.checks.some((c) => c.name === name))
    state.checks.push({ name, passed: true, ...details });
  save();
  console.log("PASS " + name);
}
async function wait(label, fn, ms = 120000) {
  const until = Date.now() + ms;
  let last;
  while (Date.now() < until) {
    last = await fn();
    if (last) return last;
    await sleep(1000);
  }
  throw new Error("Timeout " + label);
}
class User {
  constructor(name) {
    this.name = name;
    this.sessionFile = root + "/session-" + name + ".json";
    const stored = fs.existsSync(this.sessionFile)
      ? JSON.parse(fs.readFileSync(this.sessionFile))
      : {};
    this.jar = new Map(stored.jar || []);
    this.csrf = stored.csrf || null;
  }
  saveSession() {
    fs.writeFileSync(this.sessionFile, JSON.stringify({
      jar: [...this.jar], csrf: this.csrf,
    }), { mode: 0o600 });
  }
  async request(route, method = "GET", body, expected = 200, headers = {}) {
    if (method !== "GET" && !this.csrf)
      this.csrf = (await this.request("/api/csrf-token")).csrfToken;
    const r = await fetch(base + route, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(12000),
      headers: {
        Cookie: [...this.jar].map(([k, v]) => k + "=" + v).join("; "),
        "Content-Type": "application/json",
        ...(this.csrf ? { "x-csrf-token": this.csrf } : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    for (const cookie of r.headers.getSetCookie()) {
      const pair = cookie.split(";")[0],
        i = pair.indexOf("=");
      this.jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    this.saveSession();
    const raw = await r.text();
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { text: raw.slice(0, 100) };
    }
    // Do not log request/response bodies or authentication headers.
    fs.appendFileSync(
      root + "/http-transcript.jsonl",
      JSON.stringify({
        at: new Date().toISOString(),
        actor: this.name,
        method,
        route: route.replace(/verify-email\/.+/, "verify-email/[redacted]"),
        status: r.status,
        code: data.code || null,
      }) + "\n",
    );
    assert.ok(
      [].concat(expected).includes(r.status),
      `${this.name} ${method} ${route}: ${r.status} ${JSON.stringify(data)}`,
    );
    return data;
  }
  async login(email, password) {
    if (this.jar.size) {
      const session = await this.request("/api/session");
      if (session.loggedIn && session.user?.email === email) {
        this.csrf = (await this.request("/api/csrf-token")).csrfToken;
        this.saveSession();
        return;
      }
    }
    await this.request("/auth/login", "POST", { email, password });
    this.csrf = null;
    this.csrf = (await this.request("/api/csrf-token")).csrfToken;
    this.saveSession();
  }
}
const owner = new User("owner"),
  approver = new User("approver");
async function customer(action, name = "issuer", extra = {}) {
  const r = await fetch(controlBase, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, name, ...extra }),
    signal: AbortSignal.timeout(20000),
  });
  const body = await r.json();
  assert.equal(r.status, 200, JSON.stringify(body));
  return body;
}
async function emailToken(email, type) {
  return wait(
    "captured " + type + " email",
    async () => {
      const list = await fetch(mailBase + "/api/v1/messages").then(
        (r) => r.json(),
      );
      for (const m of list.messages || []) {
        if (!(m.To || []).some((to) => to.Address === email)) continue;
        const message = await fetch(
          mailBase + "/api/v1/message/" + m.ID,
        ).then((r) => r.json());
        const text = (message.Text || "") + " " + (message.HTML || "");
        const match =
          type === "invite"
            ? text.match(/[?&]token=([a-f0-9]+)/)
            : text.match(/\/auth\/verify-email\/([A-Za-z0-9_-]+)/);
        if (match) return match[1];
      }
    },
    30000,
  );
}
const api = () => "/api/v1/workspaces/" + state.workspaceId + "/certops";
const group = () => api() + "/distribution-groups/" + state.groupId;
const job = async (id) => (await owner.request(api() + "/jobs/" + id)).job;
async function terminal(id, expected = "succeeded") {
  return wait(
    "job " + id,
    async () => {
      const j = await job(id);
      if (
        [
          "succeeded",
          "failed",
          "blocked",
          "rejected",
          "cancelled",
          "orphaned_unknown_effect",
        ].includes(j.status)
      ) {
        assert.ok([].concat(expected).includes(j.status), JSON.stringify(j));
        return j;
      }
    },
    180000,
  );
}
async function createJob(key, operation = "renew", payload = {}) {
  return (
    await owner.request(
      api() + "/jobs",
      "POST",
      {
        operation,
        ...(operation === "renew"
          ? {
              subjectType: "managed_certificate",
              subjectId: state.certificateId,
            }
          : {}),
        ...(operation === "issue"
          ? { assignedAgentId: state.agents.issuer.id }
          : {}),
        requiresApproval: true,
        idempotencyKey: state.runId + "-" + key,
        payload,
      },
      201,
    )
  ).job;
}
async function approve(id) {
  if ((await job(id)).status === "pending_approval")
    await approver.request(api() + "/jobs/" + id + "/approve", "POST", {
      reason: "Isolated UX lab approval",
    });
}
const versions = async () =>
  (await owner.request(group() + "/versions")).versions;
const matrix = async () =>
  (await owner.request(group() + "/consumers")).consumers;
async function rollout(
  key,
  version = state.versionId,
  extra = {},
  expected = 201,
) {
  return owner.request(
    group() + "/rollouts",
    "POST",
    { materialVersionId: version, maxParallel: 1, ...extra },
    expected,
    { "Idempotency-Key": state.runId + "-" + key },
  );
}
async function converge(ids = state.bindings.map((b) => b.id)) {
  return wait(
    "consumer convergence",
    async () => {
      const rows = await matrix();
      return ids.every(
        (id) => rows.find((row) => row.binding_id === id)?.converged === true,
      )
        ? rows
        : false;
    },
    180000,
  );
}
async function step(name, fn) {
  if (state.completed.includes(name)) return;
  console.log("RUN " + name);
  await fn();
  state.completed.push(name);
  save();
}
async function setup() {
  if (!state.workspaceId) {
    const w = await owner.request(
      "/api/v1/workspaces",
      "POST",
      { name: "Shared Certificate UX Lab " + state.runId.slice(0, 8) },
      201,
    );
    state.workspaceId = w.id || w.workspace?.id;
    assert.ok(state.workspaceId);
    save();
  }
  if (!state.approverEmail) {
    state.approverEmail =
      "approver-" + state.runId.slice(0, 8) + "@wildcard.test";
    save();
  }
  if (!state.approverCreated) {
    await owner.request(
      "/api/v1/workspaces/" + state.workspaceId + "/members",
      "POST",
      { email: state.approverEmail, role: "workspace_manager" },
      201,
    );
    const invite = await emailToken(state.approverEmail, "invite");
    await approver.request(
      "/auth/register",
      "POST",
      {
        token: invite,
        email: state.approverEmail,
        password: "LabApprover-2026!Only",
        first_name: "Lab",
        last_name: "Approver",
      },
      201,
    );
    state.approverCreated = true;
    save();
  }
  if (!state.approverRegistered) {
    const verification = await emailToken(state.approverEmail, "verify");
    await approver.request(
      "/auth/verify-email/" + verification,
      "GET",
      undefined,
      302,
    );
    state.approverRegistered = true;
    save();
  }
  await approver.login(state.approverEmail, "LabApprover-2026!Only");
  state.agents ||= {};
  state.consumerBindingIds ||= {
    nginx: crypto.randomUUID(),
    haproxy: crypto.randomUUID(),
  };
  save();
  for (const name of ["issuer", "nginx", "haproxy"]) {
    if (state.agents[name]) continue;
    const boot = await owner.request(
      api() + "/agent-bootstrap-tokens",
      "POST",
      {
        name: "UX " + name,
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
      201,
    );
    await customer("enroll", name, {
      token: boot.plaintextToken,
      ...(name === "issuer"
        ? {}
        : { selectors: [state.consumerBindingIds[name]] }),
    });
    const facts = await wait(
      "enrolled " + name,
      async () => {
        const f = await customer("facts", name);
        return f.wireId ? f : false;
      },
      30000,
    );
    const enrolled = (await owner.request(api() + "/agents")).items.find(
      (a) => a.agentId === facts.wireId,
    );
    assert.ok(enrolled);
    state.agents[name] = enrolled;
    save();
    await customer("stop", name);
  }
  check(
    "normal admin bootstrap, email invitation/verification and three enrolled agents",
  );
}
async function preparePublication() {
  if (!state.issueJob) {
    const j = await createJob("issue", "issue", {
      target: { type: "domain", reference: certificateSans[0] },
      sans: certificateSans,
      caEndpoint: "https://pebble:14000/dir",
      commandRef: "certbot",
      dnsProvider: "pebble-challtestsrv",
      dnsZone: "wildcard.test",
      keyAlgorithm: "ecdsa",
      keySize: 256,
      keyRotation: true,
      publicationDestination: {
        materialStoreRef: "customer",
        issuanceProfileRef: "wildcard",
        profileRevision: 1,
      },
    });
    state.issueJob = j.id;
    state.certificateId = j.subjectId;
    state.groupId = j.payload.publication.groupId;
    save();
  }
  if (!state.publicationPrepared) {
    await customer("configure", "issuer", {
      workspaceId: state.workspaceId,
      groupId: state.groupId,
    });
    await customer("start");
    state.publicationPrepared = true;
    save();
  }
}
async function publish() {
  await preparePublication();
  if ((await job(state.issueJob)).status === "pending_approval")
    await approve(state.issueJob);
  const j = await terminal(state.issueJob);
  state.versionId = j.payload.publication.materialVersionId;
  state.firstFacts = await customer("facts", "issuer", {
    certificateId: state.certificateId,
  });
  save();
  assert.equal(state.firstFacts.orders.length, 1);
  assert.equal(state.firstFacts.canonicalMode, "600");
  assert.equal(state.firstFacts.defaultKeyExists, false);
  check(
    "signed enrolled issuer: real DNS-01 order, Vault publication and custom canonical key",
    { jobId: j.id, versionId: state.versionId },
  );
  const detail = await owner.request(
    api() + "/certificates/" + state.certificateId,
  );
  assert.ok(detail.certificate.profileId);
  assert.equal(detail.certificate.renewal.state, "auto");
  assert.deepEqual([...detail.certificate.subjectAltNames].sort(), [...certificateSans].sort());
  const repairRoute =
    api() + "/certificates/" + state.certificateId + "/renewal-profile/repair";
  const repair = await owner.request(repairRoute, "POST", {});
  assert.equal(repair.created, false);
  assert.equal(repair.profileId, detail.certificate.profileId);
  await approver.request(repairRoute, "POST", {}, 403);
  await owner.request(repairRoute, "POST", { keyRotation: false }, 422);
  check(
    "SAN-only publication automatically configures renewal; repair preserves profile and enforces admin/input boundaries",
  );
}
async function bindings() {
  state.bindings ||= ["nginx", "haproxy"].map((name, wave) => ({
    name,
    id: state.consumerBindingIds[name],
    body: {
      agentId: state.agents[name].id,
      deploymentProfileRef: name,
      profileRevision: 1,
      required: true,
      wave,
      verificationPolicy: "trust",
      freshnessSeconds: 3600,
      state: "active",
    },
  }));
  save();
  for (const b of state.bindings) {
    const row = await owner.request(
      group() + "/consumers/" + b.id,
      "PUT",
      b.body,
    );
    assert.equal(row.authorization_revision, 1);
    await customer("configure", b.name, {
      workspaceId: state.workspaceId,
      groupId: state.groupId,
      bindingId: b.id,
    });
    await customer("start", b.name);
  }
  const r = await rollout("initial");
  state.rolloutJob = r.id;
  save();
  assert.equal((await rollout("initial")).id, r.id);
  for (const b of state.bindings) {
    const rows = await Promise.all(
      Array.from({ length: 3 }, () =>
        owner.request(group() + "/consumers/" + b.id, "PUT", b.body),
      ),
    );
    assert.ok(rows.every((row) => row.authorization_revision === 1));
  }
  check("concurrent unchanged PUTs and idempotent request before approval");
  await approve(r.id);
  await terminal(r.id);
  assert.equal((await rollout("initial")).id, r.id);
  const rows = await converge();
  const served = await Promise.all(["nginx", "haproxy"].map(name => customer("facts", name)));
  assert.equal(served[0].certificate.fingerprint256, served[1].certificate.fingerprint256);
  if (state.certificateMode === "san") {
    assert.ok(served.every(f => !f.certificate.subjectAltName.includes("*")));
    check("one ordinary SAN certificate, with no wildcard, is served by both destinations");
  }
  state.firstMatrix = rows;
  save();
  assert.equal((await rollout("initial")).id, r.id);
  await rollout("initial", state.versionId, { maxParallel: 2 }, 409);
  check(
    "actual outbox expansion, two served/trusted TLS consumers and replay after completion",
    { approvalJobId: r.id },
  );
  for (const b of state.bindings)
    await owner.request(group() + "/consumers/" + b.id, "PUT", b.body);
  assert.ok(
    (await matrix())
      .filter((row) => state.bindings.some((b) => b.id === row.binding_id))
      .every((row) => row.converged),
  );
  check("unchanged PUTs preserve deployed proof and convergence");
  const extraId = crypto.randomUUID(),
    extraBody = {
      ...state.bindings[0].body,
      deploymentProfileRef: "extra-membership-check",
      required: false,
      state: "active",
    };
  await owner.request(group() + "/consumers/" + extraId, "PUT", extraBody);
  assert.equal((await rollout("initial")).id, r.id);
  await owner.request(group() + "/consumers/" + extraId, "PUT", {
    ...extraBody,
    state: "removed",
  });
  check("request replay after consumer membership changes");
}
async function recovery() {
  if (!state.rejectedJob) {
    const rejected = await createJob("rejected");
    state.rejectedJob = rejected.id;
    save();
    await approver.request(api() + "/jobs/" + rejected.id + "/reject", "POST", {
      reason: "Correct local issuer settings",
    });
  }
  const rejectedVersion = (await versions()).find(
    (v) => v.publishing_job_id === state.rejectedJob,
  );
  assert.equal(rejectedVersion.state, "failed");
  assert.equal(
    rejectedVersion.allocation_release_reason,
    "rejected_before_execution",
  );
  if (!state.rotationJob) {
    const rotated = await createJob("corrected-rotation");
    state.rotationJob = rotated.id;
    save();
  }
  check(
    "reject unclaimed renewal, retained history and corrected same-group allocation",
  );
  if ((await job(state.rotationJob)).status === "pending_approval") {
    await customer("fault");
    await approve(state.rotationJob);
  }
  await terminal(state.rotationJob, ["failed", "orphaned_unknown_effect"]);
  await customer("stop");
  const before = await customer("facts", "issuer", {
    certificateId: state.certificateId,
  });
  assert.equal(before.fault.droppedWrites, 1);
  assert.equal(before.orders.length, 2);
  assert.equal(
    before.canonicalPublicKeySha256,
    state.firstFacts.canonicalPublicKeySha256,
  );
  await owner.request(
    api() + "/jobs",
    "POST",
    {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: state.certificateId,
      assignedAgentId: state.agents.issuer.id,
      requiresApproval: true,
      idempotencyKey: state.runId + "-must-stay-fenced",
      payload: {},
    },
    409,
  );
  check(
    "lost Vault write/read responses leave old key and block fresh issuance",
  );
  const blockedTransfer = await transferInventory(409);
  assert.equal(blockedTransfer.code, "CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED");
  assert.ok((await versions()).some(v => v.id === state.versionId));
  check("workspace transfer returns actionable 409 while a real Vault publication has uncertain effects");
  await customer("clear-fault");
  await owner.request(
    api() + "/distribution-jobs/" + state.rotationJob + "/retry",
    "POST",
    {},
  );
  await customer("start");
  await terminal(state.rotationJob);
  const rotated = await customer("facts", "issuer", {
    certificateId: state.certificateId,
  });
  assert.equal(rotated.orders.length, 2);
  assert.notEqual(
    rotated.canonicalPublicKeySha256,
    before.canonicalPublicKeySha256,
  );
  assert.equal(rotated.canonicalMode, "600");
  assert.equal(rotated.defaultKeyExists, false);
  state.rotatedFacts = rotated;
  save();
  check(
    "operator retries original job: recovery promotes rotated custom key without another order",
  );
  const recovered = await job(state.rotationJob);
  assert.equal(recovered.needsOperatorReconciliation, false);
  assert.equal(recovered.reconciliationReason, null);
  check("validated publication recovery clears its stale reconciliation fence");
  if (!state.reuseJob) {
    const certificate = await owner.request(
      api() + "/certificates/" + state.certificateId,
    );
    const profileId = certificate.certificate?.profileId;
    assert.ok(
      profileId,
      "issued certificate must expose its derived renewal profile",
    );
    await owner.request(api() + "/profiles/" + profileId, "PATCH", {
      renewalProfile: { keyRotationPolicy: { rotateOnRenew: false } },
    });
    await owner.request(
      api() +
        "/certificates/" +
        state.certificateId +
        "/renewal-profile/repair",
      "POST",
      {},
    );
    const preserved = await owner.request(api() + "/profiles/" + profileId);
    assert.equal(
      preserved.renewalProfile.keyRotationPolicy.rotateOnRenew,
      false,
    );
    const reuse = await createJob("reuse");
    state.reuseJob = reuse.id;
    save();
  }
  await approve(state.reuseJob);
  const reuse = await terminal(state.reuseJob);
  const after = await customer("facts", "issuer", {
    certificateId: state.certificateId,
  });
  assert.equal(after.orders.length, 3);
  assert.equal(
    after.orders.at(-1).publicKeySha256,
    rotated.canonicalPublicKeySha256,
  );
  state.renewedVersionId = reuse.payload.publication.materialVersionId;
  save();
  check(
    "next real ACME CSR reuses the recovered rotated key in custom directory",
  );
  await customer("stop", "haproxy");
  const renewed = await rollout("renewed", state.renewedVersionId);
  await approve(renewed.id);
  await terminal(renewed.id);
  await wait("canary current, offline consumer stale", async () => {
    const m = await matrix();
    return (
      m.find((r) => r.binding_id === state.bindings[0].id)
        ?.observed_material_version_id === state.renewedVersionId &&
      m.find((r) => r.binding_id === state.bindings[1].id)
        ?.observed_material_version_id === state.versionId
    );
  });
  check("renewed source never implies an offline consumer is current");
  await customer("start", "haproxy");
  await converge();
  check(
    "offline consumer catches up through signed pinned deployment without a fourth ACME order",
  );
}
async function authorization() {
  const b = state.bindings[0],
    pending = await rollout("revision-fence", state.renewedVersionId, {
      verificationOnly: true,
    });
  const changed = await owner.request(group() + "/consumers/" + b.id, "PUT", {
    ...b.body,
    freshnessSeconds: 1800,
  });
  assert.equal(changed.authorization_revision, 2);
  const same = await owner.request(group() + "/consumers/" + b.id, "PUT", {
    ...b.body,
    freshnessSeconds: 1800,
  });
  assert.equal(same.authorization_revision, 2);
  assert.equal(
    (await matrix()).find((r) => r.binding_id === b.id).converged,
    false,
  );
  assert.equal(
    (
      await rollout("revision-fence", state.renewedVersionId, {
        verificationOnly: true,
      })
    ).id,
    pending.id,
  );
  await approver.request(api() + "/jobs/" + pending.id + "/reject", "POST", {
    reason: "Binding authorization changed; request a fresh reviewed rollout",
  });
  check(
    "real binding change advances revision, invalidates proof and preserves original request identity",
  );
  const other = await approver.request(
    "/api/v1/workspaces",
    "POST",
    { name: "Isolated other tenant " + state.runId.slice(0, 8) },
    201,
  );
  state.otherWorkspaceId = other.id || other.workspace?.id;
  save();
  await owner.request(
    "/api/v1/workspaces/" +
      state.otherWorkspaceId +
      "/certops/distribution-groups/" +
      state.groupId +
      "/versions",
    "GET",
    undefined,
    [403, 404],
  );
  check("cross-tenant public API access denied");
  // Update customer-local policy after the genuine operator authorization change.
  await customer("configure", "nginx", {
    workspaceId: state.workspaceId,
    groupId: state.groupId,
    bindingId: b.id,
    authorizationRevision: 2,
  });
  await customer("start", "nginx");
  const repaired = await rollout("revision-approved", state.renewedVersionId);
  await approve(repaired.id);
  await terminal(repaired.id);
  await converge();
  check("reviewed local policy revision and new approval restore convergence");
}
async function rejection() {
  if (!state.rejectedIssue) {
    const pending = await createJob("reject-issue", "issue", {
      target: { type: "domain", reference: certificateSans[0] },
      sans: certificateSans,
      caEndpoint: "https://pebble:14000/dir",
      commandRef: "certbot",
      dnsProvider: "pebble-challtestsrv",
      dnsZone: "wildcard.test",
      keyAlgorithm: "ecdsa",
      keySize: 256,
      keyRotation: true,
      publicationDestination: {
        materialStoreRef: "customer",
        issuanceProfileRef: "rejection-only",
        profileRevision: 1,
      },
    });
    state.rejectedIssue = {
      id: pending.id,
      groupId: pending.payload.publication.groupId,
    };
    save();
  }
  if ((await job(state.rejectedIssue.id)).status === "pending_approval")
    await approver.request(
      api() + "/jobs/" + state.rejectedIssue.id + "/reject",
      "POST",
      { reason: "Reject unused publication before execution" },
    );
  await terminal(state.rejectedIssue.id, "rejected");
  const version = (
    await owner.request(
      api() +
        "/distribution-groups/" +
        state.rejectedIssue.groupId +
        "/versions",
    )
  ).versions.find((v) => v.publishing_job_id === state.rejectedIssue.id);
  assert.equal(version.state, "failed");
  assert.equal(version.allocation_release_reason, "rejected_before_execution");
  check(
    "public rejection releases never-claimed publication allocation and retains history",
  );
}
async function validation() {
  const before = (await owner.request(api() + "/jobs")).items.map(j => j.id).sort();
  for (const materialVersionId of [undefined, null, 42, [], "invalid-version"]) {
    const response = await owner.request(group() + "/rollouts", "POST",
      { materialVersionId, maxParallel: 1 }, 422,
      { "Idempotency-Key": state.runId + "-invalid-" + String(materialVersionId) });
    assert.equal(response.code, "CERTOPS_MATERIAL_CONTRACT_INVALID");
  }
  for (const [route, method, body] of [
    [api() + "/distribution-groups/invalid/versions", "GET"],
    [api() + "/distribution-groups/invalid/consumers", "GET"],
    [group() + "/consumers/invalid", "PUT", state.bindings[0].body],
    [api() + "/distribution-jobs/invalid/retry", "POST", {}],
  ]) {
    const response = await owner.request(route, method, body, 422);
    assert.equal(response.code, "CERTOPS_MATERIAL_CONTRACT_INVALID");
  }
  assert.deepEqual((await owner.request(api() + "/jobs")).items.map(j => j.id).sort(), before);
  check("nine malformed distribution requests return 422 and create no jobs");
}
async function scanner() {
  const prefix = state.workspaceId + "/" + state.groupId + "/bundles/";
  const before = (await customer("scanner-requests")).requests.length;
  for (const pathPrefix of [
    prefix + state.versionId,
    prefix.replace("bundles/", "%62undles/") + state.versionId,
    prefix.replace("bundles/", "%2562undles/") + state.versionId,
    prefix.replace("bundles/", "bundles//") + state.versionId,
    prefix + state.versionId + "?version=1",
  ]) {
    const result = await owner.request("/api/v1/integrations/vault/scan", "POST", {
      workspace_id: state.workspaceId,
      address: "http://customers:18020",
      token: "ux-lab-only-vault-token",
      include: { kv: true, pki: false },
      mounts: ["secret"],
      pathPrefix,
    });
    assert.deepEqual(result.items, []);
  }
  const requests = (await customer("scanner-requests")).requests.slice(before);
  assert.ok(requests.length >= 5);
  assert.ok(requests.every(r => r.method === "GET" && r.path === "/v1/sys/mounts"),
    "The product scanner must never request a real private bundle, even with a root Vault token");
  check("real Vault scans block five raw/encoded private bundle prefixes before any object request",
    { observedRequests: requests });
}
async function transferInventory(expected = 200) {
  if (!state.transferDestinationId) {
    const workspace = await owner.request("/api/v1/workspaces", "POST",
      { name: "Shared certificate destination " + state.runId.slice(0, 8) }, 201);
    state.transferDestinationId = workspace.id || workspace.workspace?.id;
    save();
  }
  const { certificate } = await owner.request(api() + "/certificates/" + state.certificateId);
  assert.ok(certificate.tokenId, "The real publication must link its public inventory asset");
  state.inventoryTokenId = certificate.tokenId;
  save();
  return owner.request("/api/v1/workspaces/" + state.transferDestinationId + "/transfer-tokens",
    "POST", { from_workspace_id: state.workspaceId, token_ids: [certificate.tokenId] }, expected);
}
async function transfer() {
  const before = await versions();
  const result = await transferInventory();
  assert.equal(result.moved, 1);
  await verifyTransferredInventory(before);
}
async function verifyTransferredInventory(before) {
  const destination = "/api/v1/workspaces/" + state.transferDestinationId + "/certops";
  const { certificate } = await owner.request(destination + "/certificates/" + state.certificateId);
  assert.equal(certificate.tokenId, state.inventoryTokenId);
  assert.equal(certificate.profileId, null);
  assert.equal(certificate.keyReference, null);
  assert.equal(certificate.deployedAgentId, null);
  assert.notEqual(certificate.renewal.state, "auto");
  assert.match(certificate.renewal.detail, /distribution is not configured in this workspace/);
  assert.doesNotMatch(certificate.renewal.detail, /repair/i);
  const refused = await owner.request(destination + "/certificates/" + state.certificateId + "/renewal-profile/repair", "POST", {}, 404);
  assert.equal(refused.code, "CERTOPS_DISTRIBUTION_NOT_FOUND");
  check("transferred inventory reports unconfigured distribution and refuses cross-workspace publication repair");
  assert.deepEqual((await owner.request(destination + "/distribution-groups")).groups, []);
  if (before) assert.deepEqual((await versions()).map(v => v.id).sort(), before.map(v => v.id).sort());
  assert.equal((await owner.request(api() + "/distribution-groups")).groups
    .find(g => g.id === state.groupId).state, "retired");
  assert.equal((await job(state.issueJob)).status, "succeeded");
  check("public inventory transfers without a destination Vault integration; source material/job history stays put and destination management is unconfigured",
    { destinationWorkspaceId: state.transferDestinationId, tokenId: state.inventoryTokenId });
}
async function main() {
  await wait(
    "API startup",
    async () => {
      try {
        return (
          (
            await fetch(base + "/api/csrf-token", {
              signal: AbortSignal.timeout(2000),
            })
          ).status === 200
        );
      } catch {
        return false;
      }
    },
    60000,
  );
  await owner.login("owner@wildcard.test", "LabOwner-2026!Only");
  if (state.approverRegistered)
    await approver.login(state.approverEmail, "LabApprover-2026!Only");
  const phase = process.argv[2] || "all";
  if (phase === "transfer-status") {
    await verifyTransferredInventory();
    return;
  }
  if (phase === "prepare-publication") {
    await preparePublication();
    assert.equal((await job(state.issueJob)).status, "pending_approval");
    check("publication prepared through the API for a different user's browser approval", { jobId: state.issueJob });
    return;
  }
  if (phase === "repair") {
    const repaired = await owner.request(
      api() +
        "/certificates/" +
        state.certificateId +
        "/renewal-profile/repair",
      "POST",
      {},
    );
    assert.ok(repaired.profileId);
    const replay = await owner.request(
      api() +
        "/certificates/" +
        state.certificateId +
        "/renewal-profile/repair",
      "POST",
      {},
    );
    assert.equal(replay.profileId, repaired.profileId);
    assert.equal(replay.created, false);
    const detail = await owner.request(
      api() + "/certificates/" + state.certificateId,
    );
    assert.equal(detail.certificate.renewal.state, "auto");
    check(
      "supported repair of existing SAN-only publication, idempotent replay and renewable UI state",
    );
    return;
  }
  if (phase === "inspect") {
    console.log(
      JSON.stringify(
        {
          certificate: await owner.request(
            api() + "/certificates/" + state.certificateId,
          ),
          issue: await job(state.issueJob),
        },
        null,
        2,
      ),
    );
    return;
  }
  if (phase === "status") {
    console.log(
      JSON.stringify(
        {
          jobs: await owner.request(api() + "/jobs"),
          consumers: await matrix(),
        },
        null,
        2,
      ),
    );
    return;
  }
  if (phase === "resume-consumer") {
    for (const row of await matrix())
      if (row.latest_deployment?.stage === "orphaned_unknown_effect") {
        const j = await job(row.latest_deployment.jobId);
        await owner.request(
          group() +
            "/rollouts/" +
            j.payload.materialDeployment.rolloutId +
            "/state",
          "POST",
          { state: "deploying" },
        );
        await owner.request(
          api() + "/distribution-jobs/" + j.id + "/retry",
          "POST",
          {},
        );
      }
    check(
      "operator repairs local service, reconciles uncertain binding and retries through API",
    );
    return;
  }
  for (const [name, fn] of Object.entries({
    setup,
    publish,
    bindings,
    validation,
    scanner,
    rejection,
    authorization,
    recovery,
    transfer,
  }))
    if (phase === "all" || phase === name) await step(name, fn);
  if (phase === "all") {
    const facts = await customer("facts", "issuer", {
      certificateId: state.certificateId,
    });
    assert.equal(facts.orders.length, 3);
    state.passed = true;
    state.finishedAt = new Date().toISOString();
    state.databaseInjection = false;
    state.experimentalAgentBuild = true;
    state.limits = [
      "Core lab only; Cloud/Enterprise billing/license flows are not exercised here.",
      "Lab-only experimental build, Pebble CA and development Vault token; no customer/release qualification.",
      "Never-claimed cancellation is not exercised: no standalone public job-cancel API exists, and agent retirement fences claimed/running work only.",
      "Historical backfill cannot be manufactured through public APIs; previous migration regression remains separate evidence.",
    ];
    save();
    fs.writeFileSync(
      root + "/report.json",
      JSON.stringify(
        {
          passed: true,
          coreCommit: state.coreCommit,
          certificateMode: state.certificateMode,
          runId: state.runId,
          workspaceId: state.workspaceId,
          checks: state.checks,
          acmeOrders: 3,
          databaseInjection: false,
          limits: state.limits,
        },
        null,
        2,
      ) + "\n",
    );
    console.log(
      "Lab journey passed. Dashboard " +
        base +
        "; workspace " +
        state.workspaceId,
    );
  }
}
main().catch((e) => {
  state.passed = false;
  state.finishedAt = new Date().toISOString();
  save();
  fs.writeFileSync(
    root + "/report.json",
    JSON.stringify(
      {
        passed: false,
        coreCommit: state.coreCommit,
        certificateMode: state.certificateMode,
        runId: state.runId,
        workspaceId: state.workspaceId,
        completed: state.completed,
        checks: state.checks,
        databaseInjection: false,
        experimentalAgentBuild: true,
        failure: e.message,
        failedPhase: process.argv[2] || "all",
      },
      null,
      2,
    ) + "\n",
  );
  console.error(e);
  process.exitCode = 1;
});
