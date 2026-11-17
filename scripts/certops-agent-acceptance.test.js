"use strict";
// Synthetic API/decision fixtures only. No real acceptance or qualification.
const test = require("node:test"), assert = require("node:assert/strict");
const subject = require("./certops-agent-acceptance.cjs");
const { CAPABILITIES, TOOLCHAIN } = require("./certops-azure-keyvault-package.cjs");
const source = "a".repeat(40), merge = "b".repeat(40), head = "c".repeat(40), digest = "d".repeat(64);
function receipt() {
  const proof = i => ({ runId: String(1000 + i), artifactId: String(2000 + i), artifactSha256: String(i).repeat(64), sourceSha: source });
  return { schemaVersion: 1, status: "accepted", packageVersion: "0.20.0", packageSha256: digest,
    packageSourceSha: source, packageArtifact: proof(6), capabilities: [...CAPABILITIES], toolchain: { ...TOOLCHAIN },
    review: { pullRequest: 123, reviewer: "independent-reviewer" }, nativeAgentEvidence: "azure-operator-http-real-ca",
    evidence: Object.fromEntries(subject.REQUIRED.map((name, i) => [name, proof(i + 1)])) };
}
function api(value) {
  const prefix = "repos/tokentimerch/tokentimer-core", responses = new Map();
  responses.set(`${prefix}/pulls/123`, { merged: true, base: { ref: "main" },
    head: { sha: head, repo: { full_name: "tokentimerch/tokentimer-core" } }, user: { login: "fixture-author" }, merge_commit_sha: merge });
  responses.set(`${prefix}/pulls/123/reviews?per_page=100`, [
    { state: "APPROVED", commit_id: head, user: { login: value.review.reviewer } },
  ]);
  responses.set(`${prefix}/commits/${merge}`, { commit: { verification: { verified: true } } });
  responses.set(`${prefix}/contents/${subject.RECEIPT}?ref=${merge}`,
    { encoding: "base64", content: Buffer.from(JSON.stringify(value)).toString("base64") });
  for (const proof of [value.packageArtifact, ...Object.values(value.evidence)]) {
    responses.set(`${prefix}/actions/runs/${proof.runId}`, { id: Number(proof.runId), status: "completed", conclusion: "success",
      event: "workflow_dispatch", head_branch: "main", run_attempt: 1, head_sha: source, path: ".github/workflows/certops-fixture.yml" });
    responses.set(`${prefix}/actions/artifacts/${proof.artifactId}`, { id: Number(proof.artifactId), expired: false,
      workflow_run: { id: Number(proof.runId), head_sha: source }, digest: `sha256:${proof.artifactSha256}` });
  }
  return { responses, read: async endpoint => {
    assert.ok(responses.has(endpoint), `Unexpected offline API endpoint: ${endpoint}`);
    return structuredClone(responses.get(endpoint));
  }, isAncestor: () => true };
}

test("acceptance requires the exact package, full operator and installed-agent evidence plus advertised Azure auth modes", () => {
  const good = receipt();
  subject.verify(good, digest);
  for (const mutate of [
    r => { r.status = "pending"; },
    r => { r.packageSha256 = "e".repeat(64); },
    r => { r.packageArtifact.sourceSha = merge; },
    r => { r.capabilities.pop(); },
    r => { r.toolchain.npmVersion = "11.6.2"; },
    r => { delete r.evidence["azure-operator-http-real-ca"]; },
    r => { delete r.evidence["openbao-operator-http-real-ca"]; },
    r => { delete r.evidence["azure-imds-managed-identity"]; },
    r => { r.evidence["azure-natural-access-token-expiration"] = null; },
    r => { r.nativeAgentEvidence = "azure-provider-and-cleanup"; },
    r => { r.productionQualified = true; },
  ]) {
    const bad = structuredClone(good); mutate(bad);
    assert.throws(() => subject.verify(bad, digest), mutate.toString());
  }
  assert.throws(() => subject.verify(good, ""));
});

test("synthetic reviewed receipt is bound to its merged decision and immutable successful main artifacts", async () => {
  const value = receipt(); subject.verify(value, digest);
  await subject.verifyGithub(value, api(value));
});

test("receipt cannot borrow self-review, stale approval, an unsigned decision or a different merged receipt", async () => {
  for (const mutate of [
    a => { a.responses.get("repos/tokentimerch/tokentimer-core/pulls/123").merged = false; },
    a => { a.responses.get("repos/tokentimerch/tokentimer-core/pulls/123").base.ref = "feature"; },
    a => { a.responses.get("repos/tokentimerch/tokentimer-core/pulls/123").user.login = "independent-reviewer"; },
    a => { a.responses.get("repos/tokentimerch/tokentimer-core/pulls/123/reviews?per_page=100")[0].commit_id = source; },
    a => { a.responses.get("repos/tokentimerch/tokentimer-core/pulls/123/reviews?per_page=100")[0].state = "DISMISSED"; },
    a => { a.responses.get(`repos/tokentimerch/tokentimer-core/commits/${merge}`).commit.verification.verified = false; },
    a => { a.responses.get(`repos/tokentimerch/tokentimer-core/contents/${subject.RECEIPT}?ref=${merge}`).content = Buffer.from("{}").toString("base64"); },
    a => { a.isAncestor = () => false; },
  ]) {
    const value = receipt(), metadata = api(value); mutate(metadata);
    await assert.rejects(subject.verifyGithub(value, metadata), mutate.toString());
  }
});

test("accepted decision cannot borrow a PR run, failed or rerun campaign, foreign source, expired or different artifact", async () => {
  for (const [kind, patch] of [
    ["run", { event: "pull_request" }], ["run", { conclusion: "failure" }], ["run", { run_attempt: 2 }],
    ["run", { head_branch: "feature" }], ["run", { head_sha: merge }], ["run", { path: ".github/workflows/ci.yml" }],
    ["artifact", { expired: true }], ["artifact", { digest: `sha256:${"e".repeat(64)}` }],
    ["artifact", { workflow_run: { id: 9999, head_sha: source } }],
  ]) {
    const value = receipt(), metadata = api(value), proof = value.packageArtifact;
    const endpoint = kind === "run" ? `actions/runs/${proof.runId}` : `actions/artifacts/${proof.artifactId}`;
    Object.assign(metadata.responses.get(`repos/tokentimerch/tokentimer-core/${endpoint}`), patch);
    await assert.rejects(subject.verifyGithub(value, metadata), JSON.stringify(patch));
  }
});
