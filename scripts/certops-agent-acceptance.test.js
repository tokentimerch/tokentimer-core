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
    evidence: Object.fromEntries(subject.REQUIRED.map((name, i) => [name, { ...proof(i + 1), ...(i === 0 ? { runId: "1006" } : {}) }])) };
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
      workflow_run: { id: Number(proof.runId), head_sha: source }, digest: `sha256:${proof.artifactSha256}`, size_in_bytes: 100 });
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

test("metadata contract binds its merged decision and immutable main artifacts, without accepting their contents", async () => {
  const value = receipt(); subject.verify(value, digest);
  await subject.verifyMetadata(value, api(value));
  await assert.rejects(subject.verifyGithub(value, api(value)), "metadata alone must never authorize publication");
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
    await assert.rejects(subject.verifyMetadata(value, metadata), mutate.toString());
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
    await assert.rejects(subject.verifyMetadata(value, metadata), JSON.stringify(patch));
  }
});

const fixture = require("./test-support/final-package-evidence.cjs");
const profiles = require("./certops-final-package-evidence.cjs");
function contentSuite(t) {
  const value = receipt(), candidate = fixture.candidate(t, source), payloads = new Map(), reports = new Map();
  value.packageSha256 = candidate.digest;
  payloads.set(value.packageArtifact.artifactId, fixture.zip(candidate.entries));
  const identity = subject.packageIdentity(value), azure = require("./certops-azure-keyvault-report");
  const provider = azure.emptyReport(source, candidate.digest, identity);
  provider.scenarios.forEach(row => { row.status = "passed"; }); provider.counts = azure.counts(provider.scenarios);
  Object.assign(provider, { status: "passed", databaseCleanup: "completed", facts: { ambiguousPutAttempts: 1,
    recoveredProviderVersions: 1, acceptedProviderPins: 2, azure401Responses: 1, azure403Responses: 4, entraTokenExchanges: 4, exactPackageVerified: true } });
  for (const scope of subject.REQUIRED) {
    const proof = value.evidence[scope];
    if (scope === "azure-provider-and-cleanup") payloads.set(proof.artifactId, fixture.zip([
      ["azure-keyvault-evidence.json", JSON.stringify(provider)], ["azure-keyvault-cleanup.json", JSON.stringify({ schemaVersion: 1,
        sourceSha: source, cleanup: "completed", purgeRequested: false })],
    ]));
    else {
      const report = fixture.report(scope, source, proof.runId, identity, candidate.files); reports.set(scope, report);
      payloads.set(proof.artifactId, fixture.zip([[profiles.PROFILES[scope].file, JSON.stringify(report)]]));
    }
  }
  const dependencies = () => {
    for (const proof of [value.packageArtifact, ...Object.values(value.evidence)]) proof.artifactSha256 = fixture.hash(payloads.get(proof.artifactId));
    const metadata = api(value);
    for (const proof of [value.packageArtifact, ...Object.values(value.evidence)]) {
      metadata.responses.get(`repos/tokentimerch/tokentimer-core/actions/artifacts/${proof.artifactId}`).size_in_bytes = payloads.get(proof.artifactId).length;
      Object.assign(metadata.responses.get(`repos/tokentimerch/tokentimer-core/actions/runs/${proof.runId}`), {
        run_started_at: "2026-11-17T12:00:00Z", updated_at: "2026-11-17T14:10:00Z" });
    }
    return { ...metadata, download: async id => payloads.get(id) };
  };
  return { value, candidate, provider, reports, payloads, dependencies };
}

test("content gate authenticates ZIP bytes and accepts only complete synthetic profiles bound to the archive", async t => {
  const suite = contentSuite(t);
  subject.verify(suite.value, suite.candidate.digest);
  await subject.verifyGithub(suite.value, suite.dependencies());
  const dependencies = suite.dependencies(), id = suite.value.evidence["azure-provider-and-cleanup"].artifactId;
  const changed = Buffer.from(suite.payloads.get(id)); changed[40] ^= 1;
  await assert.rejects(subject.verifyGithub(suite.value, { ...dependencies, download: async key => key === id ? changed : suite.payloads.get(key) }));
});

test("green metadata cannot substitute provider-only, generic PASS, wrong source or incomplete native/operator payloads", async t => {
  const suite = contentSuite(t), scope = "azure-operator-http-real-ca", id = suite.value.evidence[scope].artifactId;
  const valid = structuredClone(suite.reports.get(scope));
  const substitutions = [suite.payloads.get(suite.value.evidence["azure-provider-and-cleanup"].artifactId),
    fixture.zip([[profiles.PROFILES[scope].file, JSON.stringify(suite.provider)]]),
    fixture.zip([[profiles.PROFILES[scope].file, JSON.stringify({ status: "passed" })]])];
  for (const mutate of [r => { r.sourceSha = merge; }, r => { r.packageArtifact.packageSha256 = "0".repeat(64); },
    r => { r.scenarios.pop(); }, r => { r.cleanup.resources = "failed"; }, r => { r.nativeService = null; },
    r => { r.nativeService.kind = "node-process-container"; }, r => { r.nativeService.installedFileHashes["bin/tokentimer-agent.js"] = "0".repeat(64); },
    r => { r.nativeService.after.procUid = 999; }, r => { r.nativeService.after = structuredClone(r.nativeService.before); },
    r => { r.facts.ca.fixture = true; }, r => { r.facts.http.directDatabaseInjection = true; },
    r => { r.facts.jobs.verified = 0; }, r => { r.facts.identities[1].subjectSha256 = r.facts.identities[0].subjectSha256; }]) {
    const bad = structuredClone(valid); mutate(bad); substitutions.push(fixture.zip([[profiles.PROFILES[scope].file, JSON.stringify(bad)]]));
  }
  for (const bytes of substitutions) {
    suite.payloads.set(id, bytes);
    await assert.rejects(subject.verifyGithub(suite.value, suite.dependencies()));
  }
});

test("ZIP reader rejects CRC corruption, duplicate/traversing members, links and unbounded declared sizes", () => {
  const zip = require("./certops-artifact-zip.cjs"), valid = fixture.zip([["report.json", "{}"]]);
  assert.equal(zip.read(valid).get("report.json").toString(), "{}");
  const corrupt = Buffer.from(valid); corrupt[30 + "report.json".length] ^= 1;
  const link = Buffer.from(valid), central = valid.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  link.writeUInt32LE(0xa0000000, central + 38);
  const bomb = Buffer.from(valid); bomb.writeUInt32LE(zip.LIMIT + 1, central + 24);
  for (const bytes of [corrupt, link, bomb, fixture.zip([["report.json", "{}"], ["report.json", "{}"]]),
    fixture.zip([["../report.json", "{}"]])]) assert.throws(() => zip.read(bytes));
});

test("IMDS and natural-expiry slots reject simulated endpoints, forced failures and clocks outside the real run", t => {
  const suite = contentSuite(t);
  for (const [scope, mutate] of [
    ["azure-imds-managed-identity", r => { r.facts.authMode = "token-file"; }],
    ["azure-imds-managed-identity", r => { r.facts.imdsHost = "127.0.0.1"; }],
    ["azure-imds-managed-identity", r => { r.facts.azureConsumerWriteStatus = 200; }],
    ["azure-imds-managed-identity", r => { r.facts.identities[1].hostIdSha256 = r.facts.identities[0].hostIdSha256; }],
    ["azure-imds-managed-identity", r => { r.facts.identities[0].oppositeIdentityTokenStatus = 200; }],
    ["azure-natural-access-token-expiration", r => { r.facts.azureStatusExpired = "network-error"; }],
    ["azure-natural-access-token-expiration", r => { r.facts.azureStatusBefore = 401; }],
    ["azure-natural-access-token-expiration", r => { r.facts.forced401 = true; }],
    ["azure-natural-access-token-expiration", r => { r.facts.clockOverridden = true; }],
    ["azure-natural-access-token-expiration", r => { r.facts.renewedAt = r.facts.expiresAt - 1; }],
    ["azure-natural-access-token-expiration", r => { r.facts.observedExpiredAt += 10000; r.facts.renewedAt += 10000; r.facts.renewedExpiresAt += 10000; }],
  ]) {
    const report = structuredClone(suite.reports.get(scope)); mutate(report);
    assert.throws(() => profiles.verify(scope, report, { sourceSha: source, runId: suite.value.evidence[scope].runId,
      packageIdentity: subject.packageIdentity(suite.value), files: suite.candidate.files, requireNative: false,
      run: { run_started_at: "2026-11-17T12:00:00Z", updated_at: "2026-11-17T14:10:00Z" } }));
  }
});
