"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseArgs, verifyArchiveChecksum, ownsResource, resourceIsMissing, redactDiagnostic, assertLedgerUpgrade, assertAgentContinuity, OWNER_LABEL } = require("./rehearse-core-upgrade");

const digest = "a".repeat(64);
const args = () => [
  "--candidate-api", "ghcr.io/tokentimerch/tokentimer-core-api@sha256:" + digest,
  "--candidate-worker", "ghcr.io/tokentimerch/tokentimer-core-worker@sha256:" + digest,
  "--source-sha", "a".repeat(40),
  "--image-source-sha", "b".repeat(40),
  "--agent-source-sha", "c".repeat(40),
  "--old-agent", "/tmp/old.tgz",
  "--candidate-agent", "/tmp/new.tgz",
  "--candidate-agent-sha256", digest,
  "--out", "/tmp/receipt.json",
];

test("rehearsal refuses mutable or wrong-component candidate images and missing provenance", () => {
  assert.equal(parseArgs(args())["image-source-sha"], "b".repeat(40));
  assert.equal(parseArgs(args())["agent-source-sha"], "c".repeat(40));
  for (const value of ["ghcr.io/tokentimerch/tokentimer-core-api:0.18.0", "ghcr.io/tokentimerch/tokentimer-core-worker@sha256:" + digest, "other.example/core-api@sha256:" + digest]) {
    const input = args(); input[1] = value;
    assert.throws(() => parseArgs(input), /immutable Core image digest/);
  }
  for (const option of ["--image-source-sha", "--agent-source-sha"]) {
    const missing = args(); missing.splice(missing.indexOf(option), 2);
    assert.throws(() => parseArgs(missing), new RegExp(option));
  }
  assert.throws(() => parseArgs([...args(), "--source-sha", "c".repeat(40)]), /exactly once/);
});

test("agent archive bytes must match the separately supplied receipt", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "tt-upgrade-checksum-test-"));
  try {
    const archive = path.join(temporary, "archive.tgz");
    fs.writeFileSync(archive, "known artifact bytes");
    const checksum = crypto.createHash("sha256").update("known artifact bytes").digest("hex");
    verifyArchiveChecksum(archive, checksum);
    fs.appendFileSync(archive, "changed");
    assert.throws(() => verifyArchiveChecksum(archive, checksum), /checksum mismatch/);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
});

test("cleanup requires both this run's exact owner label and its name namespace", () => {
  const owner = "0123456789abcdef";
  const name = "tt-upgrade-" + owner + "-database";
  assert.equal(ownsResource(name, { [OWNER_LABEL]: owner }, owner), true);
  assert.equal(ownsResource(name, {}, owner), false);
  assert.equal(ownsResource(name, { [OWNER_LABEL]: "another-run" }, owner), false);
  assert.equal(ownsResource("production-db", { [OWNER_LABEL]: owner }, owner), false);
  assert.equal(ownsResource("tt-upgrade-" + owner + "suffix-database", { [OWNER_LABEL]: owner }, owner), false);
});

test("cleanup cannot mistake daemon or permission failures for an absent resource", () => {
  const name = "tt-upgrade-0123456789abcdef-probe-1";
  assert.equal(resourceIsMissing("Error: No such container: " + name, name), true);
  assert.equal(resourceIsMissing("Error response from daemon: network " + name + " not found", name), true);
  assert.equal(resourceIsMissing("permission denied while inspecting " + name, name), false);
  assert.equal(resourceIsMissing("Cannot connect to the Docker daemon", name), false);
  assert.equal(resourceIsMissing("Error: No such container: another-name", name), false);
});

test("failure diagnostics redact credentials and withhold private material or raw row data", () => {
  const secret = "isolated-password-value";
  const safe = redactDiagnostic("startup failed: password=" + secret + " Authorization: Bearer bearer-value ttagent_abcdef0123456789.secret", [secret]);
  assert.ok(!safe.includes(secret) && !safe.includes("bearer-value") && !safe.includes("ttagent_"));
  assert.equal(redactDiagnostic("connect ECONNREFUSED database:5432"), "connect ECONNREFUSED database:5432");
  const key = crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" });
  for (const material of [key, Buffer.from(key).toString("base64"), "A".repeat(64) + "\n-----END PRIVATE KEY-----", "A".repeat(64) + "\n", "2026-10-25T00:03:22.123456789Z " + "A".repeat(64) + "\n", "x".repeat(32769), 'database error: Failing row contains (private fixture)', 'query result: {"rows":[{"password":"hidden"}]}']) {
    assert.match(redactDiagnostic(material), /^\[DIAGNOSTIC_WITHHELD:/);
  }
});

function ledgers() {
  const before = Array.from({ length: 67 }, (_, index) => ({ version: index + 1, name: "migration_" + (index + 1), executed_at: "2026-01-01T00:00:00.000Z" }));
  const after = [...before, ...Array.from({ length: 10 }, (_, index) => ({ version: index + 68, name: "migration_" + (index + 68), executed_at: "2026-10-25T00:00:00.000Z" }))];
  return { before, after };
}

test("upgrade cannot pass by rewriting old migration identity or execution history", () => {
  const { before, after } = ledgers();
  assertLedgerUpgrade(before, after);
  for (const field of ["name", "executed_at"]) {
    const changed = structuredClone(after); changed[0][field] = "changed";
    assert.throws(() => assertLedgerUpgrade(before, changed), /Historical migration/);
  }
});

test("upgrade refuses a partial baseline, omitted migration or duplicated version", () => {
  const { before, after } = ledgers();
  assert.throws(() => assertLedgerUpgrade(before.slice(0, -1), after), /Baseline/);
  assert.throws(() => assertLedgerUpgrade(before, after.filter((row) => row.version !== 74)));
  assert.throws(() => assertLedgerUpgrade(before, [...after.slice(0, -1), after[68], after.at(-1)]), /Duplicate/);
  assert.throws(() => assertLedgerUpgrade(before, after.slice(0, -1)), /migration 77/);
});

test("agent continuity requires preserved identity, credentials and pin plus a greater sequence", () => {
  const before = { id: "database-id", agent_id: "protocol-id", credential_hash: "credential-hash", pinned_signing_key_id: "key-id", last_sequence: "9007199254740993", agent_version: "0.17.3" };
  const after = { ...before, last_sequence: "9007199254740994", agent_version: "0.18.0" };
  const state = { "config.json": digest, credential: digest, "signing-key-pin.json": digest };
  assertAgentContinuity(before, after, state, state);
  for (const [field, value] of [["id", "new-id"], ["agent_id", "new-protocol-id"], ["credential_hash", "new-credential"], ["pinned_signing_key_id", null], ["last_sequence", before.last_sequence], ["agent_version", "0.17.3"]]) {
    assert.throws(() => assertAgentContinuity(before, { ...after, [field]: value }, state, state));
  }
  assert.throws(() => assertAgentContinuity(before, after, {}, {}), /Missing persisted/);
  assert.throws(() => assertAgentContinuity(before, after, state, { ...state, credential: "b".repeat(64) }), /Persisted agent file changed/);
});
