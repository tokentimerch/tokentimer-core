"use strict";
/** Pure observation/contract checks, never native CA or agent execution. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-acme-bulk-renewal");
const ids = [crypto.randomUUID(), crypto.randomUUID()],
  unknown = crypto.randomUUID(),
  jobs = [crypto.randomUUID(), crypto.randomUUID()];
const response = (replay = false) => ({
  summary: { requested: 3, succeeded: 2, failed: 1 },
  results: [
    ...ids.map((certificateId, index) => ({
      certificateId,
      ok: true,
      jobId: jobs[index],
      ...(replay ? { replayed: true } : {}),
    })),
    {
      certificateId: unknown,
      ok: false,
      errorCode: "CERTOPS_CERTIFICATE_NOT_FOUND",
    },
  ],
});
function proof() {
  return {
    scope: h.SCOPE,
    client: "certbot",
    originalServingFingerprint: "9".repeat(64),
    originalServingSpki: "8".repeat(64),
    originalServingProfileId: crypto.randomUUID(),
    certificateIds: [...ids],
    jobIds: [...jobs],
    issueJobIds: [crypto.randomUUID(), crypto.randomUUID()],
    claimIds: [crypto.randomUUID(), crypto.randomUUID()],
    fingerprints: ["a", "b", "c", "d"].map((x) => x.repeat(64)),
    serials: ["01", "02", "03", "04"],
    spkiFingerprints: ["e", "f", "1", "2"].map((x) => x.repeat(64)),
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("bulk observation requires both exact eligible jobs, unknown-item refusal and replay identity", () => {
  assert.deepEqual(h.verifyAdmission(response(), ids, unknown), jobs);
  assert.deepEqual(
    h.verifyAdmission(response(true), ids, unknown, { replay: true }),
    jobs,
  );
  for (const change of [
    (p) => p.results.pop(),
    (p) => (p.results[0].certificateId = unknown),
    (p) => (p.results[1].jobId = jobs[0]),
    (p) => (p.results[2].jobId = crypto.randomUUID()),
    (p) => (p.summary.failed = 0),
    (p) => (p.results[0].replayed = true),
  ]) {
    const p = response();
    change(p);
    assert.throws(() => h.verifyAdmission(p, ids, unknown));
  }
  assert.throws(() =>
    h.verifyAdmission(response(), ids, unknown, { replay: true }),
  );
});
test("bulk native proof cannot qualify missing facts, duplicate current claims or unchanged material", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    const p = proof();
    delete p[flag];
    assert.throws(() => h.verifyProof(p));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const field of [
    "certificateIds",
    "issueJobIds",
    "jobIds",
    "claimIds",
    "fingerprints",
    "serials",
    "spkiFingerprints",
  ]) {
    const p = proof();
    p[field][1] = p[field][0];
    assert.throws(() => h.verifyProof(p));
  }
  const p = proof();
  p.claimIds = [jobs[0], jobs[0].toUpperCase()];
  assert.throws(() => h.verifyProof(p));
  assert.throws(() => h.verifyProof({ ...proof(), client: "acme.sh" }));
  assert.throws(() =>
    h.verifyProof({ ...proof(), privateKey: "not public proof" }),
  );
});
test("actual public bulk request parser accepts mixed identities and refuses invalid batches", () => {
  const { parseBulkRenewRequest } = require("../apps/api/routes/certops")._test;
  const input = {
    certificateIds: [...ids, unknown],
    idempotencyKey: crypto.randomUUID(),
  };
  const parsed = parseBulkRenewRequest(input);
  assert.equal(parsed.error, undefined);
  assert.deepEqual(parsed.certificateIds, input.certificateIds);
  assert.equal(parsed.idempotencyKey, input.idempotencyKey);
  assert.ok(
    parseBulkRenewRequest({ ...input, certificateIds: [ids[0], ids[0]] }).error,
  );
  assert.ok(parseBulkRenewRequest({ ...input, certificateIds: [] }).error);
});

test("actual inner and outer native budgets retain two-minute margin only for bulk base scope", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    parser = require("node:module").createRequire(
      require.resolve("../packages/agent/node_modules/eslint/package.json"),
    )("espree");
  const main = require("./certops-acme-bulk-report").MAIN;
  const sources = [
    "../tests/e2e/certops-agent-e2e.test.js",
    "./certops-real-acme.js",
  ].map((file) => fs.readFileSync(path.resolve(__dirname, file), "utf8"));
  const expressions = [];
  for (const [index, source] of sources.entries()) {
    const ast = parser.parse(source, {
        ecmaVersion: "latest",
        sourceType: "script",
        range: true,
      }),
      found = [];
    function visit(node) {
      if (!node || typeof node !== "object") return;
      if (
        node.type === "CallExpression" &&
        ((index === 0 && node.arguments[0]?.value === main) ||
          (index === 1 && node.callee?.name === "spawnSync"))
      ) {
        for (const arg of node.arguments.filter(
          (value) => value.type === "ObjectExpression",
        )) {
          const value = arg.properties.find(
            (item) => item.key?.name === "timeout",
          )?.value;
          if (value?.type === "ConditionalExpression")
            found.push(source.slice(...value.range));
        }
      }
      for (const [key, value] of Object.entries(node)) {
        if (key === "range") continue;
        if (Array.isArray(value)) value.forEach(visit);
        else if (value && typeof value === "object") visit(value);
      }
    }
    visit(ast);
    assert.equal(found.length, 1);
    expressions.push(found[0]);
  }
  const inner = new Function("process", "return " + expressions[0]),
    outer = new Function("scope", "return " + expressions[1]);
  for (const scope of [
    "real-agent-acme-filesystem",
    "real-agent-acme-eab-filesystem",
    "real-agent-acmesh-filesystem",
    "real-agent-acmesh-eab-filesystem",
    "real-agent-alpine-acmesh",
  ]) {
    const expected = scope === "real-agent-acme-filesystem" ? 1800000 : 1200000;
    assert.equal(inner({ env: { CERTOPS_REPORT_SCOPE: scope } }), expected);
    assert.equal(outer(scope), expected + 120000);
  }
});
