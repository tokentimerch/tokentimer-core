"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-k8s-rbac-outage");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration keeps Kubernetes real-host work pending", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "pending");
  assert.equal(suite.evidenceLevel, "real-host");
  assert.equal(suite.proofEvidenceLevel, "script");
  assert.equal(suite.qualified, false);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
});

test("timeout, missed watch, and missing RBAC fail closed without a cluster", () => {
  const source = fs.readFileSync(path.join(ROOT, "tests", "e2e", "helpers", "certops-k8s-rbac-outage.js"), "utf8");
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("kubectl"), false);
  assert.equal(source.includes("http.request"), false);
  for (const [kind, code] of Object.entries(contract.FAULTS)) {
    assert.throws(() => contract.observe(kind), (error) => {
      assert.equal(error.code, code);
      assert.equal(error.result.status, "failed");
      assert.equal(error.result.kubernetesQualified, false);
      assert.equal(error.result.talkedToCluster, false);
      assert.equal(error.result.hostCapabilityAbsentIsPass, false);
      return true;
    });
  }
  const cluster = contract.assessCluster({ cluster: true });
  assert.equal(cluster.kubernetesQualified, false);
  assert.equal(cluster.talkedToCluster, false);
  assert.equal(cluster.available, false);
  contract.verifyProof(contract.localProof());
});

test("missing cluster fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `k8s-rbac-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, probe: null, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.suiteStatus, "pending");
  assert.equal(report.evidenceLevel, "real-host");
  assert.equal(report.kubernetesQualified, false);
  assert.equal(report.talkedToCluster, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  const spawned = spawnSync(process.execPath, ["scripts/certops-k8s-rbac-outage.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  fs.rmSync(reportPath, { force: true });
});
