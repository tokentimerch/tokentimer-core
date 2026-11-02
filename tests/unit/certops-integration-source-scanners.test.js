/**
 * Regression coverage: production certificate scanners normalize all six upstream fixture sources without private material.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { scanFixtureSources } = require("../e2e/helpers/certops-integration-scanners");
const inventory = require("../../docs/certops/integration-source-inventory.json");
test("production certificate scanners normalize all six upstream fixture sources without private material", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-scanner-fixture-"));
  const previousFetch = global.fetch;
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=scanner.integration.invalid", "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem")], { stdio: "ignore", timeout: 15000 });
    const publicPem = fs.readFileSync(path.join(directory, "cert.pem"), "utf8"), privatePem = fs.readFileSync(path.join(directory, "key.pem"), "utf8");
    const result = await scanFixtureSources(publicPem, privatePem);
    const items = result.outputs.flatMap(output => output.items);
    assert.deepEqual(items.map(item => item.sourceKind).sort(), inventory.sources.map(source => source.sourceKind).sort());
    for (const item of items) { assert.equal(item.category, "cert"); assert.equal(item.type, "ssl_cert"); assert.equal(item.expiration, result.expiry); assert.ok(item.sourceObjectId); }
    // Boolean assertions keep generated private material out of failure output.
    assert.equal(JSON.stringify(result.outputs).includes(privatePem), false);
    assert.equal(JSON.stringify(result.outputs).includes("BEGIN PRIVATE KEY"), false);
    assert.equal(global.fetch, previousFetch);
    assert.ok(result.calls.some(call => call === "aws:describe"));
    assert.ok(result.calls.some(call => call.startsWith("vault.integration.invalid/v1/pki/cert/")));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test("production scanner pagination and upstream failures preserve completeness boundaries", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-scanner-fault-"));
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=scanner.integration.invalid", "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem")], { stdio: "ignore", timeout: 15000 });
    const pem = fs.readFileSync(path.join(directory, "cert.pem"), "utf8"), key = fs.readFileSync(path.join(directory, "key.pem"), "utf8");
    await t.test("all pages are normalized before complete enumeration", async () => {
      const result = await scanFixtureSources(pem, key, { gcpPagination: true });
      const output = result.outputs.find(output => output.provider === "gcp");
      assert.deepEqual(output.items.filter(item => item.sourceKind === "gcp-certificate-manager-cert").map(item => item.sourceObjectId), ["page-one", "page-two"]);
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert").complete, true);
      assert.equal(result.calls.filter(call => call.startsWith("certificatemanager.googleapis.com")).length, 2);
    });
    await t.test("malformed successful list body cannot qualify absence", async () => {
      const output = (await scanFixtureSources(pem, key, { gcpMalformed: true })).outputs.find(output => output.provider === "gcp");
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert").complete, false);
    });
    for (const [label, body] of [["null", null], ["array", []], ["wrong repeated field", { certificates: "invalid" }]]) await t.test("malformed " + label + " body is incomplete", async () => {
      const output = (await scanFixtureSources(pem, key, { gcpMalformed: body })).outputs.find(output => output.provider === "gcp");
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert").complete, false);
    });
    await t.test("legitimate omitted repeated field remains complete empty protobuf response", async () => {
      const output = (await scanFixtureSources(pem, key, { gcpEmpty: true })).outputs.find(output => output.provider === "gcp");
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert").complete, true);
      assert.equal(output.items.filter(item => item.sourceKind === "gcp-certificate-manager-cert").length, 0);
    });
    for (const [label, body] of [["primitive", "invalid"], ["scope list", { items: [] }], ["certificate list", { items: { global: { sslCertificates: "invalid" } } }], ["unreachable list", { unreachables: "regions/unreachable" }]]) await t.test("malformed Compute " + label + " cannot qualify absence", async () => {
      const output = (await scanFixtureSources(pem, key, { computeMalformed: body })).outputs.find(output => output.provider === "gcp");
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-compute-ssl-cert").complete, false);
    });
    await t.test("legitimate empty Compute response remains complete", async () => {
      const output = (await scanFixtureSources(pem, key, { computeMalformed: {} })).outputs.find(output => output.provider === "gcp");
      assert.equal(output.summary.find(scope => scope.sourceKind === "gcp-compute-ssl-cert").complete, true);
    });
    for (const status of [401, 429, 503]) await t.test(`HTTP ${status} cannot qualify certificate absence`, async () => {
      const output = (await scanFixtureSources(pem, key, { gcpStatus: status })).outputs.find(output => output.provider === "gcp");
      const scope = output.summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert");
      assert.equal(scope.status, status); assert.equal(scope.complete, false);
      assert.equal(output.items.filter(item => item.sourceKind === "gcp-certificate-manager-cert").length, 0);
      assert.equal(output.items.filter(item => item.sourceKind === "gcp-compute-ssl-cert").length, 1);
    });
    await t.test("unreachable Compute scope preserves partial discoveries without complete absence", async () => {
      const output = (await scanFixtureSources(pem, key, { gcpUnreachable: true })).outputs.find(output => output.provider === "gcp");
      const scope = output.summary.find(scope => scope.sourceKind === "gcp-compute-ssl-cert");
      assert.equal(scope.complete, false); assert.deepEqual(scope.unreachableScopes, ["regions/unreachable"]);
      assert.equal(output.items.filter(item => item.sourceKind === "gcp-compute-ssl-cert").length, 1);
    });
    await t.test("ACM permission denial cannot qualify an empty successful scan", async () => {
      const output = (await scanFixtureSources(pem, key, { awsDenied: true })).outputs.find(output => output.provider === "aws");
      assert.equal(output.items.length, 0); assert.equal(output.summary.find(scope => scope.sourceKind === "aws-acm").complete, false);
    });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
