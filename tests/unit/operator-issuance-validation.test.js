"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeIssuance } = require("../../apps/api/services/operator/issuanceValidation");

const valid = {
  agentId: "e858429d-1c25-4cf0-a7b2-1b989f995541",
  commonName: "example.test", sans: ["example.test", "www.example.test"],
  commandRef: "certbot", caEndpoint: "https://ca.example.test/directory",
  dnsZone: "example.test", dnsProvider: "dns-provider",
  certPath: "/etc/ssl/certs/example.test.pem",
};

test("normalizes the supported ACME issuance request", () => {
  const result = normalizeIssuance(valid);
  assert.equal(result.payload.target.reference, "example.test");
  assert.deepEqual(result.payload.sans, valid.sans);
  assert.equal(result.payload.certPath, valid.certPath);
});

test("rejects private material, unreviewed overrides and invalid destinations", () => {
  for (const input of [
    { ...valid, privateKey: "secret" }, { ...valid, reloadService: "nginx" },
    { ...valid, certPath: "relative.pem" }, { ...valid, sans: ["other.test"] },
    { ...valid, caEndpoint: "https://user:pass@ca.example.test/" },
    { ...valid, agentId: "not-a-uuid" }, { ...valid, commandRef: "" },
  ]) assert.throws(() => normalizeIssuance(input), { code: "OPERATOR_VALIDATION_ERROR" });
});
