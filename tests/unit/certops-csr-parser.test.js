"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { generateKeyPairToFile, generateCsr } = require("../../packages/agent/src/keys");
const { parsePublicCsr } = require("../../apps/api/services/certops/csrParser");

describe("public CSR parser", () => {
  it("rejects long malformed whitespace bodies without regex backtracking", () => {
    const result = spawnSync(process.execPath, ["-e", `
      const assert = require('node:assert/strict');
      const { parsePublicCsr } = require('./apps/api/services/certops/csrParser');
      (async () => {
        for (const tail of ['', '!', '-----END CERTIFICATE REQUEST-----']) {
          await assert.rejects(parsePublicCsr('-----BEGIN CERTIFICATE REQUEST-----' + '\\t'.repeat(64000) + tail), { code: 'CERTOPS_CSR_INVALID' });
        }
      })().catch(() => process.exitCode = 1);
    `], { cwd: path.resolve(__dirname, "../.."), timeout: 5000, encoding: "utf8", windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  });
  it("canonicalizes a signed CSR and derives DER and SPKI identities", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-csr-parser-"));
    try {
      const keyPath = path.join(dir, "local.key.pem");
      generateKeyPairToFile({ keyPath });
      const { csrPem } = generateCsr({
        keyPath,
        subject: { commonName: "csr.example.test" },
        altNames: ["csr.example.test", "www.example.test"],
      });
      const parsed = await parsePublicCsr(`\n${csrPem}\n`);
      assert.equal(parsed.csrPem, csrPem.trim());
      assert.match(parsed.csrDerSha256, /^[a-f0-9]{64}$/);
      assert.match(parsed.spkiFingerprintSha256, /^[a-f0-9]{64}$/);
      assert.deepEqual(parsed.requestedNames, ["csr.example.test", "www.example.test"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects bundled private material and extra PEM blocks", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-csr-parser-"));
    try {
      const keyPath = path.join(dir, "local.key.pem");
      generateKeyPairToFile({ keyPath });
      const { csrPem } = generateCsr({ keyPath, subject: { commonName: "csr.example.test" } });
      await assert.rejects(parsePublicCsr(`${csrPem}\n${fs.readFileSync(keyPath, "utf8")}`),
        { code: "PRIVATE_KEY_MATERIAL_REJECTED" });
      await assert.rejects(parsePublicCsr(`${csrPem}\n${csrPem}`),
        { code: "CERTOPS_CSR_INVALID" });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects unsafe CSR common names and DNS SANs", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-csr-identity-"));
    try {
      const keyPath = path.join(dir, "local.key.pem");
      generateKeyPairToFile({ keyPath });
      const unsafeCn = generateCsr({ keyPath, subject: { commonName: "safe\u202E.example.test" } });
      await assert.rejects(parsePublicCsr(unsafeCn.csrPem), { code: "CERTOPS_CSR_INVALID" });
      const unsafeSan = generateCsr({ keyPath,
        subject: { commonName: "safe.example.test" }, altNames: ["xn--!.example.test"] });
      await assert.rejects(parsePublicCsr(unsafeSan.csrPem), { code: "CERTOPS_CSR_INVALID" });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
