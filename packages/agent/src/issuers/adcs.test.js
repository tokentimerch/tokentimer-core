"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { mapAdcsDisposition, HRESULT } = require("./adcs-disposition.js");
const { decodeCmcResponse, EXIT_OK, EXIT_UNKNOWN, EXIT_FAIL } = require("./cmc-helper.js");
const { createAdcsIssuer, derB64ToPem } = require("./adcs.js");
const { assertIssuanceOutcome, createAdcsIssuer: exported } = require("./index.js");

const PIN = "1aefab442a37a51b6ccb8a319af784c6c37fe227d9a1c2ecf5bf6c65889017f3";
const CA_CONFIG = "ttadcsdc.ad.ttlab.internal\\TTLab Issuing CA";
const CSR_PEM =
  "-----BEGIN CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END CERTIFICATE REQUEST-----\n";

describe("mapAdcsDisposition", () => {
  it("maps CMC issued to issued", () => {
    const m = mapAdcsDisposition({
      phase: "submit",
      responsePresent: true,
      certificatePresent: true,
      exitCode: 1,
      cmc: { disposition: "issued", certificateDerB64: "AAAA" },
    });
    assert.equal(m.outcome, "issued");
  });

  it("maps pending only with exit 0", () => {
    assert.equal(
      mapAdcsDisposition({
        phase: "submit",
        responsePresent: true,
        certificatePresent: false,
        exitCode: 0,
        cmc: { disposition: "pending", requestId: 5 },
      }).outcome,
      "pending",
    );
    assert.equal(
      mapAdcsDisposition({
        phase: "submit",
        responsePresent: true,
        certificatePresent: false,
        exitCode: 1,
        cmc: { disposition: "pending", requestId: 5 },
      }).outcome,
      "uncertain",
    );
  });

  it("maps submit denied for any failed CMC", () => {
    const m = mapAdcsDisposition({
      phase: "submit",
      responsePresent: true,
      certificatePresent: false,
      exitCode: HRESULT.CERTSRV_E_TEMPLATE_DENIED,
      cmc: { disposition: "denied" },
    });
    assert.equal(m.outcome, "denied");
  });

  it("maps retrieve denied only for admin deny", () => {
    assert.equal(
      mapAdcsDisposition({
        phase: "retrieve",
        responsePresent: true,
        certificatePresent: false,
        exitCode: HRESULT.CERTSRV_E_ADMIN_DENIED_REQUEST,
        cmc: { disposition: "denied" },
      }).outcome,
      "denied",
    );
    assert.equal(
      mapAdcsDisposition({
        phase: "retrieve",
        responsePresent: true,
        certificatePresent: false,
        exitCode: HRESULT.E_ACCESSDENIED,
        cmc: { disposition: "denied" },
      }).outcome,
      "uncertain",
    );
  });

  it("maps RPC unavailable without artefacts to not_submitted on submit", () => {
    const m = mapAdcsDisposition({
      phase: "submit",
      responsePresent: false,
      certificatePresent: false,
      chainPresent: false,
      exitCode: HRESULT.RPC_S_SERVER_UNAVAILABLE,
      cmc: null,
    });
    assert.equal(m.outcome, "not_submitted");
  });

  it("maps RPC unavailable with a chain artefact to uncertain", () => {
    const m = mapAdcsDisposition({
      phase: "submit",
      responsePresent: false,
      certificatePresent: false,
      chainPresent: true,
      exitCode: HRESULT.RPC_S_SERVER_UNAVAILABLE,
      cmc: null,
    });
    assert.equal(m.outcome, "uncertain");
  });
});

describe("decodeCmcResponse", () => {
  it("parses exit 0 JSON", async () => {
    const decoded = await decodeCmcResponse({
      helperPath: "tokentimer-adcs-cmc.exe",
      responsePath: "r.rsp",
      caKeySha256: PIN,
      execFileImpl: async () => ({
        stdout: JSON.stringify({ disposition: "pending", requestId: 5 }),
        stderr: "",
      }),
    });
    assert.equal(decoded.ok, true);
    assert.equal(decoded.exitCode, EXIT_OK);
    assert.equal(decoded.result.requestId, 5);
  });

  it("keeps unknown on exit 1", async () => {
    const err = new Error("fail");
    err.code = EXIT_UNKNOWN;
    err.stdout = JSON.stringify({ disposition: "unknown", error: "hash mismatch" });
    const decoded = await decodeCmcResponse({
      helperPath: "helper",
      responsePath: "r.rsp",
      caKeySha256: PIN,
      execFileImpl: async () => {
        throw err;
      },
    });
    assert.equal(decoded.ok, true);
    assert.equal(decoded.exitCode, EXIT_UNKNOWN);
    assert.equal(decoded.result.disposition, "unknown");
  });

  it("hard-fails on exit 2", async () => {
    const err = new Error("fail");
    err.code = EXIT_FAIL;
    err.stdout = JSON.stringify({ error: "CMS signature verify failed" });
    const decoded = await decodeCmcResponse({
      helperPath: "helper",
      responsePath: "r.rsp",
      caKeySha256: PIN,
      execFileImpl: async () => {
        throw err;
      },
    });
    assert.equal(decoded.ok, false);
    assert.equal(decoded.exitCode, EXIT_FAIL);
  });
});

describe("createAdcsIssuer", () => {
  let scratchDir;

  beforeEach(() => {
    scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-issuer-"));
  });

  afterEach(() => {
    fs.rmSync(scratchDir, { recursive: true, force: true });
  });

  function makeIssuer(overrides = {}) {
    return createAdcsIssuer({
      caConfig: CA_CONFIG,
      template: "TTWebServer",
      caKeySha256: PIN,
      caCertPath: path.join(scratchDir, "ca.cer"),
      helperPath: path.join(scratchDir, "tokentimer-adcs-cmc.exe"),
      scratchDir,
      jobId: "job-1",
      enrollmentId: "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
      ...overrides,
    });
  }

  it("is exported from the issuers package and frozen as kind adcs", () => {
    assert.equal(exported, createAdcsIssuer);
    const issuer = makeIssuer({
      execFileImpl: async () => ({ stdout: "", stderr: "" }),
      decodeCmcImpl: async () => ({ ok: true, result: { disposition: "denied" } }),
    });
    assert.equal(issuer.kind, "adcs");
    assert.equal(typeof issuer.submit, "function");
    assert.equal(typeof issuer.retrieve, "function");
  });

  it("submit pending via CMC requestId", async () => {
    const issuer = makeIssuer({
      execFileImpl: async (_bin, argv) => {
        assert.ok(argv.includes("-submit"));
        assert.ok(argv.includes(`CertificateTemplate:TTWebServer`));
        const rsp = argv[argv.length - 1];
        fs.writeFileSync(rsp, "fake-rsp");
        return { stdout: "", stderr: "" };
      },
      decodeCmcImpl: async () => ({
        ok: true,
        result: { disposition: "pending", requestId: 42 },
      }),
    });
    const outcome = await issuer.submit({ csrPem: CSR_PEM });
    assertIssuanceOutcome(outcome);
    assert.equal(outcome.outcome, "pending");
    assert.equal(outcome.requestId, 42);
  });

  it("submit issued returns PEM from CMC der", async () => {
    const der = Buffer.from("leaf-cert-bytes");
    const issuer = makeIssuer({
      execFileImpl: async (_bin, argv) => {
        const rsp = argv[argv.length - 1];
        fs.writeFileSync(rsp, "fake-rsp");
        return { stdout: "", stderr: "" };
      },
      decodeCmcImpl: async () => ({
        ok: true,
        result: { disposition: "issued", certificateDerB64: der.toString("base64") },
      }),
    });
    const outcome = await issuer.submit({ csrPem: CSR_PEM });
    assertIssuanceOutcome(outcome);
    assert.equal(outcome.outcome, "issued");
    assert.equal(outcome.certificatePem, derB64ToPem(der.toString("base64")));
  });

  it("submit maps RPC unavailable with no rsp to not_submitted", async () => {
    const err = new Error("rpc");
    err.code = HRESULT.RPC_S_SERVER_UNAVAILABLE;
    const issuer = makeIssuer({
      execFileImpl: async () => {
        throw err;
      },
      decodeCmcImpl: async () => {
        throw new Error("should not decode");
      },
    });
    const outcome = await issuer.submit({ csrPem: CSR_PEM });
    assert.equal(outcome.outcome, "not_submitted");
  });

  it("submit maps RPC unavailable with a chain file to uncertain", async () => {
    const err = new Error("rpc");
    err.code = HRESULT.RPC_S_SERVER_UNAVAILABLE;
    const issuer = makeIssuer({
      execFileImpl: async (_bin, argv) => {
        const chainPath = argv[argv.length - 2];
        fs.writeFileSync(chainPath, "p7b-bytes");
        throw err;
      },
      decodeCmcImpl: async () => {
        throw new Error("should not decode");
      },
    });
    const outcome = await issuer.submit({ csrPem: CSR_PEM });
    assert.equal(outcome.outcome, "uncertain");
    assert.match(outcome.detail, /artefact was written/);
  });

  it("retrieve refuses a mismatched pend token", async () => {
    const issuer = makeIssuer({
      execFileImpl: async (_bin, argv) => {
        assert.ok(argv.includes("-retrieve"));
        const rsp = argv[argv.length - 1];
        fs.writeFileSync(rsp, "fake-rsp");
        return { stdout: "", stderr: "" };
      },
      decodeCmcImpl: async () => ({
        ok: true,
        result: { disposition: "pending", requestId: 99 },
      }),
    });
    const outcome = await issuer.retrieve(5);
    assert.equal(outcome.outcome, "uncertain");
    assert.match(outcome.detail, /differs from journaled RequestId 5/);
  });
});
