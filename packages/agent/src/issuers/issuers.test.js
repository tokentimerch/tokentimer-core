"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  ISSUANCE_OUTCOMES,
  resolveJobIssuerKind,
  assertIssuanceOutcome,
  createAcmeIssuer,
} = require("./index.js");

const CA_ENDPOINT = "https://acme.example.test/directory";
const JOB_ID = "job-issuer-1";
const DOMAINS = ["app.example.com", "www.example.com"];
const CSR_PEM =
  "-----BEGIN CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END CERTIFICATE REQUEST-----\n";
const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nTEVBRg==\n-----END CERTIFICATE-----\n";
const FULLCHAIN_PEM = `${LEAF_PEM}-----BEGIN CERTIFICATE-----\nSU5U\n-----END CERTIFICATE-----\n`;

describe("resolveJobIssuerKind", () => {
  it("treats a job without issuerKind as an acme job", () => {
    assert.deepEqual(resolveJobIssuerKind({ action: "renew" }), { kind: "acme" });
  });

  it("accepts an explicit acme kind", () => {
    assert.deepEqual(resolveJobIssuerKind({ issuerKind: "acme" }), { kind: "acme" });
  });

  it("accepts adcs once the renew/continue-enrollment path is wired", () => {
    assert.deepEqual(resolveJobIssuerKind({ issuerKind: "adcs" }), { kind: "adcs" });
  });

  it("refuses unknown kinds rather than falling back to ACME", () => {
    for (const issuerKind of ["venafi", "ACME", "", null, 1, { kind: "acme" }]) {
      const resolved = resolveJobIssuerKind({ issuerKind });
      assert.equal(resolved.kind, undefined, JSON.stringify(issuerKind));
      assert.match(resolved.error, /which this agent does not implement/);
    }
  });
});

describe("assertIssuanceOutcome", () => {
  const WELL_FORMED = {
    issued: { outcome: "issued", certificatePem: LEAF_PEM },
    pending: { outcome: "pending", requestId: 4242 },
    denied: { outcome: "denied", detail: "denied by the CA policy module" },
    refused: {
      outcome: "refused",
      rejectionReason: "ca_endpoint_not_allowlisted",
      detail: "not in the CA endpoint allowlist",
    },
    failed: { outcome: "failed", detail: "acme step failed with exit code 1" },
    not_submitted: { outcome: "not_submitted", detail: "RPC server unavailable, no output" },
    uncertain: { outcome: "uncertain", detail: "connection reset after the request was sent" },
  };

  it("has a well-formed example for every outcome in the vocabulary", () => {
    assert.deepEqual(Object.keys(WELL_FORMED).sort(), [...ISSUANCE_OUTCOMES].sort());
  });

  it("returns each well-formed outcome unchanged", () => {
    for (const outcome of Object.values(WELL_FORMED)) {
      assert.equal(assertIssuanceOutcome(outcome), outcome);
      assert.equal(assertIssuanceOutcome({ ...outcome, evidence: [] }).outcome, outcome.outcome);
    }
  });

  it("rejects anything that is not a known outcome", () => {
    for (const value of [null, undefined, "issued", {}, { outcome: "succeeded" }, { outcome: "ISSUED" }]) {
      assert.throws(() => assertIssuanceOutcome(value), /unknown outcome/);
    }
  });

  it("never accepts an issued outcome without a certificate", () => {
    for (const certificatePem of [undefined, null, "", 42]) {
      assert.throws(
        () => assertIssuanceOutcome({ outcome: "issued", certificatePem }),
        /malformed issued outcome: certificatePem is required/,
      );
    }
  });

  it("requires pending to carry a 32-bit unsigned CA RequestId", () => {
    for (const requestId of [undefined, 0, -1, 1.5, "4242", 4294967296]) {
      assert.throws(
        () => assertIssuanceOutcome({ outcome: "pending", requestId }),
        /malformed pending outcome/,
      );
    }
    assert.doesNotThrow(() => assertIssuanceOutcome({ outcome: "pending", requestId: 1 }));
    assert.doesNotThrow(() =>
      assertIssuanceOutcome({ outcome: "pending", requestId: 4294967295 }),
    );
  });

  it("requires refused to name the rejection reason and the detail", () => {
    assert.throws(
      () => assertIssuanceOutcome({ outcome: "refused", detail: "no reason" }),
      /rejectionReason is required/,
    );
    assert.throws(
      () => assertIssuanceOutcome({ outcome: "refused", rejectionReason: "ca_endpoint_not_allowlisted" }),
      /detail is required/,
    );
  });

  it("requires a detail on every outcome that ends without a certificate", () => {
    for (const outcome of ["denied", "failed", "not_submitted", "uncertain"]) {
      assert.throws(() => assertIssuanceOutcome({ outcome }), /detail is required/);
      assert.throws(() => assertIssuanceOutcome({ outcome, detail: "" }), /detail is required/);
    }
  });

  it("rejects evidence that is not an array", () => {
    assert.throws(
      () => assertIssuanceOutcome({ ...WELL_FORMED.failed, evidence: { eventType: "validation.failed" } }),
      /evidence must be an array/,
    );
  });
});

describe("createAcmeIssuer", () => {
  let workDir;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-acme-issuer-"));
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function scratchDir() {
    return path.join(workDir, "keys");
  }

  function scratchLeftovers() {
    return fs.existsSync(scratchDir()) ? fs.readdirSync(scratchDir()) : [];
  }

  /**
   * Stands in for certbot: records the argv and the CSR it was pointed at,
   * and stages whichever artifacts the case asks for.
   */
  function makeCertbotStub({
    exitCode = 0,
    writeLeaf = true,
    writeFullchain = false,
    stdout = "",
    stderr = "",
  } = {}) {
    const calls = [];
    function execFileStub(file, args, options, callback) {
      const csrAt = args.indexOf("--csr");
      calls.push({
        file,
        args,
        csrPem: csrAt === -1 ? null : fs.readFileSync(args[csrAt + 1], "utf8"),
      });
      const leafAt = args.indexOf("--cert-path");
      if (writeLeaf && leafAt !== -1) fs.writeFileSync(args[leafAt + 1], LEAF_PEM);
      const fullchainAt = args.indexOf("--fullchain-path");
      if (writeFullchain && fullchainAt !== -1) {
        fs.writeFileSync(args[fullchainAt + 1], FULLCHAIN_PEM);
      }
      const error =
        exitCode === 0 ? null : Object.assign(new Error("Command failed"), { code: exitCode });
      process.nextTick(() => callback(error, stdout, stderr));
    }
    execFileStub.calls = calls;
    return execFileStub;
  }

  function makeIssuer(overrides = {}) {
    return createAcmeIssuer({
      acmeKind: "certbot",
      argv: ["certbot"],
      caEndpoint: CA_ENDPOINT,
      stateDir: workDir,
      scratchDir: scratchDir(),
      jobId: JOB_ID,
      checkCaEndpoint: () => ({ allowed: true }),
      ...overrides,
    });
  }

  function metadataValue(item, name) {
    return item.metadata.find((entry) => entry.name === name)?.value;
  }

  it("is a frozen acme issuer, journaled as the acme step, with no retrieve", () => {
    const issuer = makeIssuer({ execFileImpl: makeCertbotStub() });
    assert.equal(issuer.kind, "acme");
    assert.equal(issuer.step, "acme");
    assert.equal(issuer.retrieve, undefined);
    assert.equal(Object.isFrozen(issuer), true);
  });

  it("hands the CSR to the ACME tool and returns the staged certificate as issued", async () => {
    const execFileImpl = makeCertbotStub();
    const issuance = await makeIssuer({ execFileImpl }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.equal(assertIssuanceOutcome(issuance), issuance);
    assert.equal(issuance.outcome, "issued");
    assert.equal(issuance.certificatePem, LEAF_PEM);
    assert.equal(execFileImpl.calls.length, 1);
    assert.equal(execFileImpl.calls[0].csrPem, CSR_PEM);
    const { args } = execFileImpl.calls[0];
    assert.equal(args[args.indexOf("--server") + 1], CA_ENDPOINT);
    assert.equal(args.includes("--preferred-chain"), false);
    assert.equal(args.includes("--eab-kid"), false);

    assert.equal(issuance.evidence.length, 1);
    const [passed] = issuance.evidence;
    assert.equal(passed.eventType, "validation.passed");
    assert.equal(metadataValue(passed, "step"), "acme");
    assert.equal(metadataValue(passed, "exitCode"), 0);
    assert.deepEqual(scratchLeftovers(), []);
  });

  it("prefers the fullchain artifact over the bare leaf", async () => {
    const issuance = await makeIssuer({
      execFileImpl: makeCertbotStub({ writeFullchain: true }),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.equal(issuance.outcome, "issued");
    assert.equal(issuance.certificatePem, FULLCHAIN_PEM);
  });

  it("returns failed with validation.failed evidence and leaves nothing staged when the order fails", async () => {
    const issuance = await makeIssuer({
      execFileImpl: makeCertbotStub({ exitCode: 1, writeLeaf: true, stderr: "order failed" }),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.equal(assertIssuanceOutcome(issuance), issuance);
    assert.equal(issuance.outcome, "failed");
    assert.equal(issuance.detail, "acme step failed with exit code 1: order failed");
    const [failed] = issuance.evidence;
    assert.equal(failed.eventType, "validation.failed");
    assert.equal(metadataValue(failed, "step"), "acme");
    assert.equal(metadataValue(failed, "exitCode"), 1);
    assert.equal(metadataValue(failed, "stderrExcerpt"), "order failed");
    assert.deepEqual(scratchLeftovers(), []);
  });

  it("explains a failure from stdout when the tool wrote nothing to stderr", async () => {
    const issuance = await makeIssuer({
      acmeKind: "acme.sh",
      argv: ["/root/.acme.sh/acme.sh"],
      execFileImpl: makeCertbotStub({ exitCode: 2, stdout: "Skipping renew, Next renewal time is: ..." }),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.equal(issuance.outcome, "failed");
    assert.match(issuance.detail, /exit code 2: Skipping renew, Next renewal time is/);
  });

  it("returns failed when the tool reports success but staged no certificate", async () => {
    const issuance = await makeIssuer({
      execFileImpl: makeCertbotStub({ writeLeaf: false }),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.equal(issuance.outcome, "failed");
    assert.match(issuance.detail, /reported success but produced no certificate file/);
    assert.equal(issuance.evidence[0].eventType, "validation.passed");
  });

  it("returns refused without running the tool when the CA endpoint re-check fails", async () => {
    const execFileImpl = makeCertbotStub();
    const issuance = await makeIssuer({
      execFileImpl,
      checkCaEndpoint: () => ({
        allowed: false,
        rejectionReason: "ca_endpoint_not_allowlisted",
        detail: "CA endpoint is not present in the agent-local CA endpoint allowlist.",
      }),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.deepEqual(assertIssuanceOutcome(issuance), {
      outcome: "refused",
      rejectionReason: "ca_endpoint_not_allowlisted",
      detail: "CA endpoint is not present in the agent-local CA endpoint allowlist.",
    });
    assert.equal(execFileImpl.calls.length, 0);
    assert.deepEqual(scratchLeftovers(), []);
  });

  it("passes the preferred chain and EAB credentials through to the tool", async () => {
    const execFileImpl = makeCertbotStub();
    await makeIssuer({
      execFileImpl,
      preferredChain: "ISRG Root X1",
      eabCredentials: { eabKid: "kid-1", eabHmacKey: "hmac-secret-1" },
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    const { args } = execFileImpl.calls[0];
    assert.equal(args[args.indexOf("--preferred-chain") + 1], "ISRG Root X1");
    assert.equal(args[args.indexOf("--eab-kid") + 1], "kid-1");
    assert.equal(args[args.indexOf("--eab-hmac-key") + 1], "hmac-secret-1");
  });

  it("removes the CSR when the run throws", async () => {
    const issuer = makeIssuer({
      execFileImpl: makeCertbotStub(),
      checkCaEndpoint: () => {
        throw new Error("policy engine unavailable");
      },
    });

    await assert.rejects(
      issuer.submit({ csrPem: CSR_PEM, domains: DOMAINS }),
      /policy engine unavailable/,
    );
    assert.deepEqual(scratchLeftovers(), []);
  });

  it("logs the order start and its success", async () => {
    const messages = [];
    await makeIssuer({
      execFileImpl: makeCertbotStub(),
      info: (message) => messages.push(message),
    }).submit({ csrPem: CSR_PEM, domains: DOMAINS });

    assert.deepEqual(messages, [
      `job ${JOB_ID}: starting ACME order (certbot) against ${CA_ENDPOINT} for app.example.com, www.example.com`,
      `job ${JOB_ID}: ACME order succeeded`,
    ]);
  });
});
