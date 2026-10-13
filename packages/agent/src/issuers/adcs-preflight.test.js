"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { executeJob } = require("../index.js");
const {
  executeAdcsPreflight,
  parseCaCheck,
  parseTemplateDump,
  runCertutilPreflight,
} = require("./adcs-preflight.js");

const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const SAFE_TEMPLATE = [
  "cn = TokenTimerWebServer",
  "msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
  "msPKI-Template-Schema-Version = 2",
  "pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1",
  "msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.1",
  "msPKI-Minimal-Key-Size = 2048",
  "msPKI-Certificate-Name-Flag = 1",
].join("\n");

function preflightJob(overrides = {}) {
  return {
    action: "adcs-preflight",
    mode: "real",
    transport: "dcom",
    caConfig: CA,
    template: TEMPLATE,
    ...overrides,
  };
}

describe("adcs-preflight enrollment rule gate", () => {
  it("rejects a CA that no local rule names and does not call the probe", async () => {
    let calls = 0;
    const outcome = await executeAdcsPreflight({
      job: preflightJob(),
      rules: [{ caConfig: CA, template: "OtherTemplate" }],
      probe() {
        calls += 1;
        return { preflightResult: { caConfig: CA } };
      },
    });
    assert.equal(calls, 0);
    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "issuer_not_allowlisted");
    assert.equal(outcome.preflightResult, undefined);
  });

  it("reports the probe result only after the rule matches", async () => {
    const preflightResult = {
      caConfig: CA,
      template: TEMPLATE,
      templateCheck: { verdict: "safe", reasons: [] },
      caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
      caCertificates: [],
    };
    const outcome = await executeAdcsPreflight({
      job: preflightJob(),
      rules: [{ caConfig: CA, template: TEMPLATE }],
      probe() {
        return { preflightResult };
      },
    });
    assert.equal(outcome.status, "succeeded");
    assert.equal(outcome.preflightResult, preflightResult);
  });

  it("writes template, CA, and certificate details to the job console", async () => {
    const lines = [];
    const outcome = await executeAdcsPreflight({
      job: preflightJob(),
      jobId: "job-preflight-log",
      rules: [{ caConfig: CA, template: TEMPLATE, operatorAttested: true }],
      info: (message) => lines.push(message),
      probe() {
        return {
          preflightResult: {
            caConfig: CA,
            template: TEMPLATE,
            templateCheck: {
              verdict: "unsafe",
              reasons: ["eku_not_server_auth_only"],
              schemaVersion: 3,
              minimalKeySize: 2048,
              asymmetricAlgorithm: "RSA",
              enrolleeSuppliesSubject: true,
            },
            caCheck: {
              verdict: "safe",
              reasons: [],
              operatorAttested: false,
            },
            caCertificates: [
              { thumbprintSha1: "95854BD29D68DFB63476FECB668D4654DF07A127" },
            ],
          },
        };
      },
    });
    assert.equal(outcome.status, "succeeded");
    const text = lines.join("\n");
    assert.match(text, /job job-preflight-log: AD CS preflight starting for template TokenTimerWebServer/);
    assert.match(text, /verdict=unsafe schema=3 minKey=2048 algorithm=RSA subjectFromRequest=yes reasons=eku_not_server_auth_only/);
    assert.match(text, /AD CS preflight CA verdict=safe operatorAttested=false/);
    assert.match(text, /CA certificates=1 thumbprints=95854BD29D68DFB63476FECB668D4654DF07A127/);
  });

  it("writes the template OID and each CA certificate into the agent cache", async () => {
    const lines = [];
    const calls = [];
    const outcome = await executeAdcsPreflight({
      job: preflightJob(),
      jobId: "job-preflight-cache",
      stateDir: "C:/agent-state",
      rules: [{ caConfig: CA, template: TEMPLATE }],
      info: (message) => lines.push(message),
      cacheOid: async (args) => {
        calls.push(["oid", args.templateOid, args.template]);
      },
      cacheCa: async (args) => {
        calls.push(["ca", args.caKeySha256, args.certBytes.toString("utf8")]);
      },
      probe() {
        return {
          preflightResult: {
            template: TEMPLATE,
            templateCheck: { templateOid: "1.3.6.1.4.1.311.21.8.9", verdict: "safe", reasons: [] },
            caCheck: { verdict: "safe", reasons: [] },
            caCertificates: [
              { certificateB64: Buffer.from("ca-one").toString("base64"), keySha256: "ab".repeat(32) },
              { certificateB64: Buffer.from("ca-two").toString("base64"), keySha256: "cd".repeat(32) },
            ],
          },
        };
      },
    });
    assert.equal(outcome.status, "succeeded");
    assert.deepEqual(calls, [
      ["oid", "1.3.6.1.4.1.311.21.8.9", TEMPLATE],
      ["ca", "ab".repeat(32), "ca-one"],
      ["ca", "cd".repeat(32), "ca-two"],
    ]);
    assert.match(lines.join("\n"), /cached CA pins=2 templateOid=1\.3\.6\.1\.4\.1\.311\.21\.8\.9/);
  });

  it("executeJob no longer blocks adcs-preflight before the rule gate", async () => {
    let calls = 0;
    const outcome = await executeJob({
      job: preflightJob(),
      jobId: "job-preflight-1",
      policyEngine: {},
      client: {},
      executionContext: {
        execution: {},
        adcsEnrollmentRules: [],
        adcsPreflightImpl() {
          calls += 1;
          throw new Error("probe must not run");
        },
      },
      log() {},
    });
    assert.equal(calls, 0);
    assert.equal(outcome.status, "rejected");
    assert.equal(outcome.rejectionReason, "issuer_not_allowlisted");
  });
});

describe("adcs-preflight certutil parsing", () => {
  it("marks a server-auth template and clean CA flags safe", () => {
    const templateCheck = parseTemplateDump(SAFE_TEMPLATE);
    assert.equal(templateCheck.verdict, "safe");
    assert.deepEqual(templateCheck.reasons, []);
    assert.equal(templateCheck.schemaVersion, 2);
    const caCheck = parseCaCheck(
      "EditFlags REG_DWORD = 0x10000 (65536)",
      "InterfaceFlags REG_DWORD = 0x200 (512)",
      false,
    );
    assert.equal(caCheck.verdict, "safe");
  });

  it("does not mark an unreadable template safe", () => {
    const templateCheck = parseTemplateDump("not a template dump");
    assert.equal(templateCheck.verdict, "unreadable");
    assert.ok(templateCheck.reasons.includes("template_unreadable"));
  });

  it("builds fixed certutil argv and never returns command text", async () => {
    const argv = [];
    const outcome = await runCertutilPreflight({
      caConfig: CA,
      template: TEMPLATE,
      execFileImpl(file, args) {
        argv.push([file, args]);
        const joined = args.join(" ");
        if (joined.includes("-dstemplate")) return { stdout: SAFE_TEMPLATE };
        if (joined.includes("EditFlags")) return { stdout: "EditFlags REG_DWORD = 0x10000 (65536)" };
        if (joined.includes("InterfaceFlags")) return { stdout: "InterfaceFlags REG_DWORD = 0x200 (512)" };
        if (joined.includes("certcount")) return { stdout: "Cert count: 1" };
        return { stdout: "" };
      },
    });
    assert.deepEqual(argv.map((call) => call[1][0]), ["-dstemplate", "-config", "-config", "-config", "-config"]);
    assert.ok(argv.slice(1).every((call) => call[1][1] === CA));
    assert.equal(outcome.preflightResult.templateCheck.verdict, "safe");
    assert.equal(outcome.preflightResult.caCheck.verdict, "safe");
    assert.equal(JSON.stringify(outcome).includes(SAFE_TEMPLATE), false);
    const templateCall = argv.find((call) => call[1].includes("-dstemplate"));
    assert.deepEqual(templateCall[1], ["-dstemplate", TEMPLATE]);
    assert.equal(templateCall[1].includes("-config"), false);
    const caCertCall = argv.find((call) => call[1].includes("-ca.cert"));
    assert.equal(caCertCall[1][2], "-ca.cert");
    assert.equal(caCertCall[1][4], "0");
    assert.match(caCertCall[1][3], /0\.cer$/);
  });

  it("queries the named template and does not treat another template's dump as safe", async () => {
    const unsafeName = "ClientAuthTemplate";
    const clientAuth = "1.3.6.1.5.5.7.3.2";
    function dump(name, eku) {
      return [
        `cn = ${name}`,
        "msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
        "msPKI-Template-Schema-Version = 2",
        `pKIExtendedKeyUsage = ${eku}`,
        `msPKI-Certificate-Application-Policy = ${eku}`,
        "msPKI-Minimal-Key-Size = 2048",
      ].join("\n");
    }
    function execFor(selected) {
      return function execFileImpl(_file, args) {
        const requested = args[args.indexOf("-dstemplate") + 1];
        if (args.includes("-dstemplate")) {
          if (selected) return { stdout: dump(selected, "1.3.6.1.5.5.7.3.1") };
          if (requested === TEMPLATE) return { stdout: dump(TEMPLATE, "1.3.6.1.5.5.7.3.1") };
          if (requested === unsafeName) return { stdout: dump(unsafeName, clientAuth) };
        }
        if (args.includes("EditFlags")) return { stdout: "EditFlags REG_DWORD = 0x10000 (65536)" };
        if (args.includes("InterfaceFlags")) return { stdout: "InterfaceFlags REG_DWORD = 0x200 (512)" };
        if (args.includes("certcount")) return { stdout: "Cert count: 0" };
        return { stdout: "" };
      };
    }
    const safe = await runCertutilPreflight({
      caConfig: CA,
      template: TEMPLATE,
      execFileImpl: execFor(null),
    });
    const unsafe = await runCertutilPreflight({
      caConfig: CA,
      template: unsafeName,
      execFileImpl: execFor(null),
    });
    assert.equal(safe.preflightResult.templateCheck.verdict, "safe");
    assert.equal(safe.preflightResult.template, TEMPLATE);
    assert.equal(unsafe.preflightResult.templateCheck.verdict, "unsafe");
    assert.equal(unsafe.preflightResult.template, unsafeName);
    assert.ok(unsafe.preflightResult.templateCheck.reasons.includes("eku_not_server_auth_only"));

    const confused = await runCertutilPreflight({
      caConfig: CA,
      template: unsafeName,
      execFileImpl: execFor(TEMPLATE),
    });
    assert.equal(confused.preflightResult.templateCheck.verdict, "unreadable");
    assert.ok(confused.preflightResult.templateCheck.reasons.includes("template_unreadable"));
  });

  it("parses quoted certutil template dumps and parenthesized flag values", () => {
    const quoted = [
      '[TTWebServer]',
      '    cn = "TTWebServer"',
      '    pKIExtendedKeyUsage = "1.3.6.1.5.5.7.3.1"',
      '    msPKI-Certificate-Name-Flag = "1"',
      '    msPKI-Minimal-Key-Size = "2048"',
      '    msPKI-Template-Schema-Version = "2"',
      '    msPKI-Cert-Template-OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6"',
      '    msPKI-Certificate-Application-Policy = "1.3.6.1.5.5.7.3.1"',
    ].join("\n");
    const templateCheck = parseTemplateDump(quoted, "TTWebServer");
    assert.equal(templateCheck.verdict, "safe");
    assert.equal(templateCheck.schemaVersion, 2);
    assert.equal(templateCheck.templateOid, "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6");
    assert.equal(templateCheck.minimalKeySize, 2048);
    const mixed = quoted.replace(
      'msPKI-Certificate-Application-Policy = "1.3.6.1.5.5.7.3.1"',
      'msPKI-Certificate-Application-Policy = "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"',
    );
    const unsafe = parseTemplateDump(mixed, "TTWebServer");
    assert.equal(unsafe.verdict, "unsafe");
    assert.ok(unsafe.reasons.includes("application_policy_not_server_auth_only"));
    const caCheck = parseCaCheck(
      "EditFlags REG_DWORD = 11014e (1114446)",
      "InterfaceFlags REG_DWORD = 641 (1601)",
      false,
    );
    assert.equal(caCheck.verdict, "safe");
    assert.deepEqual(caCheck.reasons, []);
  });

  it("decodes a UTF-16 certutil pipe before parsing", async () => {
    const dump = Buffer.from(
      [
        'cn = "TokenTimerWebServer"',
        "msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
        "msPKI-Template-Schema-Version = 2",
        "pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.1",
        "msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.1",
        "msPKI-Minimal-Key-Size = 2048",
        "msPKI-Certificate-Name-Flag = 1",
      ].join("\r\n"),
      "utf16le",
    );
    const outcome = await runCertutilPreflight({
      caConfig: CA,
      template: TEMPLATE,
      execFileImpl(_file, args) {
        const joined = args.join(" ");
        if (joined.includes("-dstemplate")) return { stdout: dump };
        if (joined.includes("EditFlags")) {
          return { stdout: Buffer.from("EditFlags REG_DWORD = 11014e (1114446)", "utf16le") };
        }
        if (joined.includes("InterfaceFlags")) {
          return { stdout: Buffer.from("InterfaceFlags REG_DWORD = 641 (1601)", "utf16le") };
        }
        if (joined.includes("certcount")) return { stdout: Buffer.from("Cert count: 0", "utf16le") };
        return { stdout: Buffer.alloc(0) };
      },
    });
    assert.equal(outcome.preflightResult.templateCheck.verdict, "safe");
    assert.equal(outcome.preflightResult.caCheck.verdict, "safe");
  });
});
