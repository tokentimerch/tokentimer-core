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
        if (joined.includes("certcount")) return { stdout: "Cert count: 0" };
        return { stdout: "" };
      },
    });
    assert.deepEqual(argv.map((call) => call[1][0]), ["-config", "-config", "-config", "-config"]);
    assert.ok(argv.every((call) => call[1][1] === CA));
    assert.equal(outcome.preflightResult.templateCheck.verdict, "safe");
    assert.equal(outcome.preflightResult.caCheck.verdict, "safe");
    assert.equal(JSON.stringify(outcome).includes(SAFE_TEMPLATE), false);
    const templateCall = argv.find((call) => call[1].includes("-dstemplate"));
    assert.deepEqual(templateCall[1], ["-config", CA, "-dstemplate", TEMPLATE]);
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
});
