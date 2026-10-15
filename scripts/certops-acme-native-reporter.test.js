"use strict";
/** Controlled actual reporter execution; synthetic observations never qualify a native host. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm"),
  { createRequire } = require("node:module");
test("actual streaming reporter emits every validated Linux native sidecar", async () => {
  const filename = path.join(__dirname, "certops-stack-reporter.js"),
    realRequire = createRequire(filename),
    event = require("./test-support/acme-stage-artifact.cjs")
      .artifact()
      .events.find((x) => x.nativeAcmeBulkRenewal);
  const observations = {
    "./certops-acme-stage-report": event.nativeAcmeStageFaults,
    "./certops-acme-background-report": event.nativeAcmeBackgroundRenewals,
    "./certops-acme-bulk-report": event.nativeAcmeBulkRenewal,
    "./certops-acme-native-adoption-report": event.nativeAcmeRenewalSetup,
    "./certops-acme-certificate-outbox-report":
      event.nativeAcmeCertificateOutbox,
    "./certops-acme-disabled-profile-report": event.nativeAcmeDisabledProfile,
  };
  const controlledFs = {
    ...fs,
    readFileSync(file, ...args) {
      if (String(file) === "/etc/os-release")
        return 'ID=ubuntu\nVERSION_ID="24.04"\n';
      if (String(file).endsWith("acme-key-reuse-certbot.json"))
        return JSON.stringify(event.nativeAcmeKeyReuse);
      return fs.readFileSync(file, ...args);
    },
  };
  const controlledRequire = (name) => {
    if (name === "node:fs") return controlledFs;
    const actual = realRequire(name);
    return Object.hasOwn(observations, name)
      ? { ...actual, readProof: () => observations[name] }
      : actual;
  };
  const module = { exports: {} };
  vm.runInNewContext(
    fs.readFileSync(filename, "utf8"),
    {
      module,
      exports: module.exports,
      require: controlledRequire,
      __dirname: path.dirname(filename),
      process: {
        platform: "linux",
        env: { CERTOPS_REPORT_SCOPE: "real-agent-acme-filesystem" },
        getuid: () => 65534,
        report: {
          getReport: () => ({ header: { glibcVersionRuntime: "2.39" } }),
        },
      },
      console,
      Buffer,
    },
    { filename },
  );
  const lines = [];
  for await (const line of module.exports([
    { type: "test:pass", data: { name: event.name } },
  ]))
    lines.push(JSON.parse(line));
  assert.equal(lines.length, 1);
  for (const [name, value] of Object.entries(event))
    if (name.startsWith("nativeAcme"))
      assert.deepEqual(JSON.parse(JSON.stringify(lines[0][name])), value, name);
});
