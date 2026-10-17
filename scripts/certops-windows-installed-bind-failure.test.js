"use strict";

/** Parser and cleanup-guard proof. No IIS site, http.sys binding, or netsh
 * process is started. A missing host must not be reported as a pass. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const bind = require("../tests/e2e/helpers/certops-windows-installed-bind-failure");

const RUN = "ab".repeat(16);
const APP_IDS = [
  "{11111111-1111-1111-1111-111111111111}",
  "{22222222-2222-2222-2222-222222222222}",
];

function manifest(patch = {}) {
  return bind.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-bindfail-${RUN}`,
    predecessorThumbprint: "AB".repeat(20),
    siblingThumbprint: "CD".repeat(20),
    appIds: APP_IDS,
    ...patch,
  });
}

function listingFor(owned) {
  const primary = owned.sites.find((site) => site.role === "primary");
  const sibling = owned.sites.find((site) => site.role === "sibling");
  const spaced = "EE".repeat(20).split("").join(" ").trim();
  return [
    "SSL Certificate bindings:",
    "-------------------------",
    "",
    `    IP:port                      : 0.0.0.0:443`,
    `    Certificate Hash             : ${spaced}`,
    "    Application ID               : {aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}",
    "    Certificate Store Name       : MY",
    "",
    `    Hostname:port                : ${primary.binding.host}:${primary.binding.port}`,
    `    Certificate Hash             : ${primary.binding.thumbprint}`,
    `    Application ID               : ${primary.binding.appId}`,
    "    Certificate Store Name       : My",
    "",
    `    Hostname:port                : ${sibling.binding.host}:${sibling.binding.port}`,
    `    Certificate Hash             : ${sibling.binding.thumbprint}`,
    `    Application ID               : ${sibling.binding.appId}`,
    "    Certificate Store Name       : My",
    "",
  ].join("\n");
}

test("run manifest owns two unique sites and hostname bindings", () => {
  const owned = manifest();
  assert.equal(owned.sites.length, 2);
  assert.equal(
    new Set(owned.sites.map((site) => site.name)).size,
    2,
  );
  assert.equal(
    new Set(owned.sites.map((site) => site.binding.selector)).size,
    2,
  );
  assert.equal(owned.nativeExecutionQualified, false);
  assert.throws(() => manifest({ root: `C:\\Windows\\System32\\tt-bindfail-${RUN}` }));
  assert.throws(() => manifest({ root: "C:\\inetpub\\wwwroot" }));
  assert.throws(() =>
    manifest({
      appIds: [APP_IDS[0], APP_IDS[0]],
    }),
  );
});

test("netsh and appcmd parsers keep owned records and reject broken output", () => {
  const owned = manifest();
  const parsed = bind.parseNetshSslCertListing(listingFor(owned));
  assert.equal(parsed.length, 3);
  assert.equal(parsed[0].selector, "ipport=0.0.0.0:443");
  assert.equal(parsed[0].thumbprint, "EE".repeat(20));
  assert.equal(parsed[1].kind, "hostnameport");
  assert.equal(parsed[1].store, "My");
  const primary = owned.sites.find((site) => site.role === "primary");
  const sites = bind.parseAppcmdSiteList(
    `SITE "${primary.name}" (id:4,bindings:https/127.0.0.1:${primary.binding.port}:${primary.binding.host},state:Started)\nnot a site\n`,
  );
  assert.equal(sites.length, 1);
  assert.equal(sites[0].bindings[0].port, primary.binding.port);
  assert.equal(sites[0].bindings[0].hostHeader, primary.binding.host);
  assert.throws(() =>
    bind.parseNetshSslCertListing(
      "    Certificate Hash             : ABABABABABABABABABABABABABABABABABABABAB\n",
    ),
  );
  assert.throws(() =>
    bind.parseNetshSslCertListing(
      "    Hostname:port                : only.example:443\n\n",
    ),
  );
  assert.throws(() =>
    bind.parseAppcmdSiteList(
      'SITE "broken" (id:1,bindings:https/noport,state:Started)\n',
    ),
  );
});

test("injection touches only the owned primary selector and rollback restores it", () => {
  const owned = manifest();
  const plan = bind.buildCommandPlan(owned);
  const primary = owned.sites.find((site) => site.role === "primary").binding.selector;
  const sibling = owned.sites.find((site) => site.role === "sibling").binding.selector;
  for (const step of plan.steps.filter((item) =>
    ["inject-delete", "inject-add", "rollback-add"].includes(item.step),
  )) {
    assert.equal(step.args.join(" ").includes(primary), true);
    assert.equal(step.args.join(" ").includes(sibling), false);
  }
  const inject = plan.steps.find((step) => step.step === "inject-add");
  assert.equal(inject.expectedStatus, 1);
  assert.equal(inject.args.includes(`certhash=${bind.BAD_THUMBPRINT}`), true);
  const result = bind.simulateScriptContract(owned, {
    bindings: [
      {
        selector: "ipport=0.0.0.0:443",
        endpoint: "0.0.0.0:443",
        thumbprint: "EE".repeat(20),
        store: "MY",
      },
    ],
    sites: [{ name: "Default Web Site" }],
  });
  bind.verifyProof(result.proof);
  assert.deepEqual(result.remainingBindings, ["ipport=0.0.0.0:443"]);
  assert.deepEqual(result.remainingSites, ["Default Web Site"]);
  assert.equal(
    result.cleanup.some((command) => command.args.join(" ").includes("0.0.0.0")),
    false,
  );
  const port = owned.sites[0].binding.port;
  assert.throws(
    () =>
      bind.simulateScriptContract(owned, {
        bindings: [
          {
            selector: `hostnameport=other.example:${port}`,
            endpoint: `other.example:${port}`,
            thumbprint: "EE".repeat(20),
          },
        ],
        sites: [],
      }),
    /Preserve unresolved bind-failure fixture/,
  );
});

test("cleanup deletes only owned manifest resources and refuses a blanket reset", () => {
  const owned = manifest();
  const commands = bind.planCleanup(owned, {
    bindings: bind.parseNetshSslCertListing(listingFor(owned)),
    sites: owned.sites.map((site) => ({ name: site.name })),
  });
  assert.deepEqual(
    commands.filter((command) => command.file === "netsh.exe").map((command) => command.args[3]),
    owned.sites.map((site) => site.binding.selector),
  );
  assert.equal(
    commands.some((command) => command.args.includes("ipport=0.0.0.0:443")),
    false,
  );
  assert.throws(() =>
    bind.assertCleanupSafe(owned, [
      {
        file: "netsh.exe",
        args: ["http", "delete", "sslcert", "ipport=0.0.0.0:443"],
      },
    ]),
  );
  assert.throws(() =>
    bind.assertCleanupSafe(owned, [
      { file: "netsh.exe", args: ["int", "ip", "reset"] },
    ]),
  );
  assert.throws(() =>
    bind.assertCleanupSafe(owned, [
      { file: "netsh.exe", args: ["http", "delete", "sslcert"] },
    ]),
  );
  const rooted = bind.parseNetshSslCertListing(listingFor(owned));
  rooted[1].store = "Root";
  assert.throws(() =>
    bind.planCleanup(owned, { bindings: rooted, sites: [] }),
  );
});

test("a missing host capability is not a pass", () => {
  for (const probe of [undefined, {}, { windows: true }, { windows: true, iis: true, netsh: true }]) {
    const gate = bind.assessHostCapabilities(probe);
    assert.equal(gate.available, false);
    assert.equal(gate.passed, false);
    assert.equal(gate.nativeQualified, false);
  }
  const readyProbe = { windows: true, iis: true, netsh: true, appcmd: true };
  const ready = bind.assessHostCapabilities(readyProbe);
  assert.equal(ready.available, true);
  assert.equal(ready.passed, false);
  const entry = require("./certops-windows-installed-bind-failure");
  assert.equal(entry.run({ probe: {} }).passed, false);
  assert.equal(entry.run({ probe: {} }).reason, "host capability absent");
  assert.equal(
    entry.run({ probe: readyProbe, execute: false }).reason,
    "host execution not requested",
  );
  const planned = entry.run({
    probe: { windows: true, iis: true, netsh: true, appcmd: true },
    execute: true,
    plan: bind.buildCommandPlan(manifest()),
  });
  assert.equal(planned.passed, false);
  assert.equal(planned.nativeQualified, false);
  assert.equal(planned.planSafe, true);
});

test("command entry fails closed without claiming native qualification", () => {
  const script = path.resolve(__dirname, "certops-windows-installed-bind-failure.js");
  const absent = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(absent.status, 1);
  const absentBody = JSON.parse(absent.stdout);
  assert.equal(absentBody.passed, false);
  assert.equal(absentBody.nativeQualified, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-bindfail-"));
  try {
    const plan = bind.buildCommandPlan(manifest());
    const file = path.join(dir, "plan.json");
    fs.writeFileSync(file, JSON.stringify(plan));
    const checked = spawnSync(process.execPath, [script, "--check-plan", file], {
      encoding: "utf8",
    });
    assert.equal(checked.status, 0);
    assert.equal(JSON.parse(checked.stdout).passed, false);
    assert.equal(JSON.parse(checked.stdout).nativeQualified, false);
    plan.steps.push({
      step: "inject-add",
      file: "netsh.exe",
      args: ["http", "add", "sslcert", "ipport=0.0.0.0:443"],
    });
    fs.writeFileSync(file, JSON.stringify(plan));
    const refused = spawnSync(process.execPath, [script, "--check-plan", file], {
      encoding: "utf8",
    });
    assert.equal(refused.status, 1);
    assert.equal(JSON.parse(refused.stdout).passed, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("host script and workflow keep execution behind a fail-closed gate", () => {
  const root = path.resolve(__dirname, "..");
  const ps1 = fs.readFileSync(
    path.join(root, "scripts", "certops-windows-installed-bind-failure.ps1"),
    "utf8",
  );
  const workflow = fs.readFileSync(
    path.join(root, ".github", "workflows", "certops-windows-installed-bind-failure.yml"),
    "utf8",
  );
  assert.ok(
    ps1.indexOf("host capability absent") < ps1.indexOf("& $allowed[$fileName]"),
  );
  assert.match(ps1, /CERTOPS_WINDOWS_BIND_FAILURE_REQUIRED/);
  assert.match(ps1, /CERTOPS_WINDOWS_BIND_FAILURE_EXECUTE/);
  assert.doesNotMatch(ps1, /Invoke-Expression/);
  assert.doesNotMatch(ps1, /netsh int ip reset/);
  assert.doesNotMatch(ps1, /winsock reset/);
  assert.match(workflow, /^on:\n {2}workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /actions\/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd/);
  assert.match(workflow, /actions\/setup-node@53b83947a5a98c8d113130e565377fae1a50d02f/);
  assert.match(workflow, /Install-WindowsFeature/);
  assert.match(workflow, /scripts\/certops-windows-bind-failure-native\.js/);
  assert.match(workflow, /certops-windows-bind-interposer-compile\.test\.ps1/);
  for (const rel of bind.REQUIRED_SOURCES) {
    assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
  }
  for (const flag of ["nativeExecutionQualified", "verifyFailureQualified", "failedRollbackQualified", "hostCapabilityAbsentIsPass"]) {
    assert.throws(() => bind.verifyProof({ ...bind.simulateScriptContract(manifest()).proof, [flag]: true }));
  }
});
