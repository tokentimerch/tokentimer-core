"use strict";
// Benign temporary-file ownership checks. Portable modes do not qualify Linux
// DAC or systemd; the native config wrapper always requires Unix mode0600.
const test = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const {
  retainOwnedFile,
} = require("../tests/e2e/helpers/certops-linux-installed-discovery");
function fixture(action) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-retained-config-"),
  );
  const file = path.join(root, "config.json");
  fs.writeFileSync(file, '{"publicFixture":true}\n', { mode: 0o600 });
  const stat = fs.statSync(file);
  try {
    action({
      root,
      file,
      retain: () =>
        retainOwnedFile(file, {
          uid: stat.uid,
          gid: stat.gid,
          mode: stat.mode & 0o777,
        }),
    });
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith("certops-retained-config-"));
    fs.rmSync(root, { recursive: true, force: true });
  }
}
test("retained file restores exact original bytes without changing original identity", () =>
  fixture(({ file, retain }) => {
    const original = fs.readFileSync(file),
      stat = fs.statSync(file),
      held = retain();
    held.write(Buffer.from('{"ownedTemporaryChange":true}\n'));
    held.restore();
    held.close();
    assert.ok(fs.readFileSync(file).equals(original));
    assert.equal(fs.statSync(file).ino, stat.ino);
  }));

test("database cleanup refuses an existing or dangling ownership receipt", () =>
  fixture(({ root }) => {
    const {
      assertHostReceiptRemoved,
    } = require("./certops-linux-systemd-ownership");
    assert.doesNotThrow(() => assertHostReceiptRemoved(root));
    const receipt = path.join(root, "certops-linux-systemd-owned.json");
    fs.writeFileSync(receipt, "foreign ownership");
    assert.throws(() => assertHostReceiptRemoved(root));
    assert.equal(fs.readFileSync(receipt, "utf8"), "foreign ownership");
    fs.unlinkSync(receipt);
    const target = path.join(root, "absent-target");
    fs.mkdirSync(target);
    fs.symlinkSync(
      target,
      receipt,
      process.platform === "win32" ? "junction" : "dir",
    );
    fs.rmdirSync(target);
    assert.throws(() => assertHostReceiptRemoved(root));
    fs.unlinkSync(receipt);
    const active = path.join(
      root,
      "certops-linux-systemd-discovery-active.json",
    );
    fs.writeFileSync(active, "unknown restoration");
    assert.throws(() => assertHostReceiptRemoved(root));
  }));

test("both installed workflows always attempt cleanup and require successful host drain before database deletion", () => {
  const { createRequire } = require("node:module"),
    yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
  for (const name of [
    "certops-linux-systemd.yml",
    "certops-linux-published-upgrade.yml",
  ]) {
    const workflow = yaml.load(
      fs.readFileSync(
        path.join(__dirname, "../.github/workflows", name),
        "utf8",
      ),
    );
    let checked = 0;
    for (const job of Object.values(workflow.jobs)) {
      const host = job.steps.find((step) => step.id === "owned-host-cleanup"),
        database = job.steps.find(
          (step) => step.name === "Destroy disposable database stack",
        );
      if (!database) continue;
      checked++;
      assert.equal(host.if, "always()");
      assert.equal(database.if, "always()");
      assert.ok(job.steps.indexOf(host) < job.steps.indexOf(database));
      assert.equal(
        database.env.CERTOPS_HOST_CLEANUP_OUTCOME,
        "${{ steps.owned-host-cleanup.outcome }}",
      );
      const outcome = database.run.indexOf(
          'test "$CERTOPS_HOST_CLEANUP_OUTCOME" = success',
        ),
        guard = database.run.indexOf("assertHostReceiptRemoved"),
        destroy = database.run.indexOf("docker compose");
      assert.ok(outcome >= 0 && outcome < guard && guard < destroy);
    }
    assert.equal(
      checked,
      1,
      "Exactly one installed-host database cleanup must be checked",
    );
  }
});

test("actual independent cleanup refuses missing completion even after its active guard disappears", () =>
  fixture(({ root }) => {
    // Execute the actual cleanup source with native command execution forbidden.
    // Only the outer receipt's platform metadata is controlled to reach the new
    // restoration boundary on Windows. This can never produce native proof.
    const helper = require("../tests/e2e/helpers/certops-linux-installed-discovery"),
      crypto = require("node:crypto");
    const source = fs.readFileSync(
      path.join(__dirname, "certops-linux-systemd-cleanup.js"),
      "utf8",
    );
    const digest = (file) =>
      crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    const runId = "0123456789",
      writeRoot = `/var/lib/tokentimer-qualification-${runId}`;
    const receipt = {
      root: "/opt/tokentimer-agent",
      unit: "tokentimer-agent.service",
      user: "tokentimer-agent",
      installer: path.resolve(
        __dirname,
        "../packages/agent/scripts/install-agent.sh",
      ),
      fixtureSha256: digest(
        path.resolve(__dirname, "../tests/e2e/linux-systemd-real-journey.js"),
      ),
      writeFixture: {
        runId,
        root: writeRoot,
        allowed: `${writeRoot}/allowed`,
        denied: `${writeRoot}/denied`,
        probe: `${writeRoot}/write-probe.js`,
        probeSha256: digest(
          path.resolve(
            __dirname,
            "../tests/e2e/helpers/linux-systemd-write-probe.js",
          ),
        ),
      },
      installedDiscoveryRequired: true,
      installedDiscoveryNonce: "a".repeat(64),
      installedDiscoveryCompletion: helper.completionPath(root),
    };
    const receiptPath = path.join(root, "certops-linux-systemd-owned.json");
    fs.writeFileSync(receiptPath, JSON.stringify(receipt));
    let nativeCalls = 0,
      acceptRestoration = false,
      destructiveCalls = 0;
    const localRequire = (name) => {
      if (name === "node:fs")
        return {
          ...fs,
          existsSync(file) {
            return acceptRestoration && file.endsWith("/cgroup.procs")
              ? true
              : fs.existsSync(file);
          },
          readFileSync(file, options) {
            return acceptRestoration && file.endsWith("/cgroup.procs")
              ? "123\n"
              : fs.readFileSync(file, options);
          },
          rmSync() {
            destructiveCalls++;
            throw new Error("Destructive cleanup forbidden");
          },
          unlinkSync() {
            destructiveCalls++;
            throw new Error("Receipt deletion forbidden");
          },
          lstatSync(file, options) {
            const stat = fs.lstatSync(file, options);
            if (file !== receiptPath) return stat;
            return Object.assign(Object.create(stat), {
              uid: 0,
              mode: 0o100600,
            });
          },
        };
      if (name === "node:child_process")
        return {
          spawnSync(executable, args) {
            nativeCalls++;
            if (acceptRestoration && executable === "sh") return { status: 0 };
            if (
              acceptRestoration &&
              executable === "systemctl" &&
              args.includes("--property=MainPID")
            )
              return { status: 0, stdout: "0\n" };
            throw new Error(
              "No native process permitted in cleanup refusal control",
            );
          },
        };
      if (
        acceptRestoration &&
        name === "../tests/e2e/helpers/certops-linux-installed-discovery"
      )
        return { ...helper, assertCompletion() {} };
      if (acceptRestoration && name === "./certops-linux-systemd-ownership")
        return { ...require(name), assertNoSymlinkTargets() {} };
      return require(name);
    };
    const localModule = { exports: {} };
    const cleanup = new Function(
      "require",
      "process",
      "__dirname",
      "module",
      source + "\nreturn module.exports.cleanup;",
    )(
      localRequire,
      {
        platform: "linux",
        getuid: () => 0,
        env: {
          GITHUB_ACTIONS: "true",
          RUNNER_ENVIRONMENT: "github-hosted",
          CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST: "1",
          RUNNER_TEMP: root,
        },
      },
      __dirname,
      localModule,
    );
    const guard = helper.guardPath(root);
    fs.writeFileSync(guard, "owned unresolved restoration");
    assert.throws(cleanup, /Active discovery guard preserves installed state/);
    assert.equal(nativeCalls, 0);
    fs.unlinkSync(guard);
    assert.throws(
      cleanup,
      (error) =>
        error.code === "ENOENT" && error.path === helper.completionPath(root),
    );
    assert.equal(nativeCalls, 0);
    assert.ok(fs.existsSync(receiptPath));
    // Control only the already-restored prerequisite and native command returns;
    // execute the real cleanup ordering without performing any host operation.
    acceptRestoration = true;
    assert.throws(cleanup, /owned systemd cgroup still has processes/);
    assert.equal(nativeCalls, 2);
    assert.equal(destructiveCalls, 0);
    assert.ok(fs.existsSync(receiptPath));
  }));

test("original plan requires bound completion and cannot be weakened to absent or false", () => {
  const helper = require("../tests/e2e/helpers/certops-linux-installed-discovery"),
    runnerTemp = path.resolve(os.tmpdir());
  const original = {
    installedDiscoveryRequired: true,
    installedDiscoveryNonce: "a".repeat(64),
    installedDiscoveryCompletion: helper.completionPath(runnerTemp),
  };
  assert.doesNotThrow(() => helper.assertReceiptPlan(original, runnerTemp));
  for (const change of [
    { installedDiscoveryRequired: false },
    { installedDiscoveryRequired: undefined },
    { installedDiscoveryNonce: "foreign" },
    { installedDiscoveryCompletion: path.join(runnerTemp, "foreign.json") },
  ])
    assert.throws(() =>
      helper.assertReceiptPlan({ ...original, ...change }, runnerTemp),
    );
});

test("fresh restored-service heartbeat requires real uptime change beyond independent DB cutoff", () => {
  const {
    freshAuthenticatedHeartbeat,
  } = require("../tests/e2e/helpers/certops-linux-installed-discovery");
  const before = { uptime_seconds: 30, checked_at: "2026-10-15T10:00:00.000Z" };
  const fresh = { uptime_seconds: 2, last_seen_at: "2026-10-15T10:00:01.000Z" };
  assert.equal(
    freshAuthenticatedHeartbeat(before, fresh),
    true,
    "A genuine restart may reset uptime",
  );
  for (const row of [
    { ...fresh, uptime_seconds: 30 },
    { ...fresh, uptime_seconds: null },
    { ...fresh, uptime_seconds: undefined },
    { ...fresh, uptime_seconds: NaN },
    { ...fresh, last_seen_at: before.checked_at },
  ])
    assert.equal(freshAuthenticatedHeartbeat(before, row), false);
});

test("actual parent finally preserves private roots, accounts and database after uninstall or process-drain failure", async () => {
  const { createRequire } = require("node:module");
  const espree = createRequire(
    require.resolve("../packages/agent/node_modules/eslint/package.json"),
  )("espree");
  const source = fs.readFileSync(
    path.join(__dirname, "../tests/e2e/linux-systemd-real-journey.js"),
    "utf8",
  );
  const ast = espree.parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    range: true,
  });
  const matches = [];
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (
      node.type === "TryStatement" &&
      node.finalizer &&
      source.slice(...node.finalizer.range).includes("let discoverySafe")
    )
      matches.push(node.finalizer);
    for (const child of Object.values(node))
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === "object") visit(child);
  };
  visit(ast);
  assert.equal(matches.length, 1);
  const body = source.slice(matches[0].range[0] + 1, matches[0].range[1] - 1);
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  const names = [
    "owned",
    "discoveryResources",
    "installedDiscovery",
    "ownershipPlan",
    "process",
    "cleanupErrors",
    "require",
    "ROOT",
    "UNIT_FILE",
    "DROPINS",
    "POLKIT",
    "writeFixture",
    "command",
    "installer",
    "mainPid",
    "fs",
    "spawnSync",
    "USER",
    "serviceProperty",
    "ownershipReceipt",
    "agentId",
    "pool",
    "workspaceId",
    "assert",
    "UNIT",
  ];
  const run = new AsyncFunction(...names, body);
  for (const state of [
    {},
    { uninstallFails: true },
    { livePid: true },
    { cgroupLive: true },
    { discoveryUnknown: true },
  ]) {
    const calls = [],
      errors = [],
      unresolved = Object.values(state).some(Boolean);
    const values = [
      true,
      [
        {
          assertCleanupSafe() {
            calls.push("discovery");
            if (state.discoveryUnknown)
              throw Error("controlled unknown discovery");
          },
        },
      ],
      {
        assertCompletion() {
          calls.push("completion");
        },
      },
      {},
      { env: { RUNNER_TEMP: "/owned/temp" } },
      errors,
      () => ({
        assertNoSymlinkTargets() {
          calls.push("ownership");
        },
      }),
      "/owned/root",
      "/owned/unit",
      "/owned/dropins",
      "/owned/polkit",
      { root: "/owned/write" },
      (file) => {
        calls.push(file);
        if (file === "sh" && state.uninstallFails)
          throw Error("controlled uninstall failure");
      },
      "/owned/installer",
      () => (state.livePid ? 123 : 0),
      {
        lstatSync() {
          return undefined;
        },
        rmSync() {
          calls.push("private-delete");
        },
        existsSync(file) {
          return Boolean(state.cgroupLive && file.includes("cgroup.procs"));
        },
        readFileSync() {
          return "123\n";
        },
        unlinkSync() {
          calls.push("receipt-delete");
        },
      },
      () => {
        calls.push("account-query");
        return { status: 2 };
      },
      "owned-user",
      () => "not-found",
      "/owned/receipt",
      "owned-agent",
      {
        async query() {
          calls.push("database-delete");
          return { rows: [] };
        },
      },
      "owned-workspace",
      assert,
      "tokentimer-agent.service",
    ];
    await run(...values);
    assert.equal(errors.length > 0, unresolved);
    for (const action of [
      "private-delete",
      "account-query",
      "receipt-delete",
      "database-delete",
    ])
      assert.equal(calls.includes(action), !unresolved, action);
  }
});
test("byte-identical foreign replacement is refused before either original or replacement mutation", () =>
  fixture(({ root, file, retain }) => {
    const held = retain(),
      bytes = fs.readFileSync(file),
      moved = path.join(root, "original-moved.json");
    fs.renameSync(file, moved);
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    assert.throws(() => held.write(Buffer.from('{"mustNotWrite":true}\n')));
    assert.throws(() => held.restore());
    assert.ok(fs.readFileSync(file).equals(bytes));
    assert.ok(fs.readFileSync(moved).equals(bytes));
    held.disposeHandle();
  }));
