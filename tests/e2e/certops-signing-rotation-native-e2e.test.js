/**
 * Exercise signing-key rotation with real agent processes and a disposable API database.
 * certops-signing-rotation-qualification.yml owns the agents, signing keys and temporary credential
 * directories. Persisted key pins and actual signed claims survive process restart;
 * these checks do not qualify an external CA or an installed Windows service. */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  http = require("node:http");
const { spawn, spawnSync } = require("node:child_process"),
  { createApiFixture } = require("./helpers/certops-api-fixture"),
  { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = [
  "rotation-native-owned-fleet",
  "rotation-native-old-signed-job",
  "rotation-native-begin",
  "rotation-native-pending-refusal",
  "rotation-native-heartbeat-acks",
  "rotation-native-complete",
  "rotation-native-restart-new-signed-job",
  "rotation-native-repeat-complete-refusal",
  "rotation-native-cleanup",
];
async function wait(check, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Owned signing rotation fixture exceeded deadline");
}
function directoryIdentity(file, expected) {
  const before = fs.lstatSync(file, { bigint: true });
  assert.ok(
    before.isDirectory() && !before.isSymbolicLink() && before.ino > 0n,
    "Original regular owned directory required",
  );
  assert.equal(fs.realpathSync.native(file), path.resolve(file));
  const after = fs.lstatSync(file, { bigint: true });
  assert.ok(
    after.isDirectory() &&
      !after.isSymbolicLink() &&
      after.dev === before.dev &&
      after.ino === before.ino,
    "Owned directory changed during observation",
  );
  const current = { dev: before.dev, ino: before.ino };
  if (expected)
    assert.ok(
      current.dev === expected.dev && current.ino === expected.ino,
      "Foreign directory replacement preserved",
    );
  return current;
}

test(
  "isolated operator signing rotation adopts native pins and fences incomplete fleet completion",
  { timeout: 300000 },
  async (t) => {
    const baseUrl = process.env.CERTOPS_SIGNING_ROTATION_API_URL;
    if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
      // skip-reason: no-host - requires separate empty signing database and real Linux agents
      t.skip("Separate disposable signing rotation stack required");
      return;
    }
    assert.equal(process.env.CERTOPS_SIGNING_ROTATION_DISPOSABLE_STACK, "1");
    assert.equal(process.platform, "linux");
    assert.ok(baseUrl);
    const endpoint = new URL(baseUrl);
    assert.equal(endpoint.protocol, "http:");
    assert.ok(
      ["127.0.0.1", "localhost", "host.docker.internal"].includes(
        endpoint.hostname,
      ),
    );
    const fixture = await createApiFixture(baseUrl),
      root = fs.mkdtempSync(
        path.join(os.tmpdir(), "certops-signing-rotation-"),
      );
    const rootIdentity = directoryIdentity(root);
    let ready = false,
      failure,
      proxy;
    const agents = [],
      children = [],
      closedChildren = new WeakSet(),
      wireKeys = new Map();
    const attachment = require("./helpers/certops-acme-agent-attachment");
    const gate = createHostGate({
      suite: "native-signing-rotation",
      evidenceLevel: "e2e",
      strict: true,
      reportPath: process.env.CERTOPS_SIGNING_ROTATION_REPORT,
      requiredCapabilities: [
        "api",
        "postgres",
        "isolated-empty-signing-database",
        "native-node-agent",
        "rotation-cli",
      ],
      fixtureSource: {
        file: "tests/e2e/certops-signing-rotation-native-e2e.test.js",
        sha256: crypto
          .createHash("sha256")
          .update(fs.readFileSync(__filename))
          .digest("hex"),
      },
      probeCapabilities: async () => ({
        api: { available: (await fetch(new URL("/", baseUrl))).status === 200 },
        postgres: { available: true },
        "isolated-empty-signing-database": {
          available: (
            await fixture.pool.query(
              "SELECT (SELECT count(*) FROM certops_agents)::int AS agents,(SELECT count(*) FROM certops_signing_keys)::int AS keys",
            )
          ).rows.every((row) => row.agents === 0 && row.keys === 0),
        },
        "native-node-agent": { available: process.platform === "linux" },
        "rotation-cli": {
          available: fs.existsSync(
            path.resolve(
              __dirname,
              "../../scripts/certops-rotate-signing-key.js",
            ),
          ),
        },
      }),
    });
    const requiredSources = [
      ...new Set([
        ...require("./helpers/certops-acme-native-adoption").REQUIRED_SOURCES,
        "tests/e2e/certops-signing-rotation-native-e2e.test.js",
        "tests/e2e/helpers/certops-acme-agent-attachment.js",
        "tests/e2e/helpers/certops-acme-agent-pidfd.py",
        "scripts/certops-rotate-signing-key.js",
        "apps/api/services/certops/jobSigning.js",
        "packages/agent/src/signing/index.js",
        ".github/workflows/certops-signing-rotation-qualification.yml",
      ]),
    ];
    gate.report.fixtureSources = requiredSources.map((file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    }));
    gate.report.executionScope =
      "Deployment-global operator CLI rotation in an explicitly separate initially empty signing database; unmodified native agents and real public noop jobs only; no force, fabricated keys or certificate side effects";
    const hash = (file) =>
        crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
      pin = (item) =>
        JSON.parse(
          fs.readFileSync(
            path.join(item.directory, "signing-key-pin.json"),
            "utf8",
          ),
        ).signingKeyId;
    async function stop(item) {
      const child = item?.child;
      if (!child) return;
      if (closedChildren.has(child)) return;
      if (!child.pid || child.exitCode !== null || child.signalCode !== null) {
        await wait(() => closedChildren.has(child), 5000);
        return;
      }
      assert.match(item.startTicks, /^[1-9][0-9]*$/);
      item.resources ??= [];
      const retained = await attachment.attachIdleAgent({
        agent: child,
        entry: path.resolve(
          __dirname,
          "../../packages/agent/bin/tokentimer-agent.js",
        ),
        workDir: item.directory,
        resources: item.resources,
        waitUntil: wait,
        isAgentClosed: () => closedChildren.has(child),
        expectedStartTicks: item.startTicks,
      });
      await retained.stopAndDrain();
      retained.release();
    }
    function start(item, bootstrap) {
      const child = spawn(
        process.execPath,
        [
          path.resolve(
            __dirname,
            "../../packages/agent/bin/tokentimer-agent.js",
          ),
        ],
        {
          env: {
            PATH: process.env.PATH,
            HOME: process.env.HOME,
            LANG: "C.UTF-8",
            TOKENTIMER_AGENT_CONFIG_DIR: item.directory,
            ...(process.env.NODE_PATH
              ? { NODE_PATH: process.env.NODE_PATH }
              : {}),
            ...(bootstrap
              ? {
                  TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken,
                  TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(
                    bootstrap.token.id,
                  ),
                }
              : {}),
          },
          stdio: "ignore",
        },
      );
      child.on("error", () => {});
      child.once("close", () => closedChildren.add(child));
      children.push(child);
      item.child = child;
      const raw = fs.readFileSync(`/proc/${child.pid}/stat`, "utf8"),
        fields = raw
          .slice(raw.lastIndexOf(") ") + 2)
          .trim()
          .split(/\s+/);
      assert.equal(Number(fields[1]), process.pid);
      assert.match(fields[19], /^[1-9][0-9]*$/);
      item.startTicks = fields[19];
    }
    const rows = async () =>
      (
        await fixture.pool.query(
          "SELECT id,agent_id,pinned_signing_key_id,status FROM certops_agents WHERE workspace_id=$1 ORDER BY agent_id",
          [fixture.workspaceId],
        )
      ).rows;
    const ownedFleet = async () => {
      const all = (
        await fixture.pool.query(
          "SELECT agent_id,workspace_id FROM certops_agents WHERE status<>'retired'",
        )
      ).rows;
      assert.equal(all.length, 2);
      assert.ok(
        all.every(
          (row) =>
            String(row.workspace_id) === String(fixture.workspaceId) &&
            agents.some((item) => item.agentId === row.agent_id),
        ),
        "Rotation must never include a foreign active agent",
      );
    };
    function cli(command, expected = 0) {
      const response = spawnSync(
        process.execPath,
        [
          path.resolve(
            __dirname,
            "../../scripts/certops-rotate-signing-key.js",
          ),
          command,
          "--json",
        ],
        {
          env: process.env,
          encoding: "utf8",
          timeout: 20000,
          maxBuffer: 65536,
        },
      );
      assert.equal(
        response.status,
        expected,
        `Operator ${command} returned unexpected exit; raw output withheld`,
      );
      const match = response.stdout.match(/(?:^|\n)(\{[\s\S]*\})\s*$/);
      assert.ok(match, "Operator must emit bounded structured status");
      return JSON.parse(match[1]);
    }
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
    let oldKey, newKey;
    async function noop(item, expectedKey) {
      const response = await fixture.request(`${prefix}/jobs`, "POST", {
        operation: "noop",
        assignedAgentId: item.dbId,
      });
      assert.equal(response.status, 201);
      const id = response.body.job.id;
      await wait(async () => {
        assert.equal(item.child.exitCode, null);
        assert.equal(item.child.signalCode, null);
        return (
          (
            await fixture.pool.query(
              "SELECT status FROM certificate_jobs WHERE id=$1",
              [id],
            )
          ).rows[0].status === "succeeded"
        );
      });
      assert.equal(
        wireKeys.get(String(id)),
        expectedKey,
        "Actual signed claim must use the expected key identity",
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT attempt_count FROM certificate_jobs WHERE id=$1",
            [id],
          )
        ).rows[0].attempt_count,
        1,
      );
    }
    try {
      assert.equal(await gate.preflight(), true);
      ready = true;
      proxy = http.createServer((request, response) => {
        const upstream = http.request(
          new URL(request.url, baseUrl),
          { method: request.method, headers: request.headers, timeout: 10000 },
          (reply) => {
            if (!request.url.endsWith("/jobs/claim")) {
              response.writeHead(reply.statusCode, reply.headers);
              reply.pipe(response);
              return;
            }
            const chunks = [];
            let size = 0;
            reply.on("data", (chunk) => {
              size += chunk.length;
              if (size > 1024 * 1024)
                reply.destroy(new Error("Claim response exceeds bound"));
              else chunks.push(chunk);
            });
            reply.on("end", () => {
              const bytes = Buffer.concat(chunks);
              try {
                for (const job of JSON.parse(bytes).jobs || []) {
                  let id = job.jobId || job.id || job.payload?.jobId;
                  if (!id && job.payloadB64)
                    id = JSON.parse(
                      Buffer.from(job.payloadB64, "base64"),
                    ).jobId;
                  if (id) wireKeys.set(String(id), job.signingKeyId);
                }
              } catch {}
              response.writeHead(reply.statusCode, reply.headers);
              response.end(bytes);
            });
            reply.on("error", () => response.destroy());
          },
        );
        upstream.on("error", () => response.writeHead(502).end());
        upstream.on("timeout", () => upstream.destroy());
        request.pipe(upstream);
      });
      await new Promise((resolve, reject) => {
        proxy.once("error", reject);
        proxy.listen(0, "127.0.0.1", () => {
          proxy.removeListener("error", reject);
          resolve();
        });
      });
      await gate.scenario(scenarios[0], async () => {
        for (let index = 0; index < 2; index++) {
          const item = {
            agentId: crypto.randomUUID(),
            directory: path.join(root, String(index)),
          };
          agents.push(item);
          fs.mkdirSync(item.directory, { mode: 0o700 });
          item.directoryIdentity = directoryIdentity(item.directory);
          fs.writeFileSync(
            path.join(item.directory, "config.json"),
            JSON.stringify({
              serverUrl: `http://127.0.0.1:${proxy.address().port}`,
              agentId: item.agentId,
              allowInsecureLocalHttp: true,
              pollIntervalMs: 250,
              heartbeatIntervalMs: 500,
              discovery: null,
              windowsDiscovery: { enabled: false },
              execution: { enabled: true, dryRun: false },
              policy: { allowedPaths: [root], allowedCommands: {} },
            }),
            { mode: 0o600 },
          );
          const bootstrap = await fixture.request(
            `${prefix}/agent-bootstrap-tokens`,
            "POST",
            {
              name: "Owned rotation native agent",
              expiresAt: new Date(Date.now() + 3600000).toISOString(),
            },
          );
          assert.equal(bootstrap.status, 201);
          start(item, bootstrap.body);
          await wait(
            async () =>
              fs.existsSync(path.join(item.directory, "credential")) &&
              fs.existsSync(
                path.join(item.directory, "signing-key-pin.json"),
              ) &&
              (await rows()).some((row) => row.agent_id === item.agentId),
          );
          item.dbId = (await rows()).find(
            (row) => row.agent_id === item.agentId,
          ).id;
        }
        await ownedFleet();
        const status = cli("status");
        oldKey = status.active.signingKeyId;
        assert.equal(status.rotationInProgress, false);
        assert.ok(agents.every((item) => pin(item) === oldKey));
      });
      await gate.scenario(scenarios[1], () => noop(agents[0], oldKey));
      await stop(agents[1]);
      await gate.scenario(scenarios[2], async () => {
        await ownedFleet();
        const begun = cli("begin");
        newKey = begun.signingKeyId;
        assert.ok(newKey && newKey !== oldKey);
        assert.equal(begun.supersedesSigningKeyId, oldKey);
        await wait(() => pin(agents[0]) === newKey);
        assert.equal(pin(agents[1]), oldKey);
      });
      await gate.scenario(scenarios[3], async () => {
        await ownedFleet();
        const result = cli("complete", 1);
        assert.equal(result.completed, false);
        assert.equal(result.reason, "fleet_incomplete");
        const status = cli("status");
        assert.equal(status.rotationInProgress, true);
        assert.equal(status.activeAgents, 2);
        assert.equal(status.fullyAcked, false);
        assert.equal(status.retiring.signingKeyId, oldKey);
      });
      await gate.scenario(scenarios[4], async () => {
        start(agents[1]);
        await wait(
          async () =>
            pin(agents[1]) === newKey &&
            (await rows()).every((row) => row.pinned_signing_key_id === newKey),
        );
        await ownedFleet();
        const status = cli("status");
        assert.equal(status.activeAgents, 2);
        assert.equal(status.ackCount, 2);
        assert.equal(status.fullyAcked, true);
      });
      await gate.scenario(scenarios[5], async () => {
        await ownedFleet();
        const complete = cli("complete");
        assert.equal(complete.completed, true);
        assert.equal(complete.forced, false);
        const status = cli("status");
        assert.equal(status.rotationInProgress, false);
        assert.equal(status.active.signingKeyId, newKey);
        assert.equal(
          (
            await fixture.pool.query(
              "SELECT status FROM certops_signing_keys WHERE signing_key_id=$1",
              [oldKey],
            )
          ).rows[0].status,
          "retired",
        );
      });
      await gate.scenario(scenarios[6], async () => {
        const before = ["credential", "signing-key-pin.json"].map((file) =>
          hash(path.join(agents[0].directory, file)),
        );
        await stop(agents[0]);
        start(agents[0]);
        await noop(agents[0], newKey);
        assert.deepEqual(
          ["credential", "signing-key-pin.json"].map((file) =>
            hash(path.join(agents[0].directory, file)),
          ),
          before,
        );
        assert.equal((await rows()).length, 2);
      });
      await gate.scenario(scenarios[7], () => {
        const repeated = cli("complete", 1);
        assert.equal(repeated.completed, false);
        assert.equal(repeated.reason, "no_retiring_key");
      });
    } catch (error) {
      failure = error;
    } finally {
      const cleanup = async () => {
        const outcomes = await Promise.allSettled([
          ...agents.map(stop),
          (async () => {
            if (proxy) {
              proxy.closeAllConnections();
              await new Promise((resolve) => proxy.close(resolve));
            }
          })(),
        ]);
        const errors = outcomes
          .filter((item) => item.status === "rejected")
          .map((item) => item.reason);
        if (errors.length)
          throw new AggregateError(
            errors,
            "Owned rotation consumers did not drain; preserve public and private recovery state",
          );
        assert.ok(
          children.every((child) => closedChildren.has(child)),
          "Original agent close required before destructive cleanup",
        );
        for (const item of agents) {
          attachment.assertCleanupSafe(item.directory);
          assert.ok(
            (item.resources || []).every(
              (resource) =>
                !resource.hasOwnershipReceipt() && !resource.hasLiveResource(),
            ),
            "Unresolved retained agent ownership preserves recovery state",
          );
        }
        const assertDirectories = () => {
          directoryIdentity(root, rootIdentity);
          for (const item of agents) {
            assert.ok(
              item.directoryIdentity,
              "Unknown original agent directory preserves state",
            );
            directoryIdentity(item.directory, item.directoryIdentity);
          }
        };
        assertDirectories();
        await fixture.cleanup();
        assertDirectories();
        assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
        assert.ok(path.basename(root).startsWith("certops-signing-rotation-"));
        fs.rmSync(root, { recursive: true, force: true });
      };
      try {
        if (ready) {
          await gate.scenario(scenarios.at(-1), cleanup);
          await gate.finish({ requiredScenarios: scenarios });
        } else await cleanup();
      } catch (error) {
        failure = failure
          ? new AggregateError([failure, error], "Rotation and cleanup failed")
          : error;
      }
      if (failure) throw failure;
    }
  },
);
