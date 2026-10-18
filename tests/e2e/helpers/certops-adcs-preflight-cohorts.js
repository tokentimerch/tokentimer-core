"use strict";
/* Rate-limit-safe native preflight cohorts: real isolated workspaces/registered candidate CLI
 * processes under measured SYSTEM identity. Owns process-tree receipts and protected state; never
 * rewrites dispatch timestamps. Called only by the protected disposable-forest AD CS harness;
 * native qualification requires that workflow to execute.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const {
  startContainedNativeProcess,
  REQUIRED_SOURCES: CONTAINED_SOURCES,
} = require("./certops-windows-contained-process");
const { createApiFixture } = require("./certops-api-fixture");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");

function exited(child) {
  return (
    !child || !child.pid || child.exitCode !== null || child.signalCode !== null
  );
}
async function stop(
  child,
  { terminateTree, graceMs = 10000, killMs = 10000 } = {},
) {
  if (exited(child)) return;
  await new Promise((resolve, reject) => {
    let timer;
    const done = (error) => {
      clearTimeout(timer);
      child.removeListener("exit", onExit);
      error ? reject(error) : resolve();
    };
    const onExit = () => done();
    child.once("exit", onExit);
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      timer = setTimeout(
        () => done(new Error("Owned preflight agent did not exit")),
        killMs,
      );
    }, graceMs);
    try {
      if (terminateTree) terminateTree();
      else child.kill();
    } catch (error) {
      done(error);
    }
  });
}
function validateNativeChildIdentity(identity, expected) {
  assert.ok(identity && typeof identity === "object");
  assert.equal(identity.pid, expected.pid);
  assert.equal(identity.parentPid, expected.parentPid);
  assert.equal(identity.sid, "S-1-5-18");
  assert.ok(Number.isFinite(Date.parse(identity.creationTime)));
  assert.equal(
    path.win32.normalize(identity.executablePath).toLowerCase(),
    path.win32.normalize(expected.executablePath).toLowerCase(),
  );
  assert.ok(
    identity.commandLine.toLowerCase().includes(expected.entry.toLowerCase()),
  );
  assert.ok(identity.commandLine.includes(expected.token));
  return identity;
}

function nativePreflightEnvironment(source, state, bootstrap) {
  const env = {};
  for (const name of [
    "PATH",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "NODE_EXTRA_CA_CERTS",
  ])
    if (source[name]) env[name] = source[name];
  env.TOKENTIMER_AGENT_CONFIG_DIR = state;
  if (bootstrap) {
    env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN = bootstrap.plaintextToken;
    env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID = bootstrap.token.id;
  }
  return env;
}
async function stopContainedCohort(cohort) {
  assert.ok(
    cohort.containment || (!cohort.child && !cohort.processIdentity),
    "Missing native containment preserves cohort state",
  );
  if (cohort.containment) {
    await cohort.containment.stopAndDrain();
    assert.equal(
      cohort.containment.hasOwnershipReceipt(),
      false,
      "Native cohort ownership must fully drain before state cleanup",
    );
  }
}

function createNativePreflightCohorts({
  baseUrl,
  configDir,
  workDir,
  caConfig,
  until,
  ps,
  report,
}) {
  const cohorts = [];
  report.fixtureSources ??= [];
  report.fixtureSources.push({
    file: "tests/e2e/helpers/certops-adcs-preflight-cohorts.js",
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(__filename))
      .digest("hex"),
  });
  for (const file of CONTAINED_SOURCES)
    report.fixtureSources.push({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../../..", file)))
        .digest("hex"),
    });
  const entry = path.resolve(
    __dirname,
    "../../../packages/agent/bin/tokentimer-agent.js",
  );
  async function start(cohort, bootstrap) {
    const env = nativePreflightEnvironment(
      process.env,
      cohort.state,
      bootstrap,
    );
    const previous = (
      await cohort.fixture.pool.query(
        "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [cohort.fixture.workspaceId, cohort.agentId],
      )
    ).rows[0]?.last_seen_at;
    cohort.launchError = null;
    cohort.processIdentity = null;
    cohort.nativeIdentity = null;
    cohort.processToken = `certops-preflight-${crypto.randomUUID()}`;
    cohort.containment = await startContainedNativeProcess({
      executable: process.execPath,
      args: [`--title=${cohort.processToken}`, entry],
      environment: env,
      workDir: cohort.state,
      maxLifetimeMs: 3600000,
      expectedSid: "S-1-5-18",
      onCreated: (resource) => {
        cohort.containment = resource;
        cohort.child = resource.wrapper;
      },
    });
    cohort.launchedAtMonotonicMs = performance.now();
    const measured = cohort.containment.rootIdentity;
    cohort.processIdentity = validateNativeChildIdentity(measured, {
      pid: measured.pid,
      parentPid: cohort.child.pid,
      executablePath: process.execPath,
      entry,
      token: cohort.processToken,
    });
    cohort.nativeIdentity = "LocalSystem";
    cohort.rowId = await until(async () => {
      if (cohort.launchError) throw cohort.launchError;
      assert.equal(
        cohort.child.exitCode,
        null,
        "Native preflight agent exited before heartbeat",
      );
      assert.equal(
        cohort.child.signalCode,
        null,
        "Native preflight agent was signalled before heartbeat",
      );
      const row = (
        await cohort.fixture.pool.query(
          "SELECT id,last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
          [cohort.fixture.workspaceId, cohort.agentId],
        )
      ).rows[0];
      return row?.last_seen_at &&
        (!previous || new Date(row.last_seen_at) > new Date(previous))
        ? row.id
        : null;
    });
    assert.equal(
      ps(
        `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${cohort.processIdentity.pid}';(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid`,
      ),
      "S-1-5-18",
    );
    if (bootstrap)
      assert.equal(
        (
          await cohort.fixture.pool.query(
            "SELECT status FROM certops_agent_bootstrap_tokens WHERE id=$1",
            [bootstrap.token.id],
          )
        ).rows[0]?.status,
        "used",
      );
  }
  async function select() {
    assert.equal(process.platform, "win32");
    assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
    assert.equal(
      ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
      "S-1-5-18",
    );
    const relative = path.relative(os.tmpdir(), workDir);
    assert.ok(
      relative && !relative.startsWith("..") && !path.isAbsolute(relative),
    );
    assert.ok(!fs.lstatSync(workDir).isSymbolicLink());

    let cohort = cohorts.at(-1);
    const rules = JSON.parse(
      fs.readFileSync(path.join(configDir, "config.json"), "utf8"),
    ).adcs.enrollmentRules;
    const ruleBytes = JSON.stringify(rules);
    if (
      !cohort ||
      cohort.count >= 18 ||
      performance.now() - cohort.launchedAtMonotonicMs >= 45 * 60 * 1000
    ) {
      if (cohort) await stopContainedCohort(cohort);
      const fixture = await createApiFixture(baseUrl);
      cohort = {
        fixture,
        state: path.join(workDir, `preflight-cohort-${cohorts.length + 1}`),
        agentId: `preflight-${crypto.randomUUID()}`,
        count: 0,
        ruleBytes,
      };
      cohorts.push(cohort);
      assert.equal(
        fs.lstatSync(cohort.state, { throwIfNoEntry: false }),
        undefined,
        "Refusing an existing cohort state path",
      );
      fs.mkdirSync(cohort.state);
      cohort.stateOwned = true;
      applyRestrictivePermissions(cohort.state, { kind: "dir" });
      cohort.api = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
      const config = {
        serverUrl: baseUrl,
        caBundlePath: process.env.NODE_EXTRA_CA_CERTS,
        agentId: cohort.agentId,
        heartbeatIntervalMs: 5000,
        pollIntervalMs: 2000,
        windowsDiscovery: { enabled: false },
        execution: { enabled: true, dryRun: false },
        policy: {
          allowedPaths: [workDir],
          allowedCommands: {},
          allowedCaEndpoints: [],
          allowedDnsZones: [],
          allowedDnsProviders: [],
        },
        adcs: { enrollmentRules: rules },
      };
      fs.writeFileSync(
        path.join(cohort.state, "config.json"),
        JSON.stringify(config),
      );
      applyRestrictivePermissions(path.join(cohort.state, "config.json"));
      const bootstrap = await fixture.request(
        `${cohort.api}/agent-bootstrap-tokens`,
        "POST",
        {
          name: cohort.agentId,
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      );
      assert.equal(bootstrap.status, 201);
      await start(cohort, bootstrap.body);
    } else if (cohort.ruleBytes !== ruleBytes) {
      await stopContainedCohort(cohort);
      const file = path.join(cohort.state, "config.json"),
        config = JSON.parse(fs.readFileSync(file, "utf8"));
      config.adcs.enrollmentRules = rules;
      fs.writeFileSync(file, JSON.stringify(config));
      applyRestrictivePermissions(file);
      cohort.ruleBytes = ruleBytes;
      await start(cohort);
    }
    return cohort;
  }
  return {
    hasLiveChildren() {
      return cohorts.some(
        (cohort) =>
          cohort.containment &&
          (cohort.containment.hasLiveChild() ||
            cohort.containment.hasOwnershipReceipt()),
      );
    },
    async preflight(template) {
      const cohort = await select();
      const created = await cohort.fixture.request(
        `${cohort.api}/issuers`,
        "POST",
        { kind: "adcs", name: `${template}-${crypto.randomUUID()}` },
      );
      assert.equal(created.status, 201);
      const issuerId = created.body.issuer.id;
      assert.ok(cohort.count < 18);
      cohort.count++;
      const dispatch = await cohort.fixture.request(
        `${cohort.api}/issuers/${issuerId}/preflight`,
        "POST",
        { agentId: cohort.rowId, caConfig, template },
      );
      assert.equal(dispatch.status, 201);
      await until(async () => {
        const row = (
          await cohort.fixture.pool.query(
            "SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
            [cohort.fixture.workspaceId, dispatch.body.job.id],
          )
        ).rows[0];
        if (["failed", "rejected", "cancelled"].includes(row?.status))
          throw new Error("Native cohort preflight failed");
        return row?.status === "succeeded";
      });
      const result = await until(
        async () =>
          (
            await cohort.fixture.pool.query(
              "SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",
              [cohort.fixture.workspaceId, issuerId],
            )
          ).rows[0]?.last_preflight,
      );
      return {
        issuerId,
        result,
        confirm: (body) =>
          cohort.fixture.request(
            `${cohort.api}/issuers/${issuerId}/confirm`,
            "POST",
            body,
          ),
      };
    },
    async close() {
      const failures = [];
      report.nativePreflightCohorts = cohorts.map((cohort) => ({
        workspaceId: cohort.fixture.workspaceId,
        agentId: cohort.agentId,
        dispatchCount: cohort.count,
        dispatchLimit: 18,
        nativeIdentity: cohort.nativeIdentity || "unverified",
        runtime: "candidate-cli",
        nativeProcessVerified: Boolean(cohort.processIdentity),
      }));
      for (const cohort of cohorts) {
        let stopped = false;
        try {
          await stopContainedCohort(cohort);
          stopped = true;
        } catch (error) {
          failures.push(error);
        }
        if (stopped) {
          try {
            const measured = Number(
              (
                await cohort.fixture.pool.query(
                  "SELECT count(*) AS count FROM certificate_jobs WHERE workspace_id=$1 AND operation='adcs-preflight'",
                  [cohort.fixture.workspaceId],
                )
              ).rows[0].count,
            );
            assert.equal(
              measured,
              cohort.count,
              "Every actual cohort dispatch must be accounted for",
            );
            assert.ok(measured <= 18);
          } catch (error) {
            failures.push(error);
          }
          try {
            await cohort.fixture.cleanup();
          } catch (error) {
            failures.push(error);
          }
          try {
            if (cohort.stateOwned) {
              assert.equal(path.dirname(cohort.state), workDir);
              assert.ok(!fs.lstatSync(cohort.state).isSymbolicLink());
              fs.rmSync(cohort.state, { recursive: true });
              cohort.stateOwned = false;
            }
          } catch (error) {
            failures.push(error);
          }
        }
      }
      if (failures.length)
        throw new AggregateError(
          failures,
          "Native preflight cohort cleanup failed",
        );
    },
  };
}
module.exports = {
  createNativePreflightCohorts,
  stopOwnedPreflightAgent: stop,
  stopContainedCohort,
  validateNativeChildIdentity,
  nativePreflightEnvironment,
};
