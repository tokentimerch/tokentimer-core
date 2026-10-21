/**
 * Qualification: public signed native Linux trust lifecycle
 *
 * Use only certops-linux-signed-trust.yml on separate disposable root Ubuntu 24.04 with
 * isolated API/Postgres/registered foreground agent, Node 24, embedded
 * trust-anchor-deploy-v1 and local trust-store:update-ca-certificates argv explicitly
 * ["/usr/sbin/update-ca-certificates","--fresh"]. Do not broaden nonroot ACME lane,
 * rewrite operator profile or modify capability manifest to satisfy fixture. Signed
 * executor does not forward direct-call fresh seam. Admin creates trust-anchors then
 * manual distribute-trust/revoke-trust jobs with subjectType: trust_anchor, subjectId,
 * agentId, owner, idempotency; managers must receive HTTP 403. Creator binds
 * installation transaction; real executor receipts/evidence/authenticated results apply.
 * Own root, issued intermediate, intermediate-required leaf and direct-root leaf in
 * 0700/0600 state with sticky ownership before first mutation. Default OS OpenSSL
 * -purpose sslserver/exact hostname must initially reject both WITHOUT CAfile/chain.
 * Public signed root install must make direct leaf trusted; intermediate install must
 * make intermediate leaf trusted without supplying chain. Revoke only intermediate: its
 * leaf fails while direct leaf/root source+receipt unchanged. Revoke root:both fail,
 * owned sources/derived refs absent, installation rows match actual results. Bind four
 * distinct current claims/nonces/one dispatch, original agent/workspace/fingerprints/
 * typed intents. Public statuses alone are insufficient; observe actual field schema.
 * Drain retained agent before any DB/private cleanup. Recovery touches only verified
 * original receipt-owned source then refreshes OS store;
 * missing/replaced/corrupt/ambiguous receipt preserves fixture and fails. Require
 * independent distrust/owned-ref absence before deleting recovery/public rows. Unknown
 * cleanup blocks DB-volume teardown; host disposal is separate, not measured recovery.
 * linux-signed-trust.json must pass strict source/Node/Python proofs before upload. No
 * installed-service/background or automated reconciliation claim; pure
 * route/proof/directory tests are supporting.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Public signed Ubuntu trust jobs. Manual workflow_dispatch on a disposable host only. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const {
  createApiFixture,
} = require("../tests/e2e/helpers/certops-api-fixture");
const attachment = require("../tests/e2e/helpers/certops-acme-agent-attachment");
const {
  readOwnedBytes,
} = require("../tests/e2e/helpers/certops-acme-native-adoption");
const receipts = require("../packages/agent/src/trust-store/receipt");
const contract = require("./certops-linux-signed-trust-proof");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
async function waitUntil(fn, timeout = 120000) {
  const deadline = performance.now() + timeout;
  while (performance.now() < deadline) {
    const value = await fn();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw Error("Signed trust observation deadline exceeded");
}
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.ok(!s.isSymbolicLink() && s.ino > 0n);
  return { dev: String(s.dev), ino: String(s.ino), directory: s.isDirectory() };
}
function native(args) {
  const r = spawnSync("openssl", args, {
    stdio: "pipe",
    timeout: 30000,
    maxBuffer: 131072,
    env: { PATH: process.env.PATH, LANG: "C.UTF-8" },
  });
  assert.ok(
    !r.error && r.signal === null && Number.isInteger(r.status),
    "Native OpenSSL process completion required",
  );
  return r.status;
}
function assertJob(row, expected) {
  assert.equal(row.status, "succeeded");
  assert.equal(row.operation, expected.operation);
  assert.equal(String(row.subject_id), expected.anchorId);
  assert.equal(row.subject_type, "trust_anchor");
  assert.equal(String(row.claimed_by_agent_id), expected.agentId);
  assert.equal(String(row.assigned_agent_id), expected.agentId);
  assert.equal(row.attempt_count, 1);
  assert.match(row.claim_id, /^[a-f0-9-]{36}$/);
  assert.equal(row.payload.trustAnchorId, expected.anchorId);
  assert.equal(row.payload.fingerprintSha256, expected.fingerprint);
  assert.equal(row.payload.anchorType, expected.anchorType);
}
async function stopOwnedAgent(context, attach = attachment.attachIdleAgent) {
  const { child, entry, configDir, resources, waitUntil, closed, startTicks } =
    context;
  assert.ok(
    child && entry && startTicks,
    "Original agent launch identity required",
  );
  const retained =
    context.retained ||
    (await attach({
      agent: child,
      entry,
      workDir: configDir,
      resources,
      waitUntil,
      isAgentClosed: () => closed.has(child),
      expectedStartTicks: startTicks,
    }));
  await retained.stopAndDrain();
  return retained;
}
async function main() {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.versions.node.split(".")[0], "24");
  assert.equal(process.env.CERTOPS_LINUX_SIGNED_TRUST_DISPOSABLE_HOST, "1");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.match(fs.readFileSync("/etc/os-release", "utf8"), /^ID=ubuntu$/m);
  assert.match(
    fs.readFileSync("/etc/os-release", "utf8"),
    /^VERSION_ID="24.04"$/m,
  );
  assert.equal(fs.existsSync("/.dockerenv"), false);
  const base = process.env.CERTOPS_CSR_API_URL;
  assert.ok(
    base &&
      new URL(base).hostname === "127.0.0.1" &&
      new URL(base).protocol === "http:",
  );
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "certops-signed-trust-")),
  );
  fs.chmodSync(root, 0o700);
  const originalRoot = identity(root);
  const guard = path.join(root, ".native-trust-pending"),
    guardBytes = crypto.randomBytes(32);
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  const originalGuard = identity(guard),
    guardStat = fs.lstatSync(guard, { bigint: true });
  let configIdentity;
  const owned = () => {
    assert.deepEqual(identity(root), originalRoot);
    assert.deepEqual(identity(guard), originalGuard);
    assert.ok(readOwnedBytes(guard, 32, guardStat).equals(guardBytes));
    if (configIdentity)
      assert.deepEqual(identity(path.join(root, "agent")), configIdentity);
  };
  const gate = createHostGate({
    suite: contract.SUITE,
    strict: true,
    reportPath:
      process.env.CERTOPS_QUALIFICATION_REPORT ||
      "qualification-results/linux-signed-trust.json",
    requiredCapabilities: ["root-native-trust", "real-api"],
    probeCapabilities: () =>
      Promise.resolve({
        "root-native-trust": {
          available:
            fs.existsSync("/usr/local/share/ca-certificates") &&
            native(["version"]) === 0,
        },
        "real-api": { available: true },
      }),
  });
  gate.report.fixtureSource = {
    file: "scripts/certops-linux-signed-trust.js",
    sha256: sha(fs.readFileSync(__filename)),
  };
  gate.report.fixtureSources = contract.REQUIRED_SOURCES.map((file) => ({
    file,
    sha256: sha(fs.readFileSync(path.resolve(__dirname, "..", file))),
  }));
  gate.report.qualificationEnvironment = {
    osFamily: "linux",
    osVersion: "24.04",
    distribution: "ubuntu",
    measurement: "native",
    executionSurface: "disposable-vm",
  };
  let fixture,
    child,
    retained,
    completed = false,
    failure;
  const resources = [],
    closed = new WeakSet();
  let agentRow, workspaceId, entry, startTicks;
  const agentWire = crypto.randomUUID(),
    configDir = path.join(root, "agent");
  const anchorIds = [],
    jobIds = [],
    claimIds = [];
  const prefix = () => `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  async function stopAgent() {
    assert.ok(
      child && entry && startTicks,
      "Original agent launch identity required",
    );
    // The reviewed attachment is a short idle-stop protocol, not a lifetime
    // monitor. Attach only when ready to stop, pinning the original birth.
    retained = await stopOwnedAgent({
      child,
      entry,
      configDir,
      resources,
      waitUntil,
      closed,
      startTicks,
      retained,
    });
  }
  const cert = (name, issuer, isLeaf = false) => {
    const key = path.join(root, name + ".key"),
      csr = path.join(root, name + ".csr"),
      pem = path.join(root, name + ".crt"),
      ext = path.join(root, name + ".ext");
    assert.equal(
      native([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key,
        "-out",
        csr,
        "-subj",
        `/CN=SignedTrust-${crypto.randomUUID()}`,
      ]),
      0,
    );
    fs.chmodSync(key, 0o600);
    fs.writeFileSync(
      ext,
      isLeaf
        ? `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:signed-trust.example.test\n`
        : "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
      { flag: "wx", mode: 0o600 },
    );
    assert.equal(
      native([
        "x509",
        "-req",
        "-in",
        csr,
        ...(issuer
          ? ["-CA", issuer.pem, "-CAkey", issuer.key]
          : ["-signkey", key]),
        "-set_serial",
        "0x" + crypto.randomBytes(16).toString("hex"),
        "-days",
        "2",
        "-extfile",
        ext,
        "-out",
        pem,
      ]),
      0,
    );
    const bytes = fs.readFileSync(pem);
    return {
      key,
      pem,
      bytes,
      fingerprint: sha(new crypto.X509Certificate(bytes).raw),
    };
  };
  const source = (a) =>
    path.join(
      "/usr/local/share/ca-certificates",
      `tokentimer-${a.fingerprint}.crt`,
    );
  const verify = (a) =>
    native([
      "verify",
      "-purpose",
      "sslserver",
      "-verify_hostname",
      "signed-trust.example.test",
      a.pem,
    ]) === 0;
  const receipt = (a) => {
    const r = receipts.readReceipt(
      path.join(configDir, "trust-receipts"),
      "debian-ca-certificates",
      a.fingerprint,
    );
    assert.ok(r && !r.corrupt);
    return r.row;
  };
  const derivedAbsent = (a) => {
    for (const name of fs.readdirSync("/etc/ssl/certs")) {
      const f = path.join("/etc/ssl/certs", name);
      const s = fs.lstatSync(f);
      if (s.isSymbolicLink())
        assert.notEqual(
          path.resolve(path.dirname(f), fs.readlinkSync(f)),
          source(a),
        );
    }
  };
  async function dispatch(anchor, operation) {
    owned();
    const response = await fixture.request(prefix() + "/jobs", "POST", {
      operation,
      subjectType: "trust_anchor",
      subjectId: anchor.id,
      agentId: agentRow.id,
      owner: "qualification",
      idempotencyKey: crypto.randomUUID(),
    });
    assert.equal(response.status, 201);
    const id = response.body.job.id;
    jobIds.push(id);
    const row = await waitUntil(async () => {
      const r = (
        await fixture.pool.query(
          "SELECT id,status,operation,subject_type,subject_id,claim_id,claimed_by_agent_id,assigned_agent_id,attempt_count,payload FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, id],
        )
      ).rows[0];
      return r &&
        ["succeeded", "failed", "rejected", "cancelled"].includes(r.status)
        ? r
        : null;
    });
    assertJob(row, {
      operation,
      anchorId: anchor.id,
      agentId: agentRow.id,
      fingerprint: anchor.fingerprint,
      anchorType: anchor.anchorType,
    });
    claimIds.push(row.claim_id);
    assert.equal(
      (
        await fixture.pool.query(
          "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
          [fixture.workspaceId, id, agentRow.id],
        )
      ).rowCount,
      1,
    );
    const evidence = (
      await fixture.pool.query(
        "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type=$4",
        [
          fixture.workspaceId,
          id,
          row.claim_id,
          operation === "distribute-trust"
            ? "trust.distributed"
            : "trust.revoked",
        ],
      )
    ).rows;
    assert.ok(
      evidence.some(
        (e) =>
          e.metadata.trustAnchorId === anchor.id &&
          e.metadata.outcome ===
            (operation === "distribute-trust" ? "installed" : "removed") &&
          e.metadata.receiptState === "finalized" &&
          e.metadata.mutationPerformed === true &&
          e.metadata.failureCategory === null,
      ),
    );
    const installations = await fixture.request(
      prefix() + `/trust-anchors/${anchor.id}/installations`,
    );
    assert.equal(installations.status, 200);
    assert.ok(
      installations.body.items.some(
        (i) =>
          i.agentId === agentRow.id &&
          i.transitionState ===
            (operation === "distribute-trust" ? "installed" : "removed") &&
          i.lastJobId === id,
      ),
    );
    const nativeReceipt = receipt(anchor);
    assert.equal(nativeReceipt.jobId, id);
    assert.equal(nativeReceipt.fingerprintSha256, anchor.fingerprint);
    assert.equal(
      nativeReceipt.state,
      operation === "distribute-trust" ? "installed" : "removed",
    );
  }
  try {
    await gate.preflight();
    fixture = await createApiFixture(base);
    workspaceId = fixture.workspaceId;
    assert.equal(
      (
        await fixture.pool.query(
          "SELECT id FROM certops_agents WHERE status<>'retired'",
        )
      ).rowCount,
      0,
      "Isolated API must contain no foreign active agent",
    );
    fs.mkdirSync(configDir, { mode: 0o700 });
    configIdentity = identity(configDir);
    const generated = require("../packages/agent/src/capabilities/qualified-capabilities.generated");
    assert.ok(generated.qualified.includes("trust-anchor-deploy-v1"));
    fs.writeFileSync(
      path.join(configDir, "config.json"),
      JSON.stringify({
        serverUrl: base,
        agentId: agentWire,
        allowInsecureLocalHttp: true,
        pollIntervalMs: 500,
        heartbeatIntervalMs: 1000,
        discovery: null,
        windowsDiscovery: { enabled: false },
        execution: { enabled: true, dryRun: false },
        policy: {
          allowedPaths: [root],
          allowedCommands: {
            "trust-store:update-ca-certificates": {
              argv: ["/usr/sbin/update-ca-certificates", "--fresh"],
            },
          },
        },
      }),
      { mode: 0o600, flag: "wx" },
    );
    const bootstrap = await fixture.request(
      prefix() + "/agent-bootstrap-tokens",
      "POST",
      {
        name: "Owned signed trust agent",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
    );
    assert.equal(bootstrap.status, 201);
    entry = path.resolve(
      __dirname,
      "../packages/agent/bin/tokentimer-agent.js",
    );
    child = spawn(process.execPath, [entry], {
      cwd: root,
      env: {
        PATH: process.env.PATH,
        HOME: root,
        LANG: "C.UTF-8",
        TOKENTIMER_AGENT_CONFIG_DIR: configDir,
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.body.plaintextToken,
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(bootstrap.body.token.id),
      },
      stdio: "ignore",
    });
    child.on("error", () => {});
    child.once("close", () => closed.add(child));
    const fields = fs
      .readFileSync(`/proc/${child.pid}/stat`, "utf8")
      .split(") ")[1]
      .trim()
      .split(/\s+/);
    startTicks = fields[19];
    assert.equal(Number(fields[1]), process.pid);
    agentRow = await waitUntil(async () => {
      const row = (
        await fixture.pool.query(
          "SELECT id,agent_id,declared_capabilities,capabilities_updated_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
          [fixture.workspaceId, agentWire],
        )
      ).rows[0];
      return row &&
        Array.isArray(row.declared_capabilities) &&
        row.declared_capabilities.includes("trust-anchor-deploy-v1") &&
        row.capabilities_updated_at &&
        Math.abs(Date.now() - new Date(row.capabilities_updated_at).getTime()) <
          60000
        ? row
        : null;
    });
    const ca = cert("root"),
      intermediate = cert("intermediate", ca),
      leaf = cert("leaf", intermediate, true),
      direct = cert("direct", ca, true);
    assert.equal(verify(leaf), false);
    assert.equal(verify(direct), false);
    for (const [a, anchorType] of [
      [ca, "root"],
      [intermediate, "intermediate"],
    ]) {
      assert.equal(fs.existsSync(source(a)), false);
      const r = await fixture.request(prefix() + "/trust-anchors", "POST", {
        name: "Owned signed " + anchorType,
        anchorType,
        pem: a.bytes.toString("utf8"),
      });
      assert.equal(r.status, 201);
      a.id = r.body.trustAnchor.id;
      a.anchorType = anchorType;
      anchorIds.push(a.id);
      assert.equal(r.body.trustAnchor.fingerprintSha256, a.fingerprint);
    }
    // Workspace creators have implicit admin access, so use a separate manager
    // fixture to measure real authorization instead of spoofing the owner role.
    const manager = await createApiFixture(base);
    try {
      await manager.pool.query(
        "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')",
        [fixture.workspaceId, manager.userId],
      );
      for (const operation of ["distribute-trust", "revoke-trust"]) {
        const denied = await manager.request(prefix() + "/jobs", "POST", {
          operation,
          subjectType: "trust_anchor",
          subjectId: ca.id,
          agentId: agentRow.id,
          owner: "qualification",
          idempotencyKey: crypto.randomUUID(),
        });
        assert.equal(denied.status, 403);
      }
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT id FROM certificate_jobs WHERE workspace_id=$1",
            [fixture.workspaceId],
          )
        ).rowCount,
        0,
      );
    } finally {
      await manager.cleanup();
    }
    await gate.scenario(contract.SCENARIOS[0], async () => {
      await dispatch(ca, "distribute-trust");
      assert.equal(verify(direct), true);
      assert.equal(verify(leaf), false);
    });
    await gate.scenario(contract.SCENARIOS[1], async () => {
      await dispatch(intermediate, "distribute-trust");
      assert.equal(verify(leaf), true);
      assert.equal(verify(direct), true);
    });
    const rootReceipt = fs.readFileSync(
        receipts.receiptRowPath(
          path.join(configDir, "trust-receipts"),
          "debian-ca-certificates",
          ca.fingerprint,
        ),
      ),
      rootSource = fs.readFileSync(source(ca)),
      sourceIdentity = identity(source(ca)),
      receiptPath = receipts.receiptRowPath(
        path.join(configDir, "trust-receipts"),
        "debian-ca-certificates",
        ca.fingerprint,
      ),
      receiptIdentity = identity(receiptPath);
    await gate.scenario(contract.SCENARIOS[2], async () => {
      await dispatch(intermediate, "revoke-trust");
      assert.equal(verify(leaf), false);
      assert.equal(verify(direct), true);
      assert.equal(fs.existsSync(source(intermediate)), false);
      derivedAbsent(intermediate);
      assert.deepEqual(identity(source(ca)), sourceIdentity);
      assert.deepEqual(identity(receiptPath), receiptIdentity);
      assert.ok(fs.readFileSync(source(ca)).equals(rootSource));
      assert.ok(
        fs
          .readFileSync(
            receipts.receiptRowPath(
              path.join(configDir, "trust-receipts"),
              "debian-ca-certificates",
              ca.fingerprint,
            ),
          )
          .equals(rootReceipt),
      );
    });
    await gate.scenario(contract.SCENARIOS[3], async () => {
      await dispatch(ca, "revoke-trust");
      assert.equal(verify(leaf), false);
      assert.equal(verify(direct), false);
      for (const a of [ca, intermediate]) {
        assert.equal(fs.existsSync(source(a)), false);
        derivedAbsent(a);
      }
    });
    await gate.scenario(contract.SCENARIOS[4], async () => {
      assert.deepEqual(
        (
          await fixture.pool.query(
            "SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",
            [fixture.workspaceId],
          )
        ).rows.map((r) => r.id),
        [...jobIds].sort(),
      );
      await stopAgent();
      retained.release();
      assert.ok(closed.has(child));
      attachment.assertCleanupSafe(configDir);
      owned();
      await fixture.cleanup();
      fixture = null;
      owned();
      fs.unlinkSync(guard);
      fs.rmSync(root, { recursive: true });
      completed = true;
    });
    gate.report[contract.FIELD] = contract.verifyProof({
      scope: contract.SUITE,
      workspaceId,
      agentId: agentRow.id,
      anchorIds,
      jobIds,
      claimIds,
      fingerprints: [ca.fingerprint, intermediate.fingerprint],
      backgroundReconciliationQualified: false,
      ...Object.fromEntries(contract.FLAGS.map((f) => [f, true])),
    });
  } catch (error) {
    failure = error;
  } finally {
    if (!completed) {
      if (child && !closed.has(child))
        try {
          await stopAgent();
        } catch {
          /* No PID fallback or destructive cleanup on uncertainty. */
        }
      for (const resource of resources)
        try {
          await resource.stopAndDrain();
        } catch {
          /* Preserve unknown agent/native ownership. */
        }
      if (fixture)
        try {
          await fixture.pool.end();
        } catch {
          /* Preserve database rows. */
        }
    }
    try {
      await gate.finish({
        requiredScenarios: contract.SCENARIOS,
        cleanup: { status: completed ? "passed" : "failed" },
      });
    } catch (error) {
      failure ||= error;
    }
  }
  if (failure)
    throw Error(
      "Signed native trust qualification failed; preserve owned state",
    );
}
module.exports = { main, assertJob, identity, waitUntil, stopOwnedAgent };
if (require.main === module)
  main().catch(() => {
    console.error(
      "Signed native trust qualification failed; private diagnostics preserved",
    );
    process.exitCode = 1;
  });
