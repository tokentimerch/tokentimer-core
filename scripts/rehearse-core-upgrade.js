"use strict";

// Disposable, non-publishing package upgrade rehearsal. Actual released API,
// worker and agent packages run before the same database and agent state are
// upgraded. A signed noop proves protocol continuity, not CA/native renewal.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { containsPrivateKeyMaterial, redactGenericSecrets } = require("../packages/log-scrub/secret-material");

const OWNER_LABEL = "ch.tokentimer.upgrade-rehearsal";
const OLD_SOURCE = "813b0b111c7b2d6e4a5a3cbfdb458bd0b4572ecd";
const OLD_AGENT_SHA256 = "ec74ed8e1026b7a76b50e0ddc843ee8dc42d1283923ff01be11603069f94c6bb";
const IMAGE_PATTERN = /^ghcr\.io\/tokentimerch\/tokentimer-core-(api|worker)@sha256:[a-f0-9]{64}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const MARKER = "TT_UPGRADE_RESULT=";

function parseArgs(argv) {
  const options = {};
  const allowed = new Set(["candidate-api", "candidate-worker", "source-sha", "image-source-sha", "agent-source-sha", "old-agent", "candidate-agent", "candidate-agent-sha256", "out"]);
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    if (!argv[i]?.startsWith("--") || !allowed.has(name) || !argv[i + 1] || argv[i + 1].startsWith("--") || options[name]) {
      throw new Error("Expected each documented --option exactly once with a value");
    }
    options[name] = argv[i + 1];
  }
  for (const name of allowed) assert.ok(options[name], "Missing --" + name);
  for (const component of ["api", "worker"]) {
    const match = options["candidate-" + component].match(IMAGE_PATTERN);
    assert.ok(match && match[1] === component, "Candidate " + component + " must be an immutable Core image digest");
  }
  assert.match(options["source-sha"], SHA_PATTERN, "Expected full selected source SHA");
  assert.match(options["image-source-sha"], SHA_PATTERN, "Expected original image-build source SHA");
  assert.match(options["agent-source-sha"], SHA_PATTERN, "Expected agent-build source SHA");
  assert.match(options["candidate-agent-sha256"], HASH_PATTERN, "Expected independently recorded candidate archive checksum");
  return options;
}

function hash(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function verifyArchiveChecksum(filename, expected) {
  assert.match(expected, HASH_PATTERN);
  assert.equal(hash(fs.readFileSync(filename)), expected, "Agent archive checksum mismatch");
}
function ownsResource(name, labels, owner) {
  return name.startsWith("tt-upgrade-" + owner + "-") && labels?.[OWNER_LABEL] === owner;
}
function resourceIsMissing(stderr, name) {
  const message = String(stderr);
  return message.includes(name) && /no such (?:container|network|volume|object)\b|\bnetwork\b.*\bnot found\b/i.test(message);
}
function redactDiagnostic(value, secrets = []) {
  try {
    let text = String(value ?? "");
    // Do not truncate before inspecting: a cutoff could discard the PEM
    // marker while retaining its private contents. Oversized or ambiguous
    // chunks are withheld entirely, including tail fragments of PEM bodies.
    if (text.length > 32768) return "[DIAGNOSTIC_WITHHELD: oversized output]";
    for (const secret of secrets) if (secret) text = text.replaceAll(secret, "[redacted]");
    const content = text.replace(/^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})\s+/gm, "");
    if (/-----\s*(?:BEGIN|END)[^\r\n]*PRIVATE\s+KEY/i.test(text) || /(?:^|\n)\s*[A-Za-z0-9+/=_-]{48,}\s*(?:\n|$)/.test(content) || containsPrivateKeyMaterial(content)) {
      return "[DIAGNOSTIC_WITHHELD: possible private material]";
    }
    if (/failing row contains|\b(?:rows?|records?)["']?\s*[:=]\s*[\[{]/i.test(text)) return "[DIAGNOSTIC_WITHHELD: database row data]";
    text = redactGenericSecrets(text).replace(/tt(?:boot|agent|x)_[^\s,"';}\]]+/gi, "[redacted-token]");
    return text.length > 16384 ? "[DIAGNOSTIC_WITHHELD: oversized redacted output]" : text;
  } catch (_) { return "[DIAGNOSTIC_WITHHELD: redaction failed]"; }
}
function assertLedgerUpgrade(before, after) {
  assert.equal(before.at(-1)?.version, 67, "Baseline must be the released 0.17.3 migration ledger");
  assert.equal(after.at(-1)?.version, 77, "0.18.0 must apply through onboarding migration 77");
  assert.equal(new Set(after.map((row) => row.version)).size, after.length, "Duplicate migration versions");
  assert.deepEqual(after.filter((row) => row.version <= 67), before, "Historical migration identity/timestamps changed");
  assert.deepEqual(after.filter((row) => row.version > 67).map((row) => row.version), [68, 69, 70, 71, 72, 73, 74, 75, 76, 77]);
}
function assertAgentContinuity(before, after, oldState, newState) {
  assert.equal(after.id, before.id, "Upgrade created a new database agent identity");
  assert.equal(after.agent_id, before.agent_id, "Upgrade changed the protocol agent identity");
  assert.equal(after.credential_hash, before.credential_hash, "Upgrade replaced the registration credential");
  assert.equal(after.pinned_signing_key_id, before.pinned_signing_key_id, "Upgrade lost the signing-key pin");
  assert.ok(BigInt(after.last_sequence) > BigInt(before.last_sequence), "Protocol sequence did not advance");
  assert.equal(after.agent_version, "0.18.0");
  for (const file of ["config.json", "credential", "signing-key-pin.json"]) {
    assert.match(oldState[file] || "", HASH_PATTERN, "Missing persisted agent file " + file);
    assert.equal(newState[file], oldState[file], "Persisted agent file changed: " + file);
  }
}

// Executed inside the actual API package; database access uses that package's
// own installed pg/bcrypt dependencies. No product collaborator is mocked.
async function apiProbe(input) {
  const { createRequire } = require("node:module");
  const localRequire = createRequire("/app/apps/api/package.json");
  const { Pool } = localRequire("pg");
  const pool = new Pool({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
  const crypto = require("node:crypto");
  const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const f = input.fixture || {};
  const query = (sql, values) => pool.query(sql, values);
  try {
    if (input.action === "seed") {
      const bcrypt = localRequire("bcryptjs");
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const userId = (await client.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Upgrade Rehearsal',$2,'local',TRUE) RETURNING id", [f.email, await bcrypt.hash(f.password, 10)])).rows[0].id;
        const workspaceId = crypto.randomUUID();
        await client.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Upgrade preserved workspace',$2,'oss')", [workspaceId, userId]);
        await client.query("INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by) VALUES($1,$2,'admin',$1)", [userId, workspaceId]);
        const tokenId = (await client.query("INSERT INTO tokens(user_id,created_by,workspace_id,name,expiration,type,category,description) VALUES($1,$1,$2,'Upgrade preserved certificate','2040-01-01','tls_cert','cert','upgrade-rehearsal-preserve') RETURNING id", [userId, workspaceId])).rows[0].id;
        const profileId = (await client.query("INSERT INTO certificate_profiles(workspace_id,name,status,key_mode,public_metadata,created_by) VALUES($1,'Upgrade preserved profile','disabled','agent-local',$2::jsonb,$3) RETURNING id", [workspaceId, JSON.stringify({ rehearsal: "preserve" }), userId])).rows[0].id;
        const certificateId = (await client.query("INSERT INTO managed_certificates(workspace_id,token_id,profile_id,status,name,common_name,key_mode,public_metadata,created_by) VALUES($1,$2,$3,'discovered','Upgrade preserved certificate','upgrade.example.test','agent-local',$4::jsonb,$5) RETURNING id", [workspaceId, tokenId, profileId, JSON.stringify({ rehearsal: "preserve" }), userId])).rows[0].id;
        const jobId = (await client.query("INSERT INTO certificate_jobs(workspace_id,operation,status,source) VALUES($1,'renew','succeeded','api') RETURNING id", [workspaceId])).rows[0].id;
        await client.query("COMMIT");
        return { userId, workspaceId, tokenId, profileId, certificateId, jobId };
      } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    }
    if (input.action === "snapshot") {
      const rows = {};
      for (const [name, sql, values] of [
        ["user", "SELECT id,email,display_name,password_hash,auth_method,email_verified FROM users WHERE id=$1", [f.userId]],
        ["workspace", "SELECT id,name,created_by,plan FROM workspaces WHERE id=$1", [f.workspaceId]],
        ["membership", "SELECT user_id,workspace_id,role,invited_by FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2", [f.userId, f.workspaceId]],
        ["token", "SELECT id,user_id,created_by,workspace_id,name,expiration,type,category,description FROM tokens WHERE id=$1", [f.tokenId]],
        ["profile", "SELECT id,workspace_id,name,status,key_mode,public_metadata FROM certificate_profiles WHERE id=$1", [f.profileId]],
        ["certificate", "SELECT id,workspace_id,token_id,profile_id,status,name,common_name,key_mode,public_metadata FROM managed_certificates WHERE id=$1", [f.certificateId]],
        ["job", "SELECT id,workspace_id,operation,status,source FROM certificate_jobs WHERE id=$1", [f.jobId]],
      ]) {
        const result = await query(sql, values);
        if (result.rows.length !== 1) throw new Error("Missing preserved fixture: " + name);
        rows[name] = digest(result.rows[0]);
      }
      return { rowDigests: rows, ledger: (await query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows };
    }
    if (input.action === "agent") {
      const result = await query("SELECT id,agent_id,agent_version,status,last_sequence,pinned_signing_key_id,credential_hash,last_seen_at FROM certops_agents WHERE workspace_id=$1 ORDER BY created_at", [f.workspaceId]);
      if (result.rows.length > 1) throw new Error("Unexpected duplicate agent identity");
      return result.rows[0] || null;
    }
    if (input.action === "job") {
      const result = await query("SELECT id,status,mode,claim_id,assigned_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [f.workspaceId, input.jobId]);
      return { job: result.rows[0] || null, evidence: (await query("SELECT evidence_type,claim_id FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 ORDER BY created_at", [f.workspaceId, input.jobId])).rows };
    }
    if (input.action === "schema") {
      const result = await query("SELECT to_regclass('public.certificate_enrollments')::text AS enrollments,to_regclass('public.certops_distribution_groups')::text AS distribution,to_regclass('public.onboarding_sessions')::text AS onboarding");
      return result.rows[0];
    }
    if (input.action === "http") {
      const cookies = new Map();
      let csrf;
      async function request(method, route, body) {
        const headers = { Origin: "http://localhost:5173" };
        if (cookies.size) headers.Cookie = [...cookies].map(([key, value]) => key + "=" + value).join("; ");
        if (csrf) headers["X-CSRF-Token"] = csrf;
        if (body !== undefined) headers["Content-Type"] = "application/json";
        const response = await fetch("http://127.0.0.1:4000" + route, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(15000), redirect: "error" });
        for (const cookie of response.headers.getSetCookie()) {
          const pair = cookie.split(";", 1)[0];
          const at = pair.indexOf("=");
          cookies.set(pair.slice(0, at), pair.slice(at + 1));
        }
        const result = await response.json();
        if (!response.ok) throw new Error("HTTP " + response.status + " " + method + " " + route + " " + (result.code || ""));
        return result;
      }
      csrf = (await request("GET", "/api/csrf-token")).csrfToken;
      await request("POST", "/auth/login", { email: f.email, password: f.password });
      csrf = (await request("GET", "/api/csrf-token")).csrfToken;
      if (input.operation === "verify") {
        const session = await request("GET", "/api/session");
        const workspaces = await request("GET", "/api/v1/workspaces?limit=50&offset=0");
        const token = await request("GET", "/api/tokens/" + f.tokenId);
        if (!session.loggedIn || !workspaces.items.some((entry) => entry.id === f.workspaceId)) throw new Error("Preserved account/workspace not accessible through authenticated API");
        const item = token.token || token;
        if (Number(item.id) !== Number(f.tokenId)) throw new Error("Preserved inventory token not returned");
        return { authenticated: true, preservedWorkspace: true, preservedInventory: true };
      }
      if (input.operation === "bootstrap") return request("POST", "/api/v1/workspaces/" + f.workspaceId + "/certops/agent-bootstrap-tokens", { name: "Upgrade rehearsal", expiresAt: new Date(Date.now() + 3600000).toISOString() });
      if (input.operation === "noop") return request("POST", "/api/v1/workspaces/" + f.workspaceId + "/certops/jobs", { operation: "noop", mode: input.mode, assignedAgentId: input.agentId, idempotencyKey: "upgrade-" + input.phase });
      throw new Error("Unknown HTTP operation");
    }
    throw new Error("Unknown API probe");
  } finally { await pool.end(); }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  assert.ok(Number(process.versions.node.split(".")[0]) >= 22, "Node 22 or newer required");
  const root = path.resolve(__dirname, "..");
  const owner = crypto.randomBytes(8).toString("hex");
  const prefix = "tt-upgrade-" + owner + "-";
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const resources = [];
  const secrets = [];
  let activeStep = "preflight";
  const receipt = { schemaVersion: 1, scope: "packaged-control-plane-and-linux-agent-upgrade", startedAt: new Date().toISOString(), status: "failed", baseline: { version: "0.17.3", sourceSha: OLD_SOURCE }, candidate: { version: "0.18.0", selectedSourceSha: options["source-sha"], imageBuildSourceSha: options["image-source-sha"], agentBuildSourceSha: options["agent-source-sha"] }, checks: [], notQualifiedByThisRun: ["Windows installer or service upgrade", "Linux systemd installer or service upgrade", "native AD CS or real ACME renewal", "Vault publication and distribution", "worker maintenance business logic (worker boot only)", "Helm upgrade", "whole-release sign-off"] };
  const out = path.resolve(options.out);
  const redact = (value) => redactDiagnostic(value, secrets);
  function run(command, args, { input, timeout = 120000, allowFailure = false, maxBuffer = 8 * 1024 * 1024 } = {}) {
    const result = spawnSync(command, args, { cwd: root, encoding: "utf8", input, timeout, maxBuffer });
    if (!allowFailure && result.status !== 0) throw new Error(activeStep + ": " + command + " failed (" + (result.status ?? result.error?.code) + "): " + redact(result.stderr || result.stdout).slice(-3000));
    return result;
  }
  let transientSequence = 0;
  function docker(args, opts) {
    // --rm is insufficient after a timed-out Docker client: the daemon may
    // still be running its container. Own every transient probe as well.
    if (args[0] === "run" && args.includes("--rm") && !args.includes("--name")) {
      const name = prefix + "probe-" + (++transientSequence);
      resources.push({ kind: "container", name });
      args = ["run", "--name", name, "--label", OWNER_LABEL + "=" + owner, ...args.slice(1)];
    }
    return run("docker", args, opts);
  }
  function inspect(kind, name) { return JSON.parse(docker([kind, "inspect", name]).stdout)[0]; }
  function failureDiagnostics() {
    const diagnostics = [];
    for (const resource of resources) {
      if (resource.kind !== "container" || !/(?:old|candidate)-(?:api|agent|worker)$/.test(resource.name)) continue;
      try {
        const inspected = docker(["container", "inspect", resource.name], { allowFailure: true, timeout: 10000 });
        if (inspected.status !== 0) {
          diagnostics.push({ name: resource.name, unavailable: redact(inspected.stderr || inspected.error?.message || "Inspection failed") });
          continue;
        }
        const container = JSON.parse(inspected.stdout)[0];
        if (!ownsResource(resource.name, container.Config?.Labels, owner)) throw new Error("Diagnostic ownership check failed");
        const logs = docker(["logs", "--tail", "60", "--timestamps", resource.name], { allowFailure: true, timeout: 10000, maxBuffer: 65536 });
        diagnostics.push({
          name: resource.name,
          state: { status: container.State?.Status, running: container.State?.Running, exitCode: container.State?.ExitCode, oomKilled: container.State?.OOMKilled },
          logs: logs.error || logs.status !== 0 ? "[DIAGNOSTIC_WITHHELD: incomplete collection]" : redact(logs.stdout + "\n" + logs.stderr),
        });
      } catch (error) { diagnostics.push({ name: resource.name, unavailable: redact(error.message) }); }
    }
    return diagnostics;
  }
  function nodeResult(args, fn, input) {
    const code = "const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));Promise.resolve((" + fn.toString() + ")(input)).then(value=>console.log(" + JSON.stringify(MARKER) + "+JSON.stringify(value)),error=>{console.error(error.message);process.exitCode=1});";
    const result = docker([...args, "node", "-e", code], { input: JSON.stringify(input) });
    const line = result.stdout.split(/\r?\n/).findLast((entry) => entry.startsWith(MARKER));
    assert.ok(line, "Probe returned no structured result");
    return JSON.parse(line.slice(MARKER.length));
  }
  async function until(check, label, seconds = 90) {
    const end = Date.now() + seconds * 1000;
    while (Date.now() < end) {
      const value = check();
      if (value) return value;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    throw new Error("Timed out: " + label);
  }
  async function step(name, action) {
    activeStep = name;
    const result = await action();
    receipt.checks.push({ name, status: "passed", ...(result === undefined ? {} : { evidence: result }) });
    process.stdout.write("PASS " + name + "\n");
    return result;
  }
  function pullImage(reference) {
    docker(["pull", reference], { timeout: 300000 });
    const image = inspect("image", reference);
    assert.match(image.Id, /^sha256:[a-f0-9]{64}$/);
    return { reference, imageId: image.Id, repositoryDigests: image.RepoDigests || [] };
  }
  function own(kind, name, command) {
    resources.push({ kind, name });
    docker(command);
    return name;
  }
  function unpack(filename, checksum, version, directory) {
    verifyArchiveChecksum(filename, checksum);
    const entries = run("tar", ["-tzf", filename]).stdout.trim().split(/\r?\n/);
    assert.ok(entries.length && entries.every((entry) => entry.startsWith("package/") && !entry.split("/").includes("..") && !/[\u0000-\u001f\\]/.test(entry)), "Unexpected archive entry");
    const modes = run("tar", ["-tvzf", filename]).stdout.trim().split(/\r?\n/);
    assert.ok(modes.every((line) => line[0] === "-" || line[0] === "d"), "Agent archive may contain only regular files and directories");
    fs.mkdirSync(directory);
    run("tar", ["-xzf", filename, "--no-same-owner", "--no-same-permissions", "-C", directory]);
    const packageDir = path.join(directory, "package");
    const pkg = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8"));
    assert.equal(pkg.name, "@tokentimer/agent");
    assert.equal(pkg.version, version);
    return packageDir;
  }
  function runtimeManifest(component) {
    const all = run("git", ["ls-files", "-z"]).stdout.split("\0").filter(Boolean);
    const workerExtra = new Set(["apps/api/src/shared/retiredCertificateAlerts.js", "apps/api/src/shared/contactGroupPluralWrites.js", "apps/api/src/shared/contactGroups.js", "apps/api/src/shared/replaceAssetContactGroups.js", "apps/api/services/audit.js", "apps/api/utils/secretMaterial.js", "apps/api/utils/logger.js", "apps/api/config/runtime-labels.js", "apps/api/db/database.js"]);
    const files = all.filter((name) => /\.(?:js|cjs|json)$/.test(name) && !/\.(?:test|spec)\.js$|\/__tests__\/|^packages\/[^/]+\/scripts\//.test(name) && (name.startsWith("packages/") || (component === "api" ? name.startsWith("apps/api/") : name.startsWith("apps/worker/") || name.startsWith("apps/api/services/certops/") || workerExtra.has(name))));
    assert.ok(files.length > 100, "Runtime source inventory unexpectedly small");
    return Object.fromEntries(files.map((name) => [name, hash(fs.readFileSync(path.join(root, name)))]));
  }
  const envPath = path.join(temporary, "runtime.env");
  let network;
  let agentVolume;
  let currentApi;
  let fixture;
  let candidateApi;
  let oldApi;
  function probe(action, more = {}, container = currentApi) { return nodeResult(["exec", "-i", container], apiProbe, { action, fixture, ...more }); }
  function stateProbe(write = false) {
    return nodeResult(["run", "--rm", "-i", "--network", "none", "--user", "0", "--mount", "type=volume,source=" + agentVolume + ",target=/state", candidateApi.imageId], function (input) {
      const fs = require("node:fs");
      const crypto = require("node:crypto");
      if (input.write) {
        fs.chmodSync("/state", 0o700);
        fs.writeFileSync("/state/config.json", JSON.stringify({ serverUrl: "http://127.0.0.1:4000", allowInsecureLocalHttp: true, heartbeatIntervalMs: 1500, pollIntervalMs: 1500, execution: { enabled: true, dryRun: true }, policy: {} }), { mode: 0o600 });
      }
      const result = {};
      for (const name of ["config.json", "credential", "signing-key-pin.json"]) if (fs.existsSync("/state/" + name)) result[name] = crypto.createHash("sha256").update(fs.readFileSync("/state/" + name)).digest("hex");
      return result;
    }, { write });
  }
  function startApi(image, suffix) {
    currentApi = own("container", prefix + suffix, ["run", "-d", "--name", prefix + suffix, "--label", OWNER_LABEL + "=" + owner, "--network", network, "--env-file", envPath, image.imageId]);
    return currentApi;
  }
  async function readyApi() {
    await until(() => docker(["exec", currentApi, "node", "-e", "fetch('http://127.0.0.1:4000/health').then(r=>process.exit(r.status===200?0:1),()=>process.exit(1))"], { allowFailure: true, timeout: 10000 }).status === 0, "API readiness");
  }
  function startWorker(image, suffix) {
    return own("container", prefix + suffix, ["run", "-d", "--name", prefix + suffix, "--label", OWNER_LABEL + "=" + owner, "--network", network, "--env-file", envPath, image.imageId, "node", "apps/worker/src/runner.js", "certops"]);
  }
  function startAgent(packageDir, suffix, bootstrap) {
    const bootstrapArgs = [];
    if (bootstrap) {
      assert.ok(typeof bootstrap.plaintextToken === "string" && bootstrap.token?.id, "Bootstrap response missing one-time credential");
      secrets.push(bootstrap.plaintextToken);
      const bootstrapPath = path.join(temporary, "bootstrap.env");
      fs.writeFileSync(bootstrapPath, "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=" + bootstrap.plaintextToken + "\nTOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID=" + bootstrap.token.id + "\n", { mode: 0o600 });
      bootstrapArgs.push("--env-file", bootstrapPath);
    }
    return own("container", prefix + suffix, ["run", "-d", "--name", prefix + suffix, "--label", OWNER_LABEL + "=" + owner, "--user", "0", "--cap-drop", "ALL", "--network", "container:" + currentApi, "--mount", "type=bind,source=" + packageDir + ",target=/agent,readonly", "--mount", "type=volume,source=" + agentVolume + ",target=/state", "-e", "TOKENTIMER_AGENT_CONFIG_DIR=/state", ...bootstrapArgs, candidateApi.imageId, "node", "/agent/bin/tokentimer-agent.js"]);
  }
  async function waitAgent(version) {
    return until(() => { const agent = probe("agent"); return agent?.agent_version === version && agent.last_seen_at && agent.status === "active" && BigInt(agent.last_sequence) > 0n ? agent : null; }, "agent registration/heartbeat " + version);
  }
  async function signedNoop(agent, phase) {
    // The released 0.17.3 session route does not forward body.mode, so its
    // public API creates real-mode noops. Noop requests no side effects in
    // either mode. The candidate must honor dry_run through that same route.
    const mode = phase === "before" ? "real" : "dry_run";
    const terminalStatus = mode === "real" ? "succeeded" : "dry_run_complete";
    const result = probe("http", { operation: "noop", phase, mode, agentId: agent.id });
    const jobId = result.job?.id;
    assert.ok(jobId, "API did not return a created job");
    assert.equal(result.job.payload?.mode, mode, "Public API did not persist the requested noop mode");
    const outcome = await until(() => {
      const value = probe("job", { jobId });
      if (value.job) assert.equal(value.job.mode, mode, "Stored job mode differs from the requested noop mode");
      if (value.job && ["failed", "blocked", "cancelled", "succeeded", "dry_run_complete"].includes(value.job.status) && value.job.status !== terminalStatus) throw new Error("Signed noop ended as " + value.job.status);
      return value.job?.status === terminalStatus ? value : null;
    }, "signed noop completion (" + mode + ")");
    assert.equal(outcome.job.mode, mode);
    assert.ok(outcome.job.claim_id, "Noop did not pass through claim/dispatch");
    assert.ok(outcome.evidence.some((entry) => entry.evidence_type === "validation.passed" && entry.claim_id === outcome.job.claim_id), "Missing claim-bound validation evidence");
    return { operation: "noop", mode, terminalStatus: outcome.job.status, claimBoundEvidence: true, sideEffectsRequested: false };
  }
  try {
    await step("source-and-artifact-inputs", () => {
      assert.equal(run("git", ["rev-parse", "HEAD"]).stdout.trim(), options["source-sha"], "Selected source checkout moved");
      // A dedicated tooling branch may add this runner, but product files
      // must still be identical to the selected source revision.
      const dirtyProduct = run("git", ["diff", "--name-only", "HEAD", "--", "apps", "packages", "pnpm-lock.yaml", "pnpm-workspace.yaml"]).stdout.trim();
      assert.equal(dirtyProduct, "", "Product checkout has uncommitted changes");
      for (const option of ["image-source-sha", "agent-source-sha"]) {
        run("git", ["merge-base", "--is-ancestor", options[option], options["source-sha"]]);
      }
      const imageDelta = run("git", ["diff", "--name-only", options["image-source-sha"], options["source-sha"], "--", "apps", "packages", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc", ".dockerignore", "deploy/compose/Dockerfile.api", "deploy/compose/Dockerfile.worker"]).stdout.trim();
      assert.equal(imageDelta, "", "Image-build source differs from selected product/build inputs");
      const agentDelta = run("git", ["diff", "--name-only", options["agent-source-sha"], options["source-sha"], "--", "packages/agent", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"]).stdout.trim();
      assert.equal(agentDelta, "", "Agent-build source differs from selected agent/build inputs");
      docker(["info", "--format", "{{.OSType}}"]);
      return { selectedSourceSha: options["source-sha"], originalImageBuildSourceSha: options["image-source-sha"], agentBuildSourceSha: options["agent-source-sha"], sourceAncestriesVerified: true, productAndBuildInputsEqual: true };
    });
    const oldPackage = unpack(path.resolve(options["old-agent"]), OLD_AGENT_SHA256, "0.17.3", path.join(temporary, "old-agent"));
    const candidatePackage = unpack(path.resolve(options["candidate-agent"]), options["candidate-agent-sha256"], "0.18.0", path.join(temporary, "candidate-agent"));
    receipt.baseline.agentSha256 = OLD_AGENT_SHA256;
    receipt.candidate.agentSha256 = options["candidate-agent-sha256"];
    await step("actual-agent-archives-verified", () => {
      let sourceFiles = 0;
      function compare(directory, relative = "") {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
          const name = path.join(relative, entry.name);
          if (entry.isDirectory()) { compare(path.join(directory, entry.name), name); continue; }
          if (!/\.(?:js|cjs|mjs|json|sh|ps1)$/.test(name)) continue;
          assert.equal(hash(fs.readFileSync(path.join(directory, entry.name))), hash(fs.readFileSync(path.join(root, "packages/agent", name))), "Packaged agent source differs: " + name);
          sourceFiles++;
        }
      }
      compare(candidatePackage);
      assert.ok(sourceFiles > 50, "Packaged agent source inventory unexpectedly small");
      return { baselineVersion: "0.17.3", candidateVersion: "0.18.0", candidateSourceFilesMatched: sourceFiles, nativeBinaryProvenance: "archive checksum and separately recorded artifact build" };
    });
    const images = await step("immutable-runtime-images", () => ({
      oldApi: pullImage("ghcr.io/tokentimerch/tokentimer-core-api:0.17.3"),
      oldWorker: pullImage("ghcr.io/tokentimerch/tokentimer-core-worker:0.17.3"),
      candidateApi: pullImage(options["candidate-api"]),
      candidateWorker: pullImage(options["candidate-worker"]),
      postgres: pullImage("postgres:17-alpine"),
    }));
    oldApi = images.oldApi;
    candidateApi = images.candidateApi;
    await step("candidate-image-runtime-source-match", () => {
      const evidence = {};
      for (const component of ["api", "worker"]) {
        const manifest = runtimeManifest(component);
        const image = component === "api" ? candidateApi : images.candidateWorker;
        const count = nodeResult(["run", "--rm", "-i", "--network", "none", image.imageId], function (input) {
          const fs = require("node:fs"); const crypto = require("node:crypto");
          for (const [name, digest] of Object.entries(input)) {
            const actual = crypto.createHash("sha256").update(fs.readFileSync("/app/" + name)).digest("hex");
            if (actual !== digest) throw new Error("Packaged source differs: " + name);
          }
          return Object.keys(input).length;
        }, manifest);
        evidence[component] = { files: count, sourceManifestSha256: hash(JSON.stringify(manifest)) };
      }
      return evidence;
    });
    network = own("network", prefix + "network", ["network", "create", "--internal", "--label", OWNER_LABEL + "=" + owner, prefix + "network"]);
    const databaseVolume = own("volume", prefix + "database", ["volume", "create", "--label", OWNER_LABEL + "=" + owner, prefix + "database"]);
    agentVolume = own("volume", prefix + "agent", ["volume", "create", "--label", OWNER_LABEL + "=" + owner, prefix + "agent"]);
    const password = crypto.randomBytes(24).toString("hex"); secrets.push(password);
    const sessionSecret = crypto.randomBytes(32).toString("hex"); secrets.push(sessionSecret);
    const signingKey = crypto.randomBytes(32).toString("hex"); secrets.push(signingKey);
    const registrationKey = crypto.randomBytes(32).toString("hex"); secrets.push(registrationKey);
    const runtimeEnv = { NODE_ENV: "production", PORT: "4000", DB_HOST: "database", DB_PORT: "5432", DB_USER: "upgrade_rehearsal", DB_PASSWORD: password, DB_NAME: "upgrade_rehearsal_test", APP_URL: "http://localhost:5173", API_URL: "http://localhost:4000", SESSION_SECRET: sessionSecret, SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true", TRUST_PROXY_HOPS: "0", DISABLE_ADMIN_BOOTSTRAP: "true", CERTOPS_ENABLED: "true", CERTOPS_SIGNING_ENCRYPTION_KEY: signingKey, CERTOPS_REGISTRATION_ENCRYPTION_KEY: registrationKey, WORKER_CERTOPS_RUN_ON_START: "false", WORKER_CERTOPS_INTERVAL_MS: "3600000", WORKER_API_KEY: sessionSecret };
    fs.writeFileSync(envPath, Object.entries(runtimeEnv).map(([key, value]) => key + "=" + value).join("\n") + "\n", { mode: 0o600 });
    const postgresEnv = path.join(temporary, "postgres.env");
    fs.writeFileSync(postgresEnv, "POSTGRES_USER=upgrade_rehearsal\nPOSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=upgrade_rehearsal_test\n", { mode: 0o600 });
    const database = own("container", prefix + "postgres", ["run", "-d", "--name", prefix + "postgres", "--label", OWNER_LABEL + "=" + owner, "--network", network, "--network-alias", "database", "--env-file", postgresEnv, "--mount", "type=volume,source=" + databaseVolume + ",target=/var/lib/postgresql/data", images.postgres.imageId]);
    await until(() => docker(["exec", database, "pg_isready", "-U", "upgrade_rehearsal", "-d", "upgrade_rehearsal_test"], { allowFailure: true }).status === 0, "owned PostgreSQL");
    function migrations(image) { docker(["run", "--rm", "--network", network, "--env-file", envPath, image.imageId, "node", "apps/api/migrations/migrate.js"]); }
    await step("released-0.17.3-migrations-and-fixtures", () => {
      migrations(oldApi);
      fixture = { email: "upgrade-" + owner + "@example.test", password: "Upgrade-" + crypto.randomBytes(18).toString("hex") + "!" }; secrets.push(fixture.password);
      Object.assign(fixture, nodeResult(["run", "--rm", "-i", "--network", network, "--env-file", envPath, oldApi.imageId], apiProbe, { action: "seed", fixture }));
    });
    startApi(oldApi, "old-api");
    await readyApi();
    const oldWorker = startWorker(images.oldWorker, "old-worker");
    const before = await step("released-runtime-auth-and-state", () => { probe("http", { operation: "verify" }); const snapshot = probe("snapshot"); assert.equal(snapshot.ledger.at(-1)?.version, 67); return snapshot; });
    stateProbe(true);
    const bootstrap = probe("http", { operation: "bootstrap" });
    const oldAgentContainer = startAgent(oldPackage, "old-agent", bootstrap);
    let oldAgent = await step("released-agent-registration-and-heartbeat", async () => { const agent = await waitAgent("0.17.3"); return { id: agent.id, version: agent.agent_version, lastSequence: agent.last_sequence }; });
    await step("released-agent-signed-noop", async () => signedNoop(probe("agent"), "before"));
    assert.equal(inspect("container", oldWorker).State.Running, true, "Released worker exited");
    docker(["stop", "--time", "20", oldAgentContainer]);
    oldAgent = probe("agent");
    const oldAgentState = stateProbe();
    docker(["stop", "--time", "20", oldWorker, currentApi]);
    await step("candidate-migrations-preserve-history-and-data", () => {
      migrations(candidateApi);
      const after = nodeResult(["run", "--rm", "-i", "--network", network, "--env-file", envPath, candidateApi.imageId], apiProbe, { action: "snapshot", fixture });
      assertLedgerUpgrade(before.ledger, after.ledger);
      assert.deepEqual(after.rowDigests, before.rowDigests);
      migrations(candidateApi);
      const restarted = nodeResult(["run", "--rm", "-i", "--network", network, "--env-file", envPath, candidateApi.imageId], apiProbe, { action: "snapshot", fixture });
      assert.deepEqual(restarted, after, "Second migration boot was not idempotent");
      return { preservedRows: Object.keys(after.rowDigests), migrationVersions: after.ledger.map((entry) => entry.version), historicalLedgerPreserved: true, secondBootNoOp: true };
    });
    startApi(candidateApi, "candidate-api");
    await readyApi();
    const candidateWorker = startWorker(images.candidateWorker, "candidate-worker");
    await step("upgraded-control-plane-auth-and-new-schema", () => {
      const http = probe("http", { operation: "verify" });
      const schema = probe("schema");
      assert.ok(schema.enrollments && schema.distribution && schema.onboarding);
      return { ...http, schema };
    });
    const candidateAgentContainer = startAgent(candidatePackage, "candidate-agent");
    await step("packaged-agent-upgrade-preserves-identity-and-state", async () => {
      const newAgent = await waitAgent("0.18.0");
      assertAgentContinuity(oldAgent, newAgent, oldAgentState, stateProbe());
      return { id: newAgent.id, version: newAgent.agent_version, credentialPreserved: true, signingPinPreserved: true, configPreserved: true, sequenceAdvanced: true };
    });
    await step("upgraded-agent-signed-dry-run", async () => signedNoop(probe("agent"), "after"));
    assert.equal(inspect("container", candidateWorker).State.Running, true, "Candidate worker exited");
    docker(["stop", "--time", "20", candidateAgentContainer]);
    await step("upgraded-runtime-restart-preserves-state", async () => {
      const saved = probe("snapshot");
      docker(["restart", currentApi, candidateWorker]);
      await readyApi();
      assert.deepEqual(probe("snapshot"), saved);
      probe("http", { operation: "verify" });
      assert.equal(inspect("container", candidateWorker).State.Running, true);
      return { databaseStatePreserved: true, authenticationPassed: true, workerRunning: true };
    });
    receipt.status = "passed";
  } catch (error) {
    receipt.failedStep = activeStep;
    receipt.error = redact(error.message);
    process.stderr.write(receipt.error + "\n");
    receipt.diagnostics = failureDiagnostics();
  } finally {
    const cleanupErrors = [];
    for (const resource of [...resources].reverse()) {
      try {
        const result = docker([resource.kind, "inspect", resource.name], { allowFailure: true });
        if (result.status !== 0) {
          if (resourceIsMissing(result.stderr, resource.name)) continue;
          throw new Error("Could not verify cleanup state for " + resource.name + ": " + result.stderr);
        }
        const found = JSON.parse(result.stdout)[0];
        const labels = resource.kind === "container" ? found.Config?.Labels : found.Labels;
        if (!ownsResource(resource.name, labels, owner)) throw new Error("Ownership check failed for " + resource.kind);
        docker([resource.kind, "rm", ...(resource.kind === "container" ? ["-f"] : []), resource.name]);
      } catch (error) { cleanupErrors.push(redact(error.message)); }
    }
    fs.rmSync(temporary, { recursive: true, force: true });
    receipt.cleanup = { complete: cleanupErrors.length === 0, errors: cleanupErrors };
    if (cleanupErrors.length) receipt.status = "failed";
    receipt.finishedAt = new Date().toISOString();
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
  }
  if (receipt.status !== "passed") process.exitCode = 1;
  return receipt;
}

module.exports = { parseArgs, verifyArchiveChecksum, ownsResource, resourceIsMissing, redactDiagnostic, assertLedgerUpgrade, assertAgentContinuity, OWNER_LABEL, OLD_AGENT_SHA256 };
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
