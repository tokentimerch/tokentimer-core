/**
 * Qualification: read-only native ACME browser console
 *
 * The dedicated Ubuntu 24.04/certbot/noEAB manual console lane runs a foreground
 * candidate agent, not an installed service. Authenticate pinned Chromium through
 * retained BrowserServer, preparePage before the command barrier's 120-second bound,
 * then admit the real public issue immediately. The wrapper pauses before certbot after
 * genuine signed claim and persisted starting line. Bind actual
 * job/certificate/claim/agent, wrapper birth/parent/group/argv and exact arm/receipt
 * before observeAndRelease. Dashboard filtered-job response and rendered starting line
 * must both be visible while nonterminal, at independently supplied UI/API origins;
 * count CertOps writes across ALL origins/workspaces and require zero. After native
 * issuance/trusted TLS, finish requires same claim success, actual completion line,
 * finalized gap-free stream with DB-matching count and leaf evidence matching the TLS
 * fingerprint. Register ownedBrowserResources before launch. Unknown launch/native
 * completion, changed receipts or incomplete drain keep an exclusive guard. Drain
 * browser AND agent/client then assertCleanupSafe before deleting API rows/private
 * files; browser closure alone is insufficient. Only successful native completion and
 * real browser close release ownership. The wrapper serves real built UI with retained
 * Vite HTTP. Upload only acme-native-console.json: UUIDs, public/curated-line hashes,
 * counts/flags; no raw logs, argv, endpoints, credentials, screenshots, traces. No
 * secret-injection or uninterrupted-delivery claim; other ACME/Alpine lanes gain no
 * browser prerequisite.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Read-only dashboard observation of one real foreground Linux agent job.
 * The existing external command wrapper pauses the actual ACME client after
 * the agent's signed claim and first persisted execution line. No log/API
 * response is injected. This actor is intended only for the explicit native
 * Ubuntu/certbot browser lane, not the cross-platform ACME baseline. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const SCOPE = "browser-console-of-real-linux-acme-agent-claim";
const FLAGS = Object.freeze([
  "actualSignedNativeClaim",
  "actualFirstNativeLineRenderedWhileRunning",
  "exactOwnedClientBarrierReleased",
  "sameClaimCompletedStream",
  "actualCompletionLineRendered",
  "zeroBrowserCertOpsWrites",
  "zeroLostOrDroppedLines",
  "claimBoundVerificationEvidence",
  "managedLeafMatchesTrustedTls",
  "retainedBrowserClosed",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-acme-browser-console.js",
  "tests/e2e/helpers/certops-acme-command-barrier.js",
  "tests/e2e/acme-real-journey.js",
  "packages/agent/src/index.js",
  "packages/agent/src/job-log-stream/index.js",
  "apps/api/services/certops/agentJobLogs.js",
  "apps/api/services/certops/evidence.js",
  "apps/api/routes/certops.js",
  "apps/dashboard/src/components/certops/AgentShellConsole.jsx",
  "apps/dashboard/src/components/certops/EvidenceTimeline.jsx",
  "apps/dashboard/src/components/certops/ExecutorJobsPanel.jsx",
  "apps/dashboard/src/components/certops/certopsJobsApi.js",
  "apps/dashboard/src/utils/apiClient.js",
  "apps/dashboard/src/utils/resolveApiBaseUrl.js",
  "package.json",
  "pnpm-lock.yaml",
]);
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const sha = /^[a-f0-9]{64}$/;
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "schemaVersion",
      "scope",
      "client",
      "jobId",
      "certificateId",
      "claimId",
      "agentId",
      "fingerprint",
      "firstLineSha256",
      "completionLineSha256",
      "acceptedLines",
      "browserCertOpsWrites",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.schemaVersion, 1);
  assert.equal(p.scope, SCOPE);
  assert.equal(p.client, "certbot");
  for (const key of ["jobId", "certificateId", "claimId", "agentId"])
    assert.match(p[key], uuid);
  for (const key of ["fingerprint", "firstLineSha256", "completionLineSha256"])
    assert.match(p[key], sha);
  assert.notEqual(p.firstLineSha256, p.completionLineSha256);
  assert.ok(
    Number.isSafeInteger(p.acceptedLines) &&
      p.acceptedLines >= 2 &&
      p.acceptedLines <= 2000,
  );
  assert.equal(p.browserCertOpsWrites, 0);
  for (const key of FLAGS)
    assert.equal(p[key], true, `Native console proof missing ${key}`);
  return true;
}
function ownedFile(file) {
  const st = fs.lstatSync(file);
  assert.ok(
    st.isFile() && !st.isSymbolicLink() && st.ino > 0 && st.size <= 16384,
    "Unsafe owned console file",
  );
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let bytes;
  try {
    const opened = fs.fstatSync(fd);
    assert.ok(
      opened.dev === st.dev && opened.ino === st.ino && opened.isFile(),
      "Console file replaced before open",
    );
    bytes = fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const after = fs.lstatSync(file);
  assert.ok(
    after.dev === st.dev && after.ino === st.ino && after.size === bytes.length,
    "Console file changed while reading",
  );
  return {
    dev: st.dev,
    ino: st.ino,
    hash: digest(bytes),
    value: JSON.parse(bytes.toString("utf8")),
  };
}
function sameOwnedFile(file, original) {
  const now = ownedFile(file);
  assert.ok(
    now.dev === original.dev &&
      now.ino === original.ino &&
      now.hash === original.hash,
    "Owned console file identity changed",
  );
  return now.value;
}
function directoryIdentity(directory) {
  const st = fs.lstatSync(directory);
  assert.ok(
    st.isDirectory() && !st.isSymbolicLink() && st.ino > 0,
    "Owned console directory required",
  );
  assert.equal(fs.realpathSync.native(directory), directory);
  return { dev: st.dev, ino: st.ino };
}
function assertDirectory(directory, original) {
  const now = directoryIdentity(directory);
  assert.ok(
    now.dev === original.dev && now.ino === original.ino,
    "Owned console directory was replaced",
  );
}
function parseProcStat(raw) {
  const end = raw.lastIndexOf(")");
  assert.ok(end > 0);
  const fields = raw
    .slice(end + 2)
    .trim()
    .split(/\s+/);
  assert.ok(fields.length >= 20 && /^\d+$/.test(fields[19]));
  return {
    parentPid: Number(fields[1]),
    processGroup: Number(fields[2]),
    startTicks: fields[19],
  };
}
function verifyBarrier(receipt, native, { token, agentPid }) {
  assert.equal(receipt.token, token);
  assert.ok(Number.isSafeInteger(receipt.pid) && receipt.pid > 0);
  assert.equal(receipt.parentPid, agentPid);
  assert.equal(native.parentPid, agentPid);
  assert.equal(receipt.startTicks, native.startTicks);
  assert.equal(receipt.processGroup, native.processGroup);
  assert.equal(receipt.binary, "certbot");
  return true;
}
async function until(read, label, timeout = 30000) {
  const start = performance.now();
  do {
    const result = await read();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 100));
  } while (performance.now() - start < timeout);
  throw new Error(`Native console observation timed out: ${label}`);
}
function isCertOpsWrite(request) {
  const url = new URL(request.url());
  return (
    /^(POST|PATCH|PUT|DELETE)$/.test(request.method()) &&
    /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(url.pathname)
  );
}
function ownedOrigin(value) {
  const url = new URL(value);
  assert.ok(
    ["http:", "https:"].includes(url.protocol) &&
      ["localhost", "127.0.0.1"].includes(url.hostname),
    "Owned loopback browser/API origin required",
  );
  assert.ok(
    !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.pathname === "/",
    "Bare owned browser/API origin required",
  );
  return url.origin;
}
function verifyLogPayload(payload, claimId, completed) {
  assert.ok(
    payload &&
      payload.storageEnabled !== false &&
      payload.linesVisible !== false,
  );
  assert.ok(
    Array.isArray(payload.items) &&
      payload.items.every(
        (line) => line.claimId === claimId && typeof line.message === "string",
      ),
  );
  assert.equal(payload.streams.length, 1);
  const stream = payload.streams[0];
  assert.equal(stream.claimId, claimId);
  assert.equal(stream.streamingEnabled, true);
  assert.equal(stream.agentGapLines, 0);
  assert.equal(stream.serverDroppedLines, 0);
  assert.equal(stream.truncated, false);
  if (completed) {
    assert.equal(payload.jobStatus, "succeeded");
    assert.equal(payload.logsComplete, true);
    assert.equal(payload.hasMore, false);
    assert.equal(stream.status, "final");
  } else {
    assert.ok(["claimed", "running"].includes(payload.jobStatus));
    assert.equal(payload.logsComplete, false);
    assert.ok(["pending", "streaming"].includes(stream.status));
  }
  return true;
}
/** Register this resource before launch; an unknown launch outcome remains
 * sticky. BrowserServer.close + the retained ChildProcess close event are both
 * necessary. No PID-based kill or screenshot/trace fallback is permitted. */
function createBrowserOwnership(register) {
  let server,
    child,
    closeObserved = false,
    launchAttempted = false,
    released = false;
  const resource = {
    hasLiveChild: () => !released && launchAttempted && !closeObserved,
    hasOwnershipReceipt: () => !released && launchAttempted,
    attach(value) {
      server = value;
      child = value.process();
      assert.ok(child && Number.isSafeInteger(child.pid));
      child.once("close", () => {
        closeObserved = true;
      });
    },
    begin() {
      launchAttempted = true;
    },
    async close() {
      if (released) return;
      if (!launchAttempted) {
        released = true;
        return;
      }
      assert.ok(server && child, "Preserve state after unknown browser launch");
      try {
        await Promise.race([
          server.close(),
          new Promise((_, reject) => {
            const timer = setTimeout(
              () => reject(new Error("Retained browser close timed out")),
              30000,
            );
            timer.unref();
          }),
        ]);
      } catch {
        throw new Error(
          "Retained browser closure unproven; preserve owned state",
        );
      }
      await until(() => closeObserved, "retained browser close");
      released = true;
    },
  };
  register(resource);
  return resource;
}
function nativeCleanupResource(browserResource, isGuardPresent) {
  let nativeResolved = false;
  return {
    hasLiveChild: () => browserResource.hasLiveChild(),
    // Registration precedes launch, so even a throwing constructor leaves this
    // durable native-operation guard visible to the parent's first cleanup.
    hasOwnershipReceipt: () =>
      !nativeResolved ||
      browserResource.hasOwnershipReceipt() ||
      isGuardPresent(),
    close: () => browserResource.close(),
    completeNativeOperation() {
      assert.equal(browserResource.hasLiveChild(), false);
      assert.equal(browserResource.hasOwnershipReceipt(), false);
      assert.equal(isGuardPresent(), false);
      nativeResolved = true;
    },
    assertCleanupSafe: () => {
      assert.equal(
        nativeResolved,
        true,
        "Native console ownership remains unresolved",
      );
      assert.equal(
        isGuardPresent(),
        false,
        "Preserve unresolved native console ownership",
      );
    },
  };
}
async function createNativeConsoleActor(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  assert.equal(c.eabRef, undefined);
  assert.ok(path.isAbsolute(c.barrierDirectory) && path.isAbsolute(c.workDir));
  assert.equal(fs.realpathSync.native(c.barrierDirectory), c.barrierDirectory);
  const workIdentity = directoryIdentity(c.workDir),
    barrierIdentity = directoryIdentity(c.barrierDirectory);
  assert.ok(
    c.barrierDirectory.startsWith(c.workDir + path.sep),
    "Barrier must belong to this native fixture",
  );
  assert.ok(Array.isArray(c.ownedBrowserResources));
  const origin = ownedOrigin(c.uiOrigin),
    apiOrigin = ownedOrigin(c.apiOrigin);
  const pin = require("../../../package.json").devDependencies.playwright;
  assert.equal(require("playwright/package.json").version, pin);
  const { chromium } = require("playwright");
  const guard = path.join(c.workDir, "native-console-active.json");
  const token = crypto.randomUUID();
  fs.writeFileSync(
    guard,
    JSON.stringify({ token, candidateSha: process.env.GITHUB_SHA }),
    { flag: "wx", mode: 0o600 },
  );
  const originalGuard = ownedFile(guard);
  let cleanupResource;
  const resource = createBrowserOwnership((value) => {
    cleanupResource = nativeCleanupResource(value, () => fs.existsSync(guard));
    c.ownedBrowserResources.push(cleanupResource);
  });
  let server,
    browser,
    page,
    writes = 0,
    armIdentity,
    receiptIdentity,
    bound,
    first,
    livePayload,
    completedPayload,
    baselineJobIds,
    responseFailed = false;
  const arm = path.join(c.barrierDirectory, "armed.json"),
    receipt = path.join(c.barrierDirectory, "process.json");
  const job = async (id) =>
    (
      await c.pool.query(
        "SELECT status,claim_id,claimed_by_agent_id,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [c.workspaceId, id],
      )
    ).rows[0];
  const logs = async (id) =>
    (
      await c.pool.query(
        "SELECT claim_id,seq,message FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2 ORDER BY ingest_order LIMIT 2001",
        [c.workspaceId, id],
      )
    ).rows;
  function assertCleanupSafe() {
    cleanupResource.assertCleanupSafe();
    assert.equal(
      fs.existsSync(guard),
      false,
      "Preserve native console state until browser and actual job are resolved",
    );
  }
  try {
    resource.begin();
    server = await chromium.launchServer({ headless: true, host: "127.0.0.1" });
    resource.attach(server);
  } catch {
    throw new Error(
      "Native console browser launch failed; preserve owned state",
    );
  }
  // launchServer endpoint stays closure-local through this explicit accessor.
  // Session setup is below so login failures never serialize Playwright inputs.
  const actor = {
    assertCleanupSafe,
    resource,
    async close() {
      await resource.close();
    },
    async preparePage() {
      browser = await chromium.connect(server.wsEndpoint(), { timeout: 30000 });
      const context = await browser.newContext({ ignoreHTTPSErrors: false });
      page = await context.newPage();
      page.setDefaultTimeout(30000);
      try {
        await page.goto(origin + "/login");
        await page.getByLabel("Email", { exact: true }).fill(c.identity.email);
        await page
          .getByLabel("Password", { exact: true })
          .fill(c.identity.password);
        await page
          .getByRole("button", { name: "Sign In", exact: true })
          .click();
        await page.waitForURL((url) => !url.pathname.includes("login"));
      } catch {
        throw new Error("Native console authentication failed");
      }
      page.on("request", (request) => {
        if (isCertOpsWrite(request)) writes++;
      });
      page.on("response", async (response) => {
        if (!bound) return;
        const url = new URL(response.url());
        if (
          response.request().method() !== "GET" ||
          url.origin !== apiOrigin ||
          url.pathname !==
            `/api/v1/workspaces/${c.workspaceId}/certops/jobs/${bound.jobId}/agent-log`
        )
          return;
        try {
          assert.equal(response.status(), 200);
          const payload = await response.json();
          assert.ok(
            payload.storageEnabled !== false && payload.linesVisible !== false,
          );
          if (
            ["claimed", "running"].includes(payload.jobStatus) &&
            payload.logsComplete === false &&
            payload.items.some(
              (line) =>
                line.claimId === bound.claimId &&
                line.message === first.message,
            )
          ) {
            verifyLogPayload(payload, bound.claimId, false);
            livePayload = payload;
          }
          if (
            payload.jobStatus === "succeeded" &&
            payload.logsComplete === true &&
            payload.hasMore === false
          ) {
            verifyLogPayload(payload, bound.claimId, true);
            completedPayload = payload;
          }
        } catch {
          responseFailed = true;
        }
      });
      const active = await c.pool.query(
        "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND status IN ('pending','pending_approval','approved','claimed','running')",
        [c.workspaceId],
      );
      assert.equal(
        active.rows.length,
        0,
        "Console barrier requires an isolated workspace",
      );
      const baseline = await c.pool.query(
        "SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id LIMIT 2001",
        [c.workspaceId],
      );
      assert.ok(
        baseline.rows.length <= 2000,
        "Bounded isolated console workspace required",
      );
      baselineJobIds = new Set(baseline.rows.map((row) => row.id));
      assert.equal(fs.existsSync(receipt), false);
      assertDirectory(c.workDir, workIdentity);
      assertDirectory(c.barrierDirectory, barrierIdentity);
      fs.writeFileSync(arm, JSON.stringify({ token }), {
        flag: "wx",
        mode: 0o600,
      });
      armIdentity = ownedFile(arm);
    },
    async observeAndRelease({ jobId, certificateId }) {
      assert.ok(page && armIdentity);
      assert.match(jobId, uuid);
      assert.match(certificateId, uuid);
      const row = await until(async () => {
        const value = await job(jobId);
        return value &&
          ["claimed", "running"].includes(value.status) &&
          value.claim_id
          ? value
          : null;
      }, "native claim");
      assert.equal(row.subject_id, certificateId);
      const agentRow = (
        await c.pool.query(
          "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
          [c.workspaceId, c.agentId],
        )
      ).rows;
      assert.equal(agentRow.length, 1);
      assert.equal(row.claimed_by_agent_id, agentRow[0].id);
      bound = {
        jobId,
        certificateId,
        claimId: row.claim_id,
        agentId: row.claimed_by_agent_id,
      };
      const newJobs = (
        await c.pool.query(
          "SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id LIMIT 2001",
          [c.workspaceId],
        )
      ).rows.filter((value) => !baselineJobIds.has(value.id));
      assert.equal(
        newJobs.length,
        1,
        "Only the admitted native console job may acquire this barrier",
      );
      assert.equal(newJobs[0].id, jobId);
      first = await until(
        async () =>
          (await logs(jobId)).find(
            (line) =>
              line.claim_id === bound.claimId &&
              line.message.includes(
                `job ${jobId}: passed signature/replay/clock/policy verification, starting execution`,
              ),
          ),
        "persisted native starting line",
      );
      await until(() => fs.existsSync(receipt), "actual client barrier");
      receiptIdentity = ownedFile(receipt);
      const native = parseProcStat(
        fs.readFileSync(`/proc/${receiptIdentity.value.pid}/stat`, "utf8"),
      );
      verifyBarrier(receiptIdentity.value, native, {
        token,
        agentPid: c.agent.pid,
      });
      const argv = fs
        .readFileSync(`/proc/${receiptIdentity.value.pid}/cmdline`, "utf8")
        .split("\0");
      assert.ok(
        argv.includes(
          path.join(
            c.repoRoot,
            "tests/e2e/helpers/certops-acme-command-barrier.js",
          ),
        ) && argv.includes(c.barrierDirectory),
      );
      const dest = new URL("/certops/jobs", origin);
      dest.searchParams.set("workspace", c.workspaceId);
      dest.searchParams.set("q", jobId);
      dest.searchParams.set("job", jobId);
      const listing = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return (
          response.request().method() === "GET" &&
          url.origin === apiOrigin &&
          url.pathname === `/api/v1/workspaces/${c.workspaceId}/certops/jobs` &&
          url.searchParams.get("q") === jobId
        );
      });
      await page.goto(dest.href);
      const response = await listing;
      assert.equal(response.status(), 200);
      const body = await response.json();
      assert.equal(body.items.length, 1);
      assert.equal(body.items[0].id, jobId);
      const console = page.getByTestId("agent-shell-console");
      await console
        .locator("[data-shell-line]")
        .filter({ hasText: first.message.replace(/^\[agent:[^\]]+\]\s*/, "") })
        .first()
        .waitFor();
      await until(() => livePayload, "actual nonterminal browser log payload");
      assert.equal(responseFailed, false);
      assert.ok(["claimed", "running"].includes((await job(jobId)).status));
      assert.equal(writes, 0);
      assertDirectory(c.workDir, workIdentity);
      assertDirectory(c.barrierDirectory, barrierIdentity);
      sameOwnedFile(receipt, receiptIdentity);
      sameOwnedFile(arm, armIdentity);
      fs.unlinkSync(arm);
    },
    async finish({ trustedFingerprint }) {
      assert.ok(bound && first);
      const fingerprint = trustedFingerprint.replace(/:/g, "").toLowerCase();
      assert.match(fingerprint, sha);
      const row = await job(bound.jobId);
      assert.equal(row.status, "succeeded");
      assert.equal(row.claim_id, bound.claimId);
      assert.equal(row.claimed_by_agent_id, bound.agentId);
      const entries = await logs(bound.jobId);
      assert.ok(entries.length >= 2 && entries.length <= 2000);
      assert.ok(entries.every((line) => line.claim_id === bound.claimId));
      const completion = entries.find((line) =>
        line.message.includes(
          `job ${bound.jobId}: execution finished with status succeeded`,
        ),
      );
      assert.ok(completion);
      await page
        .getByTestId("agent-shell-console")
        .locator("[data-shell-line]")
        .filter({
          hasText: completion.message.replace(/^\[agent:[^\]]+\]\s*/, ""),
        })
        .first()
        .waitFor();
      await until(
        () => completedPayload,
        "actual completed browser log payload",
      );
      assert.equal(responseFailed, false);
      const streams = (
        await c.pool.query(
          "SELECT claim_id,agent_id,status,streaming_enabled,accepted_lines,server_dropped_lines,agent_gap_lines FROM certops_agent_log_stream WHERE workspace_id=$1 AND job_id=$2",
          [c.workspaceId, bound.jobId],
        )
      ).rows;
      assert.equal(streams.length, 1);
      const stream = streams[0];
      assert.equal(stream.claim_id, bound.claimId);
      assert.equal(stream.agent_id, bound.agentId);
      assert.equal(stream.status, "final");
      assert.equal(stream.streaming_enabled, true);
      assert.equal(stream.accepted_lines, entries.length);
      assert.equal(stream.server_dropped_lines, 0);
      assert.equal(stream.agent_gap_lines, 0);
      const evidence = await c.pool.query(
        "SELECT 1 FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify' AND e.metadata->>'fingerprintSha256'=$3",
        [c.workspaceId, bound.jobId, fingerprint],
      );
      assert.ok(evidence.rows.length > 0);
      const managed = (
        await c.pool.query(
          "SELECT status,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
          [c.workspaceId, bound.certificateId],
        )
      ).rows;
      assert.equal(managed.length, 1);
      assert.equal(managed[0].status, "active");
      assert.equal(
        managed[0].fingerprint_sha256.replace(/:/g, "").toLowerCase(),
        fingerprint,
      );
      assert.equal(writes, 0);
      await resource.close();
      assert.equal(
        writes,
        0,
        "Browser CertOps mutation observed during closure",
      );
      assertDirectory(c.workDir, workIdentity);
      assertDirectory(c.barrierDirectory, barrierIdentity);
      sameOwnedFile(receipt, receiptIdentity);
      let current;
      try {
        current = parseProcStat(
          fs.readFileSync(`/proc/${receiptIdentity.value.pid}/stat`, "utf8"),
        );
      } catch (error) {
        if (!["ENOENT", "ESRCH"].includes(error.code)) throw error;
      }
      assert.ok(
        !current || current.startTicks !== receiptIdentity.value.startTicks,
        "Owned client wrapper must finish before receipt removal",
      );
      fs.unlinkSync(receipt);
      const proof = {
        schemaVersion: 1,
        scope: SCOPE,
        client: "certbot",
        ...bound,
        fingerprint,
        firstLineSha256: digest(first.message),
        completionLineSha256: digest(completion.message),
        acceptedLines: entries.length,
        browserCertOpsWrites: writes,
        ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
      };
      verifyProof(proof);
      sameOwnedFile(guard, originalGuard);
      fs.unlinkSync(guard);
      cleanupResource.completeNativeOperation();
      return proof;
    },
  };
  // Playwright call logs can include credential inputs or private endpoints.
  // Preserve the durable guard and report only the bounded failed phase.
  for (const name of ["preparePage", "observeAndRelease", "finish", "close"]) {
    const action = actor[name];
    actor[name] = async (...args) => {
      try {
        return await action(...args);
      } catch {
        throw new Error(
          `Native ACME console failed at ${name}; preserve owned state`,
        );
      }
    };
  }
  return actor;
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  parseProcStat,
  verifyBarrier,
  isCertOpsWrite,
  ownedOrigin,
  verifyLogPayload,
  createBrowserOwnership,
  nativeCleanupResource,
  createNativeConsoleActor,
};
