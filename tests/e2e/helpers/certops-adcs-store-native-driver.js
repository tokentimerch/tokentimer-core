"use strict";

// Lab-only driver; the caller supplies an independently configured native
// operation counter and the established disposable-lab fixture. Never infer
// absent key generation/acceptance from a job result or from the CA count.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { createHash } = require("node:crypto");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { recoveryWaitBudget } = require("./certops-adcs-uncertain-abandon");
const { qualifyImmediateStoreRecovery } = require("./certops-adcs-store-recovery-proof");
const { startNativeStoreObserver } = require("./certops-adcs-store-native-observer");
const { inspectStoreOnlyCertificate } = require("../../../packages/agent/src/windows-cert-store/store-only");
const { validateNativeCngEvidence, nativeCngEvidenceSha256 } = require("./certops-adcs-store-native-cng");
const { NAMED_STORE_SCOPE, validateNamedStoreEvidence, verifyNamedStoreIdentity, namedStoreEvidenceDigest } = require("./certops-adcs-store-named-observation");

const OBSERVATION_RUN_ID = /^[a-f0-9]{32}$/;
const STORE_SERVICE_PROCESS = "$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\" -ErrorAction Stop; " +
  "if ($s.State -ne 'Running' -or !$s.ProcessId) { return '{}' }; " +
  "$p=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $s.ProcessId) -ErrorAction Stop; " +
  "$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; " +
  "@{pid=[int]$s.ProcessId;sid=$owner.Sid;created=$p.CreationDate.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress";

async function readStoreServiceProcess(ps) {
  return JSON.parse(await ps(STORE_SERVICE_PROCESS));
}

function requireStoreServiceProcess(process) {
  assert.ok(Number.isSafeInteger(process?.pid) && process.pid > 0, "Owned service process is required");
  assert.equal(process.sid, "S-1-5-18");
  assert.ok(Number.isFinite(Date.parse(process.created)), "Owned service process creation time is required");
  return process;
}

async function verifyOwnedServiceDrainage({ stopAndVerifyOwnedService, candidateArchiveSha256, captureId, serviceProcess }) {
  const proof = await stopAndVerifyOwnedService({
    candidateArchiveSha256, captureId, pid: serviceProcess.pid, created: serviceProcess.created,
  });
  assert.equal(proof?.candidateArchiveSha256, candidateArchiveSha256);
  assert.equal(proof.captureId, captureId);
  assert.equal(proof.pid, serviceProcess.pid);
  assert.equal(proof.created, serviceProcess.created);
  assert.equal(proof.independentReader, true);
  assert.equal(proof.serviceStopped, true);
  assert.deepEqual(proof.activeDescendants, [], "Owned service descendants have not drained");
  assert.match(proof.evidenceSha256, /^[a-f0-9]{64}$/);
  return proof.evidenceSha256;
}

function validateObservedServiceStart(proof, { candidateArchiveSha256, captureId, previousObservationRunId, serviceProcess }) {
  assert.equal(proof?.candidateArchiveSha256, candidateArchiveSha256);
  assert.equal(proof.captureId, captureId, "Restart changed the independent capture");
  assert.equal(proof.independentReader, true);
  assert.equal(proof.captureContinued, true);
  assert.equal(proof.runArmedBeforeStart, true);
  assert.match(previousObservationRunId, OBSERVATION_RUN_ID);
  assert.match(proof.observationRunId, OBSERVATION_RUN_ID);
  assert.notEqual(proof.observationRunId, previousObservationRunId, "An observation run cannot be reused");
  const process = requireStoreServiceProcess(proof.process);
  assert.ok(Date.parse(process.created) > Date.parse(serviceProcess.created), "Expected a freshly started owned service");
  assert.match(proof.evidenceSha256, /^[a-f0-9]{64}$/);
  return { process, observationRunId: proof.observationRunId, serviceStartSha256: proof.evidenceSha256 };
}

async function startObservedStoreService(context, captureId, previousObservationRunId, serviceProcess) {
  // The trusted adapter arms a new observation run for the same installed
  // package before SCM starts it. The independent capture remains live.
  const target = { candidateArchiveSha256: context.candidateArchiveSha256, captureId,
    previousObservationRunId, serviceProcess };
  const restarted = validateObservedServiceStart(await context.startAndVerifyObservedService(target), target);
  const installed = await verifyCandidateHost(context);
  assert.equal(installed.observationRunId, restarted.observationRunId, "Installed service uses a different observation run");
  assert.deepEqual(installed.serviceProcess, restarted.process, "Restart evidence identifies another service process");
  return restarted;
}

// The fixture must implement independent write/flush, readback and storage
// inspection. This protocol is not evidence that a real fixture is durable.
function createPublicEvidenceRecorder({ candidateArchiveSha256, writeEvidence, readEvidence, inspectEvidenceDurability }) {
  assert.match(candidateArchiveSha256, /^[a-f0-9]{64}$/, "Expected candidate archive digest is required");
  for (const fn of [writeEvidence, readEvidence, inspectEvidenceDurability]) assert.equal(typeof fn, "function", "Independent durable evidence hooks are required");
  assert.notEqual(writeEvidence, readEvidence, "Evidence readback must use a separate hook");
  assert.notEqual(inspectEvidenceDurability, writeEvidence);
  assert.notEqual(inspectEvidenceDurability, readEvidence);
  const phases = new Set(["baseline", "post-accept", "ca-at-fault", "before-recovery-post", "before-service-start",
    "service-restarted", "ca-after-recovery", "pending-before-restart", "pending-after-restart",
    "inventory", "observations-drained", "failure"]);
  const allowed = new Set(["candidateSha256", "dnsName", "captureId", "observationId", "observationRunId", "initialObservationRunId", "caPublicKeySha256", "baselineRequestId", "enrollmentId", "jobId", "fingerprintSha256", "csrSpkiSha256", "cngEvidenceSha256", "namedStoreEvidenceSha256", "observationScope", "ephemeralCng", "serviceDrainageSha256", "serviceStartSha256", "requestId", "serialNumber", "submissions", "keygens", "accepts", "stage", "code", "promotions"]);
  const seen = new Set();
  const identities = new Map();
  let storeId = null, failed = false, busy = false;
  return async function recordEvidence(phase, fields) {
    assert.equal(failed, false, "Evidence recorder was permanently invalidated");
    if (busy) { failed = true; throw new Error("Concurrent evidence write invalidated the run"); }
    busy = true;
    try {
    assert.ok(phases.has(phase));
    assert.ok(fields && typeof fields === "object" && !Array.isArray(fields));
    const numeric = new Set(["baselineRequestId", "submissions", "keygens", "accepts", "promotions"]);
    const hashes = new Set(["candidateSha256", "caPublicKeySha256", "fingerprintSha256", "csrSpkiSha256",
      "cngEvidenceSha256", "namedStoreEvidenceSha256", "serviceDrainageSha256", "serviceStartSha256"]);
    const ids = new Set(["captureId", "observationId", "observationRunId", "initialObservationRunId"]);
    const uuids = new Set(["enrollmentId", "jobId"]);
    const entry = { ...fields };
    for (const [key, value] of Object.entries(entry)) {
      assert.ok(allowed.has(key), "Evidence field is not public or recognized");
      if (numeric.has(key)) assert.ok(Number.isSafeInteger(value) && value >= 0);
      else if (hashes.has(key)) assert.match(value, /^[a-f0-9]{64}$/);
      else if (ids.has(key)) assert.match(value, OBSERVATION_RUN_ID);
      else if (uuids.has(key)) assert.match(value, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
      else if (key === "dnsName") assert.match(value, /^certops-adcs-[a-f0-9]{16,32}-store\.example\.test$/);
      else if (key === "requestId") assert.match(value, /^[1-9][0-9]{0,9}$/);
      else if (key === "serialNumber") assert.match(value, /^[a-fA-F0-9]{1,128}$/);
      else if (key === "stage") assert.match(value, /^[a-z-]{1,48}$/);
      else if (key === "observationScope") assert.equal(value, NAMED_STORE_SCOPE);
      else if (key === "ephemeralCng") assert.equal(value, "not-qualified");
      else if (key === "code") assert.equal(value, "QUALIFICATION_FAILED");
      else throw new Error("Unvalidated public evidence field");
    }
    assert.equal(entry.candidateSha256, candidateArchiveSha256, "Evidence phase candidate archive digest does not match the run");
    if (entry.observationScope || entry.namedStoreEvidenceSha256 || entry.ephemeralCng) {
      assert.equal(entry.observationScope, NAMED_STORE_SCOPE);
      assert.equal(entry.ephemeralCng, "not-qualified");
      assert.ok(entry.captureId && entry.namedStoreEvidenceSha256, "Named Store evidence requires its capture ID and digest");
      assert.equal(entry.cngEvidenceSha256, undefined, "Named Store evidence cannot report an exhaustive CNG digest");
    } else if (Object.hasOwn(entry, "keygens")) {
      assert.ok(entry.captureId && entry.cngEvidenceSha256, "Evidence key count requires its CNG capture ID and digest");
    }
    for (const key of ["captureId", "observationId"]) {
      if (!Object.hasOwn(entry, key)) continue;
      if (identities.has(key)) assert.equal(entry[key], identities.get(key), `Evidence ${key} changed during the run`);
      else identities.set(key, entry[key]);
    }
    const json = JSON.stringify({ schema: 1, phase, ...entry });
    const sha256 = createHash("sha256").update(json, "utf8").digest("hex");
    const written = await writeEvidence({ json, sha256 });
    assert.equal(written?.flushCompleted, true, "Evidence flush was not confirmed");
    assert.match(written.receiptId, /^[a-f0-9]{32,64}$/);
    assert.ok(!seen.has(written.receiptId), "Evidence receipt was replayed");
    const readback = await readEvidence({ receiptId: written.receiptId });
    assert.equal(typeof readback, "string");
    assert.equal(createHash("sha256").update(readback, "utf8").digest("hex"), sha256, "Evidence readback mismatch");
    assert.equal(readback, json);
    const inspected = await inspectEvidenceDurability({ receiptId: written.receiptId, sha256 });
    assert.equal(inspected?.independentReader, true);
    assert.equal(inspected.flushVerified, true);
    assert.equal(inspected.persistentStore, true);
    assert.equal(inspected.continuityProven, true);
    assert.match(inspected.storeId, /^[a-f0-9]{64}$/);
    if (storeId !== null) assert.equal(inspected.storeId, storeId, "Evidence store identity changed");
    storeId = inspected.storeId;
    assert.equal(failed, false, "Evidence recorder was permanently invalidated");
    seen.add(written.receiptId);
    return { receiptId: written.receiptId, sha256 };
    } catch (error) { failed = true; throw error; } finally { busy = false; }
  };
}
async function verifyCandidateHost({ archivePath, candidateArchiveSha256, expectedRuntimeSha256, inspectCandidateHost, ps }) {
  assert.ok(typeof archivePath === "string" && path.isAbsolute(archivePath), "Absolute candidate archive path is required");
  assert.match(candidateArchiveSha256, /^[a-f0-9]{64}$/);
  assert.match(expectedRuntimeSha256, /^[a-f0-9]{64}$/);
  assert.equal(typeof inspectCandidateHost, "function", "Independent installed candidate inspection is required");
  const file = fs.lstatSync(archivePath);
  assert.equal(file.isSymbolicLink(), false, "Candidate archive cannot be a symlink");
  assert.equal(file.isFile(), true, "Candidate archive must be a file");
  const actual = createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex");
  assert.equal(actual, candidateArchiveSha256, "Candidate archive digest mismatch");
  const host = await inspectCandidateHost({ candidateArchiveSha256: actual, expectedRuntimeSha256 });
  assert.equal(host?.inspectionIndependent, true);
  assert.equal(host.archiveBytesVerified, true);
  assert.equal(host.installedFilesMatchArchive, true);
  assert.equal(host.protectedInstallation, true);
  assert.equal(host.serviceOwned, true);
  assert.equal(host.serviceIdentity, "LocalSystem");
  assert.equal(host.processTokenSid, "S-1-5-18");
  assert.equal(host.noIis, true);
  assert.equal(host.storeOnlyAdcsCapability, true);
  assert.equal(host.agentArchiveSha256, actual);
  assert.equal(host.runtimeSha256, expectedRuntimeSha256);
  const inspectedProcess = requireStoreServiceProcess(host.serviceProcess);
  const runningProcess = requireStoreServiceProcess(await readStoreServiceProcess(ps));
  assert.deepEqual(runningProcess, inspectedProcess, "Independent package inspection identifies a different running service process");
  return host;
}
function validateNativeCounts(counts, previous = null) {
  assert.ok(counts?.scope === undefined || counts.scope === NAMED_STORE_SCOPE, "Unsupported observation scope");
  const named = counts?.scope === NAMED_STORE_SCOPE;
  if (!named) assert.equal(counts?.coverageComplete, true, "Native operation capture must cover the whole recovery");
  assert.match(counts.captureId, /^[a-f0-9]{32}$/);
  for (const name of ["submissions", "keygens", "accepts"]) assert.ok(Number.isSafeInteger(counts[name]) && counts[name] >= 0);
  if (previous) {
    assert.equal(counts.scope, previous.scope, "Native observation scope changed during capture");
    assert.equal(counts.captureId, previous.captureId);
    assert.ok(named ? previous.namedEvidence : previous.cngEvidence, "Raw evidence from the previous checkpoint is required");
    for (const name of ["submissions", "keygens", "accepts"]) assert.ok(counts[name] >= previous[name]);
  }
  if (named) return { ...counts, namedEvidence: validateNamedStoreEvidence(counts, previous?.namedEvidence) };
  const cngEvidence = validateNativeCngEvidence(counts, previous?.cngEvidence);
  return { ...counts, cngEvidence };
}

function captureEvidenceDetails(counts) {
  if (counts.scope === NAMED_STORE_SCOPE) {
    return { observationScope: NAMED_STORE_SCOPE, ephemeralCng: "not-qualified",
      namedStoreEvidenceSha256: namedStoreEvidenceDigest(counts) };
  }
  return { cngEvidenceSha256: nativeCngEvidenceSha256(counts) };
}

function validateInitialNativeCounts(counts, previous) {
  const checked = validateNativeCounts(counts, previous);
  assert.equal(counts.submissions, 1, "Expected one CA submission before interruption");
  assert.equal(counts.keygens, 1, "Expected one key generation before interruption");
  assert.equal(counts.accepts, 1, "Expected one native acceptance before interruption");
  return checked;
}

function validateCaptureStart(capture, candidateArchiveSha256, expectedScope) {
  assert.equal(capture?.started, true, "Native operation capture must start before issuance");
  assert.match(capture.captureId, /^[a-f0-9]{32}$/);
  assert.equal(typeof capture.stop, "function", "Native capture must support verified drainage");
  assert.equal(typeof capture.read, "function", "Native capture must provide a live checkpoint");
  assert.equal(capture.baseline?.scope, expectedScope, "Capture does not match its approved observation scope");
  const baseline = validateNativeCounts(capture.baseline);
  assert.equal(baseline.captureId, capture.captureId, "Baseline must belong to the live capture");
  assert.equal((baseline.namedEvidence ?? baseline.cngEvidence).candidateSha256, candidateArchiveSha256,
    "Raw observation baseline belongs to another candidate");
  for (const name of ["submissions", "keygens", "accepts"]) {
    assert.equal(baseline[name], 0, `Expected zero ${name} before issuance`);
  }
  return baseline;
}

async function stopNativeCapture(capture, lastCounts = null) {
  assert.equal(typeof capture?.stop, "function", "Native capture cannot be drained");
  const stopped = await capture.stop();
  assert.equal(stopped?.drained, true, "Native capture drainage was not proven");
  assert.equal(stopped.captureId, capture.captureId, "Drained capture identity changed");
  if (!lastCounts && stopped.finalCounts === undefined) return;
  const finalCounts = validateNativeCounts(stopped.finalCounts, lastCounts);
  assert.equal(finalCounts.captureId, capture.captureId, "Final counts belong to another capture");
  if (lastCounts) {
    for (const name of ["submissions", "keygens", "accepts"]) assert.equal(finalCounts[name], lastCounts[name], "Native operation occurred after the final read");
  }
  return finalCounts;
}

function validateCaObservationStart(observation, expectedCaKeySha256) {
  assert.match(expectedCaKeySha256, /^[a-f0-9]{64}$/);
  assert.equal(observation?.started, true, "Independent CA observation must start before baseline");
  assert.match(observation.observationId, /^[a-f0-9]{32}$/);
  assert.equal(typeof observation.stop, "function", "CA observation must support verified drainage");
  assert.equal(typeof observation.readBaseline, "function", "CA observation must provide a live baseline checkpoint");
  assert.equal(observation.coverageComplete, true, "Independent CA observation must prove complete coverage");
  assert.equal(observation.startedBeforeBaseline, true);
  assert.equal(observation.lossFree, true);
  assert.equal(observation.noPurgeProven, true);
  assert.equal(observation.noRestoreProven, true);
  assert.equal(observation.caPublicKeySha256, expectedCaKeySha256);
  assert.ok(Number.isSafeInteger(observation.baselineRequestId) && observation.baselineRequestId >= 0 && observation.baselineRequestId < 2147483647);
  return observation;
}

function validateCaObservationWindow(window, observation, fingerprintSha256) {
  assert.equal(window?.coverageComplete, true, "Independent CA window must prove complete coverage");
  assert.equal(window.observationId, observation.observationId);
  assert.equal(window.caPublicKeySha256, observation.caPublicKeySha256);
  assert.equal(window.baselineRequestId, observation.baselineRequestId);
  assert.equal(window.lossFree, true);
  assert.equal(window.noPurgeProven, true);
  assert.equal(window.noRestoreProven, true);
  assert.equal(window.globalCount, 1, "Expected exactly one CA request in the complete isolated window");
  assert.equal(window.matchingIssuedCount, 1);
  assert.equal(window.unknownIssuedCount, 0);
  assert.equal(window.subjectRequestCount, 1);
  assert.equal(window.fingerprintSha256, fingerprintSha256);
  const requestId = String(window.requestId ?? "");
  assert.match(requestId, /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(requestId) > observation.baselineRequestId && Number(requestId) <= 2147483647);
  return window;
}

function validateCaBaselineWindow(window, observation) {
  assert.equal(window?.coverageComplete, true, "CA baseline checkpoint must prove complete coverage");
  assert.equal(window.observationId, observation.observationId);
  assert.equal(window.caPublicKeySha256, observation.caPublicKeySha256);
  assert.equal(window.baselineRequestId, observation.baselineRequestId);
  assert.equal(window.lossFree, true);
  assert.equal(window.noPurgeProven, true);
  assert.equal(window.noRestoreProven, true);
  assert.equal(window.globalCount, 0, "CA requests appeared before issuance");
  assert.equal(window.maxRequestId, observation.baselineRequestId);
}

async function verifyPreIssueCheckpoint(capture, observation, baseline) {
  const counts = validateNativeCounts(await capture.read(), baseline);
  for (const name of ["submissions", "keygens", "accepts"]) assert.equal(counts[name], 0, "Native operation occurred before issuance");
  validateCaBaselineWindow(await observation.readBaseline(), observation);
  return counts;
}
async function stopCaObservation(observation, lastWindow = null) {
  assert.equal(typeof observation?.stop, "function", "CA observation cannot be drained");
  const stopped = await observation.stop();
  assert.equal(stopped?.drained, true, "CA observation drainage was not proven");
  assert.equal(stopped.observationId, observation.observationId, "Drained CA observation identity changed");
  if (lastWindow) {
    validateCaObservationWindow(stopped.finalWindow, observation, lastWindow.fingerprintSha256);
    assert.equal(String(stopped.finalWindow.requestId), String(lastWindow.requestId), "CA request identity changed during drainage");
  }
  return stopped.finalWindow;
}

async function drainQualificationResources({ observer, caObservation, capture, lastWindow, lastCounts, primaryError }) {
  const failures = [];
  let finalCounts, finalWindow;
  try {
    if (observer) {
      await observer.stopAndDrain();
      if (observer.hasLiveChild()) throw new Error("Preserve native state: observer drainage was not proven");
    }
  } catch (error) {
    throw new AggregateError(primaryError ? [primaryError, error] : [error], "Native observer drainage failed; preserve live capture and CA observation for operator intervention");
  }
  try { if (capture) finalCounts = await stopNativeCapture(capture, lastCounts); }
  catch (error) {
    throw new AggregateError(primaryError ? [primaryError, error] : [error], "Native capture drainage failed; preserve live CA observation for operator intervention");
  }
  try { if (caObservation) finalWindow = await stopCaObservation(caObservation, lastWindow); }
  catch (error) { failures.push(error); }
  if (failures.length) throw new AggregateError(primaryError ? [primaryError, ...failures] : failures, "Qualification or observation drainage failed; preserve native state");
  return { finalCounts, finalWindow };
}
async function verifyRecoveryCheckpoint({ readNativeOperationCounts, readIndependentCaObservation, enrollmentId, jobId,
  containerName, dnsName, fingerprintSha256, beforeCounts, observation, lastWindow }) {
  assert.match(dnsName, /^certops-adcs-[a-f0-9]{16,32}-store\.example\.test$/);
  const counts = validateNativeCounts(await readNativeOperationCounts({ enrollmentId, jobId, containerName }), beforeCounts);
  for (const name of ["submissions", "keygens", "accepts"]) assert.equal(counts[name], beforeCounts[name], "Native operation occurred before recovery");
  const window = await readIndependentCaObservation({ dnsName, fingerprintSha256, observation });
  validateCaObservationWindow(window, observation, fingerprintSha256);
  assert.equal(String(window.requestId), String(lastWindow.requestId), "CA request identity changed before recovery");
  verifyNamedStoreIdentity(counts, { containerName, requestId: window.requestId });
  return { counts, window };
}
// A passive checkpoint cannot stop an already dispatched CA operation when an
// observer dies. The real loss-triggered service cancellation and drainage
// fixture is not implemented; no environment variable may bypass this gate.
// Before enabling it, independently prove the running service image and runtime
// match the hashed archive, including protected ACLs and parent reparse points,
// and prove the worker is quiescent before either observation is stopped.
function requireActiveObservationInterruption() {
  throw new Error("Native AD CS qualification is blocked: active observation-loss interruption is not implemented");
}
async function qualifyNativeStoreRecovery(context) {
  requireActiveObservationInterruption();
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(context.serviceOwned, true);
  const { fixture, api, agentRowId, issuerId, configDir, workDir, ps, until, jobFinished,
    prepareRun, createNativeOperationCapture, readNativeOperationCounts, createIndependentCaObservation,
    readIndependentCaObservation, expectedCaKeySha256, stopAndVerifyOwnedService, startAndVerifyObservedService } = context;
  for (const fn of [ps, until, jobFinished, prepareRun, createNativeOperationCapture, readNativeOperationCounts,
    createIndependentCaObservation, readIndependentCaObservation, stopAndVerifyOwnedService, startAndVerifyObservedService]) {
    assert.equal(typeof fn, "function", "Independent native and CA observation hooks are required");
  }
  const recordEvidence = createPublicEvidenceRecorder(context);
  const installedService = await verifyCandidateHost(context);
  let { observationRunId, serviceProcess } = installedService;
  assert.match(observationRunId, OBSERVATION_RUN_ID);
  const initialObservationRunId = observationRunId;
  const root = path.resolve(__dirname, "../../..");
  const receipt = path.join(workDir, "store-accept-target.json");
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  let observer, jobId, certificateId, enrollmentId, initial, recoveryJobId, beforeCounts, capture, caObservation, lastCounts, lastWindow, primaryError;
  let result, drained, serviceDrainageSha256;
  let stage = "initializing";
  try {
    result = await qualifyImmediateStoreRecovery({
      async inspectAndInterrupt({ dnsName }) {
        // Observe before preparation too: the injectable setup hook must not
        // generate a key or submit a CA request before our baseline.
        // Factories must not start processes or mutate the CA. Resources are
        // acquired by start only after their stop hooks are available.
        caObservation = await createIndependentCaObservation({ dnsName });
        assert.equal(typeof caObservation?.start, "function", "CA observation start is required");
        assert.equal(typeof caObservation.stop, "function", "CA observation stop is required");
        await caObservation.start();
        validateCaObservationStart(caObservation, expectedCaKeySha256);
        capture = await createNativeOperationCapture({ dnsName, agentRowId });
        assert.equal(typeof capture?.start, "function", "Native capture start is required");
        assert.equal(typeof capture.stop, "function", "Native capture stop is required");
        await capture.start();
        const baseline = validateCaptureStart(capture, context.candidateArchiveSha256, context.observationScope);
        await prepareRun({ dnsName, agentRowId, issuerId });
        lastCounts = await verifyPreIssueCheckpoint(capture, caObservation, baseline);
        stage = "baseline";
        await recordEvidence("baseline", { candidateSha256: context.candidateArchiveSha256, dnsName,
          captureId: capture.captureId, observationId: caObservation.observationId, observationRunId,
          caPublicKeySha256: caObservation.caPublicKeySha256, baselineRequestId: caObservation.baselineRequestId,
          submissions: 0, keygens: 0, accepts: 0, ...captureEvidenceDetails(lastCounts) });
        observer = startNativeStoreObserver({ workDir, configDir, root });
        await observer.ready;
        stage = "issuing";
        const created = await fixture.request(`${api}/jobs`, "POST", {
          operation: "issue", mode: "real", idempotencyKey: `native-store-${dnsName}`,
          assignedAgentId: agentRowId,
          payload: { issuerId, target: { type: "windows-cert-store", reference: dnsName, store: "My" }, automationEnabled: false },
        });
        assert.equal(created.status, 201);
        jobId = created.body.job.id;
        const rows = (await query(`SELECT j.enrollment_id,j.subject_id,e.snapshot_sha256 FROM certificate_jobs j
          JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=j.enrollment_id
          WHERE j.workspace_id=$1 AND j.id=$2`, [fixture.workspaceId, jobId])).rows;
        assert.equal(rows.length, 1); enrollmentId = rows[0].enrollment_id; certificateId = rows[0].subject_id;
        fs.writeFileSync(receipt, JSON.stringify({ enrollmentId, jobId, snapshotSha256: rows[0].snapshot_sha256,
          containerName: buildEnrollmentContainerName(enrollmentId), domain: dnsName }), { flag: "wx" });
        const fault = await observer.result;
        await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false);
        assert.equal(fault.enrollmentId, enrollmentId); assert.equal(fault.jobId, jobId);
        initial = readEnrollmentJournal(configDir, enrollmentId); assert.equal(initial.kind, "valid");
        beforeCounts = validateInitialNativeCounts(
          await readNativeOperationCounts({ enrollmentId, jobId, containerName: fault.containerName }), lastCounts);
        verifyNamedStoreIdentity(beforeCounts, { containerName: fault.containerName });
        lastCounts = beforeCounts;
        stage = "post-accept";
        await recordEvidence("post-accept", { candidateSha256: context.candidateArchiveSha256, dnsName, enrollmentId,
          jobId, fingerprintSha256: fault.fingerprintSha256, csrSpkiSha256: fault.csrSpkiSha256,
          captureId: capture.captureId, submissions: beforeCounts.submissions, keygens: beforeCounts.keygens,
          accepts: beforeCounts.accepts, ...captureEvidenceDetails(beforeCounts) });
        return fault;
      },
      async caObserver({ dnsName, fingerprintSha256 }) {
        const window = await readIndependentCaObservation({ dnsName, fingerprintSha256, observation: caObservation });
        validateCaObservationWindow(window, caObservation, fingerprintSha256);
        verifyNamedStoreIdentity(lastCounts, { requestId: window.requestId });
        if (lastWindow) assert.equal(String(window.requestId), String(lastWindow.requestId), "CA request identity changed");
        const phase = lastWindow ? "ca-after-recovery" : "ca-at-fault";
        stage = phase;
        await recordEvidence(phase, { candidateSha256: context.candidateArchiveSha256, dnsName,
          observationId: caObservation.observationId, caPublicKeySha256: caObservation.caPublicKeySha256,
          baselineRequestId: caObservation.baselineRequestId, requestId: String(window.requestId),
          serialNumber: window.serialNumber, fingerprintSha256 });
        lastWindow = window;
        return window;
      },
      async restartAndRecover({ dnsName, fault }) {
        const row = (await query("SELECT lease_expires_at,lease_renewed_at,NOW() AS measured_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0];
        assert.ok(row?.lease_renewed_at);
        const budget = recoveryWaitBudget(row.lease_expires_at, row.measured_at);
        const worker = await import(pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href);
        await until(async () => {
          const client = await fixture.pool.connect();
          try { await worker.reapExpiredLeases({ client, hardGraceMs: 60000, offlineAfterMs: 60000, log: { debug() {}, info() {}, warn() {}, error() {} } }); }
          finally { client.release(); }
          const rows = (await query("SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows;
          return rows[0]?.status === "orphaned_unknown_effect" && rows[0]?.needs_operator_reconciliation === true;
        }, budget.recoveryWaitBudgetMs);
        const checkpoint = async (phase, serviceDrainage = {}) => {
          const checked = await verifyRecoveryCheckpoint({ readNativeOperationCounts, readIndependentCaObservation,
            enrollmentId, jobId, containerName: fault.containerName, dnsName, fingerprintSha256: fault.fingerprintSha256,
            beforeCounts: lastCounts, observation: caObservation, lastWindow });
          lastCounts = checked.counts;
          stage = phase;
          await recordEvidence(phase, { candidateSha256: context.candidateArchiveSha256, dnsName, enrollmentId, jobId,
            captureId: capture.captureId, observationId: caObservation.observationId, observationRunId,
            fingerprintSha256: fault.fingerprintSha256, requestId: String(checked.window.requestId),
            submissions: checked.counts.submissions, keygens: checked.counts.keygens, accepts: checked.counts.accepts,
            ...captureEvidenceDetails(checked.counts), ...serviceDrainage });
        };
        await checkpoint("before-recovery-post");
        const recovery = await fixture.request(`${api}/enrollments/${enrollmentId}/recover`, "POST", { orphanedJobId: jobId,
          acknowledgeUnknownEffect: true, reason: "Native store certificate and key independently inspected after service interruption" });
        assert.equal(recovery.status, 201); recoveryJobId = recovery.body.jobId;
        const serviceDrainageSha256 = await verifyOwnedServiceDrainage({
          stopAndVerifyOwnedService, candidateArchiveSha256: context.candidateArchiveSha256,
          captureId: capture.captureId, serviceProcess,
        });
        await checkpoint("before-service-start", { serviceDrainageSha256 });
        const restarted = await startObservedStoreService(context, capture.captureId, observationRunId, serviceProcess);
        serviceProcess = restarted.process;
        observationRunId = restarted.observationRunId;
        await recordEvidence("service-restarted", {
          candidateSha256: context.candidateArchiveSha256, dnsName, captureId: capture.captureId,
          observationId: caObservation.observationId, observationRunId, serviceStartSha256: restarted.serviceStartSha256,
        });
        await jobFinished(recoveryJobId);
        const final = readEnrollmentJournal(configDir, enrollmentId); assert.equal(final.kind, "valid"); assert.equal(final.journal.state, "installed");
        for (const name of ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "leafSha256"]) assert.equal(final.journal[name], initial.journal[name]);
        assert.equal(final.artifacts.leafPem, initial.artifacts.leafPem); assert.equal(final.artifacts.csrPem, initial.artifacts.csrPem);
        const native = await inspectStoreOnlyCertificate({ certificatePem: final.artifacts.leafPem, containerName: final.journal.containerName });
        assert.equal(native.status, "complete"); assert.equal(native.fingerprintSha256, fault.fingerprintSha256);
        const after = validateNativeCounts(
          await readNativeOperationCounts({ enrollmentId, jobId, containerName: fault.containerName }), lastCounts);
        verifyNamedStoreIdentity(after, { containerName: fault.containerName, requestId: lastWindow.requestId });
        lastCounts = after;
        return { containerName: final.journal.containerName, fingerprintSha256: fault.fingerprintSha256,
          csrSpkiSha256: final.journal.csrSpkiSha256, newSubmissions: after.submissions - beforeCounts.submissions,
          newKeys: after.keygens - beforeCounts.keygens, repeatedAccepts: after.accepts - beforeCounts.accepts };
      },
      async readInventory({ fault }) {
        const rows = (await query("SELECT status,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, certificateId])).rows;
        const issued = (await query("SELECT id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_ISSUED' AND metadata->>'managedCertificateId'=$2", [fixture.workspaceId, certificateId])).rows;
        const service = (await query("SELECT id FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='validation.passed' AND metadata->>'step'='verify'", [fixture.workspaceId, recoveryJobId])).rows;
        assert.equal(rows.length, 1); assert.equal(rows[0].status, "active");
        assert.equal(rows[0].fingerprint_sha256, fault.fingerprintSha256);
        stage = "inventory";
        await recordEvidence("inventory", { candidateSha256: context.candidateArchiveSha256, enrollmentId, jobId,
          fingerprintSha256: fault.fingerprintSha256, promotions: issued.length });
        return { provisioningRegistrations: rows.length, promotions: issued.length, fingerprintSha256: rows[0].fingerprint_sha256, serviceVerified: service.length > 0 };
      },
    });
  } catch (error) {
    primaryError = error;
    try {
      await recordEvidence("failure", { candidateSha256: context.candidateArchiveSha256, stage, code: "QUALIFICATION_FAILED" });
    } catch (evidenceError) {
      primaryError = new AggregateError([error, evidenceError], "Qualification failed and public failure evidence was not durable");
    }
    throw primaryError;
  } finally {
    try {
      if (capture || caObservation) {
        serviceDrainageSha256 = await verifyOwnedServiceDrainage({
          stopAndVerifyOwnedService, candidateArchiveSha256: context.candidateArchiveSha256,
          captureId: capture?.captureId ?? null, serviceProcess,
        });
      }
      drained = await drainQualificationResources({ observer, caObservation, capture, lastWindow, lastCounts, primaryError });
    } catch (drainError) {
      try {
        await recordEvidence("failure", { candidateSha256: context.candidateArchiveSha256, stage: "drainage", code: "QUALIFICATION_FAILED" });
      } catch (evidenceError) {
        throw new AggregateError([drainError, evidenceError], "Drainage failed and public failure evidence was not durable");
      }
      throw drainError;
    }
    // Keep the owned target receipt for evidence; a later run needs a fresh directory.
  }
  const captureId = capture.captureId;
  const observationId = caObservation.observationId;
  const observationDetails = captureEvidenceDetails(drained.finalCounts);
  const evidence = await recordEvidence("observations-drained", {
    candidateSha256: context.candidateArchiveSha256, dnsName: result.dnsName,
    captureId, observationId, initialObservationRunId, observationRunId,
    submissions: drained.finalCounts.submissions, keygens: drained.finalCounts.keygens, accepts: drained.finalCounts.accepts,
    ...observationDetails, serviceDrainageSha256,
    requestId: String(drained.finalWindow.requestId), fingerprintSha256: drained.finalWindow.fingerprintSha256,
  });
  return { ...result, candidateArchiveSha256: context.candidateArchiveSha256, captureId, observationId,
    initialObservationRunId, observationRunId, ...observationDetails, serviceDrainageSha256,
    evidenceReceiptId: evidence.receiptId, evidenceReceiptSha256: evidence.sha256 };
}

function validateSeparateStoreRecoveryEvidence(postAccept, pending, candidateArchiveSha256) {
  assert.match(candidateArchiveSha256, /^[a-f0-9]{64}$/);
  for (const evidence of [postAccept, pending]) {
    assert.equal(evidence.candidateArchiveSha256, candidateArchiveSha256, "Recovery evidence belongs to a different signed package");
    assert.match(evidence.dnsName, /^certops-adcs-[a-f0-9]{16,32}-store\.example\.test$/);
    assert.match(evidence.captureId, OBSERVATION_RUN_ID);
    assert.match(evidence.observationId, OBSERVATION_RUN_ID);
    assert.match(evidence.initialObservationRunId, OBSERVATION_RUN_ID);
    assert.match(evidence.observationRunId, OBSERVATION_RUN_ID);
    assert.match(evidence.evidenceReceiptId, /^[a-f0-9]{32,64}$/);
    assert.match(evidence.evidenceReceiptSha256, /^[a-f0-9]{64}$/);
  }
  for (const field of ["dnsName", "captureId", "observationId", "evidenceReceiptId", "evidenceReceiptSha256"]) {
    assert.notEqual(postAccept[field], pending[field], `Recovery scenarios reused ${field}`);
  }
  const runIds = new Set([postAccept.initialObservationRunId, postAccept.observationRunId,
    pending.initialObservationRunId, pending.observationRunId]);
  assert.equal(runIds.size, 4, "Each recovery stage requires a fresh observation run");
}

async function qualifyInstalledStoreRecovery(context) {
  requireActiveObservationInterruption();
  assert.equal(typeof context.createPendingRecoveryContext, "function", "A fresh owned pending-run context is required");
  const postAccept = await qualifyNativeStoreRecovery(context);
  const { qualifyPendingStoreRecovery } = require("./certops-adcs-store-pending-native");
  // Post-accept qualification leaves its owned service stopped. The pending
  // scenario needs its own armed observation and freshly started service.
  const pendingContext = await context.createPendingRecoveryContext();
  assert.notEqual(pendingContext, context, "Pending recovery must use a fresh lab context");
  assert.equal(pendingContext.candidateArchiveSha256, context.candidateArchiveSha256);
  assert.equal(pendingContext.expectedRuntimeSha256, context.expectedRuntimeSha256);
  assert.equal(pendingContext.observationScope, context.observationScope);
  const pending = await qualifyPendingStoreRecovery(pendingContext);
  validateSeparateStoreRecoveryEvidence(postAccept, pending, context.candidateArchiveSha256);
  return { postAccept, pending };
}

module.exports = { qualifyInstalledStoreRecovery, qualifyNativeStoreRecovery, validateSeparateStoreRecoveryEvidence, captureEvidenceDetails, validateNativeCounts, validateInitialNativeCounts, validateCaptureStart, stopNativeCapture, validateCaObservationStart, validateCaObservationWindow, stopCaObservation, drainQualificationResources, verifyRecoveryCheckpoint, validateCaBaselineWindow, verifyPreIssueCheckpoint, createPublicEvidenceRecorder, verifyCandidateHost, requireActiveObservationInterruption, readStoreServiceProcess, requireStoreServiceProcess, verifyOwnedServiceDrainage, validateObservedServiceStart, startObservedStoreService, OBSERVATION_RUN_ID };
