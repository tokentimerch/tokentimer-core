"use strict";

const { addAbortListener } = require("node:events");
const { containsPrivateKeyMaterial, redactGenericSecrets } = require("../evidence");
const {
  VALIDATE_DEPLOYMENT_DESTINATION,
  EXECUTE_DEPLOYMENT_DESTINATION,
  OBSERVE_DEPLOYMENT_DESTINATION,
  hashDeploymentDestinationObservation,
  hashDeploymentDestinationValidation,
  hasMatchingDeploymentDestinationReceipt,
  hasMatchingDeploymentDestinationOperation,
} = require("../../vendor/contracts/deployment-destination.cjs");
const {
  validateJob,
  validateObservation,
  validateHistoricalObservation,
} = require("../../vendor/contracts/deployment-destination-validator.generated.js");

const { canonicalizeJobPayload } = require("../../vendor/contracts/canonical-json.cjs");
const { holdDestinationOwnership, hasDestinationOwnership } = require("./ownership");

const PREFLIGHT_TIMEOUT_MS = 30_000;
const READ_LEASE_REUSE_MS = 1000;

// Read-only adapter checks may share a recent controller confirmation. The
// runner still requests fresh authority at preflight boundaries. A lost
// refresh stays closed for the rest of this attempt.
function createReadLeaseChecks(signal, renewLease, clockOffsetMs) {
  let pending;
  let confirmedAt = -Infinity;
  let confirmedExpiry = 0;
  let lost = false;

  function assertCurrent() {
    signal.throwIfAborted();
    if (lost || confirmedExpiry <= Date.now() + (clockOffsetMs ?? 0)) {
      throw new Error("destination_job_lease_unavailable");
    }
  }

  async function refresh() {
    signal.throwIfAborted();
    if (lost) throw new Error("destination_job_lease_unavailable");
    if (!pending) {
      const startedAt = performance.now();
      pending = Promise.resolve().then(renewLease).then((expiry) => {
        if (!Number.isFinite(expiry)) throw new Error("destination_job_lease_unavailable");
        confirmedExpiry = expiry;
        confirmedAt = startedAt;
      }).catch((error) => {
        lost = true;
        throw error;
      }).finally(() => { pending = undefined; });
    }
    await pending;
    assertCurrent();
  }

  async function check() {
    if (pending || performance.now() - confirmedAt >= READ_LEASE_REUSE_MS ||
        confirmedExpiry <= Date.now() + (clockOffsetMs ?? 0)) await refresh();
    else assertCurrent();
  }

  return { check, refresh };
}

function registerDeploymentDestinations(adapters) {
  const validators = new Map();
  const executionPreparers = new Map();
  const observers = new Map();
  for (const adapter of adapters) {
    const { version, destinationKind, validate, authorizeExecution, prepareExecution, authorizeObservation, observe } = adapter;
    if (version !== 1 || typeof destinationKind !== "string" ||
        !/^[a-z][a-z0-9-]{0,63}$/.test(destinationKind) ||
        typeof validate !== "function" || validators.has(destinationKind)) {
      throw new Error("Invalid deployment destination adapter registration");
    }
    validators.set(destinationKind, validate);
    if (authorizeExecution !== undefined || prepareExecution !== undefined) {
      if (typeof authorizeExecution !== "function" || typeof prepareExecution !== "function") {
        throw new Error("Deployment destination execution preparation requires local authorization");
      }
      executionPreparers.set(destinationKind, Object.freeze({ authorizeExecution, prepareExecution }));
    }
    if (authorizeObservation !== undefined || observe !== undefined) {
      if (typeof authorizeObservation !== "function" || typeof observe !== "function") {
        throw new Error("Deployment destination observation requires independent local authorization");
      }
      observers.set(destinationKind, Object.freeze({ authorizeObservation, observe }));
    }
  }
  return Object.freeze({
    hasValidators: validators.size > 0,
    hasObservers: observers.size > 0,
    resolveValidator: (kind) => validators.get(kind),
    resolveExecutionPreparer: (kind) => executionPreparers.get(kind),
    resolveObserver: (kind) => observers.get(kind),
  });
}

function waitForDestinationWork(work, signal) {
  signal.throwIfAborted();
  let listener;
  const cancelled = new Promise((_resolve, reject) => {
    listener = addAbortListener(signal, () => reject(signal.reason));
  });
  return Promise.race([Promise.resolve().then(work), cancelled])
    .finally(() => listener[Symbol.dispose]());
}

function isDeploymentDestinationValidationJob(job) {
  return job?.action === VALIDATE_DEPLOYMENT_DESTINATION &&
    validateJob(job) && job.claimId === job.attemptId;
}

function isDeploymentDestinationExecutionJob(job) {
  return job?.action === EXECUTE_DEPLOYMENT_DESTINATION &&
    validateJob(job) && job.claimId === job.attemptId && hasMatchingDeploymentDestinationReceipt(job) &&
    (!Object.hasOwn(job, "deploymentDestinationOperation") || hasMatchingDeploymentDestinationOperation(job));
}

function isDeploymentDestinationObservationJob(job) {
  if (job?.action !== OBSERVE_DEPLOYMENT_DESTINATION || !validateJob(job) || job.claimId !== job.attemptId) return false;
  const { ownerJobId, ownerClaimId, validationJobId } = job.deploymentDestinationObservation;
  return ownerJobId !== job.jobId && ownerClaimId !== job.claimId &&
    validationJobId !== job.jobId && validationJobId !== ownerJobId;
}

function clonePublicFacts(observed, validate) {
  const facts = structuredClone(observed);
  if (!validate(facts) || containsPrivateKeyMaterial(facts) ||
      JSON.stringify(redactGenericSecrets(facts)) !== JSON.stringify(facts)) return null;
  return facts;
}

function destinationScope(job) {
  return Object.freeze({
    ...job.deploymentDestination,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
  });
}

function destinationLifetime(job, signal, clockOffsetMs) {
  const remaining = Math.floor(Date.parse(job.expiresAt) - (Date.now() + (clockOffsetMs ?? 0)));
  if (!(remaining > 0)) return null;

  const timeout = AbortSignal.timeout(Math.min(remaining, PREFLIGHT_TIMEOUT_MS));
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

async function validateDeploymentDestination({ job, jobId, claimId, attemptId, registry, signal, checkLease, clockOffsetMs }) {
  if (!isDeploymentDestinationValidationJob(job) || job.jobId !== jobId ||
      job.claimId !== claimId || job.attemptId !== attemptId) {
    return { status: "blocked", errorMessage: "destination_validation_scope_invalid" };
  }

  const validate = registry?.resolveValidator(job.deploymentDestination.destinationKind);
  if (!validate) return { status: "blocked", errorMessage: "destination_adapter_unavailable" };

  const validationSignal = destinationLifetime(job, signal, clockOffsetMs);
  if (!validationSignal) return { status: "blocked", errorMessage: "destination_validation_expired" };
  const scope = destinationScope(job);

  const lease = createReadLeaseChecks(validationSignal, checkLease, clockOffsetMs);

  try {
    const receipt = await waitForDestinationWork(async () => {
      await lease.refresh();
      const observed = await validate({ scope, jobId, signal: validationSignal, checkLease: lease.check });
      const validation = clonePublicFacts(observed, validateObservation);
      if (!validation) return null;
      await lease.refresh();
      return {
        version: 1,
        validation,
        bindingSha256: hashDeploymentDestinationValidation(job, validation),
      };
    }, validationSignal);
    if (!receipt) return { status: "blocked", errorMessage: "destination_validation_evidence_invalid" };
    return { status: "succeeded", deploymentDestinationValidation: receipt };
  } catch {
    return {
      status: "blocked",
      errorMessage: validationSignal.aborted ? "destination_validation_aborted" : "destination_validation_failed",
    };
  }
}

async function preflightDeploymentDestinationExecution({
  job, jobId, claimId, attemptId, registry, signal, checkLease, clockOffsetMs, dryRun, stateDir,
}) {
  if (!isDeploymentDestinationExecutionJob(job) || job.jobId !== jobId ||
      job.claimId !== claimId || job.attemptId !== attemptId) {
    return { status: "blocked", errorMessage: "destination_execution_scope_invalid" };
  }
  if (dryRun !== false) return { status: "blocked", errorMessage: "destination_execution_local_dry_run" };

  const adapter = registry?.resolveExecutionPreparer(job.deploymentDestination.destinationKind);
  if (!adapter) return { status: "blocked", errorMessage: "destination_execution_adapter_unavailable" };
  const executionSignal = destinationLifetime(job, signal, clockOffsetMs);
  if (!executionSignal) return { status: "blocked", errorMessage: "destination_execution_expired" };

  const lease = createReadLeaseChecks(executionSignal, checkLease, clockOffsetMs);

  try {
    return await waitForDestinationWork(async () => {
      const { validationJobId, validationClaimId, receipt } = job.deploymentDestinationExecution;
      const validation = clonePublicFacts(receipt.validation, validateObservation);
      if (!validation) return { status: "blocked", errorMessage: "destination_execution_evidence_invalid" };
      Object.freeze(validation.affectedServiceRefs);
      Object.freeze(validation.permittedEffects);
      const request = Object.freeze({
        scope: destinationScope(job), jobId, validationJobId, validationClaimId,
        validation: Object.freeze(validation), signal: executionSignal, checkLease: lease.check,
      });
      await lease.refresh();
      if (await adapter.authorizeExecution(request) !== true) {
        return { status: "blocked", errorMessage: "destination_execution_local_authorization_required" };
      }
      await lease.refresh();
      const prepared = await adapter.prepareExecution(request);
      const observed = clonePublicFacts(prepared?.validation, validateObservation);
      if (!observed || canonicalizeJobPayload(observed) !== canonicalizeJobPayload(validation)) {
        return { status: "blocked", errorMessage: "destination_execution_validation_changed" };
      }
      const operation = job.deploymentDestinationOperation;
      if (operation && prepared?.mutationDomainSha256 !== operation.mutationDomainSha256) {
        return { status: "blocked", errorMessage: "destination_execution_ownership_domain_mismatch" };
      }
      await lease.refresh();
      if (!operation) return { status: "blocked", errorMessage: "destination_execution_protection_unavailable" };

      // No mutator is invoked and ownership is never released by this slice.
      // Keep the hold independent from the job journal and result outbox.
      let held;
      try {
        held = holdDestinationOwnership({ stateDir, workspaceId: job.workspaceId, jobId, operation });
      } catch {
        return { status: "blocked", errorMessage: "destination_execution_ownership_unavailable" };
      }
      return {
        status: "blocked",
        errorMessage: held ? "destination_execution_ownership_held" : "destination_execution_ownership_conflict",
      };
    }, executionSignal);
  } catch {
    return {
      status: "blocked",
      errorMessage: executionSignal.aborted ? "destination_execution_aborted" : "destination_execution_preflight_failed",
    };
  }
}

async function observeDeploymentDestination({
  job, jobId, claimId, attemptId, registry, signal, checkLease, clockOffsetMs, stateDir,
}) {
  if (!isDeploymentDestinationObservationJob(job) || job.jobId !== jobId ||
      job.claimId !== claimId || job.attemptId !== attemptId) {
    return { status: "blocked", errorMessage: "destination_observation_scope_invalid" };
  }

  const history = job.deploymentDestinationObservation;
  const adapter = registry?.resolveObserver(history.destinationKind);
  if (!adapter) return { status: "blocked", errorMessage: "destination_observation_adapter_unavailable" };

  const observationSignal = destinationLifetime(job, signal, clockOffsetMs);
  if (!observationSignal) return { status: "blocked", errorMessage: "destination_observation_expired" };

  const lease = createReadLeaseChecks(observationSignal, checkLease, clockOffsetMs);
  const scope = Object.freeze({ ...history, workspaceId: job.workspaceId, agentId: job.agentId });
  const request = Object.freeze({ scope, jobId, signal: observationSignal, checkLease: lease.check });
  // The authorizer resolves the writer domain from current local policy; it
  // cannot inadvertently copy the dispatched digest from this request.
  const { mutationDomainSha256, ...locator } = scope;
  const authorityRequest = Object.freeze({ ...request, scope: Object.freeze(locator) });
  const ownership = { stateDir, workspaceId: job.workspaceId, observation: history };

  const blockedOwnership = { status: "blocked", errorMessage: "destination_observation_ownership_unavailable" };
  const blockedAuthority = { status: "blocked", errorMessage: "destination_observation_local_authorization_required" };

  try {
    return await waitForDestinationWork(async () => {
      if (!hasDestinationOwnership(ownership)) return blockedOwnership;
      await lease.refresh();
      if (await adapter.authorizeObservation(authorityRequest) !== mutationDomainSha256) return blockedAuthority;
      await lease.refresh();
      if (!hasDestinationOwnership(ownership)) return blockedOwnership;

      const observation = clonePublicFacts(await adapter.observe(request), validateHistoricalObservation);
      if (!observation) return { status: "blocked", errorMessage: "destination_observation_evidence_invalid" };

      await lease.refresh();
      if (await adapter.authorizeObservation(authorityRequest) !== mutationDomainSha256) return blockedAuthority;
      await lease.refresh();
      if (!hasDestinationOwnership(ownership)) return blockedOwnership;

      return {
        status: "succeeded",
        deploymentDestinationObservationReceipt: {
          version: 1,
          observation,
          bindingSha256: hashDeploymentDestinationObservation(job, observation),
        },
      };
    }, observationSignal);
  } catch {
    return {
      status: "blocked",
      errorMessage: observationSignal.aborted ? "destination_observation_aborted" : "destination_observation_failed",
    };
  }
}

module.exports = {
  isDeploymentDestinationObservationJob,
  observeDeploymentDestination,
  isDeploymentDestinationValidationJob,
  isDeploymentDestinationExecutionJob,
  preflightDeploymentDestinationExecution,
  registerDeploymentDestinations,
  validateDeploymentDestination,
};
