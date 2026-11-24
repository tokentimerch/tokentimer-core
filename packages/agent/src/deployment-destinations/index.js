"use strict";

const { addAbortListener } = require("node:events");
const { containsPrivateKeyMaterial, redactGenericSecrets } = require("../evidence");
const {
  hashDeploymentDestinationValidation,
} = require("../../vendor/contracts/deployment-destination.cjs");
const {
  validateJob,
  validateObservation,
} = require("../../vendor/contracts/deployment-destination-validator.generated.js");

const VALIDATION_TIMEOUT_MS = 30_000;

function registerDeploymentDestinations(adapters) {
  const validators = new Map();
  for (const { version, destinationKind, validate } of adapters) {
    if (version !== 1 || typeof destinationKind !== "string" ||
        !/^[a-z][a-z0-9-]{0,63}$/.test(destinationKind) ||
        typeof validate !== "function" || validators.has(destinationKind)) {
      throw new Error("Invalid deployment destination adapter registration");
    }
    validators.set(destinationKind, validate);
  }
  return Object.freeze({
    hasValidators: validators.size > 0,
    resolveValidator: (kind) => validators.get(kind),
  });
}

function waitForValidation(work, signal) {
  signal.throwIfAborted();
  let listener;
  const cancelled = new Promise((_resolve, reject) => {
    listener = addAbortListener(signal, () => reject(signal.reason));
  });
  return Promise.race([Promise.resolve().then(work), cancelled])
    .finally(() => listener[Symbol.dispose]());
}

function isDeploymentDestinationValidationJob(job) {
  return validateJob(job) && job.claimId === job.attemptId;
}

async function validateDeploymentDestination({ job, jobId, claimId, attemptId, registry, signal, checkLease, clockOffsetMs }) {
  if (!isDeploymentDestinationValidationJob(job) || job.jobId !== jobId ||
      job.claimId !== claimId || job.attemptId !== attemptId) {
    return { status: "blocked", errorMessage: "destination_validation_scope_invalid" };
  }

  const validate = registry?.resolveValidator(job.deploymentDestination.destinationKind);
  if (!validate) return { status: "blocked", errorMessage: "destination_adapter_unavailable" };

  const remaining = Math.floor(Date.parse(job.expiresAt) - (Date.now() + (clockOffsetMs ?? 0)));
  if (!(remaining > 0)) return { status: "blocked", errorMessage: "destination_validation_expired" };

  const timeout = AbortSignal.timeout(Math.min(remaining, VALIDATION_TIMEOUT_MS));
  const validationSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const scope = Object.freeze({
    ...job.deploymentDestination,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
  });

  const assertLease = async () => {
    validationSignal.throwIfAborted();
    await checkLease();
    validationSignal.throwIfAborted();
  };

  try {
    const receipt = await waitForValidation(async () => {
      await assertLease();
      const observed = await validate({ scope, jobId, signal: validationSignal, checkLease: assertLease });
      const validation = structuredClone(observed);
      if (!validateObservation(validation) || containsPrivateKeyMaterial(validation) ||
          JSON.stringify(redactGenericSecrets(validation)) !== JSON.stringify(validation)) return null;
      await assertLease();
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

module.exports = { isDeploymentDestinationValidationJob, registerDeploymentDestinations, validateDeploymentDestination };
