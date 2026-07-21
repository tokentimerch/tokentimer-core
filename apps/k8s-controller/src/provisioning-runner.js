"use strict";

const {
  isTransientError,
  isTransientStatus,
  retryDelay,
} = require("./observation-reporter");

const MAX_RECONCILE_ATTEMPTS = 4;

function errorStatus(error) {
  const visited = new Set();
  let current = error;
  for (let depth = 0; current && depth < 4 && !visited.has(current); depth += 1) {
    visited.add(current);
    for (const value of [
      current.code,
      current.statusCode,
      current.status,
      current.response?.statusCode,
      current.response?.status,
    ]) {
      const status = Number(value);
      if (Number.isInteger(status) && status >= 100 && status <= 599) return status;
    }
    current = current.cause;
  }
  return null;
}

function isTransientReconciliationError(error) {
  const status = errorStatus(error);
  return isTransientError(error) || (status !== null && isTransientStatus(status));
}

function createProvisioningRunner({
  commandClient,
  provisioner,
  intervalMs = 30_000,
  maxReconcileAttempts = MAX_RECONCILE_ATTEMPTS,
  random = Math.random,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  logger,
} = {}) {
  if (!commandClient || !provisioner) throw new TypeError("A command client and provisioner are required");
  if (!Number.isInteger(maxReconcileAttempts) || maxReconcileAttempts < 1 || maxReconcileAttempts > MAX_RECONCILE_ATTEMPTS) {
    throw new TypeError(`maxReconcileAttempts must be between 1 and ${MAX_RECONCILE_ATTEMPTS}`);
  }
  let acceptingWork = false;
  let started = false;
  let timer = null;
  let trackWork = null;
  let activeCommand = null;
  const retryWaits = new Set();

  function sleepBeforeRetry(delay) {
    return new Promise((resolve) => {
      const wait = {
        timer: null,
        resolve: () => {
          retryWaits.delete(wait);
          resolve();
        },
      };
      wait.timer = setTimeoutFn(wait.resolve, delay);
      retryWaits.add(wait);
    });
  }

  function cancelRetryWaits() {
    for (const wait of retryWaits) {
      clearTimeoutFn(wait.timer);
      wait.resolve();
    }
  }

  async function reconcileWithRetry(command) {
    let lastError;
    for (let attempt = 0; attempt < maxReconcileAttempts; attempt += 1) {
      try {
        return await provisioner.reconcile(command);
      } catch (error) {
        lastError = error;
        if (!isTransientReconciliationError(error)) throw error;
        if (!acceptingWork || attempt === maxReconcileAttempts - 1) break;
        await sleepBeforeRetry(retryDelay(attempt, random));
        if (!acceptingWork) break;
      }
    }
    throw lastError;
  }

  function safeEvidence(command, result) {
    return {
      schemaVersion: 1,
      evidenceId: `${command.jobId.replace(/-/g, "")}-provisioned`,
      eventType: "deployment.updated",
      source: "executor",
      status: "accepted",
      summary: `cert-manager Certificate ${result.operation}`,
      metadata: [
        { name: "clusterId", value: command.clusterId },
        { name: "namespace", value: command.namespace },
        { name: "certificateName", value: command.certificateName },
        { name: "secretName", value: command.secretName },
        { name: "managedCertificateId", value: command.managedCertificateId },
        { name: "operation", value: result.operation },
      ],
    };
  }
  async function execute(command) {
    // Do not write before the server has accepted the deterministic started
    // event. A failed start report leaves the command safely redeliverable.
    await commandClient.reportEvent(command, "started", { status: "running", eventType: "job.started", message: "Reconciling cert-manager Certificate" });
    let result;
    try {
      result = await reconcileWithRetry(command);
    } catch (error) {
      // Transient Kubernetes/network failures leave the running job available
      // for bounded server redelivery. Permanent policy/ownership failures are
      // authoritative terminal outcomes.
      if (!isTransientReconciliationError(error)) {
        try {
          await commandClient.reportEvent(command, "failed", {
            status: "failed", eventType: "job.failed", message: String(error?.code || "CERTOPS_PROVISIONING_FAILED"),
          });
        } catch (_) { /* The original reconciliation failure remains authoritative. */ }
      }
      throw error;
    }
    try {
      await commandClient.reportEvent(command, "completed", {
        status: "succeeded", eventType: "job.completed", message: "cert-manager Certificate reconciled",
        evidence: safeEvidence(command, result),
      });
      return result;
    } catch (error) {
      // The Kubernetes side effect succeeded. Do not convert it into a failed
      // job when the completion report is unavailable; delivery will retry.
      logger?.error?.("controller-provisioning-completion-report-failed", {
        code: error?.code || "CERTOPS_PROVISIONING_COMPLETION_REPORT_FAILED",
      });
      return { ...result, completionReportFailed: true };
    }
  }
  async function poll() {
    if (!acceptingWork || activeCommand) return;
    try {
      const command = await commandClient.nextCommand();
      if (command && acceptingWork) {
        const work = execute(command);
        const tracked = trackWork ? trackWork(work) : work;
        activeCommand = tracked;
        try {
          await tracked;
        } catch (error) {
          logger?.error?.("controller-provisioning-failed", {
            code: error?.code || "CERTOPS_PROVISIONING_FAILED",
          });
        } finally {
          activeCommand = null;
        }
      }
    } catch (error) {
      logger?.error?.("controller-provisioning-poll-failed", { code: error?.code || "CERTOPS_PROVISIONING_POLL_FAILED" });
    } finally {
      if (acceptingWork) timer = setTimeoutFn(() => { void poll(); }, intervalMs);
    }
  }
  return Object.freeze({
    async close() { acceptingWork = false; if (timer !== null) clearTimeoutFn(timer); cancelRetryWaits(); await commandClient.close(); await provisioner.close?.(); },
    isAlive: () => true,
    isReady: () => started && acceptingWork && commandClient.isReady() && provisioner.isReady(),
    async start({ trackWork: suppliedTrackWork } = {}) {
      await commandClient.start();
      trackWork = suppliedTrackWork || null;
      acceptingWork = true;
      started = true;
      void poll();
    },
    async stopAcceptingWork() { acceptingWork = false; if (timer !== null) clearTimeoutFn(timer); cancelRetryWaits(); await commandClient.stopAcceptingWork(); await provisioner.stopAcceptingWork?.(); },
  });
}

module.exports = {
  MAX_RECONCILE_ATTEMPTS,
  createProvisioningRunner,
  errorStatus,
  isTransientReconciliationError,
};
