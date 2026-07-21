"use strict";

function createProvisioningRunner({ commandClient, provisioner, intervalMs = 30_000, setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout, logger } = {}) {
  if (!commandClient || !provisioner) throw new TypeError("A command client and provisioner are required");
  let acceptingWork = false;
  let started = false;
  let timer = null;
  let trackWork = null;

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
    await commandClient.reportEvent(command, "started", { status: "running", eventType: "job.started", message: "Reconciling cert-manager Certificate" });
    try {
      const result = await provisioner.reconcile(command);
      await commandClient.reportEvent(command, "completed", {
        status: "succeeded", eventType: "job.completed", message: "cert-manager Certificate reconciled",
        evidence: safeEvidence(command, result),
      });
      return result;
    } catch (error) {
      try {
        await commandClient.reportEvent(command, "failed", {
          status: "failed", eventType: "job.failed", message: error?.code || "CERTOPS_PROVISIONING_FAILED",
        });
      } catch (_) { /* The original reconcile failure remains authoritative. */ }
      throw error;
    }
  }
  async function poll() {
    if (!acceptingWork) return;
    try {
      const command = await commandClient.nextCommand();
      if (command && acceptingWork) {
        const work = execute(command).catch((error) => {
          logger?.error?.("controller-provisioning-failed", { code: error?.code || "CERTOPS_PROVISIONING_FAILED" });
        });
        if (trackWork) trackWork(work);
      }
    } catch (error) {
      logger?.error?.("controller-provisioning-poll-failed", { code: error?.code || "CERTOPS_PROVISIONING_POLL_FAILED" });
    } finally {
      if (acceptingWork) timer = setTimeoutFn(() => { void poll(); }, intervalMs);
    }
  }
  return Object.freeze({
    async close() { acceptingWork = false; if (timer !== null) clearTimeoutFn(timer); await commandClient.close(); await provisioner.close?.(); },
    isAlive: () => true,
    isReady: () => started && acceptingWork && commandClient.isReady() && provisioner.isReady(),
    async start({ trackWork: suppliedTrackWork } = {}) {
      await commandClient.start();
      trackWork = suppliedTrackWork || null;
      acceptingWork = true;
      started = true;
      void poll();
    },
    async stopAcceptingWork() { acceptingWork = false; if (timer !== null) clearTimeoutFn(timer); await commandClient.stopAcceptingWork(); await provisioner.stopAcceptingWork?.(); },
  });
}

module.exports = { createProvisioningRunner };
