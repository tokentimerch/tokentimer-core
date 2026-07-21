"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { createProvisioningRunner } = require("../../apps/k8s-controller/src/provisioning-runner");

const command = Object.freeze({
  schemaVersion: 1,
  workspaceId: "00000000-0000-4000-8000-000000000001",
  clusterId: "cluster-a",
  jobId: "00000000-0000-4000-8000-000000000002",
  managedCertificateId: "00000000-0000-4000-8000-000000000003",
  namespace: "team-a",
  certificateName: "web-cert",
  secretName: "web-tls",
  issuerRef: { group: "cert-manager.io", kind: "ClusterIssuer", name: "issuer-a" },
  dnsNames: ["example.test"],
  eventTimestamps: {},
});

async function eventually(assertion, attempts = 50) {
  let lastError;
  for (let index = 0; index < attempts; index += 1) {
    try { return assertion(); } catch (error) { lastError = error; }
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw lastError;
}

function runnerFixture({ nextCommand, reportEvent, reconcile, timers = [] }) {
  const commandClient = {
    nextCommand,
    reportEvent,
    start: async () => {},
    close: async () => {},
    stopAcceptingWork: async () => {},
    isReady: () => true,
  };
  const provisioner = {
    reconcile,
    close: async () => {},
    stopAcceptingWork: async () => {},
    isReady: () => true,
  };
  return createProvisioningRunner({
    commandClient,
    provisioner,
    intervalMs: 1,
    setTimeoutFn: (callback) => { timers.push(callback); return timers.length; },
    clearTimeoutFn: () => {},
  });
}

describe("controller provisioning runner", () => {
  it("does not reconcile when the deterministic started event is rejected", async () => {
    let reconciled = 0;
    const stages = [];
    const runner = runnerFixture({
      nextCommand: async () => command,
      reportEvent: async (_command, stage) => {
        stages.push(stage);
        if (stage === "started") throw Object.assign(new Error("unavailable"), { code: "REPORT_UNAVAILABLE" });
      },
      reconcile: async () => { reconciled += 1; },
    });
    await runner.start({ trackWork: (work) => work });
    await eventually(() => assert.deepEqual(stages, ["started"]));
    assert.equal(reconciled, 0);
    await runner.stopAcceptingWork();
    await runner.close();
  });

  it("reports reconciliation failures as job.failed but leaves completion-report failures redeliverable", async () => {
    const failedStages = [];
    const failingRunner = runnerFixture({
      nextCommand: async () => command,
      reportEvent: async (_command, stage) => { failedStages.push(stage); },
      reconcile: async () => { throw Object.assign(new Error("kube failed"), { code: "KUBE_FAILED" }); },
    });
    await failingRunner.start({ trackWork: (work) => work });
    await eventually(() => assert.deepEqual(failedStages, ["started", "failed"]));
    await failingRunner.stopAcceptingWork();
    await failingRunner.close();

    const completionStages = [];
    const completionRunner = runnerFixture({
      nextCommand: async () => command,
      reportEvent: async (_command, stage) => {
        completionStages.push(stage);
        if (stage === "completed") throw Object.assign(new Error("report failed"), { code: "REPORT_FAILED" });
      },
      reconcile: async () => ({ operation: "created" }),
    });
    await completionRunner.start({ trackWork: (work) => work });
    await eventually(() => assert.deepEqual(completionStages, ["started", "completed"]));
    assert.equal(completionStages.includes("failed"), false);
    await completionRunner.stopAcceptingWork();
    await completionRunner.close();
  });

  it("runs one command at a time and resumes polling only after tracked work settles", async () => {
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    let fetches = 0;
    const timers = [];
    const runner = runnerFixture({
      nextCommand: async () => {
        fetches += 1;
        return fetches === 1 ? command : null;
      },
      reportEvent: async () => {},
      reconcile: async () => pending,
      timers,
    });
    await runner.start({ trackWork: (work) => work });
    await eventually(() => assert.equal(fetches, 1));
    // A server redelivery interval passing locally cannot cause a second fetch
    // while the first command remains tracked.
    assert.equal(timers.length, 0);
    release({ operation: "unchanged" });
    await eventually(() => assert.equal(timers.length, 1));
    await timers.shift()();
    await eventually(() => assert.equal(fetches, 2));
    await runner.stopAcceptingWork();
    await runner.close();
  });
});
