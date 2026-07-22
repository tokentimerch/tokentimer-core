import client from "prom-client";
import { metricsRegister } from "./metrics.js";

// CertOps maintenance worker metrics. Registered on the shared worker
// registry so pushMetrics ships them with the rest of the worker series.

export const cCertopsSweep = new client.Counter({
  name: "certops_maintenance_sweeps_total",
  help: "CertOps maintenance sweep executions by sweep and status",
  labelNames: ["sweep", "status"],
  registers: [metricsRegister],
});

export const gCertopsLeaseReaped = new client.Gauge({
  name: "certops_lease_reaper_jobs",
  help: "Jobs processed by the last lease-reaper run, by outcome",
  labelNames: ["outcome"],
  registers: [metricsRegister],
});

export const gCertopsStaleAgents = new client.Gauge({
  name: "certops_stale_agents",
  help: "Active agents detected stale (offline) in the last sweep",
  registers: [metricsRegister],
});

export const gCertopsNoncesSwept = new client.Gauge({
  name: "certops_nonces_swept",
  help: "Expired dispatch nonces deleted in the last sweep",
  registers: [metricsRegister],
});

export const gCertopsRenewalJobsCreated = new client.Gauge({
  name: "certops_renewal_jobs_created",
  help: "Renew jobs created by the last renewal-scheduler run",
  registers: [metricsRegister],
});
