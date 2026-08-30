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

export const gCertopsRegistrationReplaysSwept = new client.Gauge({
  name: "certops_registration_replays_swept",
  help: "Expired registration replay rows deleted in the last sweep",
  registers: [metricsRegister],
});

export const gCertopsRenewalJobsCreated = new client.Gauge({
  name: "certops_renewal_jobs_created",
  help: "Renew jobs created by the last renewal-scheduler run",
  registers: [metricsRegister],
});

// A fleet where every certificate is skipped for a missing renewal profile
// reports certops_renewal_jobs_created = 0, which is indistinguishable from
// "nothing was due". These make the difference observable: a non-zero skip
// series with a zero created series means certificates are expiring unrenewed.
export const gCertopsRenewalScheduler = new client.Gauge({
  name: "certops_renewal_scheduler_certificates",
  help: "Certificates handled by the last renewal-scheduler run, by outcome",
  labelNames: ["outcome"],
  registers: [metricsRegister],
});

export const gCertopsDiagnosticAgentsRetired = new client.Gauge({
  name: "certops_diagnostic_agents_retired",
  help: "Diagnostic agents processed by the last inactivity-TTL sweep, by outcome",
  labelNames: ["outcome"],
  registers: [metricsRegister],
});

export const gCertopsAgentHealthAlerts = new client.Gauge({
  name: "certops_agent_health_alerts_queued",
  help: "Agent down/recovered health alerts queued in the last sweep, by transition",
  labelNames: ["transition"],
  registers: [metricsRegister],
});

export const gCertopsTrustAnchorReconciliation = new client.Gauge({
  name: "certops_trust_anchor_reconciliation_installations",
  help: "Trust-anchor installation rows handled by the last reconciliation sweep, by outcome",
  labelNames: ["outcome"],
  registers: [metricsRegister],
});
