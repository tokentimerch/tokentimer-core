"use strict";
const assert = require("node:assert/strict");

const stages = new Set([
  "entrypoint", "lab-staging", "broker-admission", "ca-preparation", "ca-bootstrap", "role-containers",
  "public-journey", "package-proof", "broker-stop", "provider-cleanup", "local-cleanup", "teardown-proof",
]);
const codes = new Set([
  "AZURE_OPERATOR_ENTRA_RETIREMENT_TIMEOUT", "AZURE_OPERATOR_RETIREMENT_RECEIPT_MISSING",
  "AZURE_BROKER_CERTIFICATE_CREDENTIAL_REFUSED", "AZURE_BROKER_SHARED_CERTIFICATE_KEY_REFUSED",
  "AZURE_BROKER_CERTIFICATE_ISOLATION_REFUSED", "AZURE_BROKER_OWN_CERTIFICATE_EXCHANGE_REFUSED",
  "AZURE_BROKER_ADMISSION_FAILED", "AZURE_BROKER_ACCESS_TOKEN_REFUSED", "AZURE_BROKER_REFRESH_FAILED",
  "AZURE_BROKER_ENTRA_REFUSED", "AZURE_BROKER_RENEWAL_REFUSED", "AZURE_BROKER_SINK_OWNER_REFUSED",
  "AZURE_KV_GITHUB_CONFIGURATION_READ_REQUIRED", "AZURE_KV_CLEANUP_INCOMPLETE_JANITOR_REQUIRED",
  "EACCES", "EPERM", "ENOENT", "ETIMEDOUT",
]);
const coordinate = /\b(?:operator-lab|azure-keyvault-operator|azure-role-token-broker|azure-operator-(?:protected-launch|public-journey|data-plane|tls-proof))\.cjs:\d{1,5}:\d{1,5}\b/;

class OperatorStageError extends Error {
  constructor(stage, cause) {
    assert.ok(stages.has(stage));
    super("Azure operator stage failed", { cause });
    this.stage = stage;
  }
}

function requireCleanup(entries) {
  const failures = entries
    .filter(([, result]) => result.status === "rejected")
    .map(([stage, result]) => new OperatorStageError(stage, result.reason));
  if (failures.length) throw new AggregateError(failures, "Azure operator cleanup failed");
}

function diagnostics(error) {
  const rows = [];
  function append(current, stage, depth) {
    if (depth >= 8 || rows.length >= 8) return;
    if (current instanceof OperatorStageError) {
      append(current.cause, current.stage, depth + 1);
      return;
    }
    if (current instanceof AggregateError && current.errors.length) {
      for (const reason of current.errors.slice(0, 8)) append(reason, stage, depth + 1);
      return;
    }
    const candidates = [];
    for (let child = current; child && candidates.length < 8; child = child.cause) candidates.push(child);
    const located = candidates.reverse();
    const code = located.flatMap(child => [child.code, child.message]).find(value => codes.has(value));
    const frame = located.map(child => coordinate.exec(typeof child.stack === "string" ? child.stack : "")?.[0]).find(Boolean);
    const kind = code || (current?.code === "ERR_ASSERTION" ? "assertion" :
      Number.isSafeInteger(current?.status) && current.status > 0 && current.status < 256 ? "native-exit" : "error");
    rows.push(["AZURE_OPERATOR_FAILED", stage, kind, frame].filter(Boolean).join(" "));
  }
  append(error, "entrypoint", 0);
  return rows.length ? rows : ["AZURE_OPERATOR_FAILED entrypoint error"];
}

module.exports = { OperatorStageError, requireCleanup, diagnostics };
