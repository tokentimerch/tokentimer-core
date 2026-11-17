"use strict";

const path = require("node:path");
const root = path.resolve(__dirname, "..") + path.sep;
const sources = new Set([
  "tests/e2e/certops-agent-e2e.test.js",
  "tests/e2e/linux-systemd-real-journey.js",
  "tests/e2e/helpers/linux-vault-cleanup-restart.js",
  "tests/e2e/helpers/certops-api-fixture.js",
  "tests/helpers/distribution-lifecycle-fixture.cjs",
  "scripts/certops-linux-published-package.js",
  "scripts/certops-linux-systemd-ownership.js",
  "scripts/certops-linux-systemd-db-ownership.js",
]);
const types = new Set(["testCodeFailure", "hookFailed", "testTimeoutFailure", "cancelledByParent"]);
const codes = new Set(["ERR_ASSERTION", "ENOENT", "EACCES", "EPERM", "ETIMEDOUT", "ECONNREFUSED", "ECONNRESET", "23503", "23505", "42P01"]);
const caseName = "installed Linux Vault cleanup resumes after lost delete response";
const suiteName = "CertOps agent surface E2E";

function locations(error) {
  const result = [];
  const pending = [error];
  const causes = [];
  // Assertion values, messages, environment and raw stack text stay on the runner.
  for (let i = 0; i < 8 && i < pending.length; i++) {
    const current = pending[i];
    if (!current || pending.indexOf(current) !== i) continue;
    causes.unshift(current);
    pending.push(current.cause, ...(Array.isArray(current.errors) ? current.errors.slice(0, 4).reverse() : []));
  }
  for (const current of causes) {
    for (const frame of String(current.stack || "").slice(0, 16384).split("\n")) {
      const start = frame.indexOf(root);
      if (!/^\s+at /.test(frame) || start < 0) continue;
      const match = /^(.+):(\d{1,6}):\d{1,6}\)?$/.exec(frame.slice(start + root.length).trim());
      const file = match?.[1].split(path.sep).join("/");
      if (!sources.has(file)) continue;
      const entry = { file, line: Number(match[2]), ...(codes.has(current.code) ? { code: current.code } : {}) };
      if (!result.some(prior => prior.file === file && prior.line === entry.line)) result.push(entry);
      if (result.length === 4) return result;
    }
  }
  return result;
}

module.exports = async function* vaultFailureReport(events) {
  const failures = [];
  for await (const { type, data } of events) {
    if (type !== "test:fail" || failures.length >= 2 || ![caseName, suiteName].includes(data.name)) continue;
    const error = data.details?.error;
    // The suite also reports a synthetic parent failure for a failed child.
    if (data.name === suiteName && error?.failureType === "subtestsFailed") continue;
    failures.push({
      stage: data.name === suiteName ? "fixture-hook" : "installed-case",
      testcase: data.name === suiteName ? suiteName : caseName,
      category: types.has(error?.failureType) ? error.failureType : "test-failure",
      locations: locations(error),
    });
  }
  if (failures.length) yield JSON.stringify({ schemaVersion: 1, suite: "linux-vault-cleanup-restart", status: "failed", failures }) + "\n";
};
