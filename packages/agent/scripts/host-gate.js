/**
 * Shared qualification evidence gate: probe actual capabilities, record named cases,
 * and fail strict runs when prerequisites or mandatory executions are missing.
 * Host harnesses supply owned fixtures and source hashes; this module measures the
 * runtime and writes bounded reports. A source mapping is not execution evidence. */
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
let nativeEnvironment;
function classifyWindowsHost(build, productType) {
  if (Number(productType) === 1) return `desktop-${build}`;
  if (![2, 3].includes(Number(productType))) return "unknown";
  return { "17763": "2019", "20348": "2022", "26100": "2025" }[String(build)] || "unknown";
}
function measuredEnvironment() {
  if (nativeEnvironment) return { ...nativeEnvironment };
  const release = require("node:os").release();
  nativeEnvironment = { osFamily: process.platform === "win32" ? "windows" : process.platform, osVersion: release, measurement: "native" };
  if (process.platform === "linux") {
    const nativeFs=require("node:fs");
    try {
      const content=nativeFs.readFileSync("/etc/os-release","utf8");
      for (const [key,field] of [["ID","distributionId"],["VERSION_ID","distributionVersion"]]) {
        const match=content.match(new RegExp("^"+key+"=(.*)$","m"));
        const value=match?.[1].replace(/^(["'])(.*)\1$/,"$2");
        if (/^[a-z0-9._-]{1,64}$/i.test(value || "")) nativeEnvironment[field]=value;
      }
    } catch {}
    nativeEnvironment.executionSurface=nativeFs.existsSync("/.dockerenv") || nativeFs.existsSync("/run/.containerenv") ? "container" : "host";
    nativeEnvironment.libc=process.report.getReport().header.glibcVersionRuntime ? "glibc" : nativeFs.existsSync("/lib/ld-musl-x86_64.so.1") || nativeFs.existsSync("/lib/ld-musl-aarch64.so.1") ? "musl" : "unknown";
  }
  if (process.platform === "win32") {
    const result = require("node:child_process").spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';$os=Get-CimInstance Win32_OperatingSystem;@{build=$os.BuildNumber;productType=$os.ProductType}|ConvertTo-Json -Compress"], { encoding: "utf8", timeout: 10000, windowsHide: true });
    try {
      if (result.status !== 0) throw new Error("Native measurement unavailable");
      const observed = JSON.parse(result.stdout);
      nativeEnvironment = { osFamily: "windows", osVersion: classifyWindowsHost(observed.build, observed.productType), productType: Number(observed.productType), measurement: "native" };
    } catch {
      // Missing native OS evidence must never turn a desktop into a server slot.
      nativeEnvironment = { osFamily: "windows", osVersion: "unknown", measurement: "unavailable" };
    }
  }
  return { ...nativeEnvironment };
}

/** Named runtime evidence. Capability probes must observe the host, not flags. */
function createHostGate({ suite, requiredCapabilities = [], probeCapabilities = async () => ({}), strict = process.env.CERTOPS_QUALIFICATION_STRICT === "1", reportPath = process.env.CERTOPS_QUALIFICATION_REPORT, candidateSha = process.env.GITHUB_SHA || null, evidenceLevel = "real-host", fixtureSource } = {}) {
  if (!suite) throw new Error("A qualification suite name is required");
  const report = { schemaVersion: 1, suite, strict, platform: process.platform, architecture: process.arch, nodeVersion: process.version, startedAt: new Date().toISOString(), requiredCapabilities: [...requiredCapabilities], capabilities: {}, scenarios: [], status: "running" };
  let ready = false;
  report.candidateSha = candidateSha;
  report.evidenceLevel = evidenceLevel;
  if (fixtureSource !== undefined) {
    if (typeof fixtureSource?.file !== "string" || path.isAbsolute(fixtureSource.file) || fixtureSource.file.split(/[\\/]/).includes("..") || !/^[a-f0-9]{64}$/i.test(fixtureSource.sha256 || "")) throw new Error("Invalid qualification fixture source identity");
    report.fixtureSource = { file: fixtureSource.file.replaceAll("\\", "/"), sha256: fixtureSource.sha256 };
  }
  report.qualificationEnvironment = measuredEnvironment();
  report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  function bounded(value) {
    return String(value).replace(/-----BEGIN [\s\S]*?-----END [^-]+-----/g, "[REDACTED]").replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]").replace(/\b(?:(?:ttx|ttagent)_[a-f0-9]{16}_[a-f0-9]{64}|ttboot_[A-Za-z0-9_-]+)/gi, "[REDACTED]").replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, "$1[REDACTED]@").replace(/(password|token|secret|authorization|credential)\s*[:=]\s*\S+/gi, "$1=[REDACTED]").slice(0, 512);
  }
  async function save() {
    if (!reportPath) return;
    await fs.mkdir(path.dirname(reportPath), { recursive: true });
    const temporary = `${reportPath}.${process.pid}.tmp`;
    await fs.writeFile(temporary, JSON.stringify(report, null, 2) + "\n");
    await fs.rename(temporary, reportPath);
  }
  function add(id, status, extra = {}) {
    if (!id || report.scenarios.some((entry) => entry.id === id)) throw new Error(`Invalid or duplicate scenario: ${id}`);
    report.scenarios.push({ id, status, ...extra });
  }
  return {
    report,
    async preflight() {
      if (ready) throw new Error("Preflight already completed");
      try {
        const observed = await probeCapabilities();
        report.capabilities = Object.fromEntries(Object.entries(observed).map(([name, value]) => [name, { available: value?.available === true, ...(value?.evidence !== undefined ? { evidence: bounded(value.evidence) } : {}) }]));
      }
      catch (error) { report.status = "failed"; report.failure = "Capability probe failed"; await save(); throw error; }
      const missing = requiredCapabilities.filter((name) => report.capabilities[name]?.available !== true);
      report.missingCapabilities = missing;
      ready = missing.length === 0;
      if (missing.length) report.status = strict ? "failed" : "unavailable";
      await save();
      if (missing.length && strict) throw new Error(`Required host capabilities unavailable: ${missing.join(", ")}`);
      return ready;
    },
    async scenario(id, execute, metadata = {}) {
      if (!ready) throw new Error("Successful host preflight is required before scenario execution");
      const level = metadata.evidenceLevel || evidenceLevel;
      if (!["unit", "integration", "real-host", "e2e"].includes(level)) throw new Error("Invalid scenario evidence level");
      add(id, "running", { startedAt: new Date().toISOString(), evidenceLevel: level, ...(metadata.oracle ? { oracle: bounded(metadata.oracle) } : {}), ...(metadata.catalogId ? { catalogId: bounded(metadata.catalogId) } : {}) });
      const entry = report.scenarios.at(-1);
      await save();
      try { await execute(); entry.status = "passed"; }
      catch (error) { entry.status = "failed"; report.status = "failed"; throw error; }
      finally { entry.finishedAt = new Date().toISOString(); await save(); }
    },
    async skip(id, reason) {
      if (!reason) throw new Error("Skipped scenarios require a reason");
      add(id, "skipped", { reason: bounded(reason) }); await save();
      if (strict) { report.status = "failed"; await save(); throw new Error(`Required scenario skipped: ${id}`); }
    },
    async finish({ requiredScenarios = [], cleanup } = {}) {
      if (cleanup !== undefined) {
        if (!["passed", "failed"].includes(cleanup?.status)) throw new Error("Invalid cleanup outcome");
        report.cleanup = { status: cleanup.status, ...(cleanup.summary ? { summary: bounded(cleanup.summary) } : {}) };
      }
      report.requiredScenarios = [...requiredScenarios];
      report.missingScenarios = requiredScenarios.filter((id) => !report.scenarios.some((entry) => entry.id === id && entry.status === "passed"));
      const invalid = !ready || report.scenarios.length === 0 || report.scenarios.some((entry) => entry.status !== "passed") || report.missingScenarios.length > 0 || report.status === "failed" || report.cleanup?.status === "failed";
      report.status = invalid ? "failed" : "passed";
      report.finishedAt = new Date().toISOString(); await save();
      if (invalid && strict) throw new Error("Host qualification incomplete; inspect scenario report");
      return report;
    },
  };
}

module.exports = { createHostGate, classifyWindowsHost };
