"use strict";

// Boot-time fail-fast coverage for CERTOPS_SIGNING_ENCRYPTION_KEY and
// CERTOPS_REGISTRATION_ENCRYPTION_KEY (0.14.2 REL-07: core previously had no
// startup gate for these, only per-request fail-closed behavior in
// jobSigning.js / registrationCredentialCrypto.js, which reject the FIRST
// agent registration/job-dispatch after boot with CERTOPS_SIGNING_ENCRYPTION_
// KEY_MISSING / CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING rather than
// refusing to boot). apps/api/index.js's validateStartupConfig() now mirrors
// tokentimer-cloud's own gate (apps/saas/index.js): in production, with
// CertOps enabled, a missing or malformed wrap key is a deploy-time mistake
// caught immediately instead of a broken agent surface discovered later.
//
// validateStartupConfig() runs synchronously before any database code
// (main()'s waitForDatabase() call), so these assertions never require a
// live Postgres. Failing cases must exit with the expected error; passing
// cases must reach the first database connection attempt without that error.
const path = require("path");
const { spawn } = require("child_process");
const { expect } = require("chai");

const VALID_KEY_A = "a".repeat(64);
const VALID_KEY_B = "b".repeat(64);

const STARTUP_WINDOW_MS = 120000;
const DATABASE_STARTUP_MARKER = /Database connection attempt/;

function spawnApi(envOverrides = {}) {
  const mergedEnv = { ...process.env, ...envOverrides };
  for (const key of Object.keys(envOverrides)) {
    if (envOverrides[key] === undefined) delete mergedEnv[key];
  }
  return spawn(process.execPath, [path.join(__dirname, "../../apps/api/index.js")], {
    cwd: path.join(__dirname, "../.."),
    env: mergedEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

// Resolve on exit, the post-validation database marker, or a bounded timeout.
function observe(child, windowMs, readyPattern = null) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (!settled && readyPattern?.test(stdout)) {
        settled = true;
        clearTimeout(timer);
        resolve({ exited: false, ready: true, exitCode: null, stdout: () => stdout, stderr: () => stderr });
      }
    });
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exited: true, ready: false, exitCode: code, stdout: () => stdout, stderr: () => stderr });
    });
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ exited: false, ready: false, exitCode: null, stdout: () => stdout, stderr: () => stderr });
    }, windowMs);
  });
}

describe("CertOps startup validation: CERTOPS_SIGNING_ENCRYPTION_KEY / CERTOPS_REGISTRATION_ENCRYPTION_KEY", function () {
  this.timeout(130000);

  const PROD_BASE_ENV = {
    NODE_ENV: "production",
    SESSION_SECRET: "test-session-secret-key",
  };

  describe("CERTOPS_ENABLED=true in production", () => {
    it("refuses to boot when both keys are missing", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        CERTOPS_ENABLED: "true",
        CERTOPS_SIGNING_ENCRYPTION_KEY: "",
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: "",
      });
      const result = await observe(child, STARTUP_WINDOW_MS);
      if (!result.exited) child.kill();
      expect(result.exited).to.equal(true);
      expect(result.exitCode).to.not.equal(0);
      expect(result.stdout()).to.match(/CERTOPS_SIGNING_ENCRYPTION_KEY is not set/);
      expect(result.stdout()).to.match(/CERTOPS_REGISTRATION_ENCRYPTION_KEY is not set/);
    });

    it("refuses to boot when a key is present but not 64 hex characters", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        CERTOPS_ENABLED: "true",
        CERTOPS_SIGNING_ENCRYPTION_KEY: "not-hex-and-way-too-short",
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: VALID_KEY_B,
      });
      const result = await observe(child, STARTUP_WINDOW_MS);
      if (!result.exited) child.kill();
      expect(result.exited).to.equal(true);
      expect(result.exitCode).to.not.equal(0);
      expect(result.stdout()).to.match(/CERTOPS_SIGNING_ENCRYPTION_KEY must be 64 hex characters/);
      expect(result.stdout()).to.not.match(/CERTOPS_REGISTRATION_ENCRYPTION_KEY must be 64 hex characters/);
    });

    it("refuses to boot when a 64-character value contains non-hex characters", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        CERTOPS_ENABLED: "true",
        CERTOPS_SIGNING_ENCRYPTION_KEY: VALID_KEY_A,
        // 64 characters long, but "g" is not a hex digit.
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: "g".repeat(64),
      });
      const result = await observe(child, STARTUP_WINDOW_MS);
      if (!result.exited) child.kill();
      expect(result.exited).to.equal(true);
      expect(result.exitCode).to.not.equal(0);
      expect(result.stdout()).to.match(/CERTOPS_REGISTRATION_ENCRYPTION_KEY must be 64 hex characters/);
    });

    it("passes the gate (no CertOps fatal logged) when both keys are valid 64-hex-character values", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        CERTOPS_ENABLED: "true",
        CERTOPS_SIGNING_ENCRYPTION_KEY: VALID_KEY_A,
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: VALID_KEY_B,
        // Deliberately point at a DB that will never answer, so any exit
        // observed inside the survival window must come from something
        // before waitForDatabase(), not a fast real DB connection.
        DB_HOST: "192.0.2.1",
      });
      const result = await observe(child, STARTUP_WINDOW_MS, DATABASE_STARTUP_MARKER);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.ready).to.equal(true);
    });
  });

  describe("CERTOPS_ENABLED not true", () => {
    it("passes the gate with both keys missing when CERTOPS_ENABLED=false", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        CERTOPS_ENABLED: "false",
        CERTOPS_SIGNING_ENCRYPTION_KEY: "",
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: "",
        DB_HOST: "192.0.2.1",
      });
      const result = await observe(child, STARTUP_WINDOW_MS, DATABASE_STARTUP_MARKER);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.ready).to.equal(true);
    });
  });

  describe("outside production, the check does not apply", () => {
    it("passes the gate in NODE_ENV=test with CERTOPS_ENABLED=true and both keys missing", async () => {
      const child = spawnApi({
        ...PROD_BASE_ENV,
        NODE_ENV: "test",
        CERTOPS_ENABLED: "true",
        CERTOPS_SIGNING_ENCRYPTION_KEY: "",
        CERTOPS_REGISTRATION_ENCRYPTION_KEY: "",
        DB_HOST: "192.0.2.1",
      });
      const result = await observe(child, STARTUP_WINDOW_MS, DATABASE_STARTUP_MARKER);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.ready).to.equal(true);
    });
  });
});
