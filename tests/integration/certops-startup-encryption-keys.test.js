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
// live Postgres: a failing case exits within a second or two, and a passing
// case is asserted by "still running after a few seconds, no CertOps fatal
// logged" rather than waiting for a full app.listen() (which would need a
// real DB connection this test intentionally does not stand up).
const path = require("path");
const { spawn } = require("child_process");
const { expect } = require("chai");

const VALID_KEY_A = "a".repeat(64);
const VALID_KEY_B = "b".repeat(64);

const SURVIVAL_WINDOW_MS = 3000;

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

// Resolves once the child either exits or survives the window without
// exiting - whichever happens first - collecting stdout/stderr either way.
function observe(child, windowMs) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      resolve({ exited: true, exitCode: code, stdout: () => stdout, stderr: () => stderr });
    });
    setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ exited: false, exitCode: null, stdout: () => stdout, stderr: () => stderr });
    }, windowMs);
  });
}

describe("CertOps startup validation: CERTOPS_SIGNING_ENCRYPTION_KEY / CERTOPS_REGISTRATION_ENCRYPTION_KEY", function () {
  this.timeout(20000);

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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.exited).to.equal(false);
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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.exited).to.equal(false);
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
      const result = await observe(child, SURVIVAL_WINDOW_MS);
      child.kill();
      expect(result.stdout()).to.not.match(/Startup configuration error/);
      expect(result.exited).to.equal(false);
    });
  });
});
