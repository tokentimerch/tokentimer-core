"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  applyRestrictivePermissions,
} = require("../../packages/agent/src/platform");
const directory = path.resolve(__dirname, "../../.scratch/wildcard");
const destination = path.join(directory, "runtime.env");
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
applyRestrictivePermissions(directory, { kind: "directory" });
if (fs.existsSync(destination)) {
  console.log("Existing isolated runtime.env preserved.");
} else {
  const values = {
    NODE_ENV: "production",
    HOST: "0.0.0.0",
    PORT: "4000",
    DB_HOST: "postgres",
    DB_PORT: "5432",
    DB_USER: "wildcard_fixture",
    DB_PASSWORD: "isolated-fixture-only",
    DB_SSL: "false",
    DISABLE_ADMIN_BOOTSTRAP: "true",
    CERTOPS_ENABLED: "true",
    RECAPTCHA_DISABLED: "true",
    SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true",
    REDIS_URL: "redis://redis:6379/0",
    SMTP_HOST: "mail",
    SMTP_PORT: "1025",
    SMTP_SECURE: "false",
    SMTP_FROM: "fixture@example.test",
    WORKER_RUN_ON_START: "false",
  };
  for (const key of [
    "SESSION_SECRET",
    "CSRF_SECRET",
    "ENCRYPTION_KEY",
    "CERTOPS_SIGNING_ENCRYPTION_KEY",
    "CERTOPS_REGISTRATION_ENCRYPTION_KEY",
  ]) {
    values[key] = crypto.randomBytes(32).toString("hex");
  }
  fs.writeFileSync(
    destination,
    Object.entries(values)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n") + "\n",
    { flag: "wx", mode: 0o600 },
  );
  applyRestrictivePermissions(destination);
  console.log(
    "Created protected isolated runtime.env; credentials are not printed.",
  );
}
