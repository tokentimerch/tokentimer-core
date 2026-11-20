"use strict";
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const root = path.resolve(__dirname, "../..");
const dir = path.join(root, ".tmp/adcs-local-lab");
const stateFile = path.join(dir, "private-state.json");
const project = "tt-adcs-simulated";
function readState() {
  const state = JSON.parse(fs.readFileSync(stateFile));
  if (
    state.kind !== project ||
    state.root !== root ||
    process.env.NODE_ENV === "production"
  )
    throw Error("Not an owned simulated lab");
  return state;
}
function saveState(state) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2) + "\n", {
    mode: 0o600,
  });
}
function newState() {
  return {
    kind: project,
    root,
    dbPassword: crypto.randomBytes(24).toString("hex"),
    token: crypto.randomBytes(32).toString("hex"),
    password: crypto.randomBytes(18).toString("base64url"),
    email: "developer@adcs.example.test",
    scenarios: [],
  };
}
function environment(state) {
  const env = {};
  for (const key of [
    "PATH",
    "Path",
    "SystemRoot",
    "SYSTEMROOT",
    "ComSpec",
    "COMSPEC",
    "USERPROFILE",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "PNPM_HOME",
    "DOCKER_CONFIG",
  ])
    if (process.env[key]) env[key] = process.env[key];
  return {
    ...env,
    ADCS_LAB_OWNER: crypto.createHash("sha256").update(root).digest("hex"),
    NODE_ENV: "development",
    TT_ADCS_LOCAL_LAB: "simulated-only",
    DB_HOST: "127.0.0.1",
    DB_PORT: "55479",
    DB_NAME: "tt_adcs_simulated",
    DB_USER: "tt_adcs_simulated",
    DB_PASSWORD: state.dbPassword,
    ADCS_LAB_DB_PASSWORD: state.dbPassword,
    HOST: "127.0.0.1",
    PORT: "55471",
    APP_URL: "http://localhost:55174",
    API_URL: "http://localhost:55471",
    PUBLIC_BASE_URL: "http://localhost:55471",
    VITE_API_URL: "http://localhost:55471",
    CERTOPS_ENABLED: "true",
    CERTOPS_SIGNING_ENCRYPTION_KEY: crypto
      .createHash("sha256")
      .update(state.token + "signing")
      .digest("hex"),
    CERTOPS_REGISTRATION_ENCRYPTION_KEY: crypto
      .createHash("sha256")
      .update(state.token + "registration")
      .digest("hex"),
    SESSION_SECRET: state.token,
    RECIPIENT_FINGERPRINT_SECRET: state.token,
    RECIPIENT_VERIFICATION_MODE: "off",
    TT_DEPLOYMENT: "self-hosted",
    SMTP_HOST: "127.0.0.1",
    SMTP_PORT: "11025",
    SMTP_USER: "",
    SMTP_PASS: "",
    SMTP_SECURE: "false",
    SMTP_REQUIRE_TLS: "false",
    FROM_EMAIL: "simulator@adcs.example.test",
    DISABLE_ADMIN_BOOTSTRAP: "true",
    ADMIN_EMAIL: "",
    ADMIN_PASSWORD: "",
    ENABLE_METRICS: "false",
    METRICS_PUSH_ENABLED: "false",
    LOGIN_RATE_LIMIT_MAX: "1000",
    LOGIN_EMAIL_RATE_LIMIT_MAX: "1000",
    CERTOPS_RENEWAL_PER_CA_CAP: "50",
  };
}
function guard() {
  if (
    process.env.TT_ADCS_LOCAL_LAB !== "simulated-only" ||
    process.env.NODE_ENV !== "development" ||
    process.env.DB_HOST !== "127.0.0.1" ||
    process.env.DB_NAME !== "tt_adcs_simulated" ||
    process.env.API_URL !== "http://localhost:55471"
  )
    throw Error("Simulator requires the dedicated loopback development lab");
  return readState();
}
function database() {
  guard();
  const { Pool } = require("pg");
  return new Pool({
    host: "127.0.0.1",
    port: 55479,
    database: "tt_adcs_simulated",
    user: "tt_adcs_simulated",
    password: readState().dbPassword,
  });
}
async function login(state) {
  let csrf;
  const cookies = new Map();
  async function request(route, method = "GET", body) {
    const response = await fetch(new URL(route, "http://localhost:55471"), {
      method,
      signal: AbortSignal.timeout(30000),
      headers: {
        "content-type": "application/json",
        cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(csrf ? { "x-csrf-token": csrf } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    for (const value of response.headers.getSetCookie()) {
      const pair = value.split(";", 1)[0],
        i = pair.indexOf("=");
      cookies.set(pair.slice(0, i), pair.slice(i + 1));
    }
    const result = response.status === 204 ? null : await response.json();
    if (!response.ok)
      throw Error(
        `${method} ${route}: ${response.status} ${result?.code || result?.error || "request failed"}`,
      );
    return result;
  }
  csrf = (await request("/api/csrf-token")).csrfToken;
  await request("/auth/login", "POST", {
    email: state.email,
    password: state.password,
  });
  csrf = (await request("/api/csrf-token")).csrfToken;
  return request;
}
module.exports = {
  root,
  dir,
  stateFile,
  project,
  readState,
  saveState,
  newState,
  environment,
  guard,
  database,
  login,
};
