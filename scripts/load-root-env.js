const fs = require("fs");
const path = require("path");

const LOCAL_DEV_DEFAULTS = {
  NODE_ENV: "development",
  SESSION_SECRET: "dev_session_secret_change_in_production",
  DB_HOST: "localhost",
  DB_PORT: "5432",
  DB_NAME: "tokentimer",
  DB_USER: "tokentimer",
  DB_PASSWORD: "password",
  ADMIN_EMAIL: "admin@localhost.local",
  ADMIN_PASSWORD: "AdminPassword123!",
  ADMIN_NAME: "Administrator",
  APP_URL: "http://localhost:5173",
  API_URL: "http://localhost:4000",
};

function stripInlineComment(value) {
  let quote = null;
  let escaped = false;

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (quote === '"' && char === "\\") {
      escaped = true;
      continue;
    }

    if (quote) {
      if (char === quote) quote = null;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (char === "#" && (index === 0 || /\s/.test(value[index - 1]))) {
      return value.slice(0, index).trimEnd();
    }
  }

  return value;
}

function unquote(value) {
  value = stripInlineComment(value);
  if (value.length < 2) return value;
  const quote = value[0];
  if ((quote !== '"' && quote !== "'") || value[value.length - 1] !== quote) {
    return value;
  }

  const inner = value.slice(1, -1);
  if (quote === "'") return inner;

  return inner.replace(/\\([nrt"\\])/g, (_match, char) => {
    if (char === "n") return "\n";
    if (char === "r") return "\r";
    if (char === "t") return "\t";
    return char;
  });
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return false;

  const content = fs.readFileSync(filePath, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const separatorIndex = normalized.indexOf("=");
    if (separatorIndex === -1) continue;

    const key = normalized.slice(0, separatorIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (Object.prototype.hasOwnProperty.call(process.env, key)) continue;

    process.env[key] = unquote(normalized.slice(separatorIndex + 1).trim());
  }

  return true;
}

function applyLocalDevDefaults() {
  for (const [key, value] of Object.entries(LOCAL_DEV_DEFAULTS)) {
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function loadRootEnv() {
  const repoRoot = path.resolve(__dirname, "..");
  const envPath = path.join(repoRoot, ".env");
  const hasEnvFile = loadEnvFile(envPath);

  if (!hasEnvFile) {
    applyLocalDevDefaults();
    console.log(
      "[env] no .env found; using local development defaults (see .env.example)",
    );
  }

  if (!process.env.VITE_API_URL && process.env.API_URL) {
    process.env.VITE_API_URL = process.env.API_URL;
  }

  return repoRoot;
}

module.exports = {
  LOCAL_DEV_DEFAULTS,
  applyLocalDevDefaults,
  loadEnvFile,
  loadRootEnv,
};
