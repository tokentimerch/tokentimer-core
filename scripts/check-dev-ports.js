#!/usr/bin/env node

const http = require("http");
const net = require("net");

const DEFAULT_API_PORT = 4000;
const DEFAULT_DASHBOARD_PORT = 5173;

function isPortOpen(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host });
    const done = (open) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(open);
    };

    socket.setTimeout(500);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

function fetchJson(url, timeoutMs = 1000) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: timeoutMs }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(new Error(`non-JSON response from ${url}`));
        }
      });
    });

    request.on("timeout", () => {
      request.destroy(new Error(`timeout fetching ${url}`));
    });
    request.on("error", reject);
  });
}

async function describeApiPort(port) {
  try {
    const payload = await fetchJson(`http://127.0.0.1:${port}/health`);
    if (payload?.demoMode === true || payload?.status === "ok") {
      return "tokentimer-enterprise dev-mock-api";
    }
    if (payload?.status === "healthy") {
      return "tokentimer-core API";
    }
    return "unknown HTTP service";
  } catch {
    try {
      const payload = await fetchJson(`http://127.0.0.1:${port}/api/auth/features`);
      if (payload?.saml === false && payload?.oidc === false) {
        return "tokentimer-core API";
      }
    } catch {
      // ignore
    }
    return "unknown HTTP service";
  }
}

async function checkDevPort(port, label) {
  const open = await isPortOpen(port);
  if (!open) {
    return null;
  }

  if (label === "api") {
    const owner = await describeApiPort(port);
    return { port, label, owner };
  }

  return { port, label, owner: "unknown process" };
}

async function findDevPortConflicts({
  apiPort = DEFAULT_API_PORT,
  dashboardPort = DEFAULT_DASHBOARD_PORT,
} = {}) {
  const checks = await Promise.all([
    checkDevPort(apiPort, "api"),
    checkDevPort(dashboardPort, "dashboard"),
  ]);

  return checks.filter(Boolean);
}

function formatConflictMessage(conflicts) {
  const lines = [
    "[dev] local ports are already in use:",
    ...conflicts.map(
      (conflict) =>
        `  - ${conflict.port} (${conflict.label}): ${conflict.owner}`,
    ),
    "",
    "Stop the other dev stack first. Common cause: tokentimer-enterprise `pnpm demo:local`.",
    "  cd ../tokentimer-enterprise && pkill -f dev-mock-api/server.js",
    "Or stop whatever is listening on those ports, then rerun `pnpm dev`.",
  ];
  return lines.join("\n");
}

async function assertDevPortsAvailable(options = {}) {
  const conflicts = await findDevPortConflicts(options);
  if (conflicts.length === 0) {
    return;
  }

  const hasMockApi = conflicts.some((conflict) =>
    conflict.owner.includes("dev-mock-api"),
  );
  const error = new Error(formatConflictMessage(conflicts));
  error.conflicts = conflicts;
  error.hasMockApi = hasMockApi;
  throw error;
}

if (require.main === module) {
  assertDevPortsAvailable()
    .then(() => {
      console.log("[dev] ports available");
    })
    .catch((error) => {
      console.error(error.message);
      process.exit(1);
    });
}

module.exports = {
  DEFAULT_API_PORT,
  DEFAULT_DASHBOARD_PORT,
  assertDevPortsAvailable,
  findDevPortConflicts,
};
