#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const openApiPath = path.join(
  repoRoot,
  "packages",
  "contracts",
  "openapi",
  "openapi.yaml",
);
const routeDir = path.join(repoRoot, "apps", "api", "routes");
const apiIndexPath = path.join(repoRoot, "apps", "api", "index.js");
const allowlistPath = path.join(
  repoRoot,
  "packages",
  "contracts",
  "openapi",
  "missing-runtime-endpoints.allowlist.json",
);

const METHOD_PATTERN =
  /\b(?:router|app)\.(get|post|put|patch|delete|options|head)\(\s*(["'`])([^"'`]+)\2/gm;
const OPENAPI_PATH_PATTERN = /^  (\/[^:]+):\s*$/;
const OPENAPI_METHOD_PATTERN =
  /^    (get|post|put|patch|delete|options|head):\s*$/;
const INTERNAL_PATHS = new Set([
  "/",
  "/metrics",
  "/api-docs",
  "/api-docs/openapi.yaml",
]);

function fail(message) {
  console.error(`openapi-coverage: ${message}`);
  process.exit(1);
}

function normalizePath(rawPath) {
  if (typeof rawPath !== "string") return null;
  let normalized = rawPath.trim();
  if (!normalized.startsWith("/")) return null;

  // Express optional path params are represented as `:name?`.
  // OpenAPI does not model optional path segments directly, so we compare
  // against the base segment path.
  normalized = normalized.replace(/\/:([A-Za-z0-9_]+)\?/g, "");

  // Convert Express params to OpenAPI-style `{name}`.
  normalized = normalized.replace(/:([A-Za-z0-9_]+)/g, "{$1}");

  normalized = normalized.replace(/\/{2,}/g, "/");
  if (normalized.length > 1 && normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }
  return normalized || "/";
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function collectRuntimeEndpoints() {
  if (!fs.existsSync(routeDir)) fail(`missing route directory: ${routeDir}`);
  if (!fs.existsSync(apiIndexPath))
    fail(`missing API entrypoint: ${apiIndexPath}`);

  const files = [
    ...fs
      .readdirSync(routeDir)
      .filter((name) => name.endsWith(".js"))
      .map((name) => path.join(routeDir, name)),
    apiIndexPath,
  ];

  const endpointToSources = new Map();

  for (const filePath of files) {
    const raw = fs.readFileSync(filePath, "utf8");
    METHOD_PATTERN.lastIndex = 0;
    let match = METHOD_PATTERN.exec(raw);
    while (match) {
      const method = match[1].toUpperCase();
      const pathValue = normalizePath(match[3]);
      if (
        pathValue &&
        !INTERNAL_PATHS.has(pathValue) &&
        !pathValue.startsWith("/api-docs/")
      ) {
        const endpoint = `${method} ${pathValue}`;
        const rel = path.relative(repoRoot, filePath).replaceAll("\\", "/");
        const existing = endpointToSources.get(endpoint) || new Set();
        existing.add(rel);
        endpointToSources.set(endpoint, existing);
      }
      match = METHOD_PATTERN.exec(raw);
    }
  }

  return endpointToSources;
}

function collectOpenApiEndpoints() {
  if (!fs.existsSync(openApiPath)) fail(`missing OpenAPI spec: ${openApiPath}`);

  const lines = fs.readFileSync(openApiPath, "utf8").split(/\r?\n/);
  const endpoints = new Set();
  let currentPath = null;

  for (const line of lines) {
    const pathMatch = line.match(OPENAPI_PATH_PATTERN);
    if (pathMatch) {
      currentPath = normalizePath(pathMatch[1]);
      continue;
    }
    const methodMatch = line.match(OPENAPI_METHOD_PATTERN);
    if (methodMatch && currentPath) {
      endpoints.add(`${methodMatch[1].toUpperCase()} ${currentPath}`);
    }
  }

  return endpoints;
}

function loadAllowlist() {
  if (!fs.existsSync(allowlistPath)) {
    fail(`missing allowlist file: ${allowlistPath}`);
  }
  const payload = readJson(allowlistPath);
  if (!Array.isArray(payload.endpoints)) {
    fail(`allowlist must define an "endpoints" array: ${allowlistPath}`);
  }
  return new Set(payload.endpoints.map((entry) => String(entry)));
}

function main() {
  const runtime = collectRuntimeEndpoints();
  const openapi = collectOpenApiEndpoints();
  const allowlist = loadAllowlist();

  const missing = [...runtime.keys()]
    .filter((entry) => !openapi.has(entry))
    .sort();
  const uncovered = missing.filter((entry) => !allowlist.has(entry));
  const staleAllowlist = [...allowlist]
    .filter((entry) => !missing.includes(entry))
    .sort();

  if (missing.length === 0) {
    if (allowlist.size > 0) {
      fail(
        `allowlist is not empty but no missing endpoints remain. Clean up ${path.relative(repoRoot, allowlistPath)}.`,
      );
    }
    console.log("openapi-coverage: ok (all runtime endpoints are documented)");
    return;
  }

  console.log(
    `openapi-coverage: runtime endpoints=${runtime.size}, openapi endpoints=${openapi.size}, missing=${missing.length}`,
  );

  if (staleAllowlist.length > 0) {
    console.error("openapi-coverage: stale allowlist entries detected:");
    for (const entry of staleAllowlist) {
      console.error(`  - ${entry}`);
    }
    fail(
      `remove stale entries from ${path.relative(repoRoot, allowlistPath)} to keep backlog accurate`,
    );
  }

  if (uncovered.length > 0) {
    console.error("openapi-coverage: newly missing runtime endpoints:");
    for (const endpoint of uncovered) {
      const sources = [...(runtime.get(endpoint) || [])].sort();
      console.error(`  - ${endpoint}`);
      for (const source of sources) {
        console.error(`      source: ${source}`);
      }
    }
    fail("OpenAPI coverage regression detected");
  }

  console.log(
    `openapi-coverage: ok (missing endpoints fully tracked in allowlist: ${missing.length})`,
  );
}

main();
