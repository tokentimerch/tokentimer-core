"use strict";

const fs = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");

// Use the same YAML parser as the existing workflow checks.
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const ROOT = path.resolve(__dirname, "..");
const MANIFEST = "integrations.watch.yaml";

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isText(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function readRepoFile(root, relativePath) {
  requireValue(
    isText(relativePath) &&
      relativePath.split("/").every((part) => part && part !== "." && part !== "..") &&
      !/[\\:]/.test(relativePath),
    `Invalid repository path: ${relativePath}`,
  );
  const resolved = fs.realpathSync(path.join(root, relativePath));
  const relative = path.relative(root, resolved);
  requireValue(
    relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative),
    `Path leaves the repository: ${relativePath}`,
  );
  return fs.readFileSync(resolved, "utf8");
}

function checkSourceUrl(value) {
  requireValue(isText(value), "Missing source URL");
  const url = new URL(value);
  requireValue(
    url.protocol === "https:" && !url.username && !url.password,
    `Source must use HTTPS without credentials: ${value}`,
  );
}

function checkCodeLocation(root, location, apiVersion) {
  requireValue(isObject(location), "Invalid code location");
  const { path: relativePath, functions = [], contains = [] } = location;
  const source = readRepoFile(root, relativePath);
  requireValue(Array.isArray(functions), `${relativePath}: invalid functions list`);
  for (const name of functions) {
    requireValue(
      typeof name === "string" && /^[A-Za-z_]\w*$/.test(name) &&
        new RegExp(`\\b${name}\\b`).test(source),
      `${relativePath}: identifier ${name} is missing`,
    );
  }
  requireValue(Array.isArray(contains), `${relativePath}: invalid contains list`);
  for (const evidence of contains) {
    requireValue(isText(evidence), `${relativePath}: invalid source evidence`);
    requireValue(
      !evidence.includes("{api_version}") || isText(apiVersion),
      `${relativePath}: version evidence requires an API version`,
    );
    const text = evidence.replaceAll("{api_version}", apiVersion);
    requireValue(
      source.includes(text),
      `${relativePath}: source text ${JSON.stringify(text)} is missing`,
    );
  }
}

function validateManifest(manifest, root = ROOT) {
  requireValue(
    isObject(manifest) && manifest.schema_version === "1.0.0" &&
      isObject(manifest.integrations),
    "Expected a schema_version 1.0.0 integrations mapping",
  );
  const entries = Object.entries(manifest.integrations);
  requireValue(entries.length > 0, "No integrations listed");
  const packageFiles = new Map();
  for (const [id, integration] of entries) {
    try {
      requireValue(
        /^[a-z][a-z0-9-]*$/.test(id) && isObject(integration) &&
          integration.id === id && isText(integration.name),
        "Invalid integration ID or name",
      );
      requireValue(
        integration.api_version === null || isText(integration.api_version),
        "api_version must be a string or null",
      );
      const { code_locations, sources, sdks = [] } = integration;
      requireValue(Array.isArray(code_locations) && code_locations.length, "No code locations");
      requireValue(Array.isArray(sources) && sources.length, "No sources");
      requireValue(Array.isArray(sdks), "Invalid SDK list");
      for (const location of code_locations) {
        checkCodeLocation(root, location, integration.api_version);
      }
      for (const source of sources) {
        requireValue(isObject(source) && isText(source.type), "Invalid source entry");
        checkSourceUrl(source.url);
        if (source.feed !== undefined) checkSourceUrl(source.feed);
      }
      for (const sdk of sdks) {
        requireValue(
          isObject(sdk) && isText(sdk.name) && isText(sdk.version) &&
            isText(sdk.location) && path.posix.basename(sdk.location) === "package.json",
          "Invalid SDK entry",
        );
        if (!packageFiles.has(sdk.location)) {
          packageFiles.set(sdk.location, JSON.parse(readRepoFile(root, sdk.location)));
        }
        const { dependencies, devDependencies } = packageFiles.get(sdk.location);
        const version = dependencies?.[sdk.name] ?? devDependencies?.[sdk.name];
        requireValue(
          version === sdk.version,
          `${sdk.location}: ${sdk.name} is ${version ?? "missing"}, manifest says ${sdk.version}`,
        );
      }
    } catch (error) {
      throw new Error(`${id}: ${error.message}`, { cause: error });
    }
  }
  return entries.length;
}

if (require.main === module) {
  try {
    const manifest = yaml.load(readRepoFile(ROOT, MANIFEST));
    const count = validateManifest(manifest);
    console.log(`Validated ${count} integrations in ${MANIFEST}`);
  } catch (error) {
    console.error(`${MANIFEST}: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { validateManifest };
