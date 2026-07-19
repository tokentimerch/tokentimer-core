"use strict";

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "../..");

function resolveFirstExisting(candidates, label = "module") {
  for (const relativePath of candidates) {
    const absolutePath = path.join(PROJECT_ROOT, relativePath);
    if (fs.existsSync(absolutePath) || fs.existsSync(`${absolutePath}.js`)) {
      return absolutePath;
    }
  }
  throw new Error(
    `Unable to resolve ${label} from candidates: ${candidates.join(", ")}`,
  );
}

function requireFirstExisting(candidates, label = "module") {
  return require(resolveFirstExisting(candidates, label));
}

function readFirstExisting(candidates, label = "source") {
  return fs.readFileSync(resolveFirstExisting(candidates, label), "utf8");
}

function apiOrSaas(segment) {
  return [`apps/api/${segment}`, `apps/saas/${segment}`];
}

function requireMigrateModule() {
  return requireFirstExisting(
    apiOrSaas("migrations/migrate"),
    "migrate module",
  );
}

module.exports = {
  PROJECT_ROOT,
  apiOrSaas,
  resolveFirstExisting,
  requireFirstExisting,
  readFirstExisting,
  requireMigrateModule,
};
