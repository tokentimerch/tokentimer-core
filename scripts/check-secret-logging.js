#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const here = __dirname;
const repoRoot = path.resolve(here, "..");
const loggerPath = path.join(repoRoot, "apps/api/utils/logger.js");
const scanRoots = [
  path.join(repoRoot, "apps/api"),
  path.join(repoRoot, "apps/worker/src"),
];
const integrationServicesDir = path.join(repoRoot, "apps/api/services");

const REQUIRED_REDACTION_FIELDS = [
  { name: "password", aliases: ["password"] },
  { name: "token", aliases: ["token"] },
  { name: "secret", aliases: ["secret"] },
  { name: "apiKey", aliases: ["apiKey", "api_key"] },
  { name: "accessKey", aliases: ["accessKey", "access_key", "accessKeyId", "access_key_id"] },
  { name: "authorization", aliases: ["authorization"] },
  { name: "cookie", aliases: ["cookie"] },
  { name: "credentials", aliases: ["credentials"] },
  { name: "privateKey", aliases: ["privateKey", "private_key"] },
];

const RAW_LOG_HEURISTIC_PATTERNS = [
  { id: "req.body", re: /req\.body\b/ },
  { id: "secretAccessKey", re: /\bsecretAccessKey\b/ },
  { id: "client_secret", re: /\bclient_secret\b/ },
  { id: "privateKey", re: /\bprivateKey\b/ },
  { id: "personalAccessToken", re: /\bpersonalAccessToken\b/ },
  { id: "personal_access_token", re: /\bpersonal_access_token\b/ },
  { id: "vaultToken", re: /\bvaultToken\b/ },
  { id: "vault_token", re: /\bvault_token\b/ },
  { id: "apiToken+raw", re: /\bapiToken\b.*\braw\b|\braw\b.*\bapiToken\b/ },
];

const CREDENTIAL_METADATA_KEYS = new Set([
  "password",
  "token",
  "secret",
  "secretAccessKey",
  "accessKeyId",
  "access_key_id",
  "apiKey",
  "api_key",
  "accessToken",
  "refreshToken",
  "sessionToken",
  "client_secret",
  "privateKey",
  "private_key",
  "credentials",
  "vaultToken",
  "vault_token",
  "personal_access_token",
  "personalAccessToken",
  "authorization",
]);

// Verified safe logger call sites (file + regex on call text).
const RAW_LOG_ALLOWLIST = [
  {
    file: "apps/api/middleware/rateLimit.js",
    pattern: /normalizeEmail\s*\(\s*req\.body\?\.email\s*\)/,
    reason:
      "rate-limit logging extracts only the normalized email from req.body, never the credential fields",
  },
  {
    file: "apps/api/routes/auth.js",
    pattern: /req\.body\?\.email\s*\?\s*"provided"\s*:\s*"missing"/,
    reason:
      "auth attempt logging records only whether an email was provided, never its value or credentials",
  },
  {
    file: "apps/api/routes/tokens.js",
    pattern: /sanitizeForLogging\s*\(\s*req\.body\s*\)/,
    reason: "req.body is passed through sanitizeForLogging before logging",
  },
  {
    file: "apps/api/routes/workspaces.js",
    pattern: /sanitizeForLogging\s*\(\s*req\.body\s*\)/,
    reason: "req.body is passed through sanitizeForLogging before logging",
  },
  {
    file: "apps/api/services/rbac.js",
    pattern: /req\.body\?\.workspace_id/,
    reason: "Only workspace_id is read from req.body, not credential fields",
  },
  {
    file: "apps/api/routes/integrations.js",
    pattern: /req\.body\?\.address[^;]*substring/,
    reason: "Vault address is truncated to 100 chars; token is never logged",
  },
  {
    file: "apps/api/routes/integrations.js",
    pattern: /req\.body\?\.baseUrl/,
    reason: "Only baseUrl is logged on scan failure, not tokens or keys",
  },
  {
    file: "apps/api/routes/integrations.js",
    pattern: /req\.body\?\.region/,
    reason: "Only AWS region is logged on scan failure, not access keys",
  },
  {
    file: "apps/api/routes/integrations.js",
    pattern: /req\.body\?\.projectId/,
    reason: "Only GCP projectId is logged on scan failure, not access tokens",
  },
];

const ERROR_PATH_FORBIDDEN = [
  { id: "err.config", re: /\berr\.config\b/ },
  { id: "error.config", re: /\berror\.config\b/ },
  { id: "request payload", re: /\b(req\.body|credentials|accessKeyId|secretAccessKey|sessionToken|client_secret|privateKey|personal_access_token|vaultToken|vault_token)\b/ },
];

let filesScanned = 0;

function fail(message) {
  console.error(`check-secret-logging: ${message}`);
  process.exit(1);
}

function stripComments(source) {
  let out = source.replace(/\/\*[\s\S]*?\*\//g, "");
  out = out.replace(/(^|[^:\\])\/\/.*$/gm, "$1");
  return out;
}

function walkJsFiles(rootDir, relBase) {
  const results = [];
  if (!fs.existsSync(rootDir)) return results;
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "tests" || entry.name === "dist") {
      continue;
    }
    const abs = path.join(rootDir, entry.name);
    const rel = path.posix.join(relBase, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkJsFiles(abs, rel));
    } else if (entry.name.endsWith(".js")) {
      results.push({ abs, rel: rel.replace(/\\/g, "/") });
    }
  }
  return results;
}

function extractLoggerCalls(source) {
  const calls = [];
  const re = /logger\.(info|warn|error|debug)\s*\(/g;
  let match;
  while ((match = re.exec(source)) !== null) {
    const start = match.index;
    let i = re.lastIndex;
    let depth = 1;
    while (i < source.length && depth > 0) {
      const ch = source[i];
      if (ch === "(") depth += 1;
      else if (ch === ")") depth -= 1;
      i += 1;
    }
    const end = i;
    const line = source.slice(0, start).split("\n").length;
    calls.push({
      text: source.slice(start, end),
      line,
    });
    re.lastIndex = end;
  }
  return calls;
}

function isAllowlisted(relFile, callText) {
  return RAW_LOG_ALLOWLIST.some(
    (entry) => entry.file === relFile && entry.pattern.test(callText),
  );
}

function extractRedactionFields(loggerSource) {
  const fields = new Set();
  const setMatch = loggerSource.match(/sensitiveKeys\s*=\s*new\s+Set\s*\(\s*\[([\s\S]*?)\]\s*\)/);
  if (setMatch) {
    for (const m of setMatch[1].matchAll(/["'`]([^"'`]+)["'`]/g)) {
      fields.add(m[1]);
    }
  }
  for (const m of loggerSource.matchAll(/["'`]([^"'`]+)["'`]\s*:\s*["'`]?\[?REDACTED/g)) {
    fields.add(m[1]);
  }
  for (const m of loggerSource.matchAll(/REDACT_FIELDS\s*=\s*\[([\s\S]*?)\]/g)) {
    for (const f of m[1].matchAll(/["'`]([^"'`]+)["'`]/g)) {
      fields.add(f[1]);
    }
  }
  return fields;
}

function checkSanitizerPresence() {
  if (!fs.existsSync(loggerPath)) {
    fail(`missing ${loggerPath}`);
  }
  const loggerSource = fs.readFileSync(loggerPath, "utf8");
  const hasSanitization =
    /sanitizeLog(Value|Record)\b/.test(loggerSource) ||
    /sanitizeForLogging\b/.test(loggerSource) ||
    /sensitiveKeys\b/.test(loggerSource) ||
    /REDACT_FIELDS\b/.test(loggerSource);

  if (!hasSanitization) {
    fail(
      "apps/api/utils/logger.js must contain sanitization logic (sanitizeLogRecord, sensitiveKeys, or sanitizeForLogging)",
    );
  }

  const present = extractRedactionFields(loggerSource);
  const missing = [];
  for (const field of REQUIRED_REDACTION_FIELDS) {
    const covered = field.aliases.some((alias) => present.has(alias));
    if (!covered) missing.push(field.name);
  }
  if (missing.length > 0) {
    fail(
      `logger.js redaction list missing required fields: ${missing.join(", ")}`,
    );
  }
}

function checkRawCredentialLogging() {
  const violations = [];
  for (const root of scanRoots) {
    const relBase = path.relative(repoRoot, root).replace(/\\/g, "/");
    for (const file of walkJsFiles(root, relBase)) {
      filesScanned += 1;
      const source = stripComments(fs.readFileSync(file.abs, "utf8"));
      for (const call of extractLoggerCalls(source)) {
        const matched = RAW_LOG_HEURISTIC_PATTERNS.filter((p) => p.re.test(call.text));
        if (matched.length === 0) continue;
        if (isAllowlisted(file.rel, call.text)) continue;
        violations.push({
          file: file.rel,
          line: call.line,
          patterns: matched.map((p) => p.id).join(", "),
          excerpt: call.text.replace(/\s+/g, " ").slice(0, 160),
        });
      }
    }
  }
  if (violations.length > 0) {
    const detail = violations
      .map(
        (v) =>
          `  ${v.file}:${v.line} [${v.patterns}] ${v.excerpt}`,
      )
      .join("\n");
    fail(`raw credential logging heuristic matched unsafe logger calls:\n${detail}`);
  }
}

function extractWriteAuditBlocks(source) {
  const blocks = [];
  const re = /writeAudit\s*\(\s*\{/g;
  let match;
  while ((match = re.exec(source)) !== null) {
    const start = match.index;
    let i = re.lastIndex;
    let depth = 1;
    while (i < source.length && depth > 0) {
      const ch = source[i];
      if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
      i += 1;
    }
    const end = i;
    const line = source.slice(0, start).split("\n").length;
    blocks.push({
      text: source.slice(start, end),
      line,
    });
    re.lastIndex = end;
  }
  return blocks;
}

function checkAuditPersistence() {
  const apiRoot = path.join(repoRoot, "apps/api");
  const violations = [];
  for (const file of walkJsFiles(apiRoot, "apps/api")) {
    const source = stripComments(fs.readFileSync(file.abs, "utf8"));
    for (const block of extractWriteAuditBlocks(source)) {
      const metadataMatch = block.text.match(/metadata\s*:\s*(\{[\s\S]*?\})\s*,?\s*(?:workspaceId|channel|targetId|targetType|action|subjectUserId|actorUserId|\})/);
      if (!metadataMatch) continue;
      const metadataText = metadataMatch[1];
      for (const key of CREDENTIAL_METADATA_KEYS) {
        const keyRe = new RegExp(`\\b${key}\\s*:`);
        if (keyRe.test(metadataText)) {
          violations.push({
            file: file.rel,
            line: block.line,
            key,
            excerpt: metadataText.replace(/\s+/g, " ").slice(0, 120),
          });
        }
      }
    }
  }
  if (violations.length > 0) {
    const detail = violations
      .map((v) => `  ${v.file}:${v.line} metadata.${v.key} ${v.excerpt}`)
      .join("\n");
    fail(`writeAudit call sites pass raw credential fields in metadata:\n${detail}`);
  }
}

function isInsideCatchBlock(source, index) {
  const prefix = source.slice(0, index);
  const catchIdx = prefix.lastIndexOf("catch");
  if (catchIdx === -1) return false;
  const tryIdx = prefix.lastIndexOf("try");
  return catchIdx > tryIdx;
}

function checkIntegrationErrorPaths() {
  if (!fs.existsSync(integrationServicesDir)) return;
  const violations = [];
  // Core keeps provider integrations as apps/api/services/*Integration.js
  // rather than a dedicated integrations/ directory.
  const integrationFiles = walkJsFiles(
    integrationServicesDir,
    "apps/api/services",
  ).filter((file) => file.rel.endsWith("Integration.js"));
  for (const file of integrationFiles) {
    const source = stripComments(fs.readFileSync(file.abs, "utf8"));
    const calls = extractLoggerCalls(source);
    for (const call of calls) {
      const callIndex = source.indexOf(call.text);
      if (!isInsideCatchBlock(source, callIndex)) continue;
      // Only match identifiers/expressions, not words inside log message
      // strings (e.g. logger.info("AWS credentials validated")).
      const codeOnly = call.text.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');
      for (const rule of ERROR_PATH_FORBIDDEN) {
        if (!rule.re.test(codeOnly)) continue;
        if (rule.id === "request payload" && /\berror\s*:\s*(e|err|error)\.message\b/.test(call.text) && !/\b(req\.body|credentials)\s*[,}]/.test(call.text)) {
          continue;
        }
        violations.push({
          file: file.rel,
          line: call.line,
          rule: rule.id,
          excerpt: call.text.replace(/\s+/g, " ").slice(0, 160),
        });
      }
    }
  }
  if (violations.length > 0) {
    const detail = violations
      .map((v) => `  ${v.file}:${v.line} [${v.rule}] ${v.excerpt}`)
      .join("\n");
    fail(`integration catch blocks log unsafe axios/request data:\n${detail}`);
  }
}

checkSanitizerPresence();
checkRawCredentialLogging();
checkAuditPersistence();
checkIntegrationErrorPaths();

console.log(
  `check-secret-logging: ok (files scanned: ${filesScanned}, allowlist entries: ${RAW_LOG_ALLOWLIST.length})`,
);
