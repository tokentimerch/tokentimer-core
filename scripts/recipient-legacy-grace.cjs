#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const grace = require("../packages/recipient-verification/legacy-grace");

const HELP = `Temporary delivery for reviewed existing recipient destinations.

Preview is read-only and writes a private local JSON file:
  node scripts/recipient-legacy-grace.cjs preview --before <UTC-ISO> --until <UTC-ISO> --output <file> [--workspace-id <UUID>]

Review the file and its checksum, then activate its exact destinations:
  node scripts/recipient-legacy-grace.cjs activate --input <file> --sha256 <checksum> --operator <label> --apply

End a snapshot early:
  node scripts/recipient-legacy-grace.cjs revoke --snapshot-id <UUID> --apply

Activation/revocation without --apply never connect to the database.
Use the API's NODE_ENV, DB_* / PGSSLROOTCERT and recipient fingerprint secret.
For production use NODE_ENV=production (or DB_SSL=verify) to verify the DB server.
Run the normal migrations first. Grace expires within 30 days of the preview.
Delivery also requires RECIPIENT_VERIFICATION_MODE=enforce and
RECIPIENT_VERIFICATION_LEGACY_GRACE=1 on the API and every notification worker.
Consent stays pending. No invitation or notification is sent by this command.
`;

function fail(message) {
  const error = new Error(message);
  error.code = "LEGACY_GRACE_INVALID";
  throw error;
}

function parseArgs(argv) {
  if (!argv.length || argv.includes("--help")) return { command: "help" };
  const [command, ...rest] = argv;
  const permitted = {
    preview: new Set(["before", "until", "output", "workspace-id"]),
    activate: new Set(["input", "sha256", "operator", "apply"]),
    revoke: new Set(["snapshot-id", "apply"]),
  };
  if (!permitted[command]) fail("Choose preview, activate or revoke; see --help");
  const options = { command };
  for (let i = 0; i < rest.length; i++) {
    const key = rest[i].startsWith("--") ? rest[i].slice(2) : "";
    if (!permitted[command].has(key) || Object.hasOwn(options, key)) fail("Unknown or repeated option; see --help");
    if (key === "apply") options[key] = true;
    else {
      const value = rest[++i];
      if (!value || value.startsWith("--")) fail("An option value is missing; see --help");
      options[key] = value;
    }
  }
  const required = { preview: ["before", "until", "output"], activate: ["input", "sha256", "operator"], revoke: ["snapshot-id"] };
  if (required[command].some(key => !options[key])) fail("A required option is missing; see --help");
  return options;
}

function buildPool(env = process.env) {
  const { Pool } = require("pg");
  const ca = env.PGSSLROOTCERT;
  // Match the API's DB_SSL semantics, including production server identity
  // verification and the explicitly requested encrypted no-verify mode.
  const ssl = env.DB_SSL === "verify" || ca
    ? { ...(ca ? { ca: fs.readFileSync(ca, "utf8") } : {}), rejectUnauthorized: true, minVersion: "TLSv1.3" }
    : env.DB_SSL === "require"
      ? { rejectUnauthorized: env.NODE_ENV === "production", minVersion: "TLSv1.3" }
      : env.DB_SSL === "require-no-verify"
        ? { rejectUnauthorized: false, minVersion: "TLSv1.3" }
        : false;
  return new Pool({ host: env.DB_HOST || "localhost", port: Number(env.DB_PORT || 5432),
    database: env.DB_NAME || "tokentimer", user: env.DB_USER || "tokentimer", password: env.DB_PASSWORD,
    ssl, max: 1, connectionTimeoutMillis: 10000, statement_timeout: 30000 });
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.command === "help") { console.log(HELP); return; }
  let snapshot;
  if (args.command === "activate") {
    if (fs.statSync(args.input).size > 10 * 1024 * 1024) fail("Snapshot file is too large");
    snapshot = JSON.parse(fs.readFileSync(args.input, "utf8"));
    grace.validateSnapshot(snapshot);
    if (grace.snapshotDigest(snapshot) !== args.sha256) fail("Snapshot checksum does not match the reviewed preview");
  }
  if (args.command !== "preview" && !args.apply) {
    console.log("No changes made. Review the snapshot and use --apply to activate or revoke it.");
    return;
  }
  if (args.command === "preview" && fs.existsSync(args.output)) fail("Output file already exists; choose a new file");
  const pool = buildPool();
  try {
    if (args.command === "preview") {
      const result = await grace.previewLegacyGrace({ pool, cutoffAt: args.before, expiresAt: args.until, workspaceId: args["workspace-id"] });
      fs.writeFileSync(args.output, JSON.stringify(result.snapshot, null, 2) + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
      console.log(JSON.stringify({ preview: path.resolve(args.output), sha256: result.sha256,
        recipients: result.recipients, expires_at: result.snapshot.expires_at, activated: false }));
    } else if (args.command === "activate") {
      console.log(JSON.stringify(await grace.activateLegacyGrace({ pool, snapshot, expectedSha256: args.sha256, operator: args.operator })));
    } else {
      console.log(JSON.stringify(await grace.revokeLegacyGrace({ pool, snapshotId: args["snapshot-id"] })));
    }
  } finally {
    await pool.end();
  }
}

if (require.main === module) main().catch(error => {
  // Database/filesystem errors can contain credentials or recipient destinations.
  console.error(error.code === "LEGACY_GRACE_INVALID" ? error.message : "Legacy grace operation failed; no partial activation is committed.");
  process.exitCode = 1;
});

module.exports = { parseArgs, buildPool, main };
