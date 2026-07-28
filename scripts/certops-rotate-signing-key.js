"use strict";

// CertOps signing-key rotation for operators.
//
// The Ed25519 job-signing key is deployment-global (certops_signing_keys has
// no workspace_id and a unique index enforcing a single active key), so
// rotation is an operator action rather than a tenant one and is intentionally
// not exposed on any workspace HTTP route.
//
// Usage:
//   node scripts/certops-rotate-signing-key.js status
//   node scripts/certops-rotate-signing-key.js begin
//   node scripts/certops-rotate-signing-key.js complete
//   node scripts/certops-rotate-signing-key.js complete --force --reason "..."
//
// Rotation is deliberately two-phase so a fleet is never locked out. `begin`
// creates a new active key and moves the previous one to `retiring`, which
// keeps verifying jobs already in flight. Agents learn about the replacement
// through the heartbeat rotation notice and acknowledge it after re-pinning.
// `complete` retires the old key only once every active agent has
// acknowledged, unless --force is given with a reason.
//
// Requires CERTOPS_SIGNING_ENCRYPTION_KEY (64 hex chars) for `begin`, since a
// new private key must be wrapped. `status` and `complete` do not need it.

const { loadRootEnv } = require("./load-root-env");
loadRootEnv();

const {
  beginSigningKeyRotation,
  completeSigningKeyRotation,
  getSigningKeyRotationStatus,
} = require("../apps/api/services/certops/jobSigning");
const { pool } = require("../apps/api/db/database");
const { writeAudit } = require("../apps/api/services/audit");

const USAGE = `Usage:
  node scripts/certops-rotate-signing-key.js status
  node scripts/certops-rotate-signing-key.js begin
  node scripts/certops-rotate-signing-key.js complete [--force --reason "why"]

Options:
  --force            Retire the old key before the whole fleet acknowledged.
                     Agents that never acknowledged will reject new jobs with
                     job_integrity_failed until they re-pin.
  --reason "text"    Required with --force; recorded for the audit trail.
  --json             Emit machine-readable JSON instead of prose.`;

const MAX_REASON_LENGTH = 500;

function parseArgs(argv) {
  const command = argv[0] || "";
  const force = argv.includes("--force");
  const json = argv.includes("--json");

  let reason = null;
  const reasonIndex = argv.indexOf("--reason");
  if (reasonIndex !== -1) {
    reason = argv[reasonIndex + 1] || null;
  }

  return { command, force, json, reason };
}

function describeStatus(status) {
  const lines = [];
  if (!status.active) {
    lines.push(
      "No active signing key exists yet. One is generated automatically on the first agent registration or job dispatch.",
    );
    return lines.join("\n");
  }

  lines.push(`Active signing key:   ${status.active.signingKeyId}`);
  if (status.retiring) {
    lines.push(`Retiring signing key: ${status.retiring.signingKeyId}`);
    lines.push(
      `Rotation started at:  ${status.retiring.rotationStartedAt || "unknown"}`,
    );
  } else {
    lines.push("Retiring signing key: none (no rotation in progress)");
  }
  lines.push(
    `Fleet acknowledgement: ${status.ackCount}/${status.activeAgents} active agents have pinned the active key`,
  );

  if (status.rotationInProgress) {
    lines.push(
      status.fullyAcked
        ? "Ready to complete: every active agent acknowledged, run `complete`."
        : "Not ready to complete: some active agents have not acknowledged yet. Wait for their next heartbeat, or use `complete --force --reason \"...\"` to retire the old key anyway.",
    );
  }

  return lines.join("\n");
}

async function main() {
  const { command, force, json, reason } = parseArgs(process.argv.slice(2));

  if (!command || command === "help" || command === "--help") {
    console.log(USAGE);
    return 0;
  }

  if (!["status", "begin", "complete"].includes(command)) {
    console.error(`Unknown command: ${command}\n\n${USAGE}`);
    return 2;
  }

  if (command === "status") {
    const status = await getSigningKeyRotationStatus();
    console.log(json ? JSON.stringify(status, null, 2) : describeStatus(status));
    return 0;
  }

  if (command === "begin") {
    const before = await getSigningKeyRotationStatus();
    if (before.rotationInProgress) {
      console.error(
        `A rotation is already in progress (retiring ${before.retiring.signingKeyId}). Complete it before starting another.`,
      );
      return 1;
    }

    const result = await beginSigningKeyRotation();
    await writeAudit({
      actorUserId: null,
      subjectUserId: null,
      action: "CERTOPS_SIGNING_KEY_ROTATION_STARTED",
      targetType: "certops_signing_key",
      targetId: null,
      channel: null,
      workspaceId: null,
      metadata: {
        signing_key_id: result.signingKeyId,
        supersedes_signing_key_id: result.supersedesSigningKeyId || null,
        source: "certops-rotate-signing-key",
      },
    });

    if (json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`New active signing key: ${result.signingKeyId}`);
      if (result.supersedesSigningKeyId) {
        console.log(
          `Retiring signing key:   ${result.supersedesSigningKeyId} (still verifies in-flight jobs)`,
        );
        console.log(
          "\nAgents adopt the new key through their next heartbeat. Re-run `status` to watch acknowledgements, then run `complete`.",
        );
      }
    }
    return 0;
  }

  // command === "complete"
  if (force) {
    const trimmedReason = typeof reason === "string" ? reason.trim() : "";
    if (!trimmedReason) {
      console.error(
        '--force requires --reason "why the rotation is being forced".',
      );
      return 2;
    }
    if (trimmedReason.length > MAX_REASON_LENGTH) {
      console.error(
        `--reason must be ${MAX_REASON_LENGTH} characters or fewer.`,
      );
      return 2;
    }
  }

  const result = await completeSigningKeyRotation({
    force,
    reason: force ? reason.trim() : null,
  });

  if (!result.completed) {
    if (json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (result.reason === "no_retiring_key") {
      console.error(
        "No rotation is in progress: there is no retiring key to complete.",
      );
    } else {
      console.error(
        `Rotation not completed: only ${result.ackCount}/${result.activeAgents} active agents acknowledged the new key. Wait for the remaining heartbeats, or re-run with --force --reason "...".`,
      );
    }
    return 1;
  }

  await writeAudit({
    actorUserId: null,
    subjectUserId: null,
    action: "CERTOPS_SIGNING_KEY_ROTATION_COMPLETED",
    targetType: "certops_signing_key",
    targetId: null,
    channel: null,
    workspaceId: null,
    metadata: {
      retired_signing_key_id: result.retiredSigningKeyId,
      active_signing_key_id: result.activeSigningKeyId,
      forced: result.forced === true,
      force_reason: result.forced ? reason.trim() : null,
      active_agents: result.activeAgents,
      ack_count: result.ackCount,
      source: "certops-rotate-signing-key",
    },
  });

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Retired signing key: ${result.retiredSigningKeyId}`);
    console.log(`Active signing key:  ${result.activeSigningKeyId}`);
    if (result.forced) {
      console.log(
        `\nForced before full acknowledgement (${result.ackCount}/${result.activeAgents}). Agents still pinned to the retired key will reject jobs with job_integrity_failed until they re-register or re-pin.`,
      );
    }
  }
  return 0;
}

main()
  .then(async (code) => {
    await pool.end();
    process.exit(code);
  })
  .catch(async (err) => {
    console.error(`CertOps signing-key rotation failed: ${err.message}`);
    if (err.code) console.error(`Code: ${err.code}`);
    try {
      await pool.end();
    } catch (_) {}
    process.exit(1);
  });
