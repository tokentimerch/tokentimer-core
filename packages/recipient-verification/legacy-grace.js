"use strict";

const crypto = require("node:crypto");
const verification = require("./index");

const MAX_GRACE_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_SNAPSHOT_CONTACTS = 10000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function invalid(message) {
  const error = new Error(message);
  error.code = "LEGACY_GRACE_INVALID";
  return error;
}

function timestamp(value, name) {
  const text = value instanceof Date ? value.toISOString() : String(value || "");
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(text)) {
    throw invalid(`${name} must be an explicit UTC ISO timestamp`);
  }
  const time = Date.parse(text);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== text.slice(0, 19)) {
    throw invalid(`${name} is invalid`);
  }
  return new Date(time).toISOString();
}

function validateWindow({ cutoff_at, captured_at, expires_at }, now) {
  const cutoff = timestamp(cutoff_at, "cutoff_at");
  const captured = timestamp(captured_at, "captured_at");
  const expires = timestamp(expires_at, "expires_at");
  if (Date.parse(cutoff) > Date.parse(captured) || Date.parse(captured) > now) {
    throw invalid("The cutoff and snapshot must not be in the future");
  }
  const duration = Date.parse(expires) - Date.parse(captured);
  if (duration <= 0 || duration > MAX_GRACE_MS || Date.parse(expires) <= now) {
    throw invalid("Grace must expire in the future, at most 30 days after the snapshot");
  }
  return { cutoff_at: cutoff, captured_at: captured, expires_at: expires };
}

function validateSnapshot(snapshot, now = Date.now()) {
  if (!snapshot || snapshot.version !== 1 || !UUID.test(String(snapshot.id || ""))) {
    throw invalid("Unsupported legacy grace snapshot");
  }
  validateWindow(snapshot, now);
  if (!Array.isArray(snapshot.recipients) || snapshot.recipients.length === 0
      || snapshot.recipients.length > MAX_SNAPSHOT_CONTACTS * 2) {
    throw invalid("The snapshot must contain between 1 and 20000 recipients");
  }
  const seen = new Set();
  for (const entry of snapshot.recipients) {
    if (!entry || !UUID.test(String(entry.workspace_id || "")) || !UUID.test(String(entry.contact_id || ""))
        || !/^[0-9]+$/.test(String(entry.source_version || ""))) {
      throw invalid("A snapshot recipient has an invalid identity or version");
    }
    const normalized = verification.normalizeDestination(entry.channel, entry.destination);
    if (!normalized.ok || normalized.value !== entry.destination) {
      throw invalid("Snapshot destinations must be normalized email addresses or WhatsApp numbers");
    }
    const key = `${entry.workspace_id}:${entry.contact_id}:${entry.channel}`;
    if (seen.has(key)) throw invalid("Duplicate contact/channel in snapshot");
    seen.add(key);
  }
  return snapshot;
}

function snapshotDigest(snapshot) {
  return crypto.createHash("sha256").update(JSON.stringify(snapshot), "utf8").digest("hex");
}

async function candidateStatus(client, workspaceId, contactId, channel, destination) {
  const existing = await client.query(
    `-- RV_GRACE_CANDIDATE
     SELECT v.status, v.destination_normalized,
            EXISTS (SELECT 1 FROM contact_channel_legacy_grants g
                     WHERE g.workspace_id = $1 AND g.contact_id = $2 AND g.channel = $3) AS used
       FROM (SELECT 1) seed
       LEFT JOIN contact_channel_verifications v
         ON v.workspace_id = $1 AND v.contact_id = $2 AND v.channel = $3`,
    [workspaceId, contactId, channel],
  );
  const state = existing.rows[0];
  if (!state || state.used || (state.status && (state.status !== "pending" || state.destination_normalized !== destination))) {
    return false;
  }
  const decision = await verification.evaluateRecipient({ client, workspaceId, contactId, channel, destination });
  if (decision.code === "RECIPIENT_VERIFICATION_UNAVAILABLE") {
    throw invalid("Recipient verification is unavailable; no legacy grace was activated");
  }
  return !decision.allowed && decision.code === "RECIPIENT_NOT_VERIFIED";
}

async function previewLegacyGrace({ pool, cutoffAt, expiresAt, workspaceId }) {
  if (workspaceId && !UUID.test(workspaceId)) throw invalid("workspaceId must be a UUID");
  if (!verification.fingerprintSecret()) throw invalid("A shared recipient fingerprint secret is required");
  return verification.withTransaction(pool, async (client) => {
    await client.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    const clock = await client.query("SELECT clock_timestamp() AS now");
    const capturedAt = timestamp(clock.rows[0].now, "captured_at");
    const window = validateWindow({ cutoff_at: cutoffAt, captured_at: capturedAt, expires_at: expiresAt }, Date.parse(capturedAt));
    // Both timestamps are checked: creation time alone does not establish the
    // age of the current destination. xmin catches every edit after preview,
    // including an address changed back and writers that omit updated_at.
    const contacts = await client.query(
      `-- RV_GRACE_PREVIEW_CONTACTS
       SELECT id, workspace_id, phone_e164, details, xmin::text AS source_version
         FROM workspace_contacts
        WHERE created_at <= $1::timestamptz AND updated_at <= $1::timestamptz
          AND ($2::uuid IS NULL OR workspace_id = $2::uuid)
        ORDER BY workspace_id, id
        LIMIT $3`,
      [window.cutoff_at, workspaceId || null, MAX_SNAPSHOT_CONTACTS + 1],
    );
    if (contacts.rows.length > MAX_SNAPSHOT_CONTACTS) {
      throw invalid("Snapshot is too large; preview one workspace at a time");
    }
    const recipients = [];
    for (const contact of contacts.rows) {
      for (const channel of ["email", "whatsapp"]) {
        const normalized = verification.normalizeDestination(channel, channel === "email" ? contact.details?.email : contact.phone_e164);
        if (!normalized.ok) continue;
        if (!await candidateStatus(client, contact.workspace_id, contact.id, channel, normalized.value)) continue;
        recipients.push({ workspace_id: contact.workspace_id, contact_id: contact.id, channel,
          destination: normalized.value, source_version: contact.source_version });
      }
    }
    const snapshot = { version: 1, id: crypto.randomUUID(), ...window, recipients };
    validateSnapshot(snapshot, Date.parse(capturedAt));
    return { snapshot, sha256: snapshotDigest(snapshot), recipients: recipients.length };
  });
}

async function activateLegacyGrace({ pool, snapshot, expectedSha256, operator }) {
  if (!snapshot || snapshot.version !== 1 || !UUID.test(String(snapshot.id || ""))) {
    throw invalid("Unsupported legacy grace snapshot");
  }
  if (!/^[a-f0-9]{64}$/.test(String(expectedSha256 || "")) || snapshotDigest(snapshot) !== expectedSha256) {
    throw invalid("Snapshot checksum does not match the reviewed preview");
  }
  const actor = String(operator || "").trim();
  if (!actor || actor.length > 200) throw invalid("An operator label of 1 to 200 characters is required");
  if (!verification.fingerprintSecret()) throw invalid("A shared recipient fingerprint secret is required");
  return verification.withTransaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('recipient-legacy-grace-activation'))");
    const previous = await client.query(
      "SELECT snapshot_sha256, recipient_count, revoked_at FROM recipient_legacy_grace_snapshots WHERE id = $1",
      [snapshot.id],
    );
    if (previous.rows[0]) {
      if (previous.rows[0].snapshot_sha256 !== expectedSha256) throw invalid("Snapshot ID already exists with different contents");
      return { id: snapshot.id, recipients: previous.rows[0].recipient_count, alreadyActivated: true, revoked: Boolean(previous.rows[0].revoked_at) };
    }
    const clock = await client.query("SELECT clock_timestamp() AS now");
    validateSnapshot(snapshot, new Date(clock.rows[0].now).getTime());
    const entries = [...snapshot.recipients].sort((a, b) =>
      `${a.workspace_id}:${a.contact_id}:${a.channel}`.localeCompare(`${b.workspace_id}:${b.contact_id}:${b.channel}`));
    for (const entry of entries) {
      const result = await client.query(
        `-- RV_GRACE_ACTIVATION_CONTACT
         SELECT phone_e164, details, xmin::text AS source_version
           FROM workspace_contacts
          WHERE workspace_id = $1 AND id = $2
            AND created_at <= $3::timestamptz AND updated_at <= $3::timestamptz
          FOR UPDATE`,
        [entry.workspace_id, entry.contact_id, snapshot.cutoff_at],
      );
      const contact = result.rows[0];
      const normalized = verification.normalizeDestination(entry.channel,
        entry.channel === "email" ? contact?.details?.email : contact?.phone_e164);
      if (!contact || contact.source_version !== entry.source_version || !normalized.ok || normalized.value !== entry.destination) {
        throw invalid("A snapshotted contact changed or was removed; create and review a new preview");
      }
      if (!await candidateStatus(client, entry.workspace_id, entry.contact_id, entry.channel, entry.destination)) {
        throw invalid("A snapshotted recipient is no longer eligible; create and review a new preview");
      }
    }
    await client.query(
      `INSERT INTO recipient_legacy_grace_snapshots
         (id, snapshot_sha256, cutoff_at, captured_at, expires_at, activated_by, recipient_count)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [snapshot.id, expectedSha256, snapshot.cutoff_at, snapshot.captured_at, snapshot.expires_at, actor, entries.length],
    );
    for (const entry of entries) {
      await client.query(
        `INSERT INTO contact_channel_legacy_grants
           (workspace_id, contact_id, channel, snapshot_id, destination_normalized, destination_fingerprint, source_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [entry.workspace_id, entry.contact_id, entry.channel, snapshot.id, entry.destination,
          verification.destinationFingerprint(entry.channel, entry.destination), entry.source_version],
      );
    }
    return { id: snapshot.id, recipients: entries.length, alreadyActivated: false, expires_at: snapshot.expires_at };
  });
}

async function revokeLegacyGrace({ pool, snapshotId }) {
  if (!UUID.test(String(snapshotId || ""))) throw invalid("snapshotId must be a UUID");
  const result = await pool.query(
    `UPDATE recipient_legacy_grace_snapshots SET revoked_at = COALESCE(revoked_at, clock_timestamp())
      WHERE id = $1 RETURNING id, recipient_count`,
    [snapshotId],
  );
  if (!result.rows[0]) throw invalid("Snapshot was not found");
  return { id: snapshotId, recipients: result.rows[0].recipient_count, revoked: true };
}

module.exports = { MAX_GRACE_MS, validateSnapshot, snapshotDigest, previewLegacyGrace, activateLegacyGrace, revokeLegacyGrace };
