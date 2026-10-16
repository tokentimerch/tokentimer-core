/** Genuine public certificate imports/retirements for browser audit filtering.
 * Generates only owned temporary EC key/certificate files, creates no audit rows
 * directly, and measures actor/identity/workspace attribution from PostgreSQL.
 * The browser lane owns fixture users/workspaces and removes them independently. */
"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
async function createAuditRetirements(fixture, reasons) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "browser-audit-"));
  const items = [];
  let primary;
  try {
    for (const [index, reason] of reasons.entries()) {
      const key = path.join(directory, `${index}.key`),
        cert = path.join(directory, `${index}.crt`);
      assert.equal(
        spawnSync(
          "openssl",
          [
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            key,
            "-out",
            cert,
            "-subj",
            "/CN=audit-fixture.example.test",
            "-days",
            "2",
          ],
          { stdio: "ignore", timeout: 20000 },
        ).status,
        0,
      );
      const pem = fs.readFileSync(cert, "utf8"),
        fingerprint = new crypto.X509Certificate(pem).fingerprint256
          .replace(/:/g, "")
          .toLowerCase(),
        prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
      const imported = await fixture.request(`${prefix}/certificates`, "POST", {
        certificatePem: pem,
        sourceRef: "Owned browser audit public certificate",
      });
      assert.equal(imported.status, 201);
      const identity = (
        await fixture.pool.query(
          "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
          [fixture.workspaceId, fingerprint],
        )
      ).rows[0];
      assert.ok(identity);
      const retired = await fixture.request(
        `${prefix}/certificate-identities/${identity.id}/retire`,
        "POST",
        {
          status: "revoked",
          expectedFingerprintSha256: fingerprint,
          reason,
          acknowledgeUncertainty: true,
        },
      );
      assert.equal(retired.status, 200);
      const rows = (
        await fixture.pool.query(
          "SELECT id,occurred_at,actor_user_id,subject_user_id,workspace_id,action,target_type,target_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND metadata->>'identityId'=$2",
          [fixture.workspaceId, identity.id],
        )
      ).rows;
      assert.equal(rows.length, 1);
      const event = rows[0];
      assert.equal(event.actor_user_id, fixture.userId);
      assert.equal(event.subject_user_id, fixture.userId);
      assert.equal(event.workspace_id, fixture.workspaceId);
      assert.equal(event.target_type, "managed_certificate");
      assert.equal(event.target_id, null);
      assert.equal(event.metadata.fingerprintSha256, fingerprint);
      assert.equal(event.metadata.status, "revoked");
      assert.equal(event.metadata.reason, reason);
      items.push({ event, identityId: identity.id, fingerprint, reason });
    }
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    try {
      const owned = path.resolve(directory);
      assert.equal(path.dirname(owned), path.resolve(os.tmpdir()));
      assert.match(path.basename(owned), /^browser-audit-[A-Za-z0-9]{6}$/);
      assert.equal(fs.lstatSync(owned).isSymbolicLink(), false);
      fs.rmSync(owned, { recursive: true, force: true });
    } catch (error) {
      if (primary)
        throw new AggregateError(
          [primary, error],
          "Public retirement and owned temporary cleanup failed",
        );
      throw error;
    }
  }
  return items;
}
module.exports = { createAuditRetirements };
