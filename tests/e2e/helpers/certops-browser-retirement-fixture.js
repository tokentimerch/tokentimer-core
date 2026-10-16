/** Own real TLS endpoints and public retirement fixtures for the browser lane.
 * Uses OpenSSL, authenticated monitor/retirement routes and PostgreSQL oracles;
 * no observation/job rows or lifecycle outcomes are fabricated. Private keys
 * remain in temporary files and are removed with owned endpoint/user cleanup. */
"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  https = require("node:https"),
  tls = require("node:tls");
const { spawnSync } = require("node:child_process");
async function createRetirementItems(fixture) {
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "browser-retirement-"),
    ),
    items = [];
  async function cleanup() {
    const failures = [];
    for (const item of items) {
      try {
        await new Promise((resolve, reject) =>
          item.server.close((error) => (error ? reject(error) : resolve())),
        );
      } catch (error) {
        failures.push(error);
      }
    }
    try {
      const ownedDirectory = path.resolve(directory);
      assert.equal(path.dirname(ownedDirectory), path.resolve(os.tmpdir()));
      assert.match(
        path.basename(ownedDirectory),
        /^browser-retirement-[A-Za-z0-9]{6}$/,
      );
      const ownedStat = fs.lstatSync(ownedDirectory);
      assert.equal(ownedStat.isSymbolicLink(), false);
      assert.equal(ownedStat.isDirectory(), true);
      fs.rmSync(ownedDirectory, { recursive: true, force: true });
    } catch (error) {
      failures.push(error);
    }
    if (failures.length)
      throw new AggregateError(failures, "Owned TLS fixture cleanup failed");
  }
  try {
    for (const status of ["revoked", "decommissioned"]) {
      const keyFile = path.join(directory, status + ".key"),
        certFile = path.join(directory, status + ".crt");
      assert.equal(
        spawnSync(
          "openssl",
          [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            keyFile,
            "-out",
            certFile,
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-days",
            "2",
          ],
          { timeout: 20000, stdio: "ignore" },
        ).status,
        0,
      );
      const cert = fs.readFileSync(certFile),
        fingerprint = new crypto.X509Certificate(cert).fingerprint256
          .replace(/:/g, "")
          .toLowerCase();
      const server = https.createServer(
        { key: fs.readFileSync(keyFile), cert },
        (_request, response) =>
          response.end("Owned certificate browser fixture"),
      );
      const item = { status, server, fingerprint };
      items.push(item);
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      item.url = `https://127.0.0.1:${server.address().port}`;
      item.peer = () =>
        new Promise((resolve, reject) => {
          const socket = tls.connect(
            {
              host: "127.0.0.1",
              servername: "localhost",
              port: server.address().port,
              ca: cert,
              rejectUnauthorized: true,
            },
            () => {
              try {
                assert.equal(socket.authorized, true);
                resolve(
                  socket
                    .getPeerCertificate()
                    .fingerprint256.replace(/:/g, "")
                    .toLowerCase(),
                );
              } catch (error) {
                reject(error);
              } finally {
                socket.destroy();
              }
            },
          );
          socket.once("error", reject);
          socket.setTimeout(10000, () =>
            socket.destroy(new Error("Owned TLS oracle deadline")),
          );
        });
      assert.equal(await item.peer(), fingerprint);
      const route = `/api/v1/workspaces/${fixture.workspaceId}/domains`,
        created = await fixture.request(route, "POST", {
          url: item.url,
          health_check_enabled: false,
          check_interval: "1min",
        });
      assert.equal(created.status, 201);
      item.monitorId = created.body.id;
      const identities = await fixture.request(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/certificate-identities`,
      );
      assert.equal(identities.status, 200);
      item.identityId = identities.body.items.find(
        (row) => row.fingerprintSha256 === fingerprint,
      )?.identityId;
      assert.ok(item.identityId);
      item.capture = async () =>
        (
          await fixture.pool.query(
            "SELECT max(captured_at) AS captured FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2",
            [fixture.workspaceId, item.monitorId],
          )
        ).rows[0].captured;
      item.snapshot = async () => ({
        identity: (
          await fixture.pool.query(
            "SELECT id,lifecycle_status,lifecycle_reason,retired_at FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, item.identityId],
          )
        ).rows[0],
        audits: (
          await fixture.pool.query(
            "SELECT id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND metadata->>'identityId'=$2 ORDER BY id",
            [fixture.workspaceId, item.identityId],
          )
        ).rows,
        tokens: (
          await fixture.pool.query(
            "SELECT t.id,t.cert_lifecycle_status,t.expiration FROM tokens t JOIN managed_certificates mc ON mc.token_id=t.id WHERE mc.workspace_id=$1 AND certops_normalize_fingerprint(mc.fingerprint_sha256)=$2 ORDER BY t.id",
            [fixture.workspaceId, item.fingerprint],
          )
        ).rows,
      });
      item.recreateMonitor = async () => {
        const response = await fixture.request(route, "POST", {
          url: item.url,
          health_check_enabled: false,
          check_interval: "1min",
        });
        assert.equal(response.status, 201);
        item.monitorId = response.body.id;
      };
      item.removeMonitor = async () => {
        const response = await fixture.request(
          `${route}/${item.monitorId}`,
          "DELETE",
        );
        assert.equal(response.status, 200);
      };
      item.rescan = async () => {
        assert.equal(await item.peer(), fingerprint);
        const response = await fixture.request(route, "POST", {
          url: item.url,
          health_check_enabled: false,
          check_interval: "1min",
        });
        assert.equal(response.status, 200);
      };
    }
    return { items, cleanup };
  } catch (error) {
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "TLS setup and cleanup failed",
      );
    }
    throw error;
  }
}
module.exports = { createRetirementItems };
