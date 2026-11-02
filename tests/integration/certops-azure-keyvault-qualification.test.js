"use strict";
// Offline Azure protocol fixture with REAL disposable PostgreSQL and actual
// signing/governance/agent code. This is not live Azure qualification evidence.
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  https = require("node:https"),
  crypto = require("node:crypto");
const { EventEmitter } = require("node:events"),
  { PassThrough } = require("node:stream");
const { open } = require("../e2e/helpers/azure-keyvault-core.cjs");
const {
  makeMaterial,
  verifyMaterial,
} = require("../e2e/helpers/azure-keyvault-live-io.cjs");
const {
  writeProtectedJson,
} = require("../../packages/agent/src/material-store");
describe("Azure qualification bridge (offline protocol, real PostgreSQL)", function () {
  this.timeout(180000);
  let root, bridge, original;
  before(async () => {
    assert.notEqual(
      process.env.TT_AZURE_QUALIFICATION_REQUIRED,
      "1",
      "offline fixtures cannot run inside the real campaign",
    );
    root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-kvqual-bridge-"));
    const tokenFile = path.join(root, "token.json");
    writeProtectedJson(tokenFile, {
      accessToken: "isolated-offline-token-file-only",
      expiresOn: Date.now() + 3600000,
    });
    const address = "https://ttkv00000000000000000000.vault.azure.net",
      objects = new Map();
    original = https.request;
    https.request = (url, options, callback) => {
      // The fixture refuses ALL real network access and never returns a token.
      assert.equal(new URL(url).origin, address);
      const req = new EventEmitter(),
        pieces = [];
      req.write = (value) => pieces.push(Buffer.from(value));
      req.destroy = (error) => {
        if (error) req.emit("error", error);
        req.emit("close");
      };
      req.end = () =>
        process.nextTick(() => {
          const pathname = new URL(url).pathname,
            versionList = pathname.endsWith("/versions"),
            base = versionList
              ? pathname.slice(0, -9)
              : pathname.split("/").slice(0, 3).join("/");
          let row = objects.get(base),
            status = 200,
            json;
          if (options.method === "PUT") {
            assert.ok(
              row === undefined,
              "publication must never overwrite an existing object",
            );
            row = {
              ...JSON.parse(Buffer.concat(pieces).toString()),
              id: address + base + "/" + crypto.randomBytes(16).toString("hex"),
            };
            objects.set(base, row);
            json = row;
          } else if (!row) {
            status = 404;
            json = {};
          } else if (versionList) json = { value: [{ id: row.id }] };
          else if (address + pathname === row.id) json = row;
          else {
            status = 404;
            json = {};
          }
          const response = new PassThrough();
          response.statusCode = status;
          response.on("end", () => req.emit("close"));
          callback(response);
          response.end(JSON.stringify(json));
        });
      return req;
    };
    const config = {
      provider: "azure-key-vault",
      address,
      timeoutMs: 5000,
      auth: { type: "token-file", tokenFile },
    };
    bridge = await open({
      root,
      packageRoot: path.resolve(__dirname, "../../packages/agent"),
      config,
      materials: makeMaterial(root),
    });
  });
  after(async () => {
    try {
      await bridge?.close();
    } finally {
      if (original) https.request = original;
      if (root) fs.rmSync(root, { recursive: true, force: true });
    }
  });
  it("persists signed exact receipts, approves rollout, reconciles real files and authorizes retained rollback", async () => {
    const published = [];
    for (const index of [0, 1]) {
      const source = await bridge.publication(index),
        result = await source.session.publish(source.bundle, source.lease);
      await bridge.accept(source, result);
      published.push({ source, result });
    }
    for (const index of [1, 0]) {
      const { source, result } = published[index];
      const deployment = await bridge.rollout(
        source,
        result.publicationReceipt,
      );
      if (index === 1) {
        let leases = 0;
        const interrupted = await bridge.lifecycle.executePinnedDeployment({
          ...deployment.options,
          checkLease: async () => {
            await deployment.lease();
            if (++leases === 3)
              throw new Error("controlled offline interruption");
          },
        });
        assert.equal(interrupted.status, "orphaned_unknown_effect");
        await assert.rejects(
          bridge.lifecycle.executePinnedDeployment(deployment.options),
          { code: "material_binding_uncertain" },
        );
        assert.equal(
          (await bridge.lifecycle.reconcilePinnedDeployment(deployment.options))
            .reconciled,
          true,
        );
      }
      const deployed = await bridge.lifecycle.executePinnedDeployment({
        ...deployment.options,
        recoveryOnly: index === 1,
      });
      await bridge.acceptDeployment(deployment, deployed);
      assert.equal(
        verifyMaterial({
          certificatePem: fs.readFileSync(deployment.target.certPath, "utf8"),
          privateKeyPem: fs.readFileSync(deployment.target.keyPath, "utf8"),
        }),
        source.bundle.fingerprintSha256,
      );
    }
  });
});
