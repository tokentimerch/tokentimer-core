import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);
const api = require(
  path.join(root, "apps/api/services/operationalNotifications.js"),
);
const worker = await import(
  pathToFileURL(path.join(root, "apps/worker/src/shared/opNotifications.js"))
    .href
);

function recordingClient() {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: sql.replace(/\s+/g, " ").trim(), params });
      return { rows: [{ id: "incident-id" }] };
    },
  };
}

describe("API and worker operational notification parity", () => {
  it("uses the same upsert and resolve contract", async () => {
    const incident = {
      workspaceId: "workspace-id",
      tokenId: 7,
      category: "delivery",
      type: "delivery_blocked",
      severity: "critical",
      dedupeKey: "delivery_blocked:42",
      title: "Delivery blocked",
      message: "Webhook failed",
      metadata: { channel: "webhooks" },
    };
    const apiClient = recordingClient();
    const workerClient = recordingClient();

    assert.equal(
      await api.raiseOperationalNotification(apiClient, incident),
      "incident-id",
    );
    assert.equal(
      await worker.raiseOperationalNotification(workerClient, incident),
      "incident-id",
    );
    await api.resolveOperationalNotification(
      apiClient,
      incident.workspaceId,
      incident.dedupeKey,
    );
    await worker.resolveOperationalNotification(
      workerClient,
      incident.workspaceId,
      incident.dedupeKey,
    );

    assert.equal(apiClient.calls.length, 2);
    assert.deepEqual(workerClient.calls, apiClient.calls);
  });
});
