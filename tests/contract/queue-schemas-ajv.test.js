import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const queueDir = path.join(repoRoot, "packages/contracts/queue");

function loadSchema(fileName) {
  return JSON.parse(fs.readFileSync(path.join(queueDir, fileName), "utf8"));
}

describe("Queue schemas AJV contract", () => {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);

  it("validates alert-discovery payloads", () => {
    const schema = loadSchema("alert-discovery.schema.json");
    const validate = ajv.compile(schema);

    const validPayload = {
      type: "alert-discovery",
      timestamp: new Date().toISOString(),
      workspaceId: "550e8400-e29b-41d4-a716-446655440000",
      force: false,
    };
    assert.strictEqual(validate(validPayload), true);

    const invalidPayload = {
      type: "alert-discovery",
      timestamp: "not-a-date",
    };
    assert.strictEqual(validate(invalidPayload), false);
  });

  it("validates alert-delivery payloads", () => {
    const schema = loadSchema("alert-delivery.schema.json");
    const validate = ajv.compile(schema);

    const validPayload = {
      type: "alert-delivery",
      alert: {
        id: "550e8400-e29b-41d4-a716-446655440000",
        workspaceId: "550e8400-e29b-41d4-a716-446655440001",
        tokenId: "550e8400-e29b-41d4-a716-446655440002",
      },
      channels: ["email"],
      timestamp: new Date().toISOString(),
    };
    assert.strictEqual(validate(validPayload), true);

    const invalidPayload = {
      type: "alert-delivery",
      alert: {},
      channels: [],
      timestamp: new Date().toISOString(),
    };
    assert.strictEqual(validate(invalidPayload), false);
  });

  it("validates weekly-digest payloads", () => {
    const schema = loadSchema("weekly-digest.schema.json");
    const validate = ajv.compile(schema);

    const validPayload = {
      type: "weekly-digest",
      workspaceId: "550e8400-e29b-41d4-a716-446655440000",
      channels: ["email", "webhook"],
      timestamp: new Date().toISOString(),
    };
    assert.strictEqual(validate(validPayload), true);

    const invalidPayload = {
      type: "weekly-digest",
      workspaceId: "not-a-uuid",
      timestamp: "bad",
    };
    assert.strictEqual(validate(invalidPayload), false);
  });
});
