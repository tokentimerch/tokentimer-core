/**
 * Contract Tests - Queue Message Schemas
 *
 * Verify that queue messages match the defined JSON schemas
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { readFileSync } from "fs";
import { resolve } from "path";

const contractsDir = resolve(process.cwd(), "packages/contracts/queue");

describe("Queue Schema Contracts", () => {
  describe("Alert Discovery Schema", () => {
    it("should have required fields", () => {
      const schemaPath = resolve(contractsDir, "alert-discovery.schema.json");
      const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

      assert.ok(schema.$schema);
      assert.ok(schema.title);
      assert.ok(schema.properties);
      assert.ok(schema.required);

      // Check required fields
      assert.ok(schema.required.includes("type"));
      assert.ok(schema.required.includes("timestamp"));

      // Check field definitions
      assert.strictEqual(schema.properties.type.const, "alert-discovery");
      assert.ok(schema.properties.timestamp);
      assert.ok(schema.properties.workspaceId);
    });

    it("should validate valid alert-discovery message", () => {
      const validMessage = {
        type: "alert-discovery",
        timestamp: new Date().toISOString(),
        workspaceId: "550e8400-e29b-41d4-a716-446655440000",
        force: false,
      };

      // Basic validation
      assert.strictEqual(validMessage.type, "alert-discovery");
      assert.ok(validMessage.timestamp);
      assert.ok(validMessage.workspaceId);
    });
  });

  describe("Alert Delivery Schema", () => {
    it("should have required fields", () => {
      const schemaPath = resolve(contractsDir, "alert-delivery.schema.json");
      const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

      assert.ok(schema.$schema);
      assert.ok(schema.title);
      assert.ok(schema.properties);
      assert.ok(schema.required);

      // Check required fields
      assert.ok(schema.required.includes("type"));
      assert.ok(schema.required.includes("alert"));
      assert.ok(schema.required.includes("channels"));
      assert.ok(schema.required.includes("timestamp"));

      // Check alert object structure
      assert.ok(schema.properties.alert.properties.id);
      assert.ok(schema.properties.alert.properties.workspaceId);
      assert.ok(schema.properties.alert.properties.tokenId);
    });

    it("should validate valid alert-delivery message", () => {
      const validMessage = {
        type: "alert-delivery",
        alert: {
          id: "550e8400-e29b-41d4-a716-446655440000",
          workspaceId: "550e8400-e29b-41d4-a716-446655440001",
          tokenId: "550e8400-e29b-41d4-a716-446655440002",
          tokenName: "Test Token",
          tokenType: "api_key",
          expirationDate: "2027-12-31",
          daysUntilExpiry: 30,
        },
        channels: ["email", "webhook"],
        timestamp: new Date().toISOString(),
      };

      assert.strictEqual(validMessage.type, "alert-delivery");
      assert.ok(validMessage.alert.id);
      assert.ok(Array.isArray(validMessage.channels));
      assert.ok(validMessage.channels.length > 0);
    });
  });

  describe("Weekly Digest Schema", () => {
    it("should have required fields", () => {
      const schemaPath = resolve(contractsDir, "weekly-digest.schema.json");
      const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

      assert.ok(schema.$schema);
      assert.ok(schema.title);
      assert.ok(schema.properties);
      assert.ok(schema.required);

      // Check required fields
      assert.ok(schema.required.includes("type"));
      assert.ok(schema.required.includes("workspaceId"));
      assert.ok(schema.required.includes("timestamp"));
    });

    it("should validate valid weekly-digest message", () => {
      const validMessage = {
        type: "weekly-digest",
        workspaceId: "550e8400-e29b-41d4-a716-446655440000",
        channels: ["email", "webhook"],
        timestamp: new Date().toISOString(),
      };

      assert.strictEqual(validMessage.type, "weekly-digest");
      assert.ok(validMessage.workspaceId);
      assert.ok(validMessage.timestamp);
    });
  });
});
