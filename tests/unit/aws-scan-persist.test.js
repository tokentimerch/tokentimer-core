"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeAwsSweepRegions,
  awsScanPersistRecords,
} = require("../../apps/api/services/awsScanPersist");

describe("awsScanPersistRecords", () => {
  it("keeps IAM global and tags secrets/ACM with their own region", () => {
    const persist = awsScanPersistRecords(
      [
        { sourceKind: "aws-iam-key", sourceObjectId: "AKIA", region: "us-east-1" },
        {
          sourceKind: "aws-secrets-manager",
          sourceObjectId: "arn:east",
          region: "us-east-1",
        },
        {
          sourceKind: "aws-secrets-manager",
          sourceObjectId: "arn:north",
          region: "eu-north-1",
        },
      ],
      [
        { sourceKind: "aws-iam-key", complete: true },
        { sourceKind: "aws-secrets-manager", region: "us-east-1", complete: true },
        {
          sourceKind: "aws-secrets-manager",
          region: "eu-north-1",
          complete: false,
          error: "timeout",
        },
      ],
      "us-east-1",
    );

    assert.deepEqual(persist.items[0].dimensions, {});
    assert.deepEqual(persist.items[1].dimensions, { region: "us-east-1" });
    assert.deepEqual(persist.items[2].dimensions, { region: "eu-north-1" });
    assert.equal(persist.subScopes[0].complete, true);
    assert.deepEqual(persist.subScopes[0].dimensions, {});
    assert.equal(persist.subScopes[2].complete, false);
    assert.equal(persist.subScopes[2].reason, "error");
  });
});

describe("normalizeAwsSweepRegions", () => {
  it("dedupes, drops junk, and caps the list", () => {
    assert.deepEqual(
      normalizeAwsSweepRegions(["eu-north-1", "eu-north-1", "US-EAST-1", "us-east-1", "nope!"]),
      ["eu-north-1", "us-east-1"],
    );
    assert.deepEqual(normalizeAwsSweepRegions(null), []);
  });
});
