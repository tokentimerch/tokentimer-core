"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const vaultScanRequest = {
  allOf: [
    {
      type: "object",
      required: ["address"],
      properties: {
        address: { type: "string" },
        namespace: { type: "string" },
      },
    },
    {
      oneOf: [
        {
          type: "object",
          required: ["token"],
          properties: { token: { type: "string" } },
          not: {
            anyOf: [{ required: ["roleId"] }, { required: ["secretId"] }],
          },
        },
        {
          type: "object",
          required: ["roleId", "secretId"],
          properties: {
            roleId: { type: "string" },
            secretId: { type: "string" },
            authMount: { type: "string" },
          },
          not: { required: ["token"] },
        },
      ],
    },
  ],
};

function compile() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(vaultScanRequest);
}

describe("VaultScanRequest oneOf contract", () => {
  const validate = compile();

  it("accepts token mode and AppRole mode", () => {
    assert.equal(
      validate({ address: "https://vault.example", token: "s.x" }),
      true,
      ajvErrors(validate),
    );
    assert.equal(
      validate({
        address: "https://vault.example",
        roleId: "r",
        secretId: "s",
        namespace: "ops",
      }),
      true,
      ajvErrors(validate),
    );
  });

  it("rejects both modes, role-only, secret-only, and neither", () => {
    assert.equal(
      validate({
        address: "https://vault.example",
        token: "t",
        roleId: "r",
        secretId: "s",
      }),
      false,
    );
    assert.equal(
      validate({ address: "https://vault.example", roleId: "r" }),
      false,
    );
    assert.equal(
      validate({ address: "https://vault.example", secretId: "s" }),
      false,
    );
    assert.equal(validate({ address: "https://vault.example" }), false);
  });
});

function ajvErrors(validate) {
  return JSON.stringify(validate.errors || []);
}
