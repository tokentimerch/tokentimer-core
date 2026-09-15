"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const OPENAPI_PATH = path.join(
  __dirname,
  "..",
  "..",
  "packages",
  "contracts",
  "openapi",
  "openapi.yaml",
);

function loadYaml(text) {
  const yamlPath = require.resolve("js-yaml", {
    paths: [path.join(__dirname, "..", "..", "apps", "dashboard")],
  });
  return require(yamlPath).load(text);
}

function compileVaultScanRequest() {
  const spec = loadYaml(fs.readFileSync(OPENAPI_PATH, "utf8"));
  const schema = spec.components.schemas.VaultScanRequest;
  assert.ok(schema, "VaultScanRequest missing from OpenAPI");
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(schema);
}

function ajvErrors(validate) {
  return JSON.stringify(validate.errors || []);
}

describe("VaultScanRequest oneOf contract (published OpenAPI)", () => {
  const validate = compileVaultScanRequest();

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

  it("rejects both modes, role-only, secret-only, neither, and token+authMount", () => {
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
    assert.equal(
      validate({
        address: "https://vault.example",
        token: "s.x",
        authMount: "approle",
      }),
      false,
    );
  });

  it("rejects empty credential strings", () => {
    assert.equal(
      validate({ address: "https://vault.example", token: "" }),
      false,
    );
    assert.equal(
      validate({
        address: "https://vault.example",
        roleId: "",
        secretId: "s",
      }),
      false,
    );
    assert.equal(
      validate({
        address: "https://vault.example",
        roleId: "r",
        secretId: "",
      }),
      false,
    );
  });

  it("rejects whitespace-only credential strings", () => {
    assert.equal(
      validate({ address: "https://vault.example", token: " " }),
      false,
    );
    assert.equal(
      validate({
        address: "https://vault.example",
        roleId: " ",
        secretId: "s",
      }),
      false,
    );
  });
});
