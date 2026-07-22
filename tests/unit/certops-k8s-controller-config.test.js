"use strict";

const { after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  ControllerConfigError,
  loadApiTokenFromFile,
  loadControllerConfig,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/config.js"),
);

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-controller-"));
const tokenPath = path.join(tempDir, "api-token");
const controllerToken = `ttx_${"a".repeat(16)}_${"b".repeat(64)}`;
fs.writeFileSync(tokenPath, `${controllerToken}\n`, { mode: 0o600 });
after(() => fs.rmSync(tempDir, { force: true, recursive: true }));

function validEnv(overrides = {}) {
  return {
    TOKENTIMER_API_TOKEN_FILE: tokenPath,
    TOKENTIMER_API_URL: "https://tokentimer.example.test/api",
    TOKENTIMER_CLUSTER_ID: "prod-west-1",
    TOKENTIMER_WORKSPACE_ID: "00000000-0000-4000-8000-000000000001",
    CERTOPS_WATCH_NAMESPACES: "default",
    ...overrides,
  };
}

describe("CertOps Kubernetes controller configuration", () => {
  it("loads the observe-only defaults without retaining a credential", () => {
    const config = loadControllerConfig(
      validEnv({
        CERTOPS_RECONCILE_INTERVAL: "45s",
        CERTOPS_SHUTDOWN_TIMEOUT: "12s",
        CERTOPS_WATCH_NAMESPACES: "cert-manager,platform",
      }),
    );

    assert.equal(config.mode, "observe");
    assert.equal(config.secretFallbackEnabled, false);
    assert.deepEqual(config.watchNamespaces, ["cert-manager", "platform"]);
    assert.equal(config.reconcileIntervalMs, 45_000);
    assert.equal(config.shutdownTimeoutMs, 12_000);
    assert.doesNotMatch(JSON.stringify(config), /ttx_/);
  });

  it("fails closed when a required field is absent or malformed", () => {
    for (const field of [
      "TOKENTIMER_API_URL",
      "TOKENTIMER_WORKSPACE_ID",
      "TOKENTIMER_CLUSTER_ID",
      "TOKENTIMER_API_TOKEN_FILE",
    ]) {
      const env = validEnv();
      delete env[field];
      assert.throws(
        () => loadControllerConfig(env),
        (error) =>
          error instanceof ControllerConfigError &&
          error.code === "CONTROLLER_CONFIG_REQUIRED",
      );
    }

    assert.throws(
      () => loadControllerConfig(validEnv({ TOKENTIMER_API_URL: "ftp://bad" })),
      { code: "CONTROLLER_CONFIG_INVALID_URL" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({ CERTOPS_RECONCILE_INTERVAL: "0" })),
      { code: "CONTROLLER_CONFIG_INVALID_INTERVAL" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({ CERTOPS_HEALTH_PORT: "70000" })),
      { code: "CONTROLLER_CONFIG_INVALID_PORT" },
    );
  });

  it("uses the frozen lowercase RFC 1123 label rule for cluster IDs", () => {
    for (const invalidClusterId of ["Prod", "-prod", "prod-", "prod.west", "a".repeat(64)]) {
      assert.throws(
        () =>
          loadControllerConfig(
            validEnv({ TOKENTIMER_CLUSTER_ID: invalidClusterId }),
          ),
        { code: "CONTROLLER_CONFIG_INVALID_CLUSTER_ID" },
      );
    }
  });

  it("allows only the explicit provision mode", () => {
    const provision = loadControllerConfig(validEnv({
      CERTOPS_CONTROLLER_MODE: "provision",
      CERTOPS_CLUSTER_WIDE: "true",
      CERTOPS_WATCH_NAMESPACES: "",
    }));
    assert.equal(provision.mode, "provision");
    assert.equal(provision.clusterWide, true);
    assert.throws(
      () => loadControllerConfig(validEnv({ CERTOPS_CONTROLLER_MODE: "mutate" })),
      { code: "CONTROLLER_CONFIG_INVALID_MODE" },
    );
  });

  it("parses namespace lists and booleans deterministically", () => {
    const config = loadControllerConfig(
      validEnv({
        CERTOPS_SECRET_FALLBACK_ENABLED: "true",
        CERTOPS_WATCH_NAMESPACES: "team-a,team-b",
      }),
    );
    assert.equal(config.secretFallbackEnabled, true);
    assert.deepEqual(config.watchNamespaces, ["team-a", "team-b"]);

    for (const namespaces of ["team-a,,team-b", "Team-A", "team-a,team-a"]) {
      assert.throws(
        () => loadControllerConfig(validEnv({ CERTOPS_WATCH_NAMESPACES: namespaces })),
        { code: "CONTROLLER_CONFIG_INVALID_NAMESPACES" },
      );
    }
    assert.throws(
      () =>
        loadControllerConfig(
          validEnv({ CERTOPS_SECRET_FALLBACK_ENABLED: "yes" }),
        ),
      { code: "CONTROLLER_CONFIG_INVALID_BOOLEAN" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({ CERTOPS_WATCH_NAMESPACES: "" })),
      { code: "CONTROLLER_CONFIG_NAMESPACES_REQUIRED" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({
        CERTOPS_CLUSTER_WIDE: "true",
        CERTOPS_WATCH_NAMESPACES: "team-a",
      })),
      { code: "CONTROLLER_CONFIG_NAMESPACE_POLICY_CONFLICT" },
    );
  });

  it("requires a UUID workspace identity", () => {
    assert.throws(
      () => loadControllerConfig(validEnv({ TOKENTIMER_WORKSPACE_ID: "workspace-1" })),
      { code: "CONTROLLER_CONFIG_INVALID_WORKSPACE_ID" },
    );
  });

  it("accepts credentials only from a safe non-empty token file", () => {
    assert.equal(loadApiTokenFromFile(tokenPath), controllerToken);

    const emptyTokenPath = path.join(tempDir, "empty-token");
    fs.writeFileSync(emptyTokenPath, "", { mode: 0o600 });
    assert.throws(
      () => loadControllerConfig(validEnv({ TOKENTIMER_API_TOKEN_FILE: emptyTokenPath })),
      { code: "CONTROLLER_CONFIG_INVALID_TOKEN_FILE" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({ TOKENTIMER_API_TOKEN_FILE: path.join(tempDir, "missing") })),
      { code: "CONTROLLER_CONFIG_TOKEN_FILE_UNREADABLE" },
    );
    assert.throws(
      () =>
        loadApiTokenFromFile(tokenPath, {
          fsImpl: {
            readFileSync() {
              throw new Error("unreadable");
            },
            statSync() {
              return { isFile: () => true, mode: 0o100600 };
            },
          },
        }),
      { code: "CONTROLLER_CONFIG_TOKEN_FILE_UNREADABLE" },
    );
    assert.throws(
      () =>
        loadApiTokenFromFile(tokenPath, {
          fsImpl: {
            readFileSync() {
              return "token";
            },
            statSync() {
              return { isFile: () => true, mode: 0o100666 };
            },
          },
          platform: "linux",
        }),
      { code: "CONTROLLER_CONFIG_UNSAFE_TOKEN_FILE" },
    );
  });

  it("rejects a raw token environment value and private-key-looking file data", () => {
    assert.throws(
      () =>
        loadControllerConfig(
          validEnv({ TOKENTIMER_API_TOKEN: "must-not-be-accepted" }),
        ),
      { code: "CONTROLLER_CONFIG_RAW_TOKEN_FORBIDDEN" },
    );
    assert.throws(
      () => loadControllerConfig(validEnv({ KUBECONFIG: "/tmp/kubeconfig" })),
      { code: "CONTROLLER_CONFIG_KUBECONFIG_FORBIDDEN" },
    );
    const keyPath = path.join(tempDir, "key-looking-token");
    fs.writeFileSync(keyPath, "-----BEGIN PRIVATE KEY-----\nsecret", {
      mode: 0o600,
    });
    assert.throws(
      () => loadControllerConfig(validEnv({ TOKENTIMER_API_TOKEN_FILE: keyPath })),
      { code: "CONTROLLER_CONFIG_INVALID_TOKEN_FILE" },
    );
  });
});
