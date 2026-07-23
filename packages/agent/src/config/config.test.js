"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  resolveConfigDir,
  ensureConfigDir,
  loadAgentConfig,
  readCaBundle,
  writeAgentIdentity,
  readCredential,
  writeCredential,
  rotateCredential,
  persistRegistration,
  recoverPendingRegistration,
  redactCredentialForLogging,
  MAX_CA_BUNDLE_BYTES,
} = require("./index.js");

const IS_WIN32 = process.platform === "win32";

const tempDirs = [];

function makeTempConfigDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-config-test-"));
  tempDirs.push(dir);
  // Use a nested, not-yet-existing subdirectory so tests also cover
  // recursive directory creation via ensureConfigDir/writeAgentIdentity.
  return path.join(dir, "agent-config");
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_err) {
      // best-effort cleanup
    }
  }
});

function withEnv(vars, fn) {
  const previous = {};
  for (const key of Object.keys(vars)) {
    previous[key] = process.env[key];
    if (vars[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = vars[key];
    }
  }
  try {
    return fn();
  } finally {
    for (const key of Object.keys(previous)) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
  }
}

describe("resolveConfigDir", () => {
  it("prefers the explicit argument over env var and OS default", () => {
    withEnv({ TOKENTIMER_AGENT_CONFIG_DIR: "/env/path" }, () => {
      assert.equal(resolveConfigDir("/explicit/path"), "/explicit/path");
    });
  });

  it("falls back to the env var when no explicit dir is given", () => {
    withEnv({ TOKENTIMER_AGENT_CONFIG_DIR: "/env/path" }, () => {
      assert.equal(resolveConfigDir(undefined), "/env/path");
    });
  });

  it("falls back to an OS default when neither explicit dir nor env var is set", () => {
    withEnv({ TOKENTIMER_AGENT_CONFIG_DIR: undefined }, () => {
      const resolved = resolveConfigDir(undefined);
      assert.ok(typeof resolved === "string" && resolved.length > 0);
      assert.ok(resolved.includes("tokentimer-agent"));
    });
  });
});

describe("ensureConfigDir", () => {
  it("creates the directory and does not throw", () => {
    const dir = makeTempConfigDir();
    assert.doesNotThrow(() => ensureConfigDir(dir));
    assert.ok(fs.existsSync(dir));
  });

  it("sets 0700 permissions on non-win32 platforms", { skip: IS_WIN32 }, () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    const mode = fs.statSync(dir).mode & 0o777;
    assert.equal(mode, 0o700);
  });

  it("re-asserts 0700 on every call even if the mode was loosened", { skip: IS_WIN32 }, () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.chmodSync(dir, 0o755);
    ensureConfigDir(dir);
    const mode = fs.statSync(dir).mode & 0o777;
    assert.equal(mode, 0o700);
  });

  it("is idempotent and safe to call repeatedly", () => {
    const dir = makeTempConfigDir();
    assert.doesNotThrow(() => {
      ensureConfigDir(dir);
      ensureConfigDir(dir);
      ensureConfigDir(dir);
    });
  });
});

describe("loadAgentConfig", () => {
  it("throws a clear error when serverUrl is missing", () => {
    const dir = makeTempConfigDir();
    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.throws(() => loadAgentConfig({ configDir: dir }), /serverUrl is required/);
    });
  });

  it("loads serverUrl and defaults from env vars when no config file exists", () => {
    const dir = makeTempConfigDir();
    withEnv(
      {
        TOKENTIMER_AGENT_SERVER_URL: "https://control-plane.example.com",
        TOKENTIMER_AGENT_HEARTBEAT_MS: undefined,
        TOKENTIMER_AGENT_POLL_MS: undefined,
      },
      () => {
        const config = loadAgentConfig({ configDir: dir });
        assert.equal(config.serverUrl, "https://control-plane.example.com");
        assert.equal(config.agentId, null);
        assert.equal(config.protocolVersion, "1.0.0");
        assert.equal(config.heartbeatIntervalMs, 30000);
        assert.equal(config.pollIntervalMs, 15000);
        assert.deepEqual(config.declaredTargetSelectors, []);
        assert.deepEqual(config.declaredCommandProfileNames, []);
      },
    );
  });

  it("env vars override values present in config.json", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://from-file.example.com",
        heartbeatIntervalMs: 99999,
      }),
      "utf8",
    );

    withEnv(
      {
        TOKENTIMER_AGENT_SERVER_URL: "https://from-env.example.com",
        TOKENTIMER_AGENT_HEARTBEAT_MS: "5000",
      },
      () => {
        const config = loadAgentConfig({ configDir: dir });
        assert.equal(config.serverUrl, "https://from-env.example.com");
        assert.equal(config.heartbeatIntervalMs, 5000);
      },
    );
  });

  it("falls back to config.json values when env vars are unset", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://from-file.example.com",
        pollIntervalMs: 4242,
      }),
      "utf8",
    );

    withEnv(
      {
        TOKENTIMER_AGENT_SERVER_URL: undefined,
        TOKENTIMER_AGENT_POLL_MS: undefined,
      },
      () => {
        const config = loadAgentConfig({ configDir: dir });
        assert.equal(config.serverUrl, "https://from-file.example.com");
        assert.equal(config.pollIntervalMs, 4242);
      },
    );
  });

  it("throws a descriptive error when agentId in config.json fails the schema pattern", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        agentId: "invalid agent id with spaces!",
      }),
      "utf8",
    );

    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.throws(() => loadAgentConfig({ configDir: dir }), /invalid agentId/);
    });
  });

  it("accepts a valid agentId matching the schema pattern", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        agentId: "agent-01.host_A:1",
      }),
      "utf8",
    );

    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      const config = loadAgentConfig({ configDir: dir });
      assert.equal(config.agentId, "agent-01.host_A:1");
    });
  });

  it("defaults policy to null and passes through a policy object from config.json", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://control-plane.example.com" }),
      "utf8",
    );

    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.equal(loadAgentConfig({ configDir: dir }).policy, null);
    });

    const policy = { allowedCommands: [{ name: "nginx-reload", command: "systemctl", args: ["reload", "nginx"] }] };
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ serverUrl: "https://control-plane.example.com", policy }),
      "utf8",
    );

    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.deepEqual(loadAgentConfig({ configDir: dir }).policy, policy);
    });
  });

  it("rejects a non-object policy in config.json", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        policy: ["not", "an", "object"],
      }),
      "utf8",
    );

    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.throws(
        () => loadAgentConfig({ configDir: dir }),
        /policy in config\.json must be an object/,
      );
    });
  });

  it("defaults discovery to null, applies the hourly default interval, and validates the shape", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    const configPath = path.join(dir, "config.json");

    fs.writeFileSync(
      configPath,
      JSON.stringify({ serverUrl: "https://control-plane.example.com" }),
      "utf8",
    );
    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.equal(loadAgentConfig({ configDir: dir }).discovery, null);
    });

    fs.writeFileSync(
      configPath,
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        discovery: { directories: ["/etc/nginx/tls"] },
      }),
      "utf8",
    );
    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      const { discovery } = loadAgentConfig({ configDir: dir });
      assert.deepEqual(discovery.directories, ["/etc/nginx/tls"]);
      assert.equal(discovery.intervalMs, 60 * 60 * 1000);
    });

    fs.writeFileSync(
      configPath,
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        discovery: { directories: ["/etc/nginx/tls"], intervalMs: -5 },
      }),
      "utf8",
    );
    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.throws(
        () => loadAgentConfig({ configDir: dir }),
        /discovery\.intervalMs must be a positive integer/,
      );
    });

    fs.writeFileSync(
      configPath,
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        discovery: "not-an-object",
      }),
      "utf8",
    );
    withEnv({ TOKENTIMER_AGENT_SERVER_URL: undefined }, () => {
      assert.throws(
        () => loadAgentConfig({ configDir: dir }),
        /discovery in config\.json must be an object/,
      );
    });
  });
});

describe("writeAgentIdentity / config.json round trip", () => {
  it("writes agentId and merges with existing config.json content without clobbering other fields", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({
        serverUrl: "https://control-plane.example.com",
        heartbeatIntervalMs: 12345,
      }),
      "utf8",
    );

    writeAgentIdentity(dir, { agentId: "agent-xyz" });

    const persisted = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
    assert.equal(persisted.agentId, "agent-xyz");
    assert.equal(persisted.serverUrl, "https://control-plane.example.com");
    assert.equal(persisted.heartbeatIntervalMs, 12345);
    assert.ok(!("credential" in persisted));
  });

  it("creates the config directory if it does not exist yet", () => {
    const dir = makeTempConfigDir();
    assert.ok(!fs.existsSync(dir));
    writeAgentIdentity(dir, { agentId: "agent-fresh" });
    assert.ok(fs.existsSync(path.join(dir, "config.json")));
  });

  it("rejects an invalid agentId before writing", () => {
    const dir = makeTempConfigDir();
    assert.throws(() => writeAgentIdentity(dir, { agentId: "bad id!" }), /invalid agentId/);
  });
});

describe("credential file round trip", () => {
  it("returns null from readCredential when the file does not exist", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    assert.equal(readCredential(dir), null);
  });

  it("round-trips write/read of the credential file, trimming whitespace", () => {
    const dir = makeTempConfigDir();
    const credential = "ttagent_agent-01_0123456789abcdef";
    writeCredential(dir, credential);

    const readBack = readCredential(dir);
    assert.equal(readBack, credential);
  });

  it("sets 0600 permissions on the credential file on non-win32 platforms", { skip: IS_WIN32 }, () => {
    const dir = makeTempConfigDir();
    writeCredential(dir, "ttagent_agent-01_0123456789abcdef");
    const mode = fs.statSync(path.join(dir, "credential")).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it("creates the config directory itself if missing", () => {
    const dir = makeTempConfigDir();
    assert.ok(!fs.existsSync(dir));
    writeCredential(dir, "ttagent_agent-01_0123456789abcdef");
    assert.ok(fs.existsSync(path.join(dir, "credential")));
  });

  it("rejects an empty credential", () => {
    const dir = makeTempConfigDir();
    assert.throws(() => writeCredential(dir, ""), /non-empty string/);
  });

  it("rejects a credential missing the ttagent_ prefix", () => {
    const dir = makeTempConfigDir();
    assert.throws(() => writeCredential(dir, "not-a-valid-credential"), /expected/);
  });

  it("rejects a non-string credential", () => {
    const dir = makeTempConfigDir();
    assert.throws(() => writeCredential(dir, 12345), /non-empty string/);
  });

  it("never includes the raw credential value in a thrown error message", () => {
    const dir = makeTempConfigDir();
    const secretMarker = "super-secret-marker-value";
    try {
      writeCredential(dir, secretMarker);
      assert.fail("expected writeCredential to throw for an invalid shape");
    } catch (err) {
      assert.ok(!String(err.message).includes(secretMarker));
    }
  });

  it("rotateCredential overwrites the previously stored credential", () => {
    const dir = makeTempConfigDir();
    writeCredential(dir, "ttagent_agent-01_0123456789abcdef");
    rotateCredential(dir, "ttagent_agent-01_fedcba9876543210");

    assert.equal(readCredential(dir), "ttagent_agent-01_fedcba9876543210");
  });

  it("rotateCredential validates the new credential shape before writing", () => {
    const dir = makeTempConfigDir();
    writeCredential(dir, "ttagent_agent-01_0123456789abcdef");
    assert.throws(() => rotateCredential(dir, "garbage"), /expected/);
    // The original credential must remain untouched after a rejected rotation.
    assert.equal(readCredential(dir), "ttagent_agent-01_0123456789abcdef");
  });
});

describe("redactCredentialForLogging", () => {
  it("always returns the fixed placeholder", () => {
    assert.equal(redactCredentialForLogging("ttagent_a_b"), "[AGENT_CREDENTIAL_REDACTED]");
  });

  it("never returns the input value verbatim for sample credential-like strings", () => {
    const samples = [
      "ttagent_agent-01_s3cr3t",
      "ttagent_agent-02_another-secret-value",
      "not-even-a-credential",
      "",
      "ttagent_" + "x".repeat(200),
    ];
    for (const sample of samples) {
      const redacted = redactCredentialForLogging(sample);
      assert.equal(redacted, "[AGENT_CREDENTIAL_REDACTED]");
      assert.notEqual(redacted, sample);
    }
  });

  it("returns the same placeholder regardless of input type", () => {
    assert.equal(redactCredentialForLogging(null), "[AGENT_CREDENTIAL_REDACTED]");
    assert.equal(redactCredentialForLogging(undefined), "[AGENT_CREDENTIAL_REDACTED]");
    assert.equal(redactCredentialForLogging(12345), "[AGENT_CREDENTIAL_REDACTED]");
  });
});

describe("registration persistence", () => {
  const registration = {
    agentId: "agent-registration-1",
    credential: "ttagent_agent-registration-1_0123456789abcdef",
  };

  it("atomically persists a validated identity and credential without leaving a journal", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ serverUrl: "https://cp.example.test" }));

    persistRegistration(dir, registration);

    assert.equal(loadAgentConfig({ configDir: dir }).agentId, registration.agentId);
    assert.equal(readCredential(dir), registration.credential);
    assert.equal(fs.existsSync(path.join(dir, "registration.pending.json")), false);
  });

  it("recovers a partial write from the durable pending-registration journal", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ serverUrl: "https://cp.example.test" }));
    fs.writeFileSync(path.join(dir, "registration.pending.json"), JSON.stringify(registration));
    // Simulate a crash after config.json was atomically renamed but before the
    // credential rename and pending-journal cleanup.
    writeAgentIdentity(dir, { agentId: registration.agentId });

    assert.deepEqual(recoverPendingRegistration(dir), registration);
    assert.equal(readCredential(dir), registration.credential);
    assert.equal(fs.existsSync(path.join(dir, "registration.pending.json")), false);
  });

  it("fails closed on a malformed pending-registration record", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    fs.writeFileSync(path.join(dir, "registration.pending.json"), "{bad json");
    assert.throws(() => recoverPendingRegistration(dir), /recovery failed/);
    assert.equal(readCredential(dir), null);
  });
});

describe("readCaBundle", () => {
  it("accepts a bounded public PEM certificate bundle", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    const bundlePath = path.join(dir, "private-ca.pem");
    fs.writeFileSync(bundlePath, "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n");
    assert.match(readCaBundle(bundlePath), /BEGIN CERTIFICATE/);
  });

  it("rejects private-key material and oversized bundles", () => {
    const dir = makeTempConfigDir();
    ensureConfigDir(dir);
    const keyBundlePath = path.join(dir, "key.pem");
    fs.writeFileSync(keyBundlePath, "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n");
    assert.throws(() => readCaBundle(keyBundlePath), /Private key material/);

    const oversizedPath = path.join(dir, "oversized.pem");
    fs.writeFileSync(oversizedPath, Buffer.alloc(MAX_CA_BUNDLE_BYTES + 1));
    assert.throws(() => readCaBundle(oversizedPath), /must be between 1 and/);
  });
});
