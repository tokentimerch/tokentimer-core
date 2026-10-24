"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const zlib = require("node:zlib");
const {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} = require("node:crypto");

const { createAgentLogger, sanitizeLogValue } = require("./index.js");
const { scrubAgentLogText } = require("../../vendor/log-scrub/agent-log-text.js");

test("agent logger scrubs credentials, generic secrets, private material, and nested errors", () => {
  const lines = [];
  const logger = createAgentLogger({ sink: (line) => lines.push(line) });
  const nested = new Error("server returned Authorization: Bearer server-secret");
  nested.cause = new Error("credential=ttagent_agent-1_0123456789abcdef");

  logger.error("request failed", {
    credential: "ttagent_agent-1_0123456789abcdef",
    nested,
    serverBody: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
  });

  assert.equal(lines.length, 1);
  assert.doesNotMatch(lines[0], /0123456789abcdef|server-secret|BEGIN PRIVATE KEY/);
  assert.match(lines[0], /\[REDACTED\]|\[PRIVATE_KEY_REDACTED\]/);
});

test("agent logger never serializes error stacks or raw cyclic objects", () => {
  const value = { token: "secret" };
  value.self = value;
  const sanitized = sanitizeLogValue(value);
  assert.equal(sanitized.token, "[REDACTED]");
  assert.equal(sanitized.self, "[REDACTED:circular]");
});

test("agent logger prefixes every line with an ISO-8601 timestamp", () => {
  const errorLines = [];
  const infoLines = [];
  const logger = createAgentLogger({
    sink: (line) => errorLines.push(line),
    infoSink: (line) => infoLines.push(line),
  });

  logger.error("something failed", { errorMessage: "boom" });
  logger.info("job done");

  const isoPrefix = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z tokentimer-agent: /;
  assert.match(errorLines[0], isoPrefix);
  assert.match(errorLines[0], /something failed/);
  assert.match(infoLines[0], isoPrefix);
  assert.match(infoLines[0], /job done/);
});

test("agent logger warn routes to the error sink with the same scrubbing", () => {
  const lines = [];
  const logger = createAgentLogger({ sink: (line) => lines.push(line) });

  logger.warn("custody key not updated", { credential: "ttagent_agent-1_0123456789abcdef" });

  assert.equal(lines.length, 1);
  assert.match(lines[0], /custody key not updated/);
  assert.doesNotMatch(lines[0], /0123456789abcdef/);
});

test("agent logger redacts compact zlib-deflate Ed25519 material in message and metadata", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const wrapped = zlib
    .deflateSync(privateKey.export({ type: "pkcs8", format: "der" }))
    .toString("base64");
  assert.ok(Buffer.from(wrapped, "base64").length < 64, "sanity: compact under short-blob bound");

  assert.equal(sanitizeLogValue(wrapped), "[PRIVATE_KEY_REDACTED]");
  assert.deepEqual(sanitizeLogValue({ attachment: wrapped }), {
    attachment: "[PRIVATE_KEY_REDACTED]",
  });

  const lines = [];
  const logger = createAgentLogger({ sink: (line) => lines.push(line) });
  logger.error(wrapped, { attachment: wrapped });

  assert.equal(lines.length, 1);
  assert.doesNotMatch(lines[0], new RegExp(wrapped.replace(/[+/=]/g, "\\$&")));
  assert.match(lines[0], /\[PRIVATE_KEY_REDACTED\]/);
});

test("agent logger and console reject short nested private material in both alphabets", () => {
  // A valid disposable key with a repeated fresh seed half exercises the
  // compact nested case; input entropy is not an acceptance requirement.
  const half = randomBytes(16);
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      half,
      half,
    ]),
    type: "pkcs8",
    format: "der",
  });
  const message = Buffer.from("disposable logger regression");
  assert.equal(
    verify(null, message, createPublicKey(key), sign(null, message, key)),
    true,
  );
  const nested = zlib.deflateSync(
    zlib.deflateSync(key.export({ type: "pkcs8", format: "der" })),
  );
  assert.ok(nested.length < 64, "fixture must exercise the short stream branch");
  for (const encoding of ["base64", "base64url"]) {
    const value = nested.toString(encoding);
    assert.equal(sanitizeLogValue(value) === "[PRIVATE_KEY_REDACTED]", true);
    assert.equal(
      sanitizeLogValue({ attachment: value }).attachment === "[PRIVATE_KEY_REDACTED]",
      true,
    );
    const lines = [];
    createAgentLogger({ sink: (line) => lines.push(line) }).error(value, {
      attachment: value,
    });
    assert.equal(lines.length, 1);
    assert.equal(lines[0].includes(value), false);
    const consoleLine = scrubAgentLogText(value);
    assert.equal(consoleLine.rejected, true);
    assert.equal(consoleLine.text === "[PRIVATE_KEY_REDACTED]", true);
  }
});

test("agent logger and console retain the short-stream output budget", () => {
  for (const compress of [zlib.deflateSync, zlib.gzipSync]) {
    const compressed = compress(Buffer.alloc(512, 0x41));
    assert.ok(compressed.length < 64, "fixture must exercise the short stream branch");
    for (const encoding of ["base64", "base64url"]) {
      const value = compressed.toString(encoding);
      assert.equal(sanitizeLogValue(value), "[PRIVATE_KEY_REDACTED]");
      assert.equal(scrubAgentLogText(value).rejected, true);
    }
  }
});

test("agent logger and console preserve short header-shaped identifiers", () => {
  for (const prefix of [[0x78, 0x9c], [0x78, 0xbb], [0x1f, 0x8b, 0x08, 0x00]]) {
    const identifier = Buffer.concat([Buffer.from(prefix), Buffer.alloc(28, 0xff)]);
    for (const encoding of ["base64", "base64url"]) {
      const value = identifier.toString(encoding);
      assert.equal(sanitizeLogValue(value), value);
      const consoleLine = scrubAgentLogText(value);
      assert.equal(consoleLine.rejected, false);
      assert.equal(consoleLine.text, value);
    }
  }
});
