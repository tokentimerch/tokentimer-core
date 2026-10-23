"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const zlib = require("node:zlib");
const { generateKeyPairSync } = require("node:crypto");

const { createAgentLogger, sanitizeLogValue } = require("./index.js");

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