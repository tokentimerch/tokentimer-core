"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  buildOrderedLogRecord,
  redactSensitiveFields,
  scrubLogString,
} = require(path.resolve(__dirname, "../../apps/api/utils/logger.js"));
const {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
} = require(path.resolve(__dirname, "../../apps/api/utils/secretMaterial.js"));

// Synthetic fixtures only. No real key material is committed.
const FAKE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const pem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_BODY}\n-----END ${label}-----`;

const NONCANONICAL_PRIVATE_KEY_PEMS = [
  {
    name: "lowercase PEM markers",
    value: `-----begin rsa private key-----\n${FAKE_BODY}\n-----end rsa private key-----`,
  },
  {
    name: "extra whitespace in markers",
    value: `-----BEGIN  RSA   PRIVATE   KEY-----\n${FAKE_BODY}\n-----END  RSA   PRIVATE   KEY-----`,
  },
  {
    name: "mixed-case encrypted markers",
    value: `-----BeGiN EnCrYpTeD PrIvAtE KeY-----\n${FAKE_BODY}\n-----eNd EnCrYpTeD PrIvAtE KeY-----`,
  },
];

function fakePkcs8PrivateKeyBuffer() {
  const value = Buffer.alloc(96);
  value[0] = 0x30;
  value[1] = 0x5e;
  value[2] = 0x02;
  value[3] = 0x01;
  value[4] = 0x00;
  value[5] = 0x30;
  return value;
}

function fakePkcs12Buffer() {
  return Buffer.concat([
    Buffer.from([0x30, 0x5c, 0x02, 0x01, 0x03]),
    Buffer.alloc(89, 0),
  ]);
}

describe("logger content-based redaction", () => {
  it("keeps field-name redaction as the first defense layer", () => {
    const out = redactSensitiveFields({
      password: "should-not-appear",
      private_key: pem("RSA PRIVATE KEY"),
      authorization: "Bearer leaked",
      cookie: "sid=abc",
      safe: "ok",
    });

    assert.equal(out.password, "[REDACTED]");
    assert.equal(out.private_key, "[REDACTED]");
    assert.equal(out.authorization, "[REDACTED]");
    assert.equal(out.cookie, "[REDACTED]");
    assert.equal(out.safe, "ok");
  });

  it("redacts raw PEM private keys in free-form strings", () => {
    const input = `command failed:\n${pem("RSA PRIVATE KEY")}\nretry`;
    const out = scrubLogString(input);

    assert.ok(out.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!out.includes(FAKE_BODY));
    assert.ok(out.startsWith("command failed:"));
    assert.ok(out.endsWith("retry"));
  });

  for (const fixture of NONCANONICAL_PRIVATE_KEY_PEMS) {
    it(`redacts ${fixture.name} in free-form strings`, () => {
      const out = scrubLogString(`before\n${fixture.value}\nafter`);

      assert.ok(out.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
      assert.ok(!out.includes(FAKE_BODY));
      assert.ok(!/private\s+key/i.test(out));
    });
  }

  it("redacts base64-wrapped PEM private keys", () => {
    const wrapped = Buffer.from(pem("PRIVATE KEY"), "utf8").toString("base64");
    assert.equal(scrubLogString(wrapped), PRIVATE_KEY_REDACTION_PLACEHOLDER);
  });

  it("redacts DER-like Buffer private key material where supported", () => {
    const der = fakePkcs8PrivateKeyBuffer();
    const pfx = fakePkcs12Buffer();

    assert.equal(
      redactSensitiveFields({ blob: der }).blob,
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
    assert.equal(
      redactSensitiveFields({ bundle: pfx }).bundle,
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
    assert.equal(
      scrubLogString(der.toString("base64")),
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
  });

  it("redacts private keys under innocent field names", () => {
    const key = pem("EC PRIVATE KEY");
    const out = redactSensitiveFields({
      output: key,
      response: `ok ${key}`,
      details: { stdout: key, stderr: "none" },
    });

    assert.equal(out.output, PRIVATE_KEY_REDACTION_PLACEHOLDER);
    assert.ok(out.response.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!out.response.includes(FAKE_BODY));
    assert.equal(out.details.stdout, PRIVATE_KEY_REDACTION_PLACEHOLDER);
    assert.equal(out.details.stderr, "none");
  });

  it("recurses arrays and nested objects", () => {
    const key = pem("PRIVATE KEY");
    const out = redactSensitiveFields({
      steps: [
        { log: `start ${key}` },
        ["plain", key, { nested: `Authorization: Bearer secret-token-value` }],
      ],
    });

    assert.ok(out.steps[0].log.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!out.steps[0].log.includes(FAKE_BODY));
    assert.equal(out.steps[1][0], "plain");
    assert.equal(out.steps[1][1], PRIVATE_KEY_REDACTION_PLACEHOLDER);
    assert.equal(
      out.steps[1][2].nested,
      "Authorization: [REDACTED]",
    );
  });

  it("scrubs Error.message and Error.stack while preserving stack frames", () => {
    const key = pem("RSA PRIVATE KEY");
    const err = new Error(`executor failed with ${key}`);
    err.stack = [
      `Error: executor failed with ${key}`,
      "    at runJob (apps/api/services/certops/jobs.js:10:5)",
      "    at processTicksAndRejections (node:internal/process/task_queues:95:5)",
    ].join("\n");

    const ordered = buildOrderedLogRecord({
      level: "error",
      message: err,
      service: "tokentimer-api",
      timestamp: "2026-07-15T12:00:00.000Z",
    });

    assert.equal(typeof ordered.message, "object");
    assert.ok(
      ordered.message.message.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER),
    );
    assert.ok(!ordered.message.message.includes(FAKE_BODY));
    assert.ok(
      ordered.message.stack.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER),
    );
    assert.ok(!ordered.message.stack.includes(FAKE_BODY));
    assert.match(
      ordered.message.stack,
      /at runJob \(apps\/api\/services\/certops\/jobs\.js:10:5\)/,
    );
    assert.match(
      ordered.message.stack,
      /at processTicksAndRejections \(node:internal\/process\/task_queues:95:5\)/,
    );
  });

  it("redacts generic bearer tokens, cookies, credentials, and secret assignments", () => {
    const input = [
      "Authorization: Bearer abc123tokenvalue",
      "Cookie: session=abc123",
      "Set-Cookie: sid=abc123; HttpOnly",
      "credential=super-secret-login",
      "password=swordfish",
      "client-secret: abc123",
      "AWS_SECRET_ACCESS_KEY=abc123",
      "token=abc123",
    ].join("\n");

    const out = scrubLogString(input);

    assert.ok(!out.includes("abc123tokenvalue"));
    assert.ok(!out.includes("swordfish"));
    assert.ok(!out.includes("super-secret-login"));
    assert.match(out, /Authorization: \[REDACTED\]/);
    assert.match(out, /Cookie: \[REDACTED\]/);
    assert.match(out, /Set-Cookie: \[REDACTED\]/);
    assert.match(out, /credential=\[REDACTED\]/);
    assert.match(out, /password=\[REDACTED\]/);
    assert.match(out, /client-secret: \[REDACTED\]/);
    assert.match(out, /AWS_SECRET_ACCESS_KEY=\[REDACTED\]/);
    assert.match(out, /token=\[REDACTED\]/);
  });

  it("scrubs free-form top-level message strings in ordered log records", () => {
    const key = pem("PRIVATE KEY");
    const ordered = buildOrderedLogRecord({
      level: "warn",
      message: `probe output contained ${key} and Authorization: Bearer leak-me`,
      service: "tokentimer-api",
      timestamp: "2026-07-15T12:00:00.000Z",
      details: { response: key },
    });

    assert.ok(ordered.message.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!ordered.message.includes(FAKE_BODY));
    assert.match(ordered.message, /Authorization: \[REDACTED\]/);
    assert.equal(ordered.details.response, PRIVATE_KEY_REDACTION_PLACEHOLDER);
  });

  it("leaves clean short strings unchanged", () => {
    assert.equal(scrubLogString("ok"), "ok");
    assert.equal(scrubLogString("certificate renew succeeded"), "certificate renew succeeded");
    assert.equal(scrubLogString(""), "");
  });
});
