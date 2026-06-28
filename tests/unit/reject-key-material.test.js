"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_KEY_MATERIAL_REJECTED,
  CERTOPS_SECURITY_AUDIT_UNAVAILABLE,
  PRIVATE_KEY_MATERIAL_REJECTED,
  createRejectKeyMaterialMiddleware,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/reject-key-material.js"),
);
const { logger } = require(
  path.resolve(__dirname, "../../apps/api/utils/logger.js"),
);

const FAKE_PRIVATE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const fakePem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_PRIVATE_BODY}\n-----END ${label}-----`;

const NONCANONICAL_PRIVATE_KEY_PEMS = [
  `-----begin rsa private key-----\n${FAKE_PRIVATE_BODY}\n-----end rsa private key-----`,
  `-----BEGIN  RSA   PRIVATE   KEY-----\n${FAKE_PRIVATE_BODY}\n-----END  RSA   PRIVATE   KEY-----`,
  `-----BeGiN EnCrYpTeD PrIvAtE KeY-----\n${FAKE_PRIVATE_BODY}\n-----eNd EnCrYpTeD PrIvAtE KeY-----`,
];

const PUBLIC_CERTIFICATE_PEM = fakePem("CERTIFICATE");
const PUBLIC_KEY_PEM = fakePem("PUBLIC KEY");

function fakePkcs12Buffer() {
  return Buffer.concat([
    Buffer.from([0x30, 0x5c, 0x02, 0x01, 0x03]),
    Buffer.alloc(89, 0),
  ]);
}

function deeplyNested(value, depth = 14) {
  let node = value;
  for (let index = 0; index < depth; index += 1) {
    node = { child: node };
  }
  return node;
}

const WORKSPACE_ID = "550e8400-e29b-41d4-a716-446655440000";

async function runMiddleware(body, options = {}) {
  let statusCode = null;
  let responseBody = null;
  let nextCalled = false;
  const auditEvents = [];
  const order = [];
  const req = {
    body,
    method: "POST",
    params: { id: WORKSPACE_ID },
    path: "/api/v1/workspaces/:id/certops/imports",
    user: { id: 123 },
    ...(options.req || {}),
  };
  const auditWriter =
    options.auditWriter ||
    (async (event) => {
      order.push("audit");
      auditEvents.push(event);
    });
  const res = {
    status(code) {
      order.push("status");
      statusCode = code;
      return this;
    },
    json(payload) {
      order.push("json");
      responseBody = payload;
      return this;
    },
  };
  const middleware = createRejectKeyMaterialMiddleware({ auditWriter });

  await middleware(req, res, () => {
    order.push("next");
    nextCalled = true;
  });

  return { auditEvents, nextCalled, order, responseBody, statusCode };
}

async function assertRejected(body, options) {
  const result = await runMiddleware(body, options);

  assert.equal(result.nextCalled, false);
  assert.equal(result.statusCode, 422);
  assert.deepEqual(result.responseBody, {
    error: "Private key material is not accepted in CertOps requests",
    code: PRIVATE_KEY_MATERIAL_REJECTED,
  });
  if (options?.expectAuditEvent !== false) {
    assert.equal(result.auditEvents.length, 1);
  }
  return result;
}

async function assertAllowed(body) {
  const result = await runMiddleware(body);

  assert.equal(result.nextCalled, true);
  assert.equal(result.statusCode, null);
  assert.equal(result.responseBody, null);
  assert.deepEqual(result.auditEvents, []);
}

describe("rejectKeyMaterial middleware", () => {
  it("rejects a direct private key field", async () => {
    await assertRejected({ certificate: fakePem("RSA PRIVATE KEY") });
  });

  it("rejects noncanonical private key PEM armor", async () => {
    await assertRejected({ certificate: NONCANONICAL_PRIVATE_KEY_PEMS[0] });
  });

  it("rejects nested private key material", async () => {
    await assertRejected({
      import: {
        notes: "nested payload",
        certificate: { pem: fakePem("EC PRIVATE KEY") },
      },
    });
  });

  it("rejects nested noncanonical private key material", async () => {
    await assertRejected({
      import: {
        notes: "nested payload",
        certificate: { pem: NONCANONICAL_PRIVATE_KEY_PEMS[1] },
      },
    });
  });

  it("rejects array-contained private key material", async () => {
    await assertRejected({
      certificates: [PUBLIC_CERTIFICATE_PEM, fakePem("PRIVATE KEY")],
    });
  });

  it("rejects array-contained noncanonical private key material", async () => {
    await assertRejected({
      certificates: [PUBLIC_CERTIFICATE_PEM, NONCANONICAL_PRIVATE_KEY_PEMS[2]],
    });
  });

  it("rejects base64-wrapped private key PEM", async () => {
    const wrapped = Buffer.from(fakePem("ENCRYPTED PRIVATE KEY")).toString(
      "base64",
    );

    await assertRejected({ attachment: wrapped });
  });

  it("rejects base64-wrapped noncanonical private key PEM", async () => {
    const wrapped = Buffer.from(NONCANONICAL_PRIVATE_KEY_PEMS[2]).toString(
      "base64",
    );

    await assertRejected({ attachment: wrapped });
  });

  it("rejects buffer request bodies carrying noncanonical private key PEM", async () => {
    await assertRejected(Buffer.from(NONCANONICAL_PRIVATE_KEY_PEMS[1]));
  });

  it("rejects PKCS#12/PFX-like binary request bodies", async () => {
    await assertRejected(fakePkcs12Buffer());
  });

  it("rejects base64-wrapped PKCS#12/PFX-like payloads", async () => {
    await assertRejected({ bundle: fakePkcs12Buffer().toString("base64") });
  });

  it("allows public certificate PEM input", async () => {
    await assertAllowed({ certificatePem: PUBLIC_CERTIFICATE_PEM });
  });

  it("allows public key PEM input", async () => {
    await assertAllowed({ publicKeyPem: PUBLIC_KEY_PEM });
  });

  it("allows malformed non-key input", async () => {
    await assertAllowed({
      certificatePem: "not a certificate and not private key material",
    });
  });

  it("rejects over-depth request bodies without echoing nested content", async () => {
    const nestedPayload = "harmless but too deeply nested";
    const result = await assertRejected(deeplyNested(nestedPayload));

    assert.equal(
      JSON.stringify(result.responseBody).includes(nestedPayload),
      false,
    );
  });

  it("records a synchronous audit event without alert_queue dependency", async () => {
    const result = await assertRejected({
      payload: fakePem("RSA PRIVATE KEY"),
    });
    const auditEvent = result.auditEvents[0];

    assert.deepEqual(result.order, ["audit", "status", "json"]);
    assert.equal(auditEvent.action, CERTOPS_KEY_MATERIAL_REJECTED);
    assert.equal(auditEvent.actorUserId, 123);
    assert.equal(auditEvent.subjectUserId, 123);
    assert.equal(auditEvent.targetType, "certops_request");
    assert.equal(auditEvent.workspaceId, WORKSPACE_ID);
    assert.equal(auditEvent.metadata.code, PRIVATE_KEY_MATERIAL_REJECTED);
    assert.equal(auditEvent.metadata.method, "POST");
    assert.equal(auditEvent.metadata.body_type, "object");
    assert.equal(JSON.stringify(auditEvent).includes("alert_queue"), false);
    assert.equal(JSON.stringify(auditEvent).includes(FAKE_PRIVATE_BODY), false);
  });

  it("records tokenless rejection events without requiring a user or alert queue", async () => {
    const result = await assertRejected(
      { payload: fakePem("RSA PRIVATE KEY") },
      { req: { user: null } },
    );
    const auditEvent = result.auditEvents[0];

    assert.equal(auditEvent.action, CERTOPS_KEY_MATERIAL_REJECTED);
    assert.equal(auditEvent.actorUserId, null);
    assert.equal(auditEvent.subjectUserId, null);
    assert.equal(auditEvent.workspaceId, WORKSPACE_ID);
    assert.equal(JSON.stringify(auditEvent).includes("alert_queue"), false);
  });

  it("fails closed when audit recording fails", async () => {
    const privateKey = fakePem("RSA PRIVATE KEY");
    const warnings = [];
    const originalWarn = logger.warn;
    logger.warn = (message, meta) => {
      warnings.push({ message, meta });
    };

    try {
      const result = await runMiddleware(
        { payload: privateKey },
        {
          auditWriter: async () => {
            throw new Error(`audit unavailable ${privateKey}`);
          },
        },
      );

      assert.equal(result.nextCalled, false);
      assert.equal(result.statusCode, 503);
      assert.deepEqual(result.responseBody, {
        error: "Security audit unavailable",
        code: CERTOPS_SECURITY_AUDIT_UNAVAILABLE,
      });
      assert.deepEqual(Object.keys(result.responseBody).sort(), [
        "code",
        "error",
      ]);
      assert.equal(JSON.stringify(result.responseBody).includes(privateKey), false);
      assert.equal(JSON.stringify(result.responseBody).includes(FAKE_PRIVATE_BODY), false);

      assert.equal(warnings.length, 1);
      assert.equal(
        warnings[0].message,
        "Failed to record CertOps key-material rejection audit",
      );
      assert.equal(JSON.stringify(warnings).includes(privateKey), false);
      assert.equal(JSON.stringify(warnings).includes(FAKE_PRIVATE_BODY), false);
      assert.equal(warnings[0].meta.method, "POST");
      assert.equal(warnings[0].meta.path, "/api/v1/workspaces/:id/certops/imports");
    } finally {
      logger.warn = originalWarn;
    }
  });

  it("does not echo private key material in the response", async () => {
    const privateKey = fakePem("RSA PRIVATE KEY");
    const result = await assertRejected({ payload: privateKey });
    const serialized = JSON.stringify(result.responseBody);

    assert.equal(serialized.includes(privateKey), false);
    assert.equal(serialized.includes(FAKE_PRIVATE_BODY), false);
  });

  it("does not echo noncanonical private key material in the response", async () => {
    const privateKey = NONCANONICAL_PRIVATE_KEY_PEMS[0];
    const result = await assertRejected({ payload: privateKey });
    const serialized = JSON.stringify(result.responseBody);

    assert.equal(serialized.includes(privateKey), false);
    assert.equal(serialized.includes(FAKE_PRIVATE_BODY), false);
  });

  it("does not introduce private-key-looking response fields", async () => {
    const result = await assertRejected({ payload: fakePem("PRIVATE KEY") });
    const responseKeys = Object.keys(result.responseBody);

    assert.deepEqual(responseKeys.sort(), ["code", "error"]);
  });
});
