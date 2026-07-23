"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createDnsSolver } = require("../index.js");
const {
  validateCredentials,
  buildUpdateMessage,
  encodeName,
  encodeTxtRdata,
  buildTsigVariables,
  buildTsigRecord,
  computeResponseMac,
  parseTsigFromMessage,
  uint16,
} = require("./rfc2136.js");

const SECRET_BASE64 = Buffer.from("shared-secret").toString("base64"); // c2hhcmVkLXNlY3JldA==

const CREDENTIALS = {
  server: "ns1.example.com",
  keyName: "tsig-key",
  keySecretBase64: SECRET_BASE64,
};

const CHALLENGE = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  txtValue: "test-token-value",
};

const FIXED_MESSAGE_INPUTS = {
  zone: "example.com",
  recordName: "_acme-challenge.example.com",
  keyName: "tsig-key",
  keyAlgorithm: "hmac-sha256",
  keySecretBase64: SECRET_BASE64,
  messageId: 0x1234,
  timeSigned: 1700000000,
  fudge: 300,
};

/**
 * Builds a properly TSIG-signed UPDATE response for a given signed request,
 * using the same helpers the module itself exports. Options allow forging
 * (wrong id), signing with the wrong key, or omitting the TSIG entirely.
 */
function makeSignedResponse(
  requestMessage,
  {
    rcode = 0,
    id,
    secretBase64 = SECRET_BASE64,
    keyName = "tsig-key",
    keyAlgorithm = "hmac-sha256",
    unsigned = false,
  } = {},
) {
  const responseId = id !== undefined ? id : requestMessage.readUInt16BE(0);
  const flags = 0x8000 | (5 << 11) | (rcode & 0x0f);
  const headerWithoutTsig = Buffer.concat([
    uint16(responseId),
    uint16(flags),
    uint16(0),
    uint16(0),
    uint16(0),
    uint16(0),
  ]);
  if (unsigned) {
    return headerWithoutTsig;
  }

  const requestTsig = parseTsigFromMessage(requestMessage);
  const timeSigned = requestTsig.timeSigned;
  const fudge = 300;
  const mac = computeResponseMac({
    requestMac: requestTsig.mac,
    responseMessageWithoutTsig: headerWithoutTsig,
    tsigVariables: buildTsigVariables({ keyName, keyAlgorithm, timeSigned, fudge }),
    keyAlgorithm,
    keySecretBase64: secretBase64,
  });
  const tsigRecord = buildTsigRecord({
    keyName,
    keyAlgorithm,
    timeSigned,
    fudge,
    mac,
    originalId: responseId,
  });
  const signedHeader = Buffer.concat([
    uint16(responseId),
    uint16(flags),
    uint16(0),
    uint16(0),
    uint16(0),
    uint16(1),
  ]);
  return Buffer.concat([signedHeader, tsigRecord]);
}

/** @param {(request: Buffer) => Buffer} respond */
function makeDnsUpdateStub(respond) {
  const calls = [];
  async function dnsUpdateStub(options) {
    calls.push(options);
    return respond(options.message);
  }
  dnsUpdateStub.calls = calls;
  return dnsUpdateStub;
}

// ---------------------------------------------------------------------------
// credential validation
// ---------------------------------------------------------------------------

test("rfc2136: server, keyName, keySecretBase64 are required", () => {
  assert.throws(() => validateCredentials({ keyName: "k", keySecretBase64: SECRET_BASE64 }), /server/);
  assert.throws(() => validateCredentials({ server: "s", keySecretBase64: SECRET_BASE64 }), /keyName/);
  assert.throws(() => validateCredentials({ server: "s", keyName: "k" }), /keySecretBase64/);
});

test("rfc2136: invalid base64 secret throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, keySecretBase64: "!!!not-base64!!!" }),
    /not valid base64/,
  );
});

test("rfc2136: unsupported keyAlgorithm throws at construction", () => {
  assert.throws(
    () => validateCredentials({ ...CREDENTIALS, keyAlgorithm: "hmac-md5" }),
    /not supported/,
  );
});

test("rfc2136: port defaults to 53 and algorithm to hmac-sha256", () => {
  const normalized = validateCredentials(CREDENTIALS);
  assert.equal(normalized.port, 53);
  assert.equal(normalized.keyAlgorithm, "hmac-sha256");
});

// ---------------------------------------------------------------------------
// wire-format building blocks
// ---------------------------------------------------------------------------

test("rfc2136: encodeName produces uncompressed labels with a root terminator", () => {
  assert.equal(
    encodeName("example.com").toString("hex"),
    "076578616d706c6503636f6d00",
  );
});

test("rfc2136: encodeName treats a trailing dot as already-absolute", () => {
  assert.ok(encodeName("example.com.").equals(encodeName("example.com")));
});

test("rfc2136: encodeName rejects oversized labels", () => {
  assert.throws(() => encodeName(`${"a".repeat(64)}.com`), /invalid label/);
});

test("rfc2136: TXT rdata is split into 255-byte character-strings", () => {
  const short = encodeTxtRdata("abc");
  assert.equal(short.toString("hex"), "03616263");

  const long = encodeTxtRdata("x".repeat(300));
  assert.equal(long[0], 255);
  assert.equal(long[256], 45); // 300 - 255
  assert.equal(long.length, 1 + 255 + 1 + 45);
});

// ---------------------------------------------------------------------------
// stable TSIG message vectors (deterministic given messageId + timeSigned)
// ---------------------------------------------------------------------------

test("rfc2136: the signed present UPDATE matches the fixed wire vector", () => {
  const message = buildUpdateMessage({
    ...FIXED_MESSAGE_INPUTS,
    action: "present",
    txtValue: "test-token-value",
  });

  assert.equal(
    message.toString("hex"),
    "123428000001000000010001076578616d706c6503636f6d00000600010f5f61636d" +
      "652d6368616c6c656e6765076578616d706c6503636f6d00001000010000003c0011" +
      "10746573742d746f6b656e2d76616c756508747369672d6b65790000fa00ff000000" +
      "00003d0b686d61632d7368613235360000006553f100012c002061b96cd3d8993a46" +
      "82abab7b9bebee931cc3944d8ff37394086567132d968a81123400000000",
  );
});

test("rfc2136: the signed cleanup UPDATE deletes only the exact TXT RR (class NONE)", () => {
  const message = buildUpdateMessage({
    ...FIXED_MESSAGE_INPUTS,
    action: "cleanup",
    txtValue: "test-token-value",
  });

  // The update RR follows the 12-byte header + zone section
  // (encodeName("example.com") = 13 bytes + type(2) + class(2)).
  const updateOffset = 12 + 13 + 4;
  const nameLength = encodeName(FIXED_MESSAGE_INPUTS.recordName).length;
  assert.equal(message.readUInt16BE(updateOffset + nameLength), 16); // TXT
  assert.equal(message.readUInt16BE(updateOffset + nameLength + 2), 254); // NONE
  assert.equal(message.readUInt32BE(updateOffset + nameLength + 4), 0); // TTL
  const expectedRdata = encodeTxtRdata("test-token-value");
  assert.equal(message.readUInt16BE(updateOffset + nameLength + 8), expectedRdata.length);
  assert.ok(
    message
      .subarray(
        updateOffset + nameLength + 10,
        updateOffset + nameLength + 10 + expectedRdata.length,
      )
      .equals(expectedRdata),
  );
});

test("rfc2136: cleanup without a txtValue throws (programmer error)", () => {
  assert.throws(
    () => buildUpdateMessage({ ...FIXED_MESSAGE_INPUTS, action: "cleanup" }),
    /requires a txtValue/,
  );
});

test("rfc2136: the TSIG MAC is a stable HMAC for fixed inputs", () => {
  const message = buildUpdateMessage({
    ...FIXED_MESSAGE_INPUTS,
    action: "present",
    txtValue: "test-token-value",
  });
  // MAC is the 32 bytes preceding the trailing originalId+error+otherLen
  // (6 bytes) in the TSIG RDATA.
  const mac = message.subarray(message.length - 6 - 32, message.length - 6);
  assert.equal(
    mac.toString("hex"),
    "61b96cd3d8993a4682abab7b9bebee931cc3944d8ff37394086567132d968a81",
  );
});

test("rfc2136: present without a txtValue throws (programmer error)", () => {
  assert.throws(
    () => buildUpdateMessage({ ...FIXED_MESSAGE_INPUTS, action: "present" }),
    /requires a txtValue/,
  );
});

// ---------------------------------------------------------------------------
// solver behavior with an injected socket layer (no sockets ever opened)
// ---------------------------------------------------------------------------

test("rfc2136: present sends one UPDATE and succeeds on a correctly signed NOERROR", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) => makeSignedResponse(request));
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  assert.equal(dnsUpdateStub.calls.length, 1);
  const call = dnsUpdateStub.calls[0];
  assert.equal(call.host, "ns1.example.com");
  assert.equal(call.port, 53);
  assert.ok(Buffer.isBuffer(call.message));
  // Opcode UPDATE in the header flags.
  assert.equal(call.message.readUInt16BE(2) >>> 11, 5);
});

test("rfc2136: a signed REFUSED response maps to ok:false with the rcode name", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) => makeSignedResponse(request, { rcode: 5 }));
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /RCODE 5 \(REFUSED\)/);
});

test("rfc2136: a forged response with the wrong transaction ID maps to ok:false", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) =>
    makeSignedResponse(request, { id: (request.readUInt16BE(0) + 1) & 0xffff }),
  );
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /transaction ID/);
});

test("rfc2136: an unsigned response is rejected even with NOERROR", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) =>
    makeSignedResponse(request, { unsigned: true }),
  );
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /unsigned/);
});

test("rfc2136: a response signed with the wrong key fails MAC verification", async () => {
  const wrongSecret = Buffer.from("some-other-secret").toString("base64");
  const dnsUpdateStub = makeDnsUpdateStub((request) =>
    makeSignedResponse(request, { secretBase64: wrongSecret }),
  );
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /MAC verification failed/);
});

test("rfc2136: a response signed under a different key name is rejected", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) =>
    makeSignedResponse(request, { keyName: "other-key" }),
  );
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /key name does not match/);
});

test("rfc2136: a short/malformed response maps to ok:false", async () => {
  const dnsUpdateStub = makeDnsUpdateStub(() => Buffer.from([0x00, 0x01]));
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /malformed/);
});

test("rfc2136: a socket-layer rejection maps to ok:false, never a throw", async () => {
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: async () => {
      throw new Error("connect ECONNREFUSED 192.0.2.53:53");
    },
  });

  const result = await solver.presentChallenge(CHALLENGE);

  assert.equal(result.ok, false);
  assert.match(result.detail, /ECONNREFUSED/);
});

test("rfc2136: cleanup sends a class-NONE exact-RR delete (siblings preserved)", async () => {
  const dnsUpdateStub = makeDnsUpdateStub((request) => makeSignedResponse(request));
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: dnsUpdateStub,
  });

  const result = await solver.cleanupChallenge(CHALLENGE);

  assert.equal(result.ok, true);
  const message = dnsUpdateStub.calls[0].message;
  // The update RR follows the 12-byte header + zone section; its class is
  // NONE (254) with TTL 0 and the exact TXT rdata (RFC 2136 s2.5.4), so
  // only the challenge value is removed. Zone section length:
  // encodeName("example.com") = 13 bytes + type(2) + class(2).
  const updateOffset = 12 + 13 + 4;
  const nameLength = encodeName(CHALLENGE.recordName).length;
  assert.equal(message.readUInt16BE(updateOffset + nameLength), 16); // TXT
  assert.equal(message.readUInt16BE(updateOffset + nameLength + 2), 254); // NONE
  assert.equal(message.readUInt32BE(updateOffset + nameLength + 4), 0); // TTL
  const expectedRdata = encodeTxtRdata(CHALLENGE.txtValue);
  assert.equal(message.readUInt16BE(updateOffset + nameLength + 8), expectedRdata.length);
});

test("rfc2136: an error detail echoing the TSIG secret is redacted wholesale", async () => {
  const solver = createDnsSolver({
    provider: "rfc2136",
    credentials: CREDENTIALS,
    dnsUpdateImpl: async () => {
      throw new Error(`server rejected key ${SECRET_BASE64}`);
    },
  });

  const result = await solver.presentChallenge(CHALLENGE);
  assert.equal(result.detail, "[redacted]");
});
