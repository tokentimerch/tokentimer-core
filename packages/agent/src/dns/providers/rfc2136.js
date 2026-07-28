"use strict";

/**
 * RFC 2136 dynamic DNS UPDATE provider with TSIG (RFC 8945).
 *
 * Speaks the DNS wire format directly over TCP port 53 (node:net +
 * node:crypto only): one UPDATE message per operation, authenticated with
 * a TSIG HMAC. Works against BIND, Knot, PowerDNS, and anything else that
 * accepts TSIG-signed dynamic updates. Scope the TSIG key with an
 * update-policy limited to _acme-challenge TXT records where the server
 * supports it.
 *
 * Credentials shape:
 *   {
 *     server: string,               // authoritative server host/IP
 *     port?: number,                // default 53
 *     keyName: string,              // TSIG key name
 *     keyAlgorithm?: string,        // default "hmac-sha256"
 *     keySecretBase64: string,      // TSIG shared secret, base64
 *   }
 *
 * Message shapes:
 *   present: UPDATE adding  <recordName> 60 IN TXT "<txtValue>"
 *   cleanup: UPDATE deleting ONLY the exact TXT RR carrying the challenge
 *            value (CLASS NONE, TTL 0, RDATA = the value, RFC 2136
 *            s2.5.4) so sibling TXT values at the name survive.
 *
 * Responses are fully verified before being trusted: transaction ID, QR
 * bit, opcode, and the response TSIG MAC (RFC 8945 s5.3: HMAC over the
 * 2-byte length-prefixed request MAC, the response with the TSIG RR
 * removed and ARCOUNT decremented and the original ID restored, then the
 * TSIG variables). Unsigned, forged, or mis-signed responses are
 * operational failures (ok:false), never accepted.
 *
 * The socket layer is injectable (dnsUpdateImpl) so tests never open
 * sockets; buildUpdateMessage is deterministic given messageId +
 * timeSigned, so tests can assert a stable TSIG HMAC for fixed inputs.
 */

const crypto = require("node:crypto");
const net = require("node:net");

const { isNonEmptyString } = require("../internal.js");

const PROVIDER_ID = "rfc2136";
const DEFAULT_PORT = 53;
const DEFAULT_KEY_ALGORITHM = "hmac-sha256";
const DEFAULT_FUDGE_SECONDS = 300;
const TXT_TTL_SECONDS = 60;

const TYPE_TXT = 16;
const TYPE_SOA = 6;
const TYPE_TSIG = 250;
const CLASS_IN = 1;
const CLASS_NONE = 254;
const CLASS_ANY = 255;
const OPCODE_UPDATE = 5;

/** TSIG algorithm name -> node:crypto HMAC hash name. */
const TSIG_ALGORITHMS = Object.freeze({
  "hmac-sha1": "sha1",
  "hmac-sha224": "sha224",
  "hmac-sha256": "sha256",
  "hmac-sha384": "sha384",
  "hmac-sha512": "sha512",
});

const RCODE_NAMES = Object.freeze({
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  6: "YXDOMAIN",
  7: "YXRRSET",
  8: "NXRRSET",
  9: "NOTAUTH",
  10: "NOTZONE",
});

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.server)) {
    throw new Error("dns: rfc2136 credentials require a non-empty server string");
  }
  if (
    credentials.port !== undefined &&
    (!Number.isInteger(credentials.port) || credentials.port <= 0 || credentials.port > 65535)
  ) {
    throw new Error(
      `dns: rfc2136 port must be an integer in 1..65535, got ${JSON.stringify(credentials.port)}`,
    );
  }
  if (!isNonEmptyString(credentials.keyName)) {
    throw new Error("dns: rfc2136 credentials require a non-empty keyName string");
  }

  const keyAlgorithm = credentials.keyAlgorithm || DEFAULT_KEY_ALGORITHM;
  if (!TSIG_ALGORITHMS[keyAlgorithm]) {
    throw new Error(
      `dns: rfc2136 keyAlgorithm ${JSON.stringify(keyAlgorithm)} is not supported; ` +
        `supported: ${Object.keys(TSIG_ALGORITHMS).join(", ")}`,
    );
  }

  if (!isNonEmptyString(credentials.keySecretBase64)) {
    throw new Error("dns: rfc2136 credentials require a non-empty keySecretBase64 string");
  }
  const keySecret = Buffer.from(credentials.keySecretBase64, "base64");
  if (
    keySecret.length === 0 ||
    keySecret.toString("base64").replace(/=+$/, "") !==
      credentials.keySecretBase64.replace(/\s+/g, "").replace(/=+$/, "")
  ) {
    throw new Error("dns: rfc2136 keySecretBase64 is not valid base64");
  }

  return {
    server: credentials.server,
    port: credentials.port || DEFAULT_PORT,
    keyName: credentials.keyName,
    keyAlgorithm,
    keySecretBase64: credentials.keySecretBase64,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [credentials.keySecretBase64];
}

// --------------------------------------------------------------------------
// Wire-format encoding (exported pieces are used by the stable-HMAC test)
// --------------------------------------------------------------------------

/**
 * Encodes a domain name in uncompressed DNS wire format (RFC 1035 s3.1).
 * @param {string} name
 * @returns {Buffer}
 */
function encodeName(name) {
  const trimmed = name.endsWith(".") ? name.slice(0, -1) : name;
  const parts = [];
  if (trimmed.length > 0) {
    for (const label of trimmed.split(".")) {
      const labelBytes = Buffer.from(label, "ascii");
      if (labelBytes.length === 0 || labelBytes.length > 63) {
        throw new Error(`dns: rfc2136 invalid label in name ${JSON.stringify(name)}`);
      }
      parts.push(Buffer.from([labelBytes.length]), labelBytes);
    }
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function uint16(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
}

function uint32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

/** 48-bit big-endian (TSIG time signed). */
function uint48(value) {
  const buffer = Buffer.alloc(6);
  buffer.writeUIntBE(value, 0, 6);
  return buffer;
}

/** TXT RDATA: one or more <character-string>s of at most 255 bytes each. */
function encodeTxtRdata(txtValue) {
  const bytes = Buffer.from(txtValue, "utf8");
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += 255) {
    const chunk = bytes.subarray(offset, offset + 255);
    chunks.push(Buffer.from([chunk.length]), chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * TSIG "variables" block covered by every TSIG MAC (RFC 8945 s4.3.3):
 * canonical key name, class ANY, TTL 0, algorithm name, time signed,
 * fudge, error, other-len/other-data.
 *
 * @param {object} options
 * @param {string} options.keyName
 * @param {string} options.keyAlgorithm
 * @param {number} options.timeSigned epoch seconds
 * @param {number} options.fudge
 * @param {number} [options.error]
 * @param {Buffer} [options.otherData]
 * @returns {Buffer}
 */
function buildTsigVariables({
  keyName,
  keyAlgorithm,
  timeSigned,
  fudge,
  error = 0,
  otherData = Buffer.alloc(0),
}) {
  return Buffer.concat([
    encodeName(keyName.toLowerCase()),
    uint16(CLASS_ANY),
    uint32(0),
    encodeName(keyAlgorithm.toLowerCase()),
    uint48(timeSigned),
    uint16(fudge),
    uint16(error),
    uint16(otherData.length),
    otherData,
  ]);
}

/**
 * One complete TSIG RR (name through RDATA) for the additional section.
 *
 * @param {object} options
 * @param {string} options.keyName
 * @param {string} options.keyAlgorithm
 * @param {number} options.timeSigned
 * @param {number} options.fudge
 * @param {Buffer} options.mac
 * @param {number} options.originalId
 * @param {number} [options.error]
 * @param {Buffer} [options.otherData]
 * @returns {Buffer}
 */
function buildTsigRecord({
  keyName,
  keyAlgorithm,
  timeSigned,
  fudge,
  mac,
  originalId,
  error = 0,
  otherData = Buffer.alloc(0),
}) {
  const tsigRdata = Buffer.concat([
    encodeName(keyAlgorithm.toLowerCase()),
    uint48(timeSigned),
    uint16(fudge),
    uint16(mac.length),
    mac,
    uint16(originalId),
    uint16(error),
    uint16(otherData.length),
    otherData,
  ]);
  return Buffer.concat([
    encodeName(keyName.toLowerCase()),
    uint16(TYPE_TSIG),
    uint16(CLASS_ANY),
    uint32(0),
    uint16(tsigRdata.length),
    tsigRdata,
  ]);
}

/**
 * Response TSIG MAC per RFC 8945 s5.3: HMAC over the 2-byte
 * length-prefixed request MAC, the response message with the TSIG RR
 * removed (ARCOUNT decremented, original ID restored), and the TSIG
 * variables.
 *
 * @param {object} options
 * @param {Buffer} options.requestMac
 * @param {Buffer} options.responseMessageWithoutTsig
 * @param {Buffer} options.tsigVariables
 * @param {string} options.keyAlgorithm one of TSIG_ALGORITHMS keys
 * @param {string} options.keySecretBase64
 * @returns {Buffer}
 */
function computeResponseMac({
  requestMac,
  responseMessageWithoutTsig,
  tsigVariables,
  keyAlgorithm,
  keySecretBase64,
}) {
  return crypto
    .createHmac(TSIG_ALGORITHMS[keyAlgorithm], Buffer.from(keySecretBase64, "base64"))
    .update(
      Buffer.concat([
        uint16(requestMac.length),
        requestMac,
        responseMessageWithoutTsig,
        tsigVariables,
      ]),
    )
    .digest();
}

/**
 * Builds one complete, TSIG-signed DNS UPDATE message (without the TCP
 * length prefix) and returns it together with its request MAC (needed to
 * verify the response TSIG). Deterministic given messageId + timeSigned,
 * which is what makes the TSIG HMAC test vector stable.
 *
 * Per RFC 8945 s4.3.3 the MAC covers the unsigned message (ARCOUNT still
 * excluding the TSIG RR) followed by the TSIG variables (key name, class
 * ANY, TTL 0, algorithm name, time signed, fudge, error 0, other-len 0);
 * the TSIG RR itself is then appended and ARCOUNT incremented.
 *
 * @param {object} options
 * @param {"present"|"cleanup"} options.action
 * @param {string} options.zone
 * @param {string} options.recordName
 * @param {string} options.txtValue required for both actions (cleanup
 *   deletes only the exact RR carrying this value)
 * @param {string} options.keyName
 * @param {string} options.keyAlgorithm one of TSIG_ALGORITHMS keys
 * @param {string} options.keySecretBase64
 * @param {number} options.messageId 0..65535
 * @param {number} options.timeSigned epoch seconds
 * @param {number} [options.fudge] default 300
 * @returns {{ message: Buffer, mac: Buffer }}
 */
function buildSignedUpdate({
  action,
  zone,
  recordName,
  txtValue,
  keyName,
  keyAlgorithm,
  keySecretBase64,
  messageId,
  timeSigned,
  fudge = DEFAULT_FUDGE_SECONDS,
}) {
  if (action !== "present" && action !== "cleanup") {
    throw new Error(`dns: rfc2136 unknown update action ${JSON.stringify(action)}`);
  }
  if (!isNonEmptyString(txtValue)) {
    throw new Error(`dns: rfc2136 ${action} requires a txtValue`);
  }

  // Header: ZOCOUNT=1 (zone), PRCOUNT=0, UPCOUNT=1, ADCOUNT=0 (pre-TSIG).
  const header = Buffer.concat([
    uint16(messageId),
    uint16(OPCODE_UPDATE << 11),
    uint16(1),
    uint16(0),
    uint16(1),
    uint16(0),
  ]);

  // Zone section: <zone> SOA IN.
  const zoneSection = Buffer.concat([encodeName(zone), uint16(TYPE_SOA), uint16(CLASS_IN)]);

  // Update section.
  const rdata = encodeTxtRdata(txtValue);
  let updateRecord;
  if (action === "present") {
    updateRecord = Buffer.concat([
      encodeName(recordName),
      uint16(TYPE_TXT),
      uint16(CLASS_IN),
      uint32(TXT_TTL_SECONDS),
      uint16(rdata.length),
      rdata,
    ]);
  } else {
    // Delete ONLY the exact TXT RR carrying the challenge value: CLASS
    // NONE, TTL 0, RDATA = the value (RFC 2136 s2.5.4). Sibling TXT
    // values at the name are preserved.
    updateRecord = Buffer.concat([
      encodeName(recordName),
      uint16(TYPE_TXT),
      uint16(CLASS_NONE),
      uint32(0),
      uint16(rdata.length),
      rdata,
    ]);
  }

  const unsignedMessage = Buffer.concat([header, zoneSection, updateRecord]);

  // TSIG variables covered by the MAC.
  const tsigVariables = buildTsigVariables({ keyName, keyAlgorithm, timeSigned, fudge });

  const mac = crypto
    .createHmac(TSIG_ALGORITHMS[keyAlgorithm], Buffer.from(keySecretBase64, "base64"))
    .update(Buffer.concat([unsignedMessage, tsigVariables]))
    .digest();

  // TSIG RR appended to the additional section.
  const tsigRecord = buildTsigRecord({
    keyName,
    keyAlgorithm,
    timeSigned,
    fudge,
    mac,
    originalId: messageId,
  });

  // Final message: same header with ADCOUNT=1.
  const signedHeader = Buffer.concat([
    uint16(messageId),
    uint16(OPCODE_UPDATE << 11),
    uint16(1),
    uint16(0),
    uint16(1),
    uint16(1),
  ]);

  return {
    message: Buffer.concat([signedHeader, zoneSection, updateRecord, tsigRecord]),
    mac,
  };
}

/**
 * Back-compat wrapper returning only the wire message.
 * @param {Parameters<typeof buildSignedUpdate>[0]} options
 * @returns {Buffer}
 */
function buildUpdateMessage(options) {
  return buildSignedUpdate(options).message;
}

// --------------------------------------------------------------------------
// Response parsing + TSIG verification (RFC 8945 s5.3)
// --------------------------------------------------------------------------

/**
 * Skips one wire-format name starting at `offset`, following the RFC 1035
 * rules (a compression pointer terminates the name). Throws on truncation.
 * @param {Buffer} buffer
 * @param {number} offset
 * @returns {number} offset just past the name
 */
function skipEncodedName(buffer, offset) {
  for (;;) {
    if (offset >= buffer.length) {
      throw new Error("dns: rfc2136 truncated name in DNS message");
    }
    const length = buffer[offset];
    if (length === 0) {
      return offset + 1;
    }
    if ((length & 0xc0) === 0xc0) {
      if (offset + 2 > buffer.length) {
        throw new Error("dns: rfc2136 truncated compression pointer in DNS message");
      }
      return offset + 2;
    }
    offset += 1 + length;
  }
}

/**
 * Reads a wire-format name (following compression pointers) into its
 * dotted lowercase text form. Throws on truncation or pointer loops.
 * @param {Buffer} buffer
 * @param {number} offset
 * @returns {string}
 */
function readEncodedName(buffer, offset) {
  const labels = [];
  let jumps = 0;
  for (;;) {
    if (offset >= buffer.length) {
      throw new Error("dns: rfc2136 truncated name in DNS message");
    }
    const length = buffer[offset];
    if (length === 0) {
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (offset + 2 > buffer.length) {
        throw new Error("dns: rfc2136 truncated compression pointer in DNS message");
      }
      jumps += 1;
      if (jumps > 32) {
        throw new Error("dns: rfc2136 compression pointer loop in DNS message");
      }
      offset = ((length & 0x3f) << 8) | buffer[offset + 1];
      continue;
    }
    if (offset + 1 + length > buffer.length) {
      throw new Error("dns: rfc2136 truncated label in DNS message");
    }
    labels.push(buffer.subarray(offset + 1, offset + 1 + length).toString("ascii"));
    offset += 1 + length;
  }
  return labels.join(".").toLowerCase();
}

/**
 * Locates and parses the TSIG record in a DNS message's additional
 * section. Returns null when the message carries no TSIG; throws on a
 * structurally malformed message.
 *
 * @param {Buffer} message
 * @returns {null | {
 *   recordStart: number,
 *   recordEnd: number,
 *   keyName: string,
 *   algorithmName: string,
 *   timeSigned: number,
 *   fudge: number,
 *   mac: Buffer,
 *   originalId: number,
 *   error: number,
 *   otherData: Buffer,
 * }}
 */
function parseTsigFromMessage(message) {
  if (message.length < 12) {
    throw new Error("dns: rfc2136 DNS message shorter than a header");
  }
  const zoCount = message.readUInt16BE(4);
  const prCount = message.readUInt16BE(6);
  const upCount = message.readUInt16BE(8);
  const adCount = message.readUInt16BE(10);

  let offset = 12;
  // Zone/question section entries: name + type(2) + class(2).
  for (let i = 0; i < zoCount; i += 1) {
    offset = skipEncodedName(message, offset) + 4;
  }
  // Full resource records: name + type/class/ttl/rdlength(10) + rdata.
  function skipRecord(startOffset) {
    const afterName = skipEncodedName(message, startOffset);
    if (afterName + 10 > message.length) {
      throw new Error("dns: rfc2136 truncated resource record in DNS message");
    }
    const rdLength = message.readUInt16BE(afterName + 8);
    const end = afterName + 10 + rdLength;
    if (end > message.length) {
      throw new Error("dns: rfc2136 truncated RDATA in DNS message");
    }
    return end;
  }
  for (let i = 0; i < prCount + upCount; i += 1) {
    offset = skipRecord(offset);
  }

  for (let i = 0; i < adCount; i += 1) {
    const recordStart = offset;
    const afterName = skipEncodedName(message, offset);
    if (afterName + 10 > message.length) {
      throw new Error("dns: rfc2136 truncated resource record in DNS message");
    }
    const type = message.readUInt16BE(afterName);
    const rdLength = message.readUInt16BE(afterName + 8);
    const recordEnd = afterName + 10 + rdLength;
    if (recordEnd > message.length) {
      throw new Error("dns: rfc2136 truncated RDATA in DNS message");
    }
    if (type !== TYPE_TSIG) {
      offset = recordEnd;
      continue;
    }

    // TSIG RDATA: algorithm name, time signed (48), fudge, mac-len, mac,
    // original id, error, other-len, other data.
    const rdataStart = afterName + 10;
    const afterAlgorithm = skipEncodedName(message, rdataStart);
    if (afterAlgorithm + 10 > message.length) {
      throw new Error("dns: rfc2136 truncated TSIG RDATA");
    }
    const timeSigned = message.readUIntBE(afterAlgorithm, 6);
    const fudge = message.readUInt16BE(afterAlgorithm + 6);
    const macLength = message.readUInt16BE(afterAlgorithm + 8);
    const macStart = afterAlgorithm + 10;
    if (macStart + macLength + 6 > message.length) {
      throw new Error("dns: rfc2136 truncated TSIG MAC");
    }
    const mac = message.subarray(macStart, macStart + macLength);
    const originalId = message.readUInt16BE(macStart + macLength);
    const error = message.readUInt16BE(macStart + macLength + 2);
    const otherLength = message.readUInt16BE(macStart + macLength + 4);
    const otherStart = macStart + macLength + 6;
    if (otherStart + otherLength > message.length) {
      throw new Error("dns: rfc2136 truncated TSIG other data");
    }

    return {
      recordStart,
      recordEnd,
      keyName: readEncodedName(message, recordStart),
      algorithmName: readEncodedName(message, rdataStart),
      timeSigned,
      fudge,
      mac: Buffer.from(mac),
      originalId,
      error,
      otherData: Buffer.from(message.subarray(otherStart, otherStart + otherLength)),
    };
  }

  return null;
}

/**
 * Verifies a TSIG-signed response to one of our signed UPDATE requests.
 * Checks: transaction ID, QR bit, opcode, TSIG presence, key/algorithm
 * match, TSIG error field, and the response MAC (constant-time compare).
 * Never throws on a bad response; returns { ok:false, detail } instead
 * (structural parse errors included).
 *
 * @param {object} options
 * @param {Buffer} options.response
 * @param {number} options.requestId
 * @param {Buffer} options.requestMac
 * @param {string} options.keyName
 * @param {string} options.keyAlgorithm one of TSIG_ALGORITHMS keys
 * @param {string} options.keySecretBase64
 * @returns {{ ok: true, rcode: number } | { ok: false, detail: string }}
 */
function verifyTsigSignedResponse({
  response,
  requestId,
  requestMac,
  keyName,
  keyAlgorithm,
  keySecretBase64,
}) {
  if (!Buffer.isBuffer(response) || response.length < 12) {
    return { ok: false, detail: "rfc2136 server returned a malformed (short) DNS response" };
  }

  const responseId = response.readUInt16BE(0);
  if (responseId !== requestId) {
    return {
      ok: false,
      detail: "rfc2136 response transaction ID does not match the request (possible forgery)",
    };
  }

  const flags = response.readUInt16BE(2);
  if ((flags & 0x8000) === 0) {
    return { ok: false, detail: "rfc2136 response does not have the QR bit set" };
  }
  const opcode = (flags >>> 11) & 0x0f;
  if (opcode !== OPCODE_UPDATE) {
    return {
      ok: false,
      detail: `rfc2136 response opcode ${opcode} is not UPDATE (${OPCODE_UPDATE})`,
    };
  }

  let tsig;
  try {
    tsig = parseTsigFromMessage(response);
  } catch (err) {
    return {
      ok: false,
      detail: `rfc2136 response could not be parsed: ${err && err.message ? err.message : String(err)}`,
    };
  }
  if (!tsig) {
    return {
      ok: false,
      detail: "rfc2136 response is not TSIG-signed; refusing to trust an unsigned response",
    };
  }

  if (tsig.keyName !== keyName.toLowerCase().replace(/\.$/, "")) {
    return { ok: false, detail: "rfc2136 response TSIG key name does not match the configured key" };
  }
  if (tsig.algorithmName !== keyAlgorithm.toLowerCase().replace(/\.$/, "")) {
    return { ok: false, detail: "rfc2136 response TSIG algorithm does not match the configured key" };
  }

  // Reduced message: TSIG RR removed, ARCOUNT decremented, original ID
  // restored (no-op when the server kept our ID).
  const reduced = Buffer.concat([
    response.subarray(0, tsig.recordStart),
    response.subarray(tsig.recordEnd),
  ]);
  reduced.writeUInt16BE(tsig.originalId, 0);
  reduced.writeUInt16BE(response.readUInt16BE(10) - 1, 10);

  const expectedMac = computeResponseMac({
    requestMac,
    responseMessageWithoutTsig: reduced,
    tsigVariables: buildTsigVariables({
      keyName,
      keyAlgorithm,
      timeSigned: tsig.timeSigned,
      fudge: tsig.fudge,
      error: tsig.error,
      otherData: tsig.otherData,
    }),
    keyAlgorithm,
    keySecretBase64,
  });

  if (
    tsig.mac.length !== expectedMac.length ||
    !crypto.timingSafeEqual(tsig.mac, expectedMac)
  ) {
    return {
      ok: false,
      detail: "rfc2136 response TSIG MAC verification failed (wrong key or tampered response)",
    };
  }

  if (tsig.error !== 0) {
    return {
      ok: false,
      detail: `rfc2136 response TSIG error ${tsig.error} (${RCODE_NAMES[tsig.error] || "unknown"})`,
    };
  }

  return { ok: true, rcode: flags & 0x0f };
}

/**
 * Default socket layer: sends one length-prefixed DNS message over TCP and
 * resolves with the response (length prefix stripped). Rejects on connect
 * error, timeout, or truncated response; the solver layer maps rejections
 * to { ok: false } results.
 *
 * @param {{ host: string, port: number, message: Buffer, timeoutMs: number }} options
 * @returns {Promise<Buffer>}
 */
function sendTcpDnsMessage({ host, port, message, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const received = [];
    let settled = false;

    function finish(error, response) {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(response);
    }

    socket.setTimeout(timeoutMs, () => {
      finish(new Error(`rfc2136 update timed out after ${timeoutMs} ms`));
    });
    socket.on("error", (err) => finish(err));
    socket.on("connect", () => {
      const framed = Buffer.concat([uint16(message.length), message]);
      socket.write(framed);
    });
    socket.on("data", (chunk) => {
      received.push(chunk);
      const buffered = Buffer.concat(received);
      if (buffered.length < 2) return;
      const expected = buffered.readUInt16BE(0);
      if (buffered.length >= 2 + expected) {
        finish(null, buffered.subarray(2, 2 + expected));
      }
    });
    socket.on("close", () => {
      finish(new Error("rfc2136 connection closed before a full response arrived"));
    });
  });
}

function createSolverImpl({ credentials, dnsUpdateImpl, timeoutMs, excerpt }) {
  const sendMessage = dnsUpdateImpl || sendTcpDnsMessage;

  /**
   * @param {"present"|"cleanup"} action
   * @param {{ zone: string, recordName: string, txtValue: string }} inputs
   */
  async function runUpdate(action, { zone, recordName, txtValue }) {
    const messageId = crypto.randomBytes(2).readUInt16BE(0);
    const { message, mac: requestMac } = buildSignedUpdate({
      action,
      zone,
      recordName,
      txtValue,
      keyName: credentials.keyName,
      keyAlgorithm: credentials.keyAlgorithm,
      keySecretBase64: credentials.keySecretBase64,
      messageId,
      timeSigned: Math.floor(Date.now() / 1000),
    });

    const response = await sendMessage({
      host: credentials.server,
      port: credentials.port,
      message,
      timeoutMs,
    });

    // Full response verification: transaction ID, QR/opcode, and the
    // response TSIG MAC. Anything unsigned, forged, or mis-signed is an
    // operational failure, never trusted.
    const verified = verifyTsigSignedResponse({
      response,
      requestId: messageId,
      requestMac,
      keyName: credentials.keyName,
      keyAlgorithm: credentials.keyAlgorithm,
      keySecretBase64: credentials.keySecretBase64,
    });
    if (!verified.ok) {
      return { ok: false, detail: excerpt(verified.detail) };
    }

    if (verified.rcode !== 0) {
      return {
        ok: false,
        detail: excerpt(
          `rfc2136 update was refused: RCODE ${verified.rcode} (${RCODE_NAMES[verified.rcode] || "unknown"})`,
        ),
      };
    }

    return { ok: true };
  }

  return {
    presentChallenge: (inputs) => runUpdate("present", inputs),
    cleanupChallenge: (inputs) => runUpdate("cleanup", inputs),
  };
}

module.exports = {
  PROVIDER_ID,
  DEFAULT_PORT,
  DEFAULT_KEY_ALGORITHM,
  TSIG_ALGORITHMS,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for the wire-format / stable-HMAC / response-verification
  // tests (following the module's existing export-internals style).
  buildUpdateMessage,
  buildSignedUpdate,
  buildTsigVariables,
  buildTsigRecord,
  computeResponseMac,
  parseTsigFromMessage,
  verifyTsigSignedResponse,
  encodeName,
  encodeTxtRdata,
  uint16,
  uint32,
  uint48,
  OPCODE_UPDATE,
  TYPE_TSIG,
  CLASS_ANY,
  CLASS_NONE,
  sendTcpDnsMessage,
};
