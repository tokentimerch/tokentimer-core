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
 *   cleanup: UPDATE deleting the whole TXT RRset at <recordName>
 *            (CLASS ANY, TTL 0, empty RDATA per RFC 2136 s2.5.2)
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
 * Builds one complete, TSIG-signed DNS UPDATE message (without the TCP
 * length prefix). Deterministic given messageId + timeSigned, which is
 * what makes the TSIG HMAC test vector stable.
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
 * @param {string} [options.txtValue] required for "present"
 * @param {string} options.keyName
 * @param {string} options.keyAlgorithm one of TSIG_ALGORITHMS keys
 * @param {string} options.keySecretBase64
 * @param {number} options.messageId 0..65535
 * @param {number} options.timeSigned epoch seconds
 * @param {number} [options.fudge] default 300
 * @returns {Buffer}
 */
function buildUpdateMessage({
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
  if (action === "present" && !isNonEmptyString(txtValue)) {
    throw new Error("dns: rfc2136 present requires a txtValue");
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
  let updateRecord;
  if (action === "present") {
    const rdata = encodeTxtRdata(txtValue);
    updateRecord = Buffer.concat([
      encodeName(recordName),
      uint16(TYPE_TXT),
      uint16(CLASS_IN),
      uint32(TXT_TTL_SECONDS),
      uint16(rdata.length),
      rdata,
    ]);
  } else {
    // Delete the whole TXT RRset at the name: CLASS ANY, TTL 0, no RDATA.
    updateRecord = Buffer.concat([
      encodeName(recordName),
      uint16(TYPE_TXT),
      uint16(CLASS_ANY),
      uint32(0),
      uint16(0),
    ]);
  }

  const unsignedMessage = Buffer.concat([header, zoneSection, updateRecord]);

  // TSIG variables covered by the MAC.
  const algorithmWire = encodeName(keyAlgorithm.toLowerCase());
  const tsigVariables = Buffer.concat([
    encodeName(keyName.toLowerCase()),
    uint16(CLASS_ANY),
    uint32(0),
    algorithmWire,
    uint48(timeSigned),
    uint16(fudge),
    uint16(0), // error
    uint16(0), // other-len (no other data)
  ]);

  const mac = crypto
    .createHmac(TSIG_ALGORITHMS[keyAlgorithm], Buffer.from(keySecretBase64, "base64"))
    .update(Buffer.concat([unsignedMessage, tsigVariables]))
    .digest();

  // TSIG RR appended to the additional section.
  const tsigRdata = Buffer.concat([
    algorithmWire,
    uint48(timeSigned),
    uint16(fudge),
    uint16(mac.length),
    mac,
    uint16(messageId), // original ID
    uint16(0), // error
    uint16(0), // other-len
  ]);
  const tsigRecord = Buffer.concat([
    encodeName(keyName.toLowerCase()),
    uint16(TYPE_TSIG),
    uint16(CLASS_ANY),
    uint32(0),
    uint16(tsigRdata.length),
    tsigRdata,
  ]);

  // Final message: same header with ADCOUNT=1.
  const signedHeader = Buffer.concat([
    uint16(messageId),
    uint16(OPCODE_UPDATE << 11),
    uint16(1),
    uint16(0),
    uint16(1),
    uint16(1),
  ]);

  return Buffer.concat([
    signedHeader,
    zoneSection,
    updateRecord,
    tsigRecord,
  ]);
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
    const message = buildUpdateMessage({
      action,
      zone,
      recordName,
      txtValue,
      keyName: credentials.keyName,
      keyAlgorithm: credentials.keyAlgorithm,
      keySecretBase64: credentials.keySecretBase64,
      messageId: crypto.randomBytes(2).readUInt16BE(0),
      timeSigned: Math.floor(Date.now() / 1000),
    });

    const response = await sendMessage({
      host: credentials.server,
      port: credentials.port,
      message,
      timeoutMs,
    });

    if (!Buffer.isBuffer(response) || response.length < 12) {
      return {
        ok: false,
        detail: excerpt("rfc2136 server returned a malformed (short) DNS response"),
      };
    }

    const rcode = response[3] & 0x0f;
    if (rcode !== 0) {
      return {
        ok: false,
        detail: excerpt(
          `rfc2136 update was refused: RCODE ${rcode} (${RCODE_NAMES[rcode] || "unknown"})`,
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
  // Exported for the wire-format / stable-HMAC tests.
  buildUpdateMessage,
  encodeName,
  encodeTxtRdata,
  sendTcpDnsMessage,
};
