"use strict";

/**
 * Amazon Route 53 DNS-01 provider.
 *
 * Auth: AWS Signature Version 4, implemented here with node:crypto only
 * (no AWS SDK -- the agent is zero-dependency). Scope the IAM principal to
 * route53:ChangeResourceRecordSets + route53:ListHostedZonesByName on the
 * target hosted zone(s).
 *
 * Credentials shape:
 *   {
 *     accessKeyId: string,
 *     secretAccessKey: string,
 *     sessionToken?: string,     // for temporary STS credentials
 *     hostedZoneId?: string,     // "Z..." or "/hostedzone/Z..."; looked up
 *                                // by name via ListHostedZonesByName when absent
 *     region?: string,           // SigV4 scope region, default "us-east-1"
 *                                // (Route 53 is a global service signed there)
 *   }
 *
 * API surface used (route53.amazonaws.com, XML API 2013-04-01):
 *   GET  /2013-04-01/hostedzonebyname?dnsname=<zone>&maxitems=1
 *   POST /2013-04-01/hostedzone/<id>/rrset   ChangeResourceRecordSets
 *        (UPSERT on present, DELETE on cleanup)
 *
 * TXT values are wrapped in double quotes per Route 53 rules, with
 * backslash and double-quote characters escaped.
 */

const crypto = require("node:crypto");

const { isNonEmptyString, fetchWithTimeout } = require("../internal.js");

const PROVIDER_ID = "route53";
const API_HOST = "route53.amazonaws.com";
const API_VERSION = "2013-04-01";
const SERVICE = "route53";
const DEFAULT_REGION = "us-east-1";
const TXT_TTL_SECONDS = 60;

// --------------------------------------------------------------------------
// SigV4 (exported for the fixed-vector signature test)
// --------------------------------------------------------------------------

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

/** RFC 3986 strict encoding (SigV4 requires !'()* encoded too). */
function rfc3986Encode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/**
 * Builds the SigV4 canonical request and derived signature for one request
 * against a fixed host. Deterministic given amzDate, so tests can assert an
 * exact canonical request + signature for a fixed key/date.
 *
 * @param {object} options
 * @param {string} options.method
 * @param {string} options.path already-encoded absolute path (no query)
 * @param {Array<[string, string]>} options.query raw key/value pairs
 * @param {string} options.body
 * @param {string} options.amzDate "YYYYMMDDTHHMMSSZ"
 * @param {string} options.accessKeyId
 * @param {string} options.secretAccessKey
 * @param {string|null} options.sessionToken
 * @param {string} options.region
 * @returns {{
 *   canonicalRequest: string,
 *   stringToSign: string,
 *   signature: string,
 *   headers: object,
 * }}
 */
function signRequest({
  method,
  path,
  query = [],
  body = "",
  amzDate,
  accessKeyId,
  secretAccessKey,
  sessionToken = null,
  region,
}) {
  const dateStamp = amzDate.slice(0, 8);

  const canonicalQueryString = query
    .map(([key, value]) => [rfc3986Encode(key), rfc3986Encode(value)])
    .sort(([aKey, aValue], [bKey, bValue]) =>
      aKey === bKey ? aValue.localeCompare(bValue) : aKey.localeCompare(bKey),
    )
    .map(([key, value]) => `${key}=${value}`)
    .join("&");

  const headerEntries = [
    ["host", API_HOST],
    ["x-amz-date", amzDate],
  ];
  if (sessionToken) {
    headerEntries.push(["x-amz-security-token", sessionToken]);
  }
  headerEntries.sort(([a], [b]) => a.localeCompare(b));

  const canonicalHeaders = headerEntries
    .map(([name, value]) => `${name}:${value}\n`)
    .join("");
  const signedHeaders = headerEntries.map(([name]) => name).join(";");

  const payloadHash = sha256Hex(body);

  const canonicalRequest = [
    method,
    path,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${SERVICE}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, SERVICE);
  const kSigning = hmac(kService, "aws4_request");
  const signature = hmac(kSigning, stringToSign).toString("hex");

  const headers = {
    Host: API_HOST,
    "X-Amz-Date": amzDate,
    Authorization:
      `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
  if (sessionToken) {
    headers["X-Amz-Security-Token"] = sessionToken;
  }

  return { canonicalRequest, stringToSign, signature, headers };
}

// --------------------------------------------------------------------------
// Provider contract
// --------------------------------------------------------------------------

/**
 * @param {object} credentials
 */
function validateCredentials(credentials) {
  if (!isNonEmptyString(credentials.accessKeyId)) {
    throw new Error("dns: route53 credentials require a non-empty accessKeyId string");
  }
  if (!isNonEmptyString(credentials.secretAccessKey)) {
    throw new Error("dns: route53 credentials require a non-empty secretAccessKey string");
  }
  if (credentials.sessionToken !== undefined && !isNonEmptyString(credentials.sessionToken)) {
    throw new Error("dns: route53 sessionToken must be a non-empty string when provided");
  }
  if (credentials.hostedZoneId !== undefined && !isNonEmptyString(credentials.hostedZoneId)) {
    throw new Error("dns: route53 hostedZoneId must be a non-empty string when provided");
  }
  if (credentials.region !== undefined && !isNonEmptyString(credentials.region)) {
    throw new Error("dns: route53 region must be a non-empty string when provided");
  }

  const hostedZoneId = credentials.hostedZoneId
    ? credentials.hostedZoneId.replace(/^\/hostedzone\//, "")
    : null;

  return {
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
    sessionToken: credentials.sessionToken || null,
    hostedZoneId,
    region: credentials.region || DEFAULT_REGION,
  };
}

/**
 * @param {ReturnType<typeof validateCredentials>} credentials
 * @returns {string[]} secret strings to redact from any excerpt
 */
function collectSecretStrings(credentials) {
  return [
    credentials.secretAccessKey,
    credentials.sessionToken,
    credentials.accessKeyId,
  ].filter(Boolean);
}

function xmlEscape(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Route 53 TXT value quoting: wrap in double quotes, escape \ and ". */
function quoteTxtValue(txtValue) {
  return `"${txtValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * @param {"UPSERT"|"DELETE"} action
 * @param {string} recordName
 * @param {string} txtValue
 * @returns {string} ChangeResourceRecordSets XML body
 */
function buildChangeBatchXml(action, recordName, txtValue) {
  const fqdn = recordName.endsWith(".") ? recordName : `${recordName}.`;
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/${API_VERSION}/">` +
    "<ChangeBatch><Changes><Change>" +
    `<Action>${action}</Action>` +
    "<ResourceRecordSet>" +
    `<Name>${xmlEscape(fqdn)}</Name>` +
    "<Type>TXT</Type>" +
    `<TTL>${TXT_TTL_SECONDS}</TTL>` +
    "<ResourceRecords><ResourceRecord>" +
    `<Value>${xmlEscape(quoteTxtValue(txtValue))}</Value>` +
    "</ResourceRecord></ResourceRecords>" +
    "</ResourceRecordSet>" +
    "</Change></Changes></ChangeBatch>" +
    "</ChangeResourceRecordSetsRequest>"
  );
}

function createSolverImpl({ credentials, fetchImpl, timeoutMs, excerpt }) {
  function currentAmzDate() {
    return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  }

  /**
   * Signs and sends one request. Returns fetchWithTimeout's result record.
   * @param {{ method: string, path: string, query?: Array<[string,string]>, body?: string }} request
   */
  function signedFetch({ method, path, query = [], body = "" }) {
    const { headers } = signRequest({
      method,
      path,
      query,
      body,
      amzDate: currentAmzDate(),
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      sessionToken: credentials.sessionToken,
      region: credentials.region,
    });

    const queryString = query
      .map(([key, value]) => `${rfc3986Encode(key)}=${rfc3986Encode(value)}`)
      .join("&");
    const url = `https://${API_HOST}${path}${queryString ? `?${queryString}` : ""}`;

    return fetchWithTimeout(
      fetchImpl,
      url,
      {
        method,
        headers: { ...headers, "Content-Type": "text/xml" },
        ...(body ? { body } : {}),
      },
      timeoutMs,
    );
  }

  function httpFailure(operationLabel, response) {
    return {
      ok: false,
      statusCode: response.status,
      detail: excerpt(`route53 ${operationLabel} failed (HTTP ${response.status}): ${response.bodyText}`),
    };
  }

  /**
   * Resolves the hosted zone id: configured id wins, otherwise
   * ListHostedZonesByName. The response's first zone must actually match
   * the requested name (the API returns the lexicographically next zone
   * when there is no exact match).
   * @param {string} zone
   */
  async function resolveHostedZoneId(zone) {
    if (credentials.hostedZoneId) {
      return { ok: true, hostedZoneId: credentials.hostedZoneId };
    }

    const response = await signedFetch({
      method: "GET",
      path: `/${API_VERSION}/hostedzonebyname`,
      query: [
        ["dnsname", zone],
        ["maxitems", "1"],
      ],
    });
    if (!response.ok) {
      return httpFailure("hosted zone lookup", response);
    }

    const zoneFqdn = zone.endsWith(".") ? zone : `${zone}.`;
    const nameMatch = /<Name>([^<]+)<\/Name>/.exec(response.bodyText);
    const idMatch = /<Id>\/hostedzone\/([^<]+)<\/Id>/.exec(response.bodyText);

    if (!idMatch || !nameMatch || nameMatch[1].toLowerCase() !== zoneFqdn.toLowerCase()) {
      return {
        ok: false,
        statusCode: response.status,
        detail: excerpt(`route53 hosted zone lookup found no zone named ${JSON.stringify(zone)}`),
      };
    }

    return { ok: true, hostedZoneId: idMatch[1] };
  }

  /**
   * @param {"UPSERT"|"DELETE"} action
   * @param {{ zone: string, recordName: string, txtValue: string }} inputs
   */
  async function changeRecordSet(action, { zone, recordName, txtValue }) {
    const zoneResult = await resolveHostedZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const response = await signedFetch({
      method: "POST",
      path: `/${API_VERSION}/hostedzone/${zoneResult.hostedZoneId}/rrset`,
      body: buildChangeBatchXml(action, recordName, txtValue),
    });
    if (!response.ok) {
      return httpFailure(`ChangeResourceRecordSets ${action}`, response);
    }

    return { ok: true };
  }

  return {
    presentChallenge: (inputs) => changeRecordSet("UPSERT", inputs),
    cleanupChallenge: (inputs) => changeRecordSet("DELETE", inputs),
  };
}

module.exports = {
  PROVIDER_ID,
  API_HOST,
  DEFAULT_REGION,
  validateCredentials,
  collectSecretStrings,
  createSolverImpl,
  // Exported for the SigV4 fixed-vector test only.
  signRequest,
  buildChangeBatchXml,
  quoteTxtValue,
};
