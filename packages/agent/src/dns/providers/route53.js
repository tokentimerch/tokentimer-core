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
 *   GET  /2013-04-01/hostedzone/<id>/rrset?name=&type=TXT&maxitems=1
 *        ListResourceRecordSets (read-modify-write basis)
 *   POST /2013-04-01/hostedzone/<id>/rrset   ChangeResourceRecordSets
 *        (UPSERT on present, UPSERT-remainder or DELETE on cleanup)
 *
 * UPSERT replaces the WHOLE record set and DELETE must match the live set
 * exactly, so present() first lists the existing TXT values at the name
 * and UPSERTs the union plus the new value; cleanup() removes only the
 * challenge value, UPSERTing the remainder back and DELETEing the set
 * only when nothing remains. Parallel challenges at the same name and
 * third-party TXT values therefore never clobber each other.
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

function xmlUnescape(value) {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&");
}

/** Route 53 TXT value quoting: wrap in double quotes, escape \ and ". */
function quoteTxtValue(txtValue) {
  return `"${txtValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * @param {"UPSERT"|"DELETE"} action
 * @param {string} recordName
 * @param {string[]} quotedValues already-quoted TXT values (whole rrset)
 * @param {number} [ttl]
 * @returns {string} ChangeResourceRecordSets XML body
 */
function buildChangeBatchXml(action, recordName, quotedValues, ttl = TXT_TTL_SECONDS) {
  const fqdn = recordName.endsWith(".") ? recordName : `${recordName}.`;
  const resourceRecordsXml = quotedValues
    .map((value) => `<ResourceRecord><Value>${xmlEscape(value)}</Value></ResourceRecord>`)
    .join("");
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/${API_VERSION}/">` +
    "<ChangeBatch><Changes><Change>" +
    `<Action>${action}</Action>` +
    "<ResourceRecordSet>" +
    `<Name>${xmlEscape(fqdn)}</Name>` +
    "<Type>TXT</Type>" +
    `<TTL>${ttl}</TTL>` +
    `<ResourceRecords>${resourceRecordsXml}</ResourceRecords>` +
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
   * ListResourceRecordSets for the exact name/TXT. Returns
   * { ok:true, exists, values, ttl } where values are the (still-quoted)
   * live TXT values, or an ok:false operational failure.
   * @param {string} hostedZoneId
   * @param {string} recordFqdn absolute name with trailing dot
   */
  async function listExistingTxtValues(hostedZoneId, recordFqdn) {
    const response = await signedFetch({
      method: "GET",
      path: `/${API_VERSION}/hostedzone/${hostedZoneId}/rrset`,
      query: [
        ["name", recordFqdn],
        ["type", "TXT"],
        ["maxitems", "1"],
      ],
    });
    if (!response.ok) {
      return httpFailure("ListResourceRecordSets", response);
    }

    // The list starts at-or-after the requested name, so the first record
    // set must actually match name + type or the set does not exist.
    const rrsetMatch = /<ResourceRecordSet>([\s\S]*?)<\/ResourceRecordSet>/.exec(
      response.bodyText,
    );
    if (!rrsetMatch) {
      return { ok: true, exists: false, values: [], ttl: null };
    }
    const block = rrsetMatch[1];
    const nameMatch = /<Name>([^<]*)<\/Name>/.exec(block);
    const typeMatch = /<Type>([^<]*)<\/Type>/.exec(block);
    if (
      !nameMatch ||
      !typeMatch ||
      typeMatch[1] !== "TXT" ||
      xmlUnescape(nameMatch[1]).toLowerCase() !== recordFqdn.toLowerCase()
    ) {
      return { ok: true, exists: false, values: [], ttl: null };
    }

    const ttlMatch = /<TTL>(\d+)<\/TTL>/.exec(block);
    const values = [];
    const valuePattern = /<Value>([^<]*)<\/Value>/g;
    let valueMatch;
    while ((valueMatch = valuePattern.exec(block)) !== null) {
      values.push(xmlUnescape(valueMatch[1]));
    }
    return {
      ok: true,
      exists: true,
      values,
      ttl: ttlMatch ? Number.parseInt(ttlMatch[1], 10) : null,
    };
  }

  /**
   * @param {"UPSERT"|"DELETE"} action
   * @param {string} hostedZoneId
   * @param {string} recordFqdn
   * @param {string[]} quotedValues
   * @param {number} ttl
   */
  async function postChangeBatch(action, hostedZoneId, recordFqdn, quotedValues, ttl) {
    const response = await signedFetch({
      method: "POST",
      path: `/${API_VERSION}/hostedzone/${hostedZoneId}/rrset`,
      body: buildChangeBatchXml(action, recordFqdn, quotedValues, ttl),
    });
    if (!response.ok) {
      return httpFailure(`ChangeResourceRecordSets ${action}`, response);
    }
    return { ok: true };
  }

  async function presentChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveHostedZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const recordFqdn = recordName.endsWith(".") ? recordName : `${recordName}.`;
    const existing = await listExistingTxtValues(zoneResult.hostedZoneId, recordFqdn);
    if (!existing.ok) {
      return existing;
    }

    // Merge with the live set so parallel challenges and third-party TXT
    // values are preserved (UPSERT replaces the whole record set).
    const quoted = quoteTxtValue(txtValue);
    const merged = existing.values.includes(quoted)
      ? existing.values
      : [...existing.values, quoted];

    return postChangeBatch(
      "UPSERT",
      zoneResult.hostedZoneId,
      recordFqdn,
      merged,
      existing.ttl !== null ? existing.ttl : TXT_TTL_SECONDS,
    );
  }

  async function cleanupChallenge({ zone, recordName, txtValue }) {
    const zoneResult = await resolveHostedZoneId(zone);
    if (!zoneResult.ok) {
      return zoneResult;
    }

    const recordFqdn = recordName.endsWith(".") ? recordName : `${recordName}.`;
    const existing = await listExistingTxtValues(zoneResult.hostedZoneId, recordFqdn);
    if (!existing.ok) {
      return existing;
    }

    const quoted = quoteTxtValue(txtValue);
    if (!existing.exists || !existing.values.includes(quoted)) {
      // Nothing to delete: cleanup is idempotent, an already-absent value
      // is success, not failure.
      return { ok: true };
    }

    const ttl = existing.ttl !== null ? existing.ttl : TXT_TTL_SECONDS;
    const remaining = existing.values.filter((value) => value !== quoted);
    if (remaining.length > 0) {
      return postChangeBatch(
        "UPSERT",
        zoneResult.hostedZoneId,
        recordFqdn,
        remaining,
        ttl,
      );
    }

    // DELETE must carry the exact live record set.
    return postChangeBatch(
      "DELETE",
      zoneResult.hostedZoneId,
      recordFqdn,
      existing.values,
      ttl,
    );
  }

  return { presentChallenge, cleanupChallenge };
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
  xmlUnescape,
};
