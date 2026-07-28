"use strict";

/**
 * Shared internals for the DNS-01 solver layer (src/dns). This file is
 * private to the dns module: index.js, hook.js, and the providers/ files
 * require it, and nothing outside src/dns should.
 *
 * Everything here is deliberately dependency-free and side-effect-free so
 * provider implementations stay pure "data in, data out" HTTP/wire builders
 * that tests can drive with injected fakes.
 */

/** Hard cap on any provider-response excerpt carried into results. Mirrors
 * the acme module's OUTPUT_EXCERPT_MAX_CHARS. */
const OUTPUT_EXCERPT_MAX_CHARS = 1024;

/** Marker whose presence anywhere in an excerpt causes the whole excerpt to
 * be replaced, never partially scrubbed (same rule as src/acme). */
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

/** Hard cap on any provider HTTP response body. DNS APIs answer with small
 * JSON/XML payloads; anything larger is either a misconfigured endpoint or
 * an attempt to exhaust memory, and must FAIL (never be truncated, which
 * could silently hide the tail of a response a provider parses). */
const MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024;

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Suffix-with-dot-boundary match, identical in spirit to the policy
 * module's isZoneCoveredBy (duplicated, not imported, to keep src/dns
 * self-contained): `recordName` is within `zone` if they are equal or if
 * recordName ends with `.${zone}`. Prevents `evilexample.com` matching a
 * zone of `example.com`.
 *
 * @param {string} recordName
 * @param {string} zone
 * @returns {boolean}
 */
function isRecordNameWithinZone(recordName, zone) {
  const normalizedRecord = recordName.toLowerCase();
  const normalizedZone = zone.toLowerCase();
  return (
    normalizedRecord === normalizedZone ||
    normalizedRecord.endsWith(`.${normalizedZone}`)
  );
}

/**
 * The record name relative to its zone: "" when recordName === zone,
 * otherwise recordName with the trailing `.${zone}` removed. Callers map
 * "" to their provider's apex spelling ("@" for Azure, etc.). Assumes the
 * dot-boundary check already passed.
 *
 * @param {string} recordName
 * @param {string} zone
 * @returns {string}
 */
function relativeRecordName(recordName, zone) {
  if (recordName.toLowerCase() === zone.toLowerCase()) {
    return "";
  }
  return recordName.slice(0, recordName.length - zone.length - 1);
}

/**
 * Builds a bounding + redacting excerpt function closed over the caller's
 * secret strings. DNS provider credentials are takeover-grade (they can
 * redirect a whole zone), so an excerpt containing any credential value --
 * or any PRIVATE KEY marker -- is redacted WHOLESALE, never partially
 * scrubbed, exactly like the acme module treats key material.
 *
 * @param {string[]} secretValues credential strings to redact on sight
 * @returns {(output: unknown) => string}
 */
function makeExcerptRedactor(secretValues) {
  const secrets = (secretValues || []).filter(isNonEmptyString);

  return function boundAndRedactExcerpt(output) {
    let text;
    if (typeof output === "string") {
      text = output;
    } else if (Buffer.isBuffer(output)) {
      text = output.toString("utf8");
    } else if (output === undefined || output === null) {
      text = "";
    } else {
      try {
        text = JSON.stringify(output);
      } catch {
        text = String(output);
      }
    }

    // Redaction is checked on the FULL text (not just the excerpt window)
    // so a secret echoed past the first 1024 chars still triggers it.
    if (text.includes(PRIVATE_KEY_MARKER)) {
      return REDACTED_EXCERPT_PLACEHOLDER;
    }
    if (secrets.some((secret) => text.includes(secret))) {
      return REDACTED_EXCERPT_PLACEHOLDER;
    }

    return text.slice(0, OUTPUT_EXCERPT_MAX_CHARS);
  };
}

/**
 * Reads a response body stream, enforcing MAX_PROVIDER_RESPONSE_BYTES.
 * Throws (operational failure, mapped to ok:false by the solver wrapper)
 * when the bound is exceeded; the reader is cancelled first so no further
 * bytes are pulled off the wire.
 *
 * @param {{ getReader: () => any }} bodyStream WHATWG ReadableStream
 * @returns {Promise<string>}
 */
async function readBoundedBodyText(bodyStream) {
  const reader = bodyStream.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      totalBytes += chunk.length;
      if (totalBytes > MAX_PROVIDER_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error(
          `provider response exceeded the ${MAX_PROVIDER_RESPONSE_BYTES}-byte size limit`,
        );
      }
      chunks.push(chunk);
    }
  } finally {
    if (typeof reader.releaseLock === "function") {
      try {
        reader.releaseLock();
      } catch {
        // reader already released by cancel(); nothing to do
      }
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * fetch wrapper with an AbortController timeout, resolving to a plain
 * { status, ok, bodyText } record. Never inspects the body as JSON here;
 * providers parse what they need and always run raw text through their
 * excerpt redactor before surfacing any of it.
 *
 * Hardening:
 *   - redirect: "error" is always passed so credential-bearing requests
 *     are never replayed against a redirect target.
 *   - The body is read through the response stream with a hard
 *     MAX_PROVIDER_RESPONSE_BYTES bound; an over-limit body FAILS (throws)
 *     rather than being truncated. Test doubles without a body stream fall
 *     back to response.text() with the same post-hoc limit check.
 *
 * Throws on network failure / abort / oversized body; the solver layer in
 * index.js maps those throws to { ok: false } operational results.
 *
 * @param {Function} fetchImpl fetch-shaped implementation
 * @param {string} url
 * @param {object} options fetch options (method, headers, body)
 * @param {number} timeoutMs
 * @returns {Promise<{ status: number, ok: boolean, bodyText: string }>}
 */
async function fetchWithTimeout(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error(`request timed out after ${timeoutMs} ms`));
  }, timeoutMs);

  try {
    const response = await fetchImpl(url, {
      ...options,
      redirect: "error",
      signal: controller.signal,
    });

    let bodyText;
    if (response.body && typeof response.body.getReader === "function") {
      bodyText = await readBoundedBodyText(response.body);
    } else {
      // Test doubles expose only text(); the size limit still applies and
      // an over-limit body fails (truncation is never acceptable).
      bodyText = await response.text();
      if (Buffer.byteLength(bodyText, "utf8") > MAX_PROVIDER_RESPONSE_BYTES) {
        throw new Error(
          `provider response exceeded the ${MAX_PROVIDER_RESPONSE_BYTES}-byte size limit`,
        );
      }
    }

    return {
      status: response.status,
      ok: response.status >= 200 && response.status < 300,
      bodyText,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Validates a user-configured provider base URL. Throws (programmer error /
 * malformed credentials, surfaced at construction time) unless the URL is
 * parseable, carries no embedded username/password and no hash fragment,
 * and uses https: -- or http: only when `allowInsecureLocalHttp` is true
 * AND the hostname is loopback (localhost, *.localhost, 127.x.x.x, ::1).
 *
 * @param {string} url
 * @param {{ allowInsecureLocalHttp?: boolean }} [options]
 * @returns {URL} the parsed URL
 */
function assertSafeProviderBaseUrl(url, { allowInsecureLocalHttp = false } = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`dns: provider base URL is not a valid URL: ${JSON.stringify(url)}`);
  }

  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error(
      "dns: provider base URL must not embed credentials (user:pass@host)",
    );
  }
  if (parsed.hash !== "") {
    throw new Error("dns: provider base URL must not carry a hash fragment");
  }

  if (parsed.protocol === "https:") {
    return parsed;
  }

  if (parsed.protocol === "http:") {
    if (!allowInsecureLocalHttp) {
      throw new Error(
        "dns: provider base URL must use https: " +
          "(set allowInsecureLocalHttp for a loopback-only http endpoint)",
      );
    }
    const hostname = parsed.hostname.toLowerCase();
    const isLoopback =
      hostname === "localhost" ||
      hostname.endsWith(".localhost") ||
      /^127(\.\d{1,3}){3}$/.test(hostname) ||
      hostname === "::1" ||
      hostname === "[::1]";
    if (!isLoopback) {
      throw new Error(
        "dns: allowInsecureLocalHttp only permits http: for loopback hosts " +
          "(localhost, *.localhost, 127.x.x.x, ::1)",
      );
    }
    return parsed;
  }

  throw new Error(
    `dns: provider base URL protocol ${JSON.stringify(parsed.protocol)} is not allowed`,
  );
}

module.exports = {
  OUTPUT_EXCERPT_MAX_CHARS,
  PRIVATE_KEY_MARKER,
  REDACTED_EXCERPT_PLACEHOLDER,
  MAX_PROVIDER_RESPONSE_BYTES,
  isNonEmptyString,
  isRecordNameWithinZone,
  relativeRecordName,
  makeExcerptRedactor,
  fetchWithTimeout,
  assertSafeProviderBaseUrl,
};
