"use strict";

/**
 * Canonical JSON serialization for CertOps signed job payloads (ADR-0003).
 *
 * SINGLE SOURCE OF TRUTH shared by BOTH sides of the signature boundary:
 *   - control plane signer: apps/api/services/certops/jobSigning.js
 *   - agent verifier:       packages/agent/src/signing/index.js
 *
 * Both sides require this exact module so the signed bytes can never drift
 * between implementations. The implementation was extracted verbatim from
 * the agent's signing module.
 *
 * NOTE on the .cjs extension: packages/contracts/package.json declares
 * "type": "module", so a plain .js file here would be loaded as ESM. This
 * module must stay requireable from the CommonJS API service and agent, so
 * it is shipped as .cjs (always CommonJS regardless of the package type).
 *
 * CANONICALIZATION ALGORITHM (byte-for-byte contract):
 *
 *   1. Input must be a plain object (prototype Object.prototype or null).
 *      Anything else (array, class instance, Map, primitive, null) throws.
 *   2. The TOP-LEVEL property named "signature" is omitted. Properties named
 *      "signature" at any deeper nesting level are KEPT and serialized
 *      normally; per ADR-0003 only the envelope's own signature field is
 *      excluded from the signed bytes.
 *   3. Object keys are sorted lexicographically by UTF-16 code unit
 *      (JavaScript's default Array.prototype.sort() on strings), recursively
 *      at every nesting level.
 *   4. Arrays keep their original element order.
 *   5. No whitespace anywhere: `{"a":1,"b":[2,3]}` style.
 *   6. Strings and keys are encoded with JSON.stringify's standard JSON
 *      string escaping. Numbers use JSON.stringify's shortest round-trip
 *      form; non-finite numbers (NaN, Infinity) throw.
 *   7. `undefined` anywhere in the tree throws (it is not representable in
 *      JSON and dropping it silently would let two implementations sign
 *      different bytes for the "same" object).
 *   8. The resulting string is UTF-8 encoded to produce the bytes to
 *      sign/verify (Node string -> Buffer.from(str, "utf8")).
 */

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

/**
 * Recursive canonical JSON serializer shared by canonicalizeJobPayload.
 * Kept separate so the top-level signature exclusion (which applies ONLY at
 * depth 0 per ADR-0003) does not leak into nested levels.
 *
 * @param {*} value
 * @param {string} pathLabel JSON-path-ish label for error messages
 * @returns {string}
 */
function serializeCanonical(value, pathLabel) {
  if (value === undefined) {
    throw new Error(
      `signing: canonicalizeJobPayload found an undefined value at ${pathLabel}; ` +
        "undefined is not representable in JSON and would silently diverge " +
        "between implementations, so it is rejected",
    );
  }
  if (value === null) return "null";
  const valueType = typeof value;
  if (valueType === "boolean") return value ? "true" : "false";
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        `signing: canonicalizeJobPayload found a non-finite number at ${pathLabel}`,
      );
    }
    return JSON.stringify(value);
  }
  if (valueType === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    const items = value.map((item, index) =>
      serializeCanonical(item, `${pathLabel}[${index}]`),
    );
    return `[${items.join(",")}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => {
      const serialized = serializeCanonical(value[key], `${pathLabel}.${key}`);
      return `${JSON.stringify(key)}:${serialized}`;
    });
    return `{${entries.join(",")}}`;
  }
  throw new Error(
    `signing: canonicalizeJobPayload cannot serialize value of type ` +
      `${valueType} at ${pathLabel} (only plain objects, arrays, strings, ` +
      "finite numbers, booleans, and null are allowed)",
  );
}

/**
 * Deterministic canonical JSON serialization of a job payload, EXCLUDING the
 * top-level "signature" property. This is the exact byte sequence the
 * control plane signs and the agent verifies (ADR-0003: "the signature must
 * cover a canonical serialization excluding the signature field").
 *
 * @param {object} job the job payload (may include the signature field,
 *   which is excluded from the output)
 * @returns {string} canonical JSON string (UTF-8 encode it for signing)
 * @throws {Error} on non-plain-object input or unserializable values
 */
function canonicalizeJobPayload(job) {
  if (!isPlainObject(job)) {
    throw new Error(
      "signing: canonicalizeJobPayload requires a plain object job payload",
    );
  }
  const withoutSignature = {};
  for (const key of Object.keys(job)) {
    if (key === "signature") continue;
    withoutSignature[key] = job[key];
  }
  return serializeCanonical(withoutSignature, "$");
}

module.exports = {
  isPlainObject,
  serializeCanonical,
  canonicalizeJobPayload,
};
