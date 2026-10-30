"use strict";

// Neutral credential mechanics shared by every bearer-credential family
// (executor API tokens, agent bootstrap and runtime credentials, operator
// connection credentials). This module knows nothing about tables, routes or
// roles. A family supplies its own prefix and keeps its own storage and rules.

const crypto = require("crypto");

const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;

function sha256Hex(value) {
  // High-entropy credential lookup hash, not a password KDF.
  // codeql[js/insufficient-password-hash]
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

// Constant-time comparison that still does the same work when either side is
// malformed, so a bad candidate cannot be told apart from a wrong one by time.
function safeCompareSha256Hex(candidateHash, storedHash) {
  const candidateIsSha256 = SHA256_HEX_PATTERN.test(candidateHash);
  const storedIsSha256 = SHA256_HEX_PATTERN.test(String(storedHash || ""));
  const candidate = candidateIsSha256
    ? Buffer.from(candidateHash, "hex")
    : Buffer.alloc(32);
  const stored = storedIsSha256
    ? Buffer.from(storedHash, "hex")
    : Buffer.alloc(32);
  const matches = crypto.timingSafeEqual(candidate, stored);
  return candidateIsSha256 && storedIsSha256 && matches;
}

// A credential family is described once and reused for generate and parse.
// Format: <prefix><idHex>_<secretHex>. The id part is the public lookup key.
function defineCredentialFamily({ prefix, idHexLength = 16, secretHexLength = 64 }) {
  if (typeof prefix !== "string" || !/^[a-z]+_$/.test(prefix)) {
    throw new Error("Credential prefix must be lowercase letters ending in an underscore");
  }
  const idBytes = idHexLength / 2;
  const secretBytes = secretHexLength / 2;
  const pattern = new RegExp(
    `^${prefix}([a-f0-9]{${idHexLength}})_([a-f0-9]{${secretHexLength}})$`,
  );
  const rawLength = prefix.length + idHexLength + 1 + secretHexLength;

  return Object.freeze({
    prefix,
    rawLength,
    pattern,
    generate() {
      const id = crypto.randomBytes(idBytes).toString("hex");
      const secret = crypto.randomBytes(secretBytes).toString("hex");
      return `${prefix}${id}_${secret}`;
    },
    parse(raw) {
      if (typeof raw !== "string" || raw.length !== rawLength) return null;
      const match = pattern.exec(raw);
      if (!match) return null;
      return { raw, lookupPrefix: `${prefix}${match[1]}`, idHex: match[1] };
    },
    // True when the text contains something shaped like this family's
    // credential, anywhere in it. Used to keep secrets out of free-text fields.
    containsEmbedded(value) {
      return new RegExp(
        `${prefix}[a-f0-9]{${idHexLength}}_[a-f0-9]{${secretHexLength}}`,
        "i",
      ).test(String(value || ""));
    },
  });
}

module.exports = {
  SHA256_HEX_PATTERN,
  defineCredentialFamily,
  safeCompareSha256Hex,
  sha256Hex,
};
