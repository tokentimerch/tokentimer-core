"use strict";

// Last-line outbound check (ADR-0015 section 4). The API already returns only
// named fields, and every response is validated against its published schema
// before it gets here. This catches what a schema cannot: a secret that
// arrived inside an otherwise valid string field. It fails closed. A response
// that trips it is withheld whole, never partially redacted, because a
// redacted copy would still tell a model that a secret was there.

const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");
const { containsGenericSecretMaterial } = require("@tokentimer/log-scrub/secret-material");

// TokenTimer's own credential families. The shared detector does not know
// these shapes, so they are matched here.
const CREDENTIAL_SHAPES = [
  /\bttopg_[a-f0-9]{16}_[a-f0-9]{64}\b/i,
  /\bttopc_[a-f0-9]{16}_[a-f0-9]{64}\b/i,
  /\bttagent_[a-f0-9]{16}_[a-f0-9]{64}\b/i,
  /\bttboot_[a-f0-9]{16}_[a-f0-9]{64}\b/i,
  /\bttx_[a-f0-9]{16}_[a-f0-9]{64}\b/i,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
];

function inspectOutbound(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (containsPrivateKeyMaterial(text)) return { clean: false, reason: "private_key_material" };
  if (CREDENTIAL_SHAPES.some((pattern) => pattern.test(text))) return { clean: false, reason: "credential_shape" };
  if (containsGenericSecretMaterial(text)) return { clean: false, reason: "generic_secret" };
  return { clean: true, reason: null };
}

module.exports = { CREDENTIAL_SHAPES, inspectOutbound };
