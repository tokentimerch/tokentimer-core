"use strict";
const assert = require("node:assert/strict");
/** Locate the outer CMS SignerInfo signature, never certificate/attribute bytes.
 * This creates an adversarial response copy; it does not sign renewal requests.
 * All DER lengths and child boundaries are bounded before copying one byte.
 */
function responseDerBytes(input) {
  if (!Buffer.isBuffer(input) || !input.length || input.length > 65536)
    throw new Error("Expected bounded response bytes");
  if (input[0] === 0x30) return Buffer.from(input);
  const text = input.toString("ascii").trim();
  const pem = /^-----BEGIN ([A-Z0-9 ]+)-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----$/.exec(text);
  const body = (pem ? pem[2] : text).replace(/\s/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body))
    throw new Error("Expected DER or canonical base64 response");
  const der = Buffer.from(body, "base64");
  if (!der.length || der.toString("base64") !== body) throw new Error("Invalid response base64");
  return der;
}
function tamperCmsSignerSignature(input) {
  if (!Buffer.isBuffer(input) || input.length < 16 || input.length > 65536)
    throw new Error("Expected bounded CMS response bytes");
  function read(offset, limit) {
    const start = offset;
    if (offset + 2 > limit) throw new Error("Truncated DER header");
    const tag = input[offset++];
    if ((tag & 31) === 31) throw new Error("Unsupported DER high tag");
    let length = input[offset++];
    if (length & 128) {
      const count = length & 127;
      if (!count || count > 3 || offset + count > limit || input[offset] === 0)
        throw new Error("Invalid DER length");
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + input[offset++];
      if (length < 128) throw new Error("Noncanonical DER length");
    }
    if (offset + length > limit) throw new Error("DER child exceeds parent");
    return { tag, start, content: offset, end: offset + length };
  }
  function children(node) {
    const result = [];
    for (let offset = node.content; offset < node.end;) {
      if (result.length >= 96) throw new Error("Too many DER children");
      const child = read(offset, node.end);
      result.push(child);
      offset = child.end;
    }
    return result;
  }
  function requireTag(node, tag) {
    if (!node || node.tag !== tag) throw new Error("Unexpected CMS structure");
    return node;
  }
  const outer = requireTag(read(0, input.length), 0x30);
  if (outer.end !== input.length) throw new Error("Trailing CMS data");
  const contentInfo = children(outer);
  if (contentInfo.length !== 2 || contentInfo[0].tag !== 6 ||
      input.subarray(contentInfo[0].content, contentInfo[0].end).toString("hex") !== "2a864886f70d010702")
    throw new Error("Expected CMS signedData content type");
  const explicit = children(requireTag(contentInfo[1], 0xa0));
  if (explicit.length !== 1) throw new Error("Expected one SignedData");
  const signedData = children(requireTag(explicit[0], 0x30));
  requireTag(signedData[0], 2);
  requireTag(signedData[1], 0x31);
  requireTag(signedData[2], 0x30);
  let cursor = 3;
  if (signedData[cursor]?.tag === 0xa0) cursor++;
  if (signedData[cursor]?.tag === 0xa1) cursor++;
  if (cursor !== signedData.length - 1) throw new Error("Unexpected SignedData fields");
  const signers = children(requireTag(signedData[cursor], 0x31));
  if (signers.length !== 1) throw new Error("Expected exactly one CMS signer");
  const signer = children(requireTag(signers[0], 0x30));
  requireTag(signer[0], 2);
  if (![0x30, 0x80].includes(signer[1]?.tag)) throw new Error("Unexpected signer identifier");
  requireTag(signer[2], 0x30);
  cursor = 3;
  if (signer[cursor]?.tag === 0xa0) cursor++;
  requireTag(signer[cursor++], 0x30);
  const signature = requireTag(signer[cursor++], 4);
  if (signer[cursor]?.tag === 0xa1) cursor++;
  if (cursor !== signer.length || signature.end - signature.content < 32)
    throw new Error("Unexpected CMS signature shape");
  const copy = Buffer.from(input);
  const offset = signature.content + Math.floor((signature.end - signature.content) / 2);
  copy[offset] ^= 1;
  return { bytes: copy, signatureOffset: offset };
}
const scope = "read-only-native-ca-signed-response-signature-boundaries";
const flags = Object.freeze(["actualCaSignedPending", "actualPinnedSignatureVerified", "actualSignerSignatureByteTampered", "actualPristineDerControlVerified", "agentResponseUnchanged"]);
const refusedVariants = Object.freeze(["empty", "truncated", "trailing-data", "oversized", "signer-signature-tampered", "wrong-ca-key-pin"]);
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), ["scope", ...flags, "caRequestId", "responseSha256", "nativeHelperSha256", "originalResponseDerSha256", "tamperedResponseDerSha256", "refusedVariants", "syntheticCaResponse"].sort());
  assert.equal(proof.scope, scope);
  for (const field of flags) assert.equal(proof[field], true, field);
  assert.equal(proof.syntheticCaResponse, false);
  assert.match(proof.caRequestId, /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(proof.caRequestId) <= 0xffffffff);
  for (const field of ["responseSha256", "nativeHelperSha256", "originalResponseDerSha256", "tamperedResponseDerSha256"]) assert.match(proof[field], /^[a-f0-9]{64}$/);
  assert.notEqual(proof.originalResponseDerSha256, proof.tamperedResponseDerSha256);
  assert.deepEqual(proof.refusedVariants, refusedVariants);
  return true;
}
module.exports = { tamperCmsSignerSignature, responseDerBytes, scope, flags, refusedVariants, verifyProof };
