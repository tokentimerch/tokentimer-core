"use strict";

const {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
} = require("node:crypto");
const zlib = require("node:zlib");

// Generate only disposable in-memory material. Repeating a fresh seed half
// keeps a valid Ed25519 key compressible enough to exercise the short nested
// stream boundary. Detection cannot assume a particular input entropy.
function createCompactPrivateMaterialFixture() {
  const half = randomBytes(16);
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      half,
      half,
    ]),
    type: "pkcs8",
    format: "der",
  });
  const publicKey = createPublicKey(privateKey);
  const message = Buffer.from("disposable private-material regression");
  if (!verify(null, message, publicKey, sign(null, message, privateKey))) {
    throw new Error("Disposable key did not pass its validity check");
  }
  const der = privateKey.export({ type: "pkcs8", format: "der" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const compressed = zlib.deflateSync(der);
  const nested = zlib.deflateSync(compressed);
  if (compressed.length >= 64 || nested.length >= 64) {
    throw new Error("Disposable fixture did not exercise the short stream boundary");
  }
  return {
    der,
    pem,
    compressed,
    nested,
    publicDer: publicKey.export({ type: "spki", format: "der" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    representations: [
      pem,
      der.toString("hex"),
      der.toString("base64"),
      der.toString("base64url"),
      Buffer.from(pem).toString("base64"),
      Buffer.from(pem).toString("base64url"),
      compressed.toString("base64"),
      compressed.toString("base64url"),
      nested.toString("base64"),
      nested.toString("base64url"),
    ],
  };
}

module.exports = { createCompactPrivateMaterialFixture };
