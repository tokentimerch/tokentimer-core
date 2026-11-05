"use strict";

// This proof supplies a rate-limit key for a tool's same-process API hop.
// It grants no authority: ordinary bearer, scope and edition guards still run.
const crypto = require("node:crypto");
const secret = crypto.randomBytes(32);
const HEADER = "x-tokentimer-mcp-forward";
const pattern = /^(\d{13})\.([a-f0-9-]{36})\.([a-f0-9]{64})$/;
function signature(time, connectionId, token, method, path) {
  return crypto
    .createHmac("sha256", secret)
    .update(
      [
        time,
        connectionId,
        token,
        method.toUpperCase(),
        path.split("?")[0],
      ].join("\n"),
    )
    .digest("hex");
}
function forwardingHeaders(token, connectionId) {
  return ({ method, path }) => {
    const time = String(Date.now());
    return {
      [HEADER]: `${time}.${connectionId}.${signature(time, connectionId, token, method, path)}`,
    };
  };
}
function remoteRateKey(req) {
  const proof = req.headers?.[HEADER],
    authorization = req.headers?.authorization;
  if (typeof proof !== "string" || typeof authorization !== "string")
    return null;
  const match = pattern.exec(proof),
    bearer = /^Bearer (ttopm_[a-f0-9]{16}_[a-f0-9]{64})$/.exec(authorization);
  if (!match || !bearer || Math.abs(Date.now() - Number(match[1])) > 5000)
    return null;
  const expected = signature(
    match[1],
    match[2],
    bearer[1],
    req.method,
    req.originalUrl || req.url || "",
  );
  if (
    !crypto.timingSafeEqual(
      Buffer.from(expected, "hex"),
      Buffer.from(match[3], "hex"),
    )
  )
    return null;
  return `mcp-${match[2]}`;
}
module.exports = { forwardingHeaders, remoteRateKey };
