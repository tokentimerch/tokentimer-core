"use strict";

const { revocationStatus } = require("./status");
const { loadTrustMaterial } = require("./config");
const { checkObservedCertificate } = require("./helper");
const { createHash } = require("node:crypto");

async function createScanChecker(config, { load = loadTrustMaterial, check = checkObservedCertificate } = {}) {
  if (!config?.enabled) return null;
  let material;
  try { material = await load(config); } catch (_) { return async () => ({ verdict: "unknown", chainStatus: "unknown", detail: "local trust material unavailable" }); }
  return (certificate) => check({ ...certificate, roots: material.roots, intermediates: [...material.intermediates, ...(certificate.intermediateCertificates || [])], allowedOrigins: config.allowedOrigins });
}

// Keep network work bounded and reuse a single check when one certificate is
// observed in a store and one or more bindings during the same scan.
async function enrichObservedItems(entries, check, { concurrency = 4, now = () => Date.now() } = {}) {
  if (typeof check !== "function") return;
  const pending = new Map();
  let next = 0;
  async function verify(entry) {
    const fingerprintSha256 = entry.item.fingerprintSha256;
    const chain = entry.intermediateCertificates || [];
    const cacheKey = `${fingerprintSha256}:${createHash("sha256").update(JSON.stringify(chain)).digest("hex")}`;
    if (!pending.has(cacheKey)) {
      pending.set(cacheKey, (async () => {
        const attemptedAt = new Date(now()).toISOString();
        let result;
        try { result = await check({ certificatePem: entry.certificatePem, fingerprintSha256, intermediateCertificates: chain }); } catch (_) { result = null; }
        const checked = revocationStatus(result, now());
        const chainStatus = ["valid", "invalid", "unknown"].includes(result?.chainStatus) ? result.chainStatus : "unknown";
        return {
          verdict: checked.verdict,
          checkedAt: checked.checkedAt || attemptedAt,
          validUntil: checked.validUntil,
          chainStatus,
          detail: typeof result?.detail === "string" ? result.detail.slice(0, 256) : null,
        };
      })());
    }
    const result = await pending.get(cacheKey);
    const metadata = entry.item.metadata || (entry.item.metadata = []);
    metadata.push({ name: "observedRevocationVerdict", value: result.verdict });
    metadata.push({ name: "observedRevocationCheckedAt", value: result.checkedAt });
    metadata.push({ name: "observedChainStatus", value: result.chainStatus });
    if (result.validUntil) metadata.push({ name: "observedRevocationValidUntil", value: result.validUntil });
    if (result.detail) metadata.push({ name: "observedRevocationDetail", value: result.detail });
  }
  const count = Math.min(Math.max(1, Math.floor(concurrency)), 8, entries.length);
  await Promise.all(Array.from({ length: count }, async () => {
    while (next < entries.length) { const index = next++; await verify(entries[index]); }
  }));
}

module.exports = { enrichObservedItems, createScanChecker };
