"use strict";

function resolveTrustedProxyHops(raw) {
  if (raw === undefined || raw === "") return 0;
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    throw new Error("TRUST_PROXY_HOPS must be a non-negative integer");
  }
  return Number(raw);
}

module.exports = { resolveTrustedProxyHops };
