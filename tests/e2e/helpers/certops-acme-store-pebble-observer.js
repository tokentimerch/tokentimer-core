"use strict";

// Pebble wire observations are independent of the agent. They count every
// matching order only if the lab separately demonstrates that the candidate's
// CA traffic cannot bypass this continuously running proxy. The caller must
// provide a live inspection of that external isolation; this module never
// installs firewall rules or invents an isolation receipt.
const assert = require("node:assert/strict");

function createPebbleCaObserver({ proxy, inspectIsolation }) {
  assert.equal(typeof proxy?.ordersForDns, "function");
  assert.equal(typeof proxy?.snapshot, "function");
  assert.equal(typeof inspectIsolation, "function", "Independent isolation inspection is required");
  return async function observeCa({ dnsName }) {
    const isolation = await inspectIsolation();
    assert.equal(isolation?.coverageComplete, true);
    assert.equal(isolation.startedBeforeIssue, true);
    assert.equal(isolation.directCaAccessBlocked, true);
    assert.equal(isolation.proxyAccessAllowed, true);
    assert.match(isolation.coverageId, /^[a-f0-9]{32}$/);
    const snapshot = proxy.snapshot();
    assert.equal(snapshot.transportFailed, false);
    const orders = proxy.ordersForDns(dnsName);
    const finalized = orders.filter(order => order.finalized);
    return {
      source: "isolated-ca-proxy", dnsName, coverageComplete: true, coverageId: isolation.coverageId,
      ordersForDns: orders.length, finalizedOrdersForDns: finalized.length,
      orderId: orders.length === 1 ? orders[0].orderId : null,
      fingerprintSha256: finalized.length === 1 ? finalized[0].fingerprintSha256 : null,
    };
  };
}

module.exports = { createPebbleCaObserver };
