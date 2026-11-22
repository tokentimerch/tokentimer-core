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
  let failed = false, busy = false;
  return async function observeCa({ dnsName }) {
    assert.equal(failed, false, "CA observation was permanently invalidated");
    if (busy) { failed = true; throw new Error("Concurrent CA observation invalidated the interval"); }
    busy = true;
    try {
    const isolation = await inspectIsolation();
    assert.equal(isolation?.coverageComplete, true);
    assert.equal(isolation.startedBeforeIssue, true);
    assert.equal(isolation.directCaAccessBlocked, true);
    assert.equal(isolation.proxyAccessAllowed, true);
    assert.match(isolation.coverageId, /^[a-f0-9]{32}$/);
    const snapshot = proxy.snapshot();
    assert.equal(snapshot.transportFailed, false);
    assert.equal(snapshot.activeRequests, 0, "The observer cannot count while proxy requests are in flight");
    assert.equal(snapshot.activeConnections, 0, "The observer requires drained client connections");
    assert.equal(snapshot.activeUpstreamRequests, 0, "The observer requires drained upstream requests");
    const orders = proxy.ordersForDns(dnsName);
    const finalized = orders.filter(order => order.finalized);
    assert.equal(failed, false, "CA observation was permanently invalidated");
    return {
      source: "isolated-ca-proxy", dnsName, coverageComplete: true, coverageId: isolation.coverageId,
      ordersForDns: orders.length, finalizedOrdersForDns: finalized.length,
      orderId: orders.length === 1 ? orders[0].orderId : null,
      fingerprintSha256: finalized.length === 1 ? finalized[0].fingerprintSha256 : null,
    };
    } catch (error) { failed = true; throw error; } finally { busy = false; }
  };
}

module.exports = { createPebbleCaObserver };
