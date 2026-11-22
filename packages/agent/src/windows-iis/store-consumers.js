"use strict";

const { assertValidBinding, formatBindingSelector, normalizeThumbprint, deployIisBinding } = require("./index");

// The caller must supply an authenticated, immutable authorization snapshot
// and hold the My store lock. This function does not establish consent.
async function deployStoreConsumers({ consumers, predecessorThumbprint, certificatePem, signal,
  deployImpl = deployIisBinding, authorizeImpl, onBeforeMutation, onOutcome = async () => {} }) {
  if (!Array.isArray(consumers) || consumers.length > 32 || typeof certificatePem !== "string" || !certificatePem ||
      typeof onBeforeMutation !== "function" || typeof authorizeImpl !== "function") throw new Error("invalid store consumer deployment");
  const expected = normalizeThumbprint(predecessorThumbprint);
  const ids = new Set(), selectors = new Set();
  for (const consumer of consumers) {
    if (!consumer || typeof consumer.consumerId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(consumer.consumerId) || ids.has(consumer.consumerId) ||
        !Number.isSafeInteger(consumer.authorizationRevision) || consumer.authorizationRevision < 1 || consumer.binding?.store !== "My") throw new Error("invalid store consumer authorization");
    assertValidBinding(consumer.binding);
    const selector = formatBindingSelector(consumer.binding).toLowerCase();
    if (selectors.has(selector)) throw new Error("duplicate IIS selector");
    ids.add(consumer.consumerId); selectors.add(selector);
  }
  const outcomes = [];
  for (const consumer of consumers) {
    if (signal?.aborted) break;
    // Recheck the live authorization revision for every consumer. A signed
    // snapshot alone cannot authorize a binding after an operator opted out.
    let allowed = false;
    try { allowed = await authorizeImpl(consumer, signal); } catch { /* authorization unavailable: fail closed */ }
    if (signal?.aborted) break;
    if (allowed !== true) {
      outcomes.push({ id: consumer.consumerId, ok: false, code: "CONSENT_UNAVAILABLE" });
      await onOutcome(outcomes.at(-1));
      continue;
    }
    onBeforeMutation("iis-consumer");
    if (signal?.aborted) break;
    const result = await deployImpl({ binding: consumer.binding, certificatePem,
      expectedExistingThumbprint: expected, signal });
    outcomes.push({ id: consumer.consumerId, ok: result.ok === true, code: result.ok === true ? null : result.code });
    await onOutcome(outcomes.at(-1));
    if (result.code === "ABORTED" || signal?.aborted) break;
  }
  return { allAttempted: outcomes.length === consumers.length, outcomes };
}

module.exports = { deployStoreConsumers };
