"use strict";

const { deployStoreConsumers } = require("./store-consumers");
const { observeStoreOnlyPredecessor } = require("../windows-cert-store/store-only");

// The Store installation is already verified. Consumer failures must neither
// undo that installation nor cause another CA order. Replaying this tail is
// safe: deployIisBinding accepts an already switched replacement for verification.
async function runStoreConsumerTail({ snapshot, certificatePem, jobId, claimId, client,
  acquireLock, ensureLease, onBeforeMutation, reportOutcome, signal, execFileImpl,
  connectImpl, observeImpl = observeStoreOnlyPredecessor, deployImpl }) {
  const consumers = snapshot?.iisConsumers || [];
  if (!consumers.length) return { allAttempted: true, outcomes: [] };
  if (!Array.isArray(consumers) || !/^[a-f0-9]{64}$/.test(snapshot.predecessorFingerprintSha256 || "") ||
      typeof client?.authorizeIisConsumer !== "function") throw new Error("Store consumer authorization is unavailable");
  const lock = await acquireLock();
  try {
    return await lock.run(async (lockSignal) => {
      const combined = signal && lockSignal ? AbortSignal.any([signal, lockSignal]) : signal || lockSignal;
      lock.assertHeld();
      await ensureLease();
      const predecessor = await observeImpl({ fingerprintSha256: snapshot.predecessorFingerprintSha256, execFileImpl, signal: combined });
      lock.assertHeld();
      if (predecessor.error || !predecessor.existingThumbprintSha1) throw new Error("The frozen Store predecessor cannot be confirmed");
      return deployStoreConsumers({ consumers, certificatePem, predecessorThumbprint: predecessor.existingThumbprintSha1,
        signal: combined,
        ...(deployImpl ? { deployImpl } : { deployImpl: (options) => require("./index").deployIisBinding({ ...options,
          ...(execFileImpl ? { execFileImpl } : {}), ...(connectImpl ? { connectImpl } : {}) }) }),
        authorizeImpl: async (consumer) => {
          lock.assertHeld(); await ensureLease();
          const allowed = await client.authorizeIisConsumer({ jobId, claimId, consumerId: consumer.consumerId,
            authorizationRevision: consumer.authorizationRevision });
          lock.assertHeld();
          return allowed === true;
        },
        onBeforeMutation: (stage) => { lock.assertHeld(); onBeforeMutation(stage); },
        onOutcome: async (outcome) => { lock.assertHeld(); await ensureLease(); await reportOutcome(outcome); },
      });
    });
  } finally { lock.release(); }
}

module.exports = { runStoreConsumerTail };
