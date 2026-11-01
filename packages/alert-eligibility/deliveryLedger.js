"use strict";

// Shared wire contract with recipient verification (#461). Unknown ledger
// versions fail closed; a retry array remains legitimate pre-ledger data.
function parseDeliveryLedger(value) {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (
    Array.isArray(parsed) &&
    parsed.every((channel) => typeof channel === "string")
  ) {
    return {
      version: 0,
      retry: [...parsed],
      required: [],
      outcomes: {},
      legacy: true,
    };
  }
  if (
    !parsed ||
    Array.isArray(parsed) ||
    Number(parsed.version) !== 1 ||
    !Array.isArray(parsed.retry) ||
    !Array.isArray(parsed.required) ||
    ![...parsed.retry, ...parsed.required].every(
      (channel) => typeof channel === "string",
    ) ||
    !parsed.outcomes ||
    Array.isArray(parsed.outcomes) ||
    typeof parsed.outcomes !== "object"
  )
    return null;
  return {
    ...parsed,
    retry: [...parsed.retry],
    required: [...parsed.required],
    outcomes: { ...parsed.outcomes },
    legacy: false,
  };
}

function outcomeResult(channel, outcome) {
  if (outcome?.state === "sent") return { channel, success: true };
  const terminal = outcome?.terminal === true || outcome?.state === "blocked";
  return {
    channel,
    success: false,
    partialSuccess: outcome?.state === "partial",
    terminal,
    eligibilityTerminal: terminal && outcome?.reason === "eligibility",
    providerTerminal: terminal && outcome?.reason !== "eligibility",
    errorCode: outcome?.code || null,
  };
}

function queueDeliveryOutcome(results) {
  const failures = results.filter((row) => !row.success);
  const retry = failures.filter(
    (row) => !row.terminal && !row.eligibilityTerminal && !row.providerTerminal,
  );
  const success = results.some((row) => row.success || row.partialSuccess);
  return {
    status: !failures.length
      ? "sent"
      : success
        ? "partial"
        : retry.length
          ? "failed"
          : "blocked",
    retry: retry.length > 0,
    channels: retry.map((row) => row.channel),
  };
}

function mergeDeliveryAttempt({ prior, attempted = [], liveChannels } = {}) {
  const ledger = parseDeliveryLedger(prior);
  if (!ledger) throw new Error("unsupported_delivery_ledger");
  const outcomes = { ...ledger.outcomes };
  for (const row of attempted) {
    const terminal = row.terminal === true || row.eligibilityTerminal === true;
    outcomes[row.channel] = {
      ...outcomes[row.channel],
      state: row.success
        ? "sent"
        : row.partialSuccess
          ? "partial"
          : terminal
            ? "blocked"
            : "failed",
      terminal: row.success === true || terminal,
      reason: row.success
        ? null
        : row.eligibilityTerminal
          ? "eligibility"
          : terminal
            ? "provider"
            : null,
      code: row.success ? null : row.errorCode || null,
      endpoints: { ...outcomes[row.channel]?.endpoints, ...row.endpoints },
    };
  }
  const required = [
    ...new Set(
      liveChannels || [
        ...ledger.required,
        ...ledger.retry,
        ...Object.keys(outcomes),
      ],
    ),
  ];
  const results = required.map((channel) =>
    outcomeResult(channel, outcomes[channel]),
  );
  const outcome = queueDeliveryOutcome(results);
  const { legacy: _legacy, ...base } = ledger;
  return {
    ledger: {
      ...base,
      version: 1,
      retry: outcome.channels,
      required,
      outcomes,
    },
    results,
    outcome,
  };
}

module.exports = {
  parseDeliveryLedger,
  mergeDeliveryAttempt,
  queueDeliveryOutcome,
};
