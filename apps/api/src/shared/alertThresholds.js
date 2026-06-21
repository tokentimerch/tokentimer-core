const MIN_ALERT_THRESHOLD_DAYS = -365;
const MAX_ALERT_THRESHOLD_DAYS = 730;

function parseThresholdValues(input) {
  if (Array.isArray(input)) {
    return input
      .map(value =>
        typeof value === "number" ? value : String(value ?? "").trim(),
      )
      .filter(value => value !== "" && value !== null && value !== undefined);
  }

  if (typeof input === "string") {
    return input
      .split(",")
      .map(part => part.trim())
      .filter(Boolean);
  }

  return [];
}

function normalizeAlertThresholdsList(input) {
  const seen = new Set();

  return parseThresholdValues(input)
    .map(value => (typeof value === "number" ? value : Number(value)))
    .filter(
      value =>
        Number.isInteger(value) &&
        value >= MIN_ALERT_THRESHOLD_DAYS &&
        value <= MAX_ALERT_THRESHOLD_DAYS,
    )
    .filter(value => {
      if (seen.has(value)) return false;
      seen.add(value);
      return true;
    })
    .sort((a, b) => b - a);
}

module.exports = {
  MIN_ALERT_THRESHOLD_DAYS,
  MAX_ALERT_THRESHOLD_DAYS,
  normalizeAlertThresholdsList,
};
