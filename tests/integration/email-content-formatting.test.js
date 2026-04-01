const { expect } = require("chai");

// Import the buildEmailContent function from delivery-worker
// Note: This is a simplified version for testing purposes
function buildEmailContent(alert, resolvedDays) {
  const name = alert.name || `Token #${alert.token_id}`;
  const computed = computeDaysLeft(alert.expiration);
  const days = Number.isFinite(resolvedDays)
    ? resolvedDays
    : Number.isFinite(computed)
      ? computed
      : alert.threshold_days;
  const expires = alert.expiration
    ? new Date(alert.expiration).toISOString().slice(0, 10)
    : null;

  // Handle expired tokens (negative days) with appropriate messaging
  const isExpired = days < 0;
  const daysText = isExpired ? Math.abs(days) : days;
  const timePhrase = isExpired ? "expired" : "expiring";
  const subject = `${name} ${timePhrase} ${isExpired ? `${daysText} day(s) ago` : `in ${daysText} day(s)`}`;

  const lines = [];
  if (isExpired) {
    lines.push(`${name} expired ${daysText} day(s) ago.`);
  } else {
    lines.push(`${name} is scheduled to expire in ${daysText} day(s).`);
  }
  if (expires) lines.push(`Expiration date: ${expires}`);
  lines.push("");

  const text = lines.join("\n");

  const htmlLines = [];
  if (isExpired) {
    htmlLines.push(
      `<p><strong>${name}</strong> expired <strong>${daysText}</strong> day(s) ago.</p>`,
    );
  } else {
    htmlLines.push(
      `<p><strong>${name}</strong> is scheduled to expire in <strong>${daysText}</strong> day(s).</p>`,
    );
  }
  if (expires)
    htmlLines.push(`<p><strong>Expiration date:</strong> ${expires}</p>`);
  htmlLines.push("<h3>Details</h3>");
  const html = htmlLines.join("");

  return { subject, text, html };
}

// Helper function to compute days left
function computeDaysLeft(expiration) {
  if (!expiration) return null;
  try {
    const expDate = new Date(expiration);
    if (isNaN(expDate.getTime())) return null;
    const expUTC = Date.UTC(
      expDate.getUTCFullYear(),
      expDate.getUTCMonth(),
      expDate.getUTCDate(),
    );
    const now = new Date();
    const todayUTC = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
    );
    const diffDays = Math.round((expUTC - todayUTC) / 86400000);
    return diffDays;
  } catch (_) {
    return null;
  }
}

describe("Email Content Formatting", () => {
  it("should format future expiration correctly", () => {
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);

    const alert = {
      token_id: 123,
      name: "Test Token",
      expiration: futureDate.toISOString().slice(0, 10),
      threshold_days: 7,
    };

    const result = buildEmailContent(alert, 7);

    expect(result.subject).to.include("expiring in 7 day(s)");
    expect(result.text).to.include("is scheduled to expire in 7 day(s)");
    expect(result.html).to.include(
      "is scheduled to expire in <strong>7</strong> day(s)",
    );
  });

  it("should format expired tokens correctly", () => {
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 3);

    const alert = {
      token_id: 123,
      name: "Expired Token",
      expiration: pastDate.toISOString().slice(0, 10),
      threshold_days: -3,
    };

    const result = buildEmailContent(alert, -3);

    expect(result.subject).to.include("expired 3 day(s) ago");
    expect(result.text).to.include("expired 3 day(s) ago");
    expect(result.html).to.include("expired <strong>3</strong> day(s) ago");
  });

  it("should handle zero days correctly", () => {
    const today = new Date();

    const alert = {
      token_id: 123,
      name: "Today Token",
      expiration: today.toISOString().slice(0, 10),
      threshold_days: 0,
    };

    const result = buildEmailContent(alert, 0);

    expect(result.subject).to.include("expiring in 0 day(s)");
    expect(result.text).to.include("is scheduled to expire in 0 day(s)");
    expect(result.html).to.include(
      "is scheduled to expire in <strong>0</strong> day(s)",
    );
  });

  it("should handle negative days with absolute value", () => {
    const alert = {
      token_id: 123,
      name: "Negative Token",
      expiration: "2024-01-01",
      threshold_days: -5,
    };

    const result = buildEmailContent(alert, -5);

    expect(result.subject).to.include("expired 5 day(s) ago");
    expect(result.text).to.include("expired 5 day(s) ago");
    expect(result.html).to.include("expired <strong>5</strong> day(s) ago");
  });
});
