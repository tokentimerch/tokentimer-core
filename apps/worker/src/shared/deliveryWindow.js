// One admission rule for ordinary deliveries and independent outbox triggers.
export function deliveryWindowAdmission(
  settings,
  now = new Date(),
  env = process.env,
) {
  let start = String(settings?.delivery_window_start || "").trim();
  let end = String(settings?.delivery_window_end || "").trim();
  if (!start && !end) {
    start = env.DELIVERY_WINDOW_DEFAULT_START || "00:00";
    end = env.DELIVERY_WINDOW_DEFAULT_END || "23:59";
  }
  if (!start || !end) return { allowed: true, invalidTimezone: false };
  start = start.slice(0, 5);
  end = end.slice(0, 5);
  const timezone =
    String(settings?.delivery_window_tz || "UTC").trim() || "UTC";
  let time;
  let invalidTimezone = false;
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      hourCycle: "h23",
      hour: "2-digit",
      minute: "2-digit",
    }).formatToParts(now);
    time = `${parts.find((part) => part.type === "hour").value}:${parts.find((part) => part.type === "minute").value}`;
  } catch {
    invalidTimezone = true;
    time = `${String(now.getUTCHours()).padStart(2, "0")}:${String(now.getUTCMinutes()).padStart(2, "0")}`;
  }
  return {
    allowed:
      start <= end
        ? time >= start && time <= end
        : time >= start || time <= end,
    invalidTimezone,
  };
}

export function deliveryWindowDeferralMs(env = process.env) {
  const configured = Number(env.DELIVERY_WINDOW_DEFERRAL_MS);
  return Number.isFinite(configured) && configured > 0
    ? configured
    : 3 * 60 * 60 * 1000;
}
