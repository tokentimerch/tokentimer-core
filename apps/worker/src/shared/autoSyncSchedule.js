function localTimeToUtc(dateStr, hours, minutes, tz) {
  // Parse the date string as if it were UTC, then adjust for the timezone offset
  const naive = new Date(
    `${dateStr}T${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:00Z`,
  );
  // Determine what local time `naive` represents in `tz` so we can compute the offset
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(naive);
  const get = (type) => {
    const part = parts.find((x) => x.type === type);
    return part ? parseInt(part.value, 10) : 0;
  };
  const localInTz = new Date(
    Date.UTC(
      get("year"),
      get("month") - 1,
      get("day"),
      get("hour") === 24 ? 0 : get("hour"),
      get("minute"),
      get("second"),
    ),
  );
  // offset = localInTz - naive  (positive means tz is ahead of UTC)
  const offsetMs = localInTz.getTime() - naive.getTime();
  return new Date(naive.getTime() - offsetMs);
}

/**
 * Safely advance a date by N months without overflowing.
 * e.g. Jan 31 + 1 month = Feb 28 (or 29), not Mar 3.
 */
function addMonthsClamped(date, months) {
  const result = new Date(date);
  const targetMonth = result.getMonth() + months;
  result.setMonth(targetMonth);
  // If the day overflowed (e.g. 31 -> next month 3rd), clamp to last day
  if (result.getMonth() !== ((targetMonth % 12) + 12) % 12) {
    result.setDate(0); // sets to last day of previous month
  }
  return result;
}

/**
 * Compute the next sync time respecting user-chosen schedule_time and schedule_tz.
 *
 * 1. Figure out "today at HH:MM in the user's timezone" as a UTC timestamp.
 * 2. If that moment is still in the future, use it as the first sync.
 * 3. Otherwise, advance by one period and keep advancing until it is in the future.
 */
export function computeNextSync(frequency, scheduleTime, scheduleTz) {
  const tz = scheduleTz || "UTC";
  const [rawH, rawM] = (scheduleTime || "09:00").split(":").map(Number);
  const h = Number.isFinite(rawH) ? rawH : 9;
  const m = Number.isFinite(rawM) ? rawM : 0;
  const nowUtc = new Date();

  // Get "today" in the user's timezone as YYYY-MM-DD
  const todayInTz = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(nowUtc);

  // Start with "today at the scheduled time" converted to UTC
  let candidate = localTimeToUtc(todayInTz, h, m, tz);

  // If that time has already passed, advance by one period
  function advance(d) {
    if (frequency === "monthly") return addMonthsClamped(d, 1);
    if (frequency === "weekly") return new Date(d.getTime() + 7 * 86400000);
    return new Date(d.getTime() + 86400000); // daily
  }

  // Keep advancing until the candidate is strictly in the future
  while (candidate <= nowUtc) {
    candidate = advance(candidate);
  }

  return candidate;
}

