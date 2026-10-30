"use strict";
const { before, it } = require("node:test");
const assert = require("node:assert/strict");
let admission, deferral;
before(async () => {
  ({ deliveryWindowAdmission: admission, deliveryWindowDeferralMs: deferral } =
    await import("../../apps/worker/src/shared/deliveryWindow.js"));
});
const settings = (start, end, tz = "UTC") => ({
  delivery_window_start: start,
  delivery_window_end: end,
  delivery_window_tz: tz,
});
it("admits both window boundaries and rejects a trigger after the end", () => {
  const config = settings("09:00", "17:00");
  assert.equal(
    admission(config, new Date("2026-10-30T08:59:00Z")).allowed,
    false,
  );
  assert.equal(
    admission(config, new Date("2026-10-30T09:00:00Z")).allowed,
    true,
  );
  assert.equal(
    admission(config, new Date("2026-10-30T17:00:59Z")).allowed,
    true,
  );
  assert.equal(
    admission(config, new Date("2026-10-30T17:01:00Z")).allowed,
    false,
  );
});
it("handles overnight windows and midnight as hour zero", () => {
  const config = settings("22:00", "02:00");
  for (const hour of ["22:00", "00:00", "02:00"])
    assert.equal(
      admission(config, new Date(`2026-10-30T${hour}:00Z`)).allowed,
      true,
    );
  assert.equal(
    admission(config, new Date("2026-10-30T12:00:00Z")).allowed,
    false,
  );
  assert.equal(
    admission(settings("00:00", "00:01"), new Date("2026-10-30T00:00:00Z"))
      .allowed,
    true,
  );
});
it("uses IANA DST offsets and falls back to UTC for invalid zones", () => {
  const config = settings("09:00", "10:00", "Europe/Berlin");
  assert.equal(
    admission(config, new Date("2026-07-30T07:00:00Z")).allowed,
    true,
  );
  assert.equal(
    admission(config, new Date("2026-12-30T08:00:00Z")).allowed,
    true,
  );
  const fallback = admission(
    settings("09:00", "10:00", "invalid-zone"),
    new Date("2026-10-30T09:00:00Z"),
  );
  assert.deepEqual(fallback, { allowed: true, invalidTimezone: true });
});
it("retains ordinary default/partial-window semantics and bounds bad deferrals", () => {
  assert.equal(
    admission({}, new Date("2026-10-30T01:00:00Z"), {
      DELIVERY_WINDOW_DEFAULT_START: "09:00",
      DELIVERY_WINDOW_DEFAULT_END: "17:00",
    }).allowed,
    false,
  );
  assert.equal(
    admission(settings("09:00", null), new Date("2026-10-30T01:00:00Z"))
      .allowed,
    true,
  );
  for (const value of [undefined, "0", "-1", "NaN"])
    assert.equal(deferral({ DELIVERY_WINDOW_DEFERRAL_MS: value }), 10800000);
  assert.equal(deferral({ DELIVERY_WINDOW_DEFERRAL_MS: "12000" }), 12000);
});
