const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

describe("Stale Import Threshold Skipping", () => {
  let thresholds;

  before(async () => {
    const abs = path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "worker",
      "src",
      "shared",
      "thresholds.js",
    );
    const href = `${pathToFileURL(abs).href}?t=${Date.now()}`;
    thresholds = await import(href);
  });

  describe("isStaleImportThreshold", () => {
    it("marks as stale when token was imported after the threshold date (pre-expiry)", () => {
      // Token expires 2026-04-01, threshold 30 means threshold date is 2026-03-02.
      // Imported on 2026-03-15 (after threshold date) -> stale
      const result = thresholds.isStaleImportThreshold(
        "2026-03-15",
        "2026-04-01",
        30,
        false,
      );
      expect(result).to.equal(true);
    });

    it("returns false when imported before the threshold date", () => {
      // Token expires 2026-04-01, threshold 30 -> threshold date 2026-03-02.
      // Imported on 2026-02-15 (before threshold date) -> not stale
      const result = thresholds.isStaleImportThreshold(
        "2026-02-15",
        "2026-04-01",
        30,
        false,
      );
      expect(result).to.equal(false);
    });

    it("handles post-expiration thresholds (negative window)", () => {
      // Token expired 2026-03-01, threshold -7 -> threshold date is 2026-03-08.
      // Imported on 2026-03-10 (after threshold date) -> stale
      const result = thresholds.isStaleImportThreshold(
        "2026-03-10",
        "2026-03-01",
        -7,
        true,
      );
      expect(result).to.equal(true);
    });

    it("returns false for post-expiry threshold not yet passed at import", () => {
      // Token expired 2026-03-01, threshold -7 -> threshold date is 2026-03-08.
      // Imported on 2026-03-05 (before threshold date) -> not stale
      const result = thresholds.isStaleImportThreshold(
        "2026-03-05",
        "2026-03-01",
        -7,
        true,
      );
      expect(result).to.equal(false);
    });

    it("returns false when importedAt is null", () => {
      const result = thresholds.isStaleImportThreshold(
        null,
        "2026-04-01",
        30,
        false,
      );
      expect(result).to.equal(false);
    });

    it("returns false when expiration is null", () => {
      const result = thresholds.isStaleImportThreshold(
        "2026-03-15",
        null,
        30,
        false,
      );
      expect(result).to.equal(false);
    });

    it("returns false for invalid dates", () => {
      const result = thresholds.isStaleImportThreshold(
        "not-a-date",
        "2026-04-01",
        30,
        false,
      );
      expect(result).to.equal(false);
    });

    it("handles threshold 0 (day of expiry)", () => {
      // Token expires 2026-04-01, threshold 0 -> threshold date is 2026-04-01.
      // Imported on 2026-04-02 (after) -> stale
      const result = thresholds.isStaleImportThreshold(
        "2026-04-02",
        "2026-04-01",
        0,
        false,
      );
      expect(result).to.equal(true);
    });

    it("handles threshold 1 (day before expiry)", () => {
      // Token expires 2026-04-01, threshold 1 -> threshold date is 2026-03-31.
      // Imported on 2026-03-31 (same day as threshold) -> not stale (not strictly after)
      const result = thresholds.isStaleImportThreshold(
        "2026-03-31",
        "2026-04-01",
        1,
        false,
      );
      expect(result).to.equal(false);
    });
  });

  describe("computeDaysLeft", () => {
    it("returns positive for future dates", () => {
      const future = new Date();
      future.setDate(future.getDate() + 10);
      const days = thresholds.computeDaysLeft(future.toISOString().slice(0, 10));
      expect(days).to.be.at.least(9);
      expect(days).to.be.at.most(11);
    });

    it("returns negative for past dates", () => {
      const past = new Date();
      past.setDate(past.getDate() - 5);
      const days = thresholds.computeDaysLeft(past.toISOString().slice(0, 10));
      expect(days).to.be.at.most(-4);
    });

    it("returns null for null input", () => {
      expect(thresholds.computeDaysLeft(null)).to.equal(null);
    });

    it("returns null for invalid date", () => {
      expect(thresholds.computeDaysLeft("not-a-date")).to.equal(null);
    });
  });

  describe("findThresholdWindow", () => {
    const defaultThresholds = [30, 14, 7, 1, 0];

    it("maps 13 days to threshold 14", () => {
      const result = thresholds.findThresholdWindow(13, defaultThresholds);
      expect(result).to.deep.equal({
        thresholdReached: 14,
        negativeWindow: false,
      });
    });

    it("maps 7 days to threshold 7", () => {
      const result = thresholds.findThresholdWindow(7, defaultThresholds);
      expect(result).to.deep.equal({
        thresholdReached: 7,
        negativeWindow: false,
      });
    });

    it("maps 0 days to threshold 0", () => {
      const result = thresholds.findThresholdWindow(0, defaultThresholds);
      expect(result).to.deep.equal({
        thresholdReached: 0,
        negativeWindow: false,
      });
    });

    it("returns null when no threshold reached (e.g. 31 days)", () => {
      const result = thresholds.findThresholdWindow(31, defaultThresholds);
      expect(result).to.equal(null);
    });

    it("handles negative thresholds for post-expiration", () => {
      const withNeg = [30, 14, 7, 1, 0, -7, -30];
      // At -10 days (10 days past expiry), the -7 threshold is reached
      // because -10 <= -7 in the ascending sort [-30, -7]
      const result = thresholds.findThresholdWindow(-10, withNeg);
      expect(result).to.not.equal(null);
      expect(result.negativeWindow).to.equal(true);
      expect(result.thresholdReached).to.equal(-7);
    });

    it("returns null for negative days when no negative thresholds exist", () => {
      const result = thresholds.findThresholdWindow(-5, defaultThresholds);
      expect(result).to.equal(null);
    });

    it("returns null for null input", () => {
      expect(thresholds.findThresholdWindow(null, defaultThresholds)).to.equal(
        null,
      );
    });

    it("returns null for empty thresholds", () => {
      expect(thresholds.findThresholdWindow(5, [])).to.equal(null);
    });
  });
});
