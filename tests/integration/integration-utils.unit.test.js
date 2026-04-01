const { expect } = require("chai");
function loadIntegrationUtils() {
  const candidates = [
    "../../apps/api/services/integrationUtils",
    "../../apps/saas/integrations/integrationUtils",
  ];

  for (const modPath of candidates) {
    try {
      return require(modPath);
    } catch (err) {
      if (err && err.code !== "MODULE_NOT_FOUND") {
        throw err;
      }
    }
  }

  throw new Error("Unable to resolve integrationUtils module in this variant");
}

const { tryParseDate, discoverExpiryFromObject, formatDateYmd } =
  loadIntegrationUtils();

describe("integrationUtils unit tests", () => {
  describe("tryParseDate", () => {
    it("returns null for falsy values", () => {
      expect(tryParseDate(null)).to.be.null;
      expect(tryParseDate(undefined)).to.be.null;
      expect(tryParseDate("")).to.be.null;
      expect(tryParseDate(0)).to.be.null;
    });

    it("parses ISO date strings", () => {
      const d = tryParseDate("2026-06-15T00:00:00Z");
      expect(d).to.be.instanceOf(Date);
      expect(d.toISOString().slice(0, 10)).to.equal("2026-06-15");
    });

    it("parses epoch timestamps", () => {
      const d = tryParseDate(1750000000000);
      expect(d).to.be.instanceOf(Date);
    });

    it("returns null for invalid strings", () => {
      expect(tryParseDate("not-a-date")).to.be.null;
      expect(tryParseDate("abc123")).to.be.null;
    });
  });

  describe("discoverExpiryFromObject", () => {
    it("returns null for non-objects", () => {
      expect(discoverExpiryFromObject(null)).to.be.null;
      expect(discoverExpiryFromObject("string")).to.be.null;
      expect(discoverExpiryFromObject(42)).to.be.null;
    });

    it("discovers expiresAt field", () => {
      const d = discoverExpiryFromObject({ expiresAt: "2026-12-31" });
      expect(d).to.be.instanceOf(Date);
    });

    it("discovers expiration field", () => {
      const d = discoverExpiryFromObject({
        expiration: "2026-06-01T00:00:00Z",
      });
      expect(d).to.be.instanceOf(Date);
    });

    it("discovers not_after field", () => {
      const d = discoverExpiryFromObject({ not_after: "2027-01-15" });
      expect(d).to.be.instanceOf(Date);
    });

    it("returns null if no expiry fields found", () => {
      expect(discoverExpiryFromObject({ name: "test", value: "abc" })).to.be
        .null;
    });

    it("skips invalid date values in candidate fields", () => {
      expect(
        discoverExpiryFromObject({
          expiresAt: "invalid",
          expiration: "2026-06-01",
        }),
      ).to.be.instanceOf(Date);
    });
  });

  describe("formatDateYmd", () => {
    it("returns null for falsy values", () => {
      expect(formatDateYmd(null)).to.be.null;
      expect(formatDateYmd(undefined)).to.be.null;
      expect(formatDateYmd("")).to.be.null;
    });

    it("formats Date objects", () => {
      expect(formatDateYmd(new Date("2026-03-15T12:00:00Z"))).to.equal(
        "2026-03-15",
      );
    });

    it("formats ISO strings", () => {
      expect(formatDateYmd("2026-12-25T00:00:00Z")).to.equal("2026-12-25");
    });

    it("formats epoch timestamps", () => {
      const result = formatDateYmd(1750000000000);
      expect(result).to.match(/^\d{4}-\d{2}-\d{2}$/);
    });

    it("returns null for invalid dates", () => {
      expect(formatDateYmd("not-a-date")).to.be.null;
    });
  });
});
