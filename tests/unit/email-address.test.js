"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const {
  isValidEmail,
  stripHtmlToText,
} = require("../../packages/email-address");
const apiEmail = require("../../apps/api/utils/emailAddress");

const ACCEPTED = [
  "alice@example.com",
  "Alice@Example.COM",
  "alice+alerts@example.com",
  "ops@mail.example.co.uk",
  "alerts@my-company.example",
  "user@xn--mnchen-3ya.de",
];

const REJECTED = [
  '"Alice <alice@example.com>"',
  "Alice <alice@example.com>",
  "alice@example.com extra",
  "alice example.com",
  "alice@example.com,bob@example.com",
  '"alice"@example.com',
  "a\u00a0b@example.com",
  "a@b\u2003c.com",
  "\u00a0alice@example.com",
  "alice@example.com\u00a0",
  "alice\u0007@example.com",
  "alice@alice@example.com",
  "user@münchen.de",
  "alice@",
  "alice@example",
  "not-an-email",
  "",
  "  ",
];

describe("isValidEmail", () => {
  for (const value of ACCEPTED) {
    it(`accepts ${value}`, () => {
      assert.strictEqual(isValidEmail(value), true);
    });
  }

  for (const value of REJECTED) {
    it(`rejects ${JSON.stringify(value)}`, () => {
      assert.strictEqual(isValidEmail(value), false);
    });
  }

  it("trims leading and trailing ASCII whitespace", () => {
    assert.strictEqual(isValidEmail("  alice+ops@example.com  "), true);
    assert.strictEqual(isValidEmail("\talice@example.com\r\n"), true);
  });

  it("rejects 255-character addresses and accepts 254", () => {
    const at254 = `a@${"x".repeat(250)}.c`;
    const at255 = `a@${"x".repeat(251)}.c`;
    assert.strictEqual(at254.length, 254);
    assert.strictEqual(at255.length, 255);
    assert.strictEqual(isValidEmail(at254), true);
    assert.strictEqual(isValidEmail(at255), false);
  });

  it("rejects a long no-dot local-part without backtracking", () => {
    const adversarial = `${"a".repeat(20000)}@${"b".repeat(20000)}`;
    const started = process.hrtime.bigint();
    assert.strictEqual(isValidEmail(adversarial), false);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 250, `isValidEmail took ${elapsedMs}ms`);
  });

  it("agrees with the API re-export and the dashboard helper", async () => {
    const dashboard = await import(
      pathToFileURL(
        path.resolve(__dirname, "../../apps/dashboard/src/utils/emailAddress.js"),
      ).href
    );
    const samples = [
      ...ACCEPTED,
      ...REJECTED,
      "  alice+ops@example.com  ",
      `a@${"x".repeat(250)}.c`,
      `a@${"x".repeat(251)}.c`,
    ];
    for (const value of samples) {
      const expected = isValidEmail(value);
      assert.strictEqual(
        apiEmail.isValidEmail(value),
        expected,
        `API helper diverged on ${JSON.stringify(value)}`,
      );
      assert.strictEqual(
        dashboard.isValidEmail(value),
        expected,
        `dashboard helper diverged on ${JSON.stringify(value)}`,
      );
    }
  });

  it("worker notify and delivery import the shared package", () => {
    const notify = fs.readFileSync(
      path.resolve(__dirname, "../../apps/worker/src/notify/email.js"),
      "utf8",
    );
    const delivery = fs.readFileSync(
      path.resolve(__dirname, "../../apps/worker/src/delivery-worker.js"),
      "utf8",
    );
    assert.match(notify, /packages\/email-address\/index\.js/);
    assert.match(delivery, /packages\/email-address\/index\.js/);
  });
});

describe("stripHtmlToText", () => {
  it("strips nested tags in one pass", () => {
    assert.strictEqual(
      stripHtmlToText("<p>Nested <b>bold</b> <span>text</span></p>"),
      "Nested bold text",
    );
  });

  it("keeps a literal less-than that is not a tag", () => {
    assert.strictEqual(stripHtmlToText("price < 100"), "price < 100");
  });

  it("drops malformed tags that still close", () => {
    assert.strictEqual(stripHtmlToText("a<b c>d</b>e"), "ade");
  });

  it("stays linear on a long unmatched less-than run", () => {
    const adversarial = `${"<".repeat(20000)}keep`;
    const started = process.hrtime.bigint();
    const out = stripHtmlToText(adversarial);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.strictEqual(out, adversarial);
    assert.ok(elapsedMs < 250, `stripHtmlToText took ${elapsedMs}ms`);
  });
});
