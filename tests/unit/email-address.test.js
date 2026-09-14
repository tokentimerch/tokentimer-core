"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  isValidEmail,
  stripHtmlToText,
} = require("../../packages/email-address");

describe("isValidEmail", () => {
  const accepted = [
    "alice@example.com",
    "Alice@Example.COM",
    "alice+alerts@example.com",
    "ops@mail.example.co.uk",
    "alerts@my-company.example",
  ];
  const rejected = [
    '"Alice <alice@example.com>"',
    "Alice <alice@example.com>",
    "alice@example.com extra",
    "alice example.com",
    "alice@example.com,bob@example.com",
    "alice@",
    "alice@example",
    "not-an-email",
    "",
    "  ",
  ];

  for (const value of accepted) {
    it(`accepts ${value}`, () => {
      assert.strictEqual(isValidEmail(value), true);
    });
  }

  for (const value of rejected) {
    it(`rejects ${JSON.stringify(value)}`, () => {
      assert.strictEqual(isValidEmail(value), false);
    });
  }
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
