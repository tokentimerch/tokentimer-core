const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("Worker notify utilities coverage", () => {
  it("rejects non-allowed Slack webhook hosts", async () => {
    const mod = await importFresh("apps/worker/src/notify/slack.js");
    const result = await mod.sendSlackWebhook("https://example.com/hook", {
      text: "hello",
    });
    expect(result.success).to.equal(false);
    expect(String(result.error)).to.match(/not allowed/i);
  });

  it("handles malformed Slack webhook URLs", async () => {
    const mod = await importFresh("apps/worker/src/notify/slack.js");
    const result = await mod.sendSlackWebhook("not-a-url", { text: "hello" });
    expect(result.success).to.equal(false);
  });

  it("safeInc and safeObserve do not throw on metric errors", async () => {
    const mod = await importFresh("apps/worker/src/shared/safeMetrics.js");

    const okCounter = {
      name: "counter_ok",
      labels() {
        return {
          inc() {},
        };
      },
    };
    const badCounter = {
      name: "counter_bad",
      labels() {
        throw new Error("counter broken");
      },
    };

    const okHistogram = {
      name: "hist_ok",
      labels() {
        return {
          observe() {},
        };
      },
    };
    const badHistogram = {
      name: "hist_bad",
      labels() {
        return {
          observe() {
            throw new Error("observe broken");
          },
        };
      },
    };

    expect(() => mod.safeInc(okCounter, { channel: "email" })).to.not.throw();
    expect(() => mod.safeInc(badCounter, { channel: "email" })).to.not.throw();
    expect(() =>
      mod.safeObserve(okHistogram, { queue: "q" }, 12),
    ).to.not.throw();
    expect(() =>
      mod.safeObserve(badHistogram, { queue: "q" }, 12),
    ).to.not.throw();
  });
});
