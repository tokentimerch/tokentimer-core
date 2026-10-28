// Real-browser layout regression: run against a signed-in disposable workspace
// containing long audit event names. Checks actual glyph bounds and every
// clipping ancestor at desktop, narrow-desktop and mobile widths.
// AUDIT_URLS accepts comma-separated edition URLs; AUDIT_SAMPLE_API optionally
// signs in to the local in-memory demo. AUDIT_BROWSER_CHANNEL selects a browser.
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
(async () => {
  const b = await chromium.launch({
    headless: true,
    ...(process.env.AUDIT_BROWSER_CHANNEL
      ? { channel: process.env.AUDIT_BROWSER_CHANNEL }
      : {}),
  });
  try {
    for (const url of (
      process.env.AUDIT_URLS || "http://localhost:5173/audit"
    ).split(",")) {
      const p = await b.newPage();
      if (process.env.AUDIT_SAMPLE_API) {
        const sample = process.env.AUDIT_SAMPLE_API;
        assert(
          ["localhost", "127.0.0.1"].includes(new URL(sample).hostname),
          "Sample authentication is for a disposable localhost API",
        );
        await p.addInitScript((api) => {
          window.__ENV__ = { API_URL: api };
          localStorage.setItem("chakra-ui-color-mode", "dark");
        }, sample);
        await p.request.post(sample + "/auth/login", {
          data: { email: "demo@example.test", password: "demo" },
        });
      }
      for (const width of [1920, 1280, 390]) {
        await p.setViewportSize({ width, height: 1080 });
        await p.goto(url);
        await p.locator(".chakra-badge[title]:visible").first().waitFor();
        await p.evaluate(() => document.fonts.ready);
        const labels = await p
          .locator(".chakra-badge[title]")
          .evaluateAll((es) =>
            es
              .filter(
                (e) =>
                  e.textContent.length > 30 &&
                  e.getBoundingClientRect().width > 0,
              )
              .map((e) => {
                const b = e.getBoundingClientRect();
                const range = document.createRange();
                range.selectNodeContents(e);
                const text = [...range.getClientRects()].map((r) => ({
                  left: r.left,
                  right: r.right,
                  top: r.top,
                  bottom: r.bottom,
                }));
                let parent = e.parentElement;
                const clips = [];
                while (parent && parent !== document.body) {
                  const cs = getComputedStyle(parent);
                  if (["hidden", "clip", "auto"].includes(cs.overflowX)) {
                    const r = parent.getBoundingClientRect();
                    clips.push({ left: r.left, right: r.right });
                  }
                  parent = parent.parentElement;
                }
                return {
                  label: e.textContent,
                  badge: {
                    left: b.left,
                    right: b.right,
                    top: b.top,
                    bottom: b.bottom,
                  },
                  text,
                  clips,
                  scrollWidth: e.scrollWidth,
                  clientWidth: e.clientWidth,
                };
              }),
          );
        assert(labels.length, "Expected long audit event names");
        for (const e of labels) {
          assert(
            e.scrollWidth <= e.clientWidth + 1,
            `${url}/${width}: ${e.label} overflows its badge`,
          );
          for (const t of e.text) {
            assert(
              t.left >= e.badge.left - 1 && t.right <= e.badge.right + 1,
              `${url}/${width}: ${e.label} glyphs overflow badge`,
            );
            for (const c of e.clips)
              assert(
                t.left >= c.left - 1 && t.right <= c.right + 1,
                `${url}/${width}: ${e.label} is clipped by an ancestor`,
              );
          }
        }
        console.log(
          `PASS ${url} ${width}px: ${labels.length} full long names visible`,
        );
      }
      await p.close();
    }
  } finally {
    await b.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
