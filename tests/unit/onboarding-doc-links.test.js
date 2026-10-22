const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  loadRegistry,
  validateRegistry,
  hasAnchor,
  slug,
} = require("../../scripts/check-onboarding-doc-links");

describe("onboarding doc link registry", () => {
  it("has well-formed entries", () => {
    const entries = loadRegistry();
    assert.ok(entries.length > 0);
    for (const [key, entry] of entries) {
      for (const variant of [entry, entry.cloud].filter((v) => v !== undefined)) {
        if (variant === null) continue;
        if (variant.url) {
          assert.match(
            variant.url,
            /^https:\/\/github\.com\/tokentimerch\/tokentimer-core\/blob\/main\/docs\/[A-Za-z0-9/._-]+\.md$/,
            `${key} url`,
          );
          continue;
        }
        assert.match(variant.path, /^\/[a-z0-9/-]+$/, `${key} path`);
        assert.match(variant.anchor, /^[a-z0-9-]+$/, `${key} anchor`);
      }
    }
  });

  it("points the Vault and controller guides at the runbooks in every edition", () => {
    const registry = Object.fromEntries(loadRegistry());
    assert.deepEqual(registry["certops.vault"], {
      path: "/runbooks/certops-shared-certificate-distribution",
      anchor: "setup",
    });
    assert.deepEqual(registry["certops.vaultAuth"], {
      path: "/runbooks/certops-vault-agent-authentication",
      anchor: "1-create-narrowly-scoped-roles-as-a-vault-administrator",
    });
    assert.deepEqual(registry["certops.controller"], {
      path: "/runbooks/acme-cert-manager",
      anchor: "controller",
    });
  });
});

describe("onboarding doc link validator", () => {
  let root;

  before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-docs-"));
    const write = (rel, body) => {
      const file = path.join(root, rel);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, body);
    };
    write("docs-selfhosted/alerts/index.mdx", "## Thresholds {#thresholds}\n");
    write("docs-cloud/alerts/index.mdx", "## Thresholds {#thresholds}\n");
    write(
      "docs-selfhosted/quickstart.mdx",
      "import G from '@site/src/content/Guide.mdx';\n<G />\n",
    );
    write("src/content/Guide.mdx", "## 3. Create a sample asset\n");
  });

  after(() => fs.rmSync(root, { recursive: true, force: true }));

  it("accepts explicit and generated anchors, including shared guides", () => {
    const entries = [
      ["a", { path: "/alerts", anchor: "thresholds" }],
      ["b", { path: "/quickstart", anchor: "3-create-a-sample-asset", cloud: null }],
    ];
    assert.deepEqual(validateRegistry(entries, root), []);
  });

  it("reports missing pages and missing anchors per edition", () => {
    const problems = validateRegistry(
      [
        ["gone", { path: "/nope", anchor: "x" }],
        ["moved", { path: "/alerts", anchor: "renamed" }],
        ["cloudOnlyBroken", { path: "/alerts", anchor: "thresholds", cloud: { path: "/alerts", anchor: "bad" } }],
      ],
      root,
    );
    assert.equal(problems.length, 5);
    assert.match(problems.join("\n"), /gone \(selfHosted\): page \/nope not found/);
    assert.match(problems.join("\n"), /gone \(cloud\): page \/nope not found/);
    assert.match(problems.join("\n"), /moved \(selfHosted\): #renamed/);
    assert.match(problems.join("\n"), /moved \(cloud\): #renamed/);
    assert.match(problems.join("\n"), /cloudOnlyBroken \(cloud\): #bad/);
  });

  it("does not look up absolute core-docs links in the docs tree", () => {
    const entries = [
      [
        "v",
        {
          url: "https://github.com/tokentimerch/tokentimer-core/blob/main/docs/x.md",
          cloud: { path: "/alerts", anchor: "thresholds" },
        },
      ],
    ];
    assert.deepEqual(validateRegistry(entries, root), []);
  });

  it("matches the docs slug rule", () => {
    assert.equal(slug("1. Check email delivery"), "1-check-email-delivery");
    assert.equal(hasAnchor("## Fields {#fields}", "fields"), true);
    assert.equal(hasAnchor("## Something else", "fields"), false);
  });
});
