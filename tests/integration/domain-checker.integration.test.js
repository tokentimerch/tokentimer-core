const fs = require("fs");
const path = require("path");
const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const PROJECT_ROOT = path.resolve(__dirname, "../..");

function requireFirstExisting(candidates) {
  for (const relativePath of candidates) {
    const absolutePath = path.join(PROJECT_ROOT, relativePath);
    if (fs.existsSync(absolutePath) || fs.existsSync(`${absolutePath}.js`)) {
      return require(absolutePath);
    }
  }
  throw new Error(
    `Unable to resolve module from candidates: ${candidates.join(", ")}`,
  );
}

function readFirstExisting(candidates) {
  for (const relativePath of candidates) {
    const absolutePath = path.join(PROJECT_ROOT, relativePath);
    if (fs.existsSync(absolutePath)) {
      return fs.readFileSync(absolutePath, "utf8");
    }
  }
  throw new Error(
    `Unable to resolve source from candidates: ${candidates.join(", ")}`,
  );
}

function normalizeMetadata(value) {
  if (!value || typeof value !== "string") return value || {};
  try {
    return JSON.parse(value);
  } catch (_err) {
    return {};
  }
}

function buildManyCertificates(count) {
  return Array.from({ length: count }, (_value, index) => ({
    id: `bulk-${index}`,
    name: `bulk-${index}.example.com`,
    domains: [`bulk-${index}.example.com`],
    expiration: "2099-12-31",
  }));
}

const { lookupDomain, normalizeRootDomain, parseDiscoveryLines } =
  requireFirstExisting([
    "apps/api/services/domainChecker",
    "apps/saas/services/domainChecker",
  ]);

const paidPlanForDomainChecker = "pro";

describe("Domain checker discovery service integration", function () {
  this.timeout(60000);

  it("normalizes root domains from URLs and wildcards", () => {
    expect(normalizeRootDomain("https://*.Example.COM/path")).to.equal(
      "example.com",
    );
    expect(normalizeRootDomain("example.com.")).to.equal("example.com");
    expect(normalizeRootDomain("localhost")).to.equal(null);
  });

  it("parses Subfinder output and deduplicates hosts", () => {
    const parsed = parseDiscoveryLines(
      {
        subfinder: [
          JSON.stringify({ host: "www.example.com" }),
          JSON.stringify({ host: "api.example.com" }),
          JSON.stringify({ host: "cdn.example.com" }),
          JSON.stringify({ host: "ignored.other" }),
        ],
      },
      "example.com",
    );

    expect(parsed.items.map((item) => item.name)).to.deep.equal([
      "api.example.com",
      "cdn.example.com",
      "www.example.com",
    ]);
    expect(
      parsed.items.find((item) => item.name === "www.example.com").sources,
    ).to.deep.equal(["subfinder"]);
    expect(parsed.items.every((item) => item.checked)).to.equal(true);
  });

  it("returns results when Subfinder succeeds", async () => {
    const runBinary = async ({ onLine }) => {
      onLine(JSON.stringify({ host: "www.example.com" }));
    };

    const result = await lookupDomain("example.com", {
      workspaceId: "integration-partial",
      runBinary,
    });

    expect(result.items).to.have.length(1);
    expect(result.partial).to.equal(false);
    expect(result.toolErrors).to.have.length(0);
  });

  it("fails when all discovery tools fail", async () => {
    const runBinary = async () => {
      throw Object.assign(new Error("tool failed"), {
        code: "DOMAIN_CHECKER_BINARY_FAILED",
      });
    };

    let error;
    try {
      await lookupDomain("example.com", {
        workspaceId: "integration-failed",
        runBinary,
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.exist;
    expect(error.message).to.include("All domain discovery sources failed");
    expect(error.toolErrors).to.have.length(1);
  });

  it("maps all-tool timeouts to a timeout error", async () => {
    const runBinary = async () => {
      throw Object.assign(new Error("timeout"), {
        code: "DOMAIN_CHECKER_TOOL_TIMEOUT",
      });
    };

    let error;
    try {
      await lookupDomain("example.com", {
        workspaceId: "integration-timeout",
        runBinary,
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.exist;
    expect(error.code).to.equal("DOMAIN_CHECKER_TIMEOUT");
  });

  it("enforces one active lookup per workspace and domain", async () => {
    const releases = [];
    const runBinary = () =>
      new Promise((resolve) => {
        releases.push(resolve);
      });

    const first = lookupDomain("example.com", {
      workspaceId: "integration-busy",
      runBinary,
    });

    let error;
    try {
      await lookupDomain("example.com", {
        workspaceId: "integration-busy",
        runBinary,
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.exist;
    expect(error.code).to.equal("DOMAIN_CHECKER_BUSY");
    releases.forEach((release) => release());
    await first;
  });

  it("caps results at the configured maximum and reports truncation", async () => {
    const runBinary = async ({ args, onLine }) => {
      if (args[0] === "enum") return;
      for (let index = 0; index < 3; index += 1) {
        onLine(JSON.stringify({ host: `host${index}.example.com` }));
      }
    };

    const result = await lookupDomain("example.com", {
      workspaceId: "integration-cap",
      runBinary,
      maxResults: 2,
    });

    expect(result.items).to.have.length(2);
    expect(result.meta.truncated).to.equal(true);
  });

  it("keeps dedicated domain checker lookup rate-limit wiring", () => {
    const source = readFirstExisting([
      "apps/api/middleware/rateLimit.js",
      "apps/saas/middleware/rateLimit.js",
    ]);

    expect(source).to.include("DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS");
    expect(source).to.include("DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_MAX");
    expect(source).to.include("DOMAIN_CHECKER_RATE_LIMITED");
  });
});

describe("Domain checker API import integration", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    testUser = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      paidPlanForDomainChecker,
    );
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery(
        "DELETE FROM audit_events WHERE workspace_id = $1 AND action IN ('DOMAIN_CHECKER_LOOKUP', 'DOMAIN_CHECKER_IMPORT')",
        [workspaceId],
      );
      await TestUtils.execQuery(
        "DELETE FROM domain_monitors WHERE workspace_id = $1 AND url LIKE 'https://%.example.com'",
        [workspaceId],
      );
      await TestUtils.execQuery(
        "DELETE FROM tokens WHERE workspace_id = $1 AND notes ILIKE '%Imported by domain checker%'",
        [workspaceId],
      );
    }
    if (testUser?.email && session?.cookie) {
      await TestUtils.cleanupTestUser(testUser.email, session.cookie);
    }
  });

  it("rejects unauthenticated and invalid import requests", async () => {
    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .send({ domain: "example.com", certificates: [] })
      .expect(401);

    const invalidDomain = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .set("Cookie", session.cookie)
      .send({ domain: "localhost", certificates: [{ id: "one" }] })
      .expect(400);
    expect(invalidDomain.body.code).to.equal("INVALID_DOMAIN");

    const noneSelected = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .set("Cookie", session.cookie)
      .send({ domain: "example.com", certificates: [] })
      .expect(400);
    expect(noneSelected.body.code).to.equal("NO_CERTIFICATES_SELECTED");

    const tooMany = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .set("Cookie", session.cookie)
      .send({
        domain: "example.com",
        certificates: buildManyCertificates(50001),
      })
      .expect(400);
    expect(tooMany.body.code).to.equal("TOO_MANY_CERTIFICATES");
  });

  it("imports discovered SSL tokens, creates monitors, reports skipped reasons, and writes audit metadata", async () => {
    const certificates = [
      {
        id: "disc-www",
        name: "www.example.com",
        domains: ["www.example.com"],
        expiration: "2099-02-03",
        issuer: "Integration Test CA",
        subject: "CN=www.example.com",
        serialNumber: "serial-www",
        fingerprint: "fp-www",
        sources: ["subfinder"],
      },
      {
        id: "disc-api",
        name: "api.example.com",
        domains: ["api.example.com"],
        validTo: "2099-02-04",
        issuerName: "Integration Test CA 2",
        commonName: "api.example.com",
        sourceCertId: "source-api",
        sources: ["subfinder"],
      },
      {
        id: "disc-outside",
        name: "outside.invalid",
        domains: ["outside.invalid"],
        expiration: "2099-02-05",
        sources: ["subfinder"],
      },
      {
        id: "disc-empty",
        name: "outside.invalid",
        domains: ["outside.invalid"],
        sources: ["subfinder"],
      },
    ];

    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .set("Cookie", session.cookie)
      .send({
        domain: "example.com",
        certificates,
        monitorOptions: {
          enabled: true,
          health_check_enabled: false,
          check_interval: "daily",
          alert_after_failures: 3,
        },
      })
      .expect(201);

    expect(response.body.imported).to.have.length(2);
    expect(response.body.skipped).to.have.length(2);
    expect(response.body.skippedCounts).to.deep.equal({
      duplicate: 0,
      invalid: 2,
    });
    expect(response.body.monitors).to.deep.equal({ created: 2, existing: 0 });
    expect(
      response.body.skipped.map((entry) => entry.detail).sort(),
    ).to.deep.equal([
      "no_matching_domains",
      "no_matching_domains_and_missing_expiration",
    ]);

    const tokenIds = response.body.imported.map((entry) => entry.tokenId);
    const tokenRows = await TestUtils.execQuery(
      `SELECT id, name, type, category, issuer, subject, domains, notes
         FROM tokens
        WHERE id = ANY($1::int[])
        ORDER BY name`,
      [tokenIds],
    );
    expect(tokenRows.rows).to.have.length(2);
    expect(tokenRows.rows.every((row) => row.type === "ssl_cert")).to.equal(
      true,
    );
    expect(tokenRows.rows.every((row) => row.category === "cert")).to.equal(
      true,
    );
    expect(
      tokenRows.rows.some((row) => row.domains.includes("www.example.com")),
    ).to.equal(true);
    expect(
      tokenRows.rows.some((row) =>
        row.notes.includes("domain checker source id: source-api"),
      ),
    ).to.equal(true);

    const monitors = await TestUtils.execQuery(
      `SELECT url, health_check_enabled, check_interval, alert_after_failures
         FROM domain_monitors
        WHERE workspace_id = $1 AND url = ANY($2::text[])
        ORDER BY url`,
      [workspaceId, ["https://api.example.com", "https://www.example.com"]],
    );
    expect(monitors.rows).to.have.length(2);
    expect(monitors.rows.map((row) => row.url)).to.deep.equal([
      "https://api.example.com",
      "https://www.example.com",
    ]);
    expect(
      monitors.rows.every((row) => row.health_check_enabled === false),
    ).to.equal(true);
    expect(
      monitors.rows.every((row) => row.check_interval === "daily"),
    ).to.equal(true);
    expect(
      monitors.rows.every((row) => Number(row.alert_after_failures) === 3),
    ).to.equal(true);

    const audit = await TestUtils.execQuery(
      `SELECT metadata
         FROM audit_events
        WHERE workspace_id = $1 AND action = 'DOMAIN_CHECKER_IMPORT'
        ORDER BY occurred_at DESC
        LIMIT 1`,
      [workspaceId],
    );
    expect(audit.rowCount).to.equal(1);
    const metadata = normalizeMetadata(audit.rows[0].metadata);
    expect(metadata.domain).to.equal("example.com");
    expect(metadata.source).to.equal("subfinder");
    expect(metadata.submitted).to.equal(4);
    expect(metadata.imported).to.equal(2);
    expect(metadata.skipped).to.equal(2);
    expect(metadata.skipped_invalid).to.equal(2);
    expect(metadata.skipped_duplicate).to.equal(0);
    expect(metadata.skipped_unreachable).to.equal(0);
    expect(metadata.skipped_other_invalid).to.equal(2);
    expect(metadata.create_monitors).to.equal(true);
    expect(metadata.monitors_created).to.equal(2);
    expect(metadata.monitor_health_check_enabled).to.equal(false);
    expect(metadata.monitor_check_interval).to.equal("daily");
    expect(metadata.monitor_alert_after_failures).to.equal(3);
  });

  it("deduplicates repeated imports by domain checker source id and certificate shape", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domain-checker/import`)
      .set("Cookie", session.cookie)
      .send({
        domain: "example.com",
        certificates: [
          {
            id: "disc-www-repeat",
            name: "www.example.com",
            domains: ["www.example.com"],
            expiration: "2099-02-03",
            issuer: "Integration Test CA",
            subject: "CN=www.example.com",
            sources: ["subfinder"],
          },
          {
            id: "disc-api-repeat",
            name: "api.example.com",
            domains: ["api.example.com"],
            validTo: "2099-02-04",
            issuerName: "Integration Test CA 2",
            commonName: "api.example.com",
            sourceCertId: "source-api",
            sources: ["subfinder"],
          },
        ],
        monitorOptions: {
          enabled: true,
          health_check_enabled: false,
          check_interval: "daily",
          alert_after_failures: 3,
        },
      })
      .expect(201);

    expect(response.body.imported).to.have.length(0);
    expect(response.body.skippedCounts).to.deep.equal({
      duplicate: 2,
      invalid: 0,
    });
    expect(response.body.skipped.map((entry) => entry.reason)).to.deep.equal([
      "duplicate",
      "duplicate",
    ]);
    expect(
      response.body.skipped.map((entry) => entry.detail).sort(),
    ).to.deep.equal([
      "existing_token_for_domain_checker_source_id",
      "existing_token_for_expiration_issuer_and_domain",
    ]);
  });
});
