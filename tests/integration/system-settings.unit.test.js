const { expect } = require("chai");
const path = require("path");

const systemSettings = require(path.join(
  __dirname,
  "..",
  "..",
  "apps",
  "api",
  "services",
  "systemSettings",
));

describe("System settings unit coverage", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SMTP_SECURE;
    delete process.env.SMTP_REQUIRE_TLS;
  });

  after(() => {
    process.env = originalEnv;
  });

  it("maps SMTP TLS env keys for UI/system settings resolution", () => {
    expect(systemSettings.ENV_MAP.smtp_secure).to.equal("SMTP_SECURE");
    expect(systemSettings.ENV_MAP.smtp_require_tls).to.equal(
      "SMTP_REQUIRE_TLS",
    );
  });

  it("persists explicit false-like values instead of null", async () => {
    let captured = null;
    const fakePool = {
      async query(sql, params) {
        captured = { sql, params };
        return { rowCount: 1 };
      },
    };

    await systemSettings.saveSettings(
      fakePool,
      {
        smtp_secure: false,
        smtp_require_tls: "false",
      },
      42,
    );

    expect(captured).to.be.an("object");
    expect(String(captured.sql)).to.include("smtp_secure =");
    expect(String(captured.sql)).to.include("smtp_require_tls =");
    expect(captured.params).to.include("false");
    expect(captured.params).to.include(42);
  });
});

describe("registerJsonColumn + saveJsonColumn strict mode", () => {
  it("throws JSON_COLUMN_NOT_REGISTERED when the column is unknown", async () => {
    let threw = null;
    try {
      await systemSettings.saveJsonColumn(
        { query: async () => ({ rows: [] }) },
        "never_registered_extra",
        { foo: "bar" },
        1,
      );
    } catch (e) {
      threw = e;
    }
    expect(threw, "must throw").to.exist;
    expect(threw.code).to.equal("JSON_COLUMN_NOT_REGISTERED");
    expect(threw.message).to.match(/registerJsonColumn/);
  });

  it("strictKeys=true throws JSON_COLUMN_UNKNOWN_KEYS for typos", async () => {
    systemSettings.registerJsonColumn("test_strict_extra", {
      envMap: { real_key: "TEST_REAL_KEY" },
      secretFields: [],
      responseKey: "test_strict",
    });
    // Stub the DB so we don't reach an actual table.
    const pool = {
      query: async () => ({ rows: [{ test_strict_extra: {} }] }),
    };

    let threw = null;
    try {
      await systemSettings.saveJsonColumn(
        pool,
        "test_strict_extra",
        { real_key: "ok", bogus_field: "oops" },
        1,
        { strictKeys: true },
      );
    } catch (e) {
      threw = e;
    }
    expect(threw, "must throw").to.exist;
    expect(threw.code).to.equal("JSON_COLUMN_UNKNOWN_KEYS");
    expect(threw.unknownKeys).to.include("bogus_field");
  });

  it("strictKeys=false (default) silently drops unknown keys", async () => {
    systemSettings.registerJsonColumn("test_lenient_extra", {
      envMap: { real_key: "TEST_LENIENT_REAL_KEY" },
      secretFields: [],
      responseKey: "test_lenient",
    });
    const queries = [];
    const pool = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        if (sql.includes("SELECT *")) {
          return { rows: [{ test_lenient_extra: {} }] };
        }
        return { rowCount: 1, rows: [] };
      },
    };

    // No throw expected; the unknown key is logged + dropped.
    await systemSettings.saveJsonColumn(
      pool,
      "test_lenient_extra",
      { real_key: "ok", bogus_field: "ignored" },
      1,
    );
    const updateQuery = queries.find((q) => /UPDATE system_settings/.test(q.sql));
    expect(updateQuery, "expected an UPDATE to fire").to.exist;
    const updated = JSON.parse(updateQuery.params[0]);
    expect(updated).to.have.property("real_key", "ok");
    expect(updated).to.not.have.property("bogus_field");
  });

  it("listRegisteredJsonColumns surfaces the optional featureGate", () => {
    let called = 0;
    const gate = () => {
      called += 1;
      return true;
    };
    systemSettings.registerJsonColumn("test_gated_extra", {
      envMap: { x: "X" },
      featureGate: gate,
      responseKey: "test_gated",
    });
    const list = systemSettings.listRegisteredJsonColumns();
    const entry = list.find((e) => e.column === "test_gated_extra");
    expect(entry).to.exist;
    expect(entry.featureGate).to.equal(gate);
    expect(called).to.equal(0);
  });
});
