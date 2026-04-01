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
