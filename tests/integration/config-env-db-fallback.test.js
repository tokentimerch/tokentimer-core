const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

function setEnv(patch) {
  const previous = {};
  for (const [key, value] of Object.entries(patch)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }
  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("System Settings: ENV vs DB Fallback", () => {
  let systemSettings;

  before(async () => {
    systemSettings = require(
      path.join(__dirname, "..", "..", "apps", "api", "services", "systemSettings"),
    );
  });

  afterEach(() => {
    systemSettings.invalidateCache();
  });

  describe("getSetting priority", () => {
    it("returns env value when env var is set (takes precedence over DB)", async () => {
      const restore = setEnv({ SMTP_HOST: "env-smtp.example.com" });
      try {
        const fakePool = {
          query: async () => ({
            rows: [{ smtp_host: "db-smtp.example.com" }],
          }),
        };

        const result = await systemSettings.getSetting(fakePool, "smtp_host");
        expect(result.value).to.equal("env-smtp.example.com");
        expect(result.source).to.equal("env");
        expect(result.locked).to.equal(true);
      } finally {
        restore();
      }
    });

    it("returns DB value when env var is not set", async () => {
      const restore = setEnv({ SMTP_HOST: undefined });
      try {
        systemSettings.invalidateCache();
        const fakePool = {
          query: async () => ({
            rows: [{ smtp_host: "db-smtp.example.com" }],
          }),
        };

        const result = await systemSettings.getSetting(fakePool, "smtp_host");
        expect(result.value).to.equal("db-smtp.example.com");
        expect(result.source).to.equal("database");
        expect(result.locked).to.equal(false);
      } finally {
        restore();
      }
    });

    it("returns null when neither env nor DB is set", async () => {
      const restore = setEnv({ SMTP_HOST: undefined });
      try {
        systemSettings.invalidateCache();
        const fakePool = {
          query: async () => ({ rows: [{ smtp_host: null }] }),
        };

        const result = await systemSettings.getSetting(fakePool, "smtp_host");
        expect(result.value).to.equal(null);
        expect(result.source).to.equal(null);
      } finally {
        restore();
      }
    });

    it("returns null for unknown keys", async () => {
      const fakePool = { query: async () => ({ rows: [] }) };
      const result = await systemSettings.getSetting(
        fakePool,
        "unknown_key_xyz",
      );
      expect(result.value).to.equal(null);
      expect(result.source).to.equal(null);
    });
  });

  describe("getSettingValue convenience", () => {
    it("returns just the value string", async () => {
      const restore = setEnv({ SMTP_PORT: "2525" });
      try {
        const fakePool = { query: async () => ({ rows: [] }) };
        const value = await systemSettings.getSettingValue(
          fakePool,
          "smtp_port",
        );
        expect(value).to.equal("2525");
      } finally {
        restore();
      }
    });
  });

  describe("saveSettings skips env-locked fields", () => {
    it("does not write env-locked fields to DB", async () => {
      // Lock smtp_host via env, but ensure smtp_port is NOT locked
      const restore = setEnv({
        SMTP_HOST: "locked-host.example.com",
        SMTP_PORT: undefined,
      });
      try {
        systemSettings.invalidateCache();
        let capturedSql = null;
        const fakePool = {
          query: async (sql, params) => {
            capturedSql = { sql, params };
            return { rowCount: 1 };
          },
        };

        await systemSettings.saveSettings(
          fakePool,
          { smtp_host: "should-be-skipped", smtp_port: "2525" },
          42,
        );

        // smtp_host should be skipped (env-locked), only smtp_port should be in the query
        expect(capturedSql).to.not.equal(null);
        expect(capturedSql.sql).to.not.include("smtp_host");
        expect(capturedSql.sql).to.include("smtp_port");
        expect(capturedSql.params).to.include("2525");
      } finally {
        restore();
      }
    });
  });

  describe("getAllSettings returns metadata", () => {
    it("includes source and locked status for each setting", async () => {
      const restore = setEnv({
        SMTP_HOST: "env-host.example.com",
        SMTP_PORT: undefined,
      });
      try {
        systemSettings.invalidateCache();
        const fakePool = {
          query: async () => ({
            rows: [
              {
                smtp_host: "db-host.example.com",
                smtp_port: "9999",
                smtp_user: null,
                smtp_pass_encrypted: null,
                smtp_from_email: null,
                smtp_from_name: null,
                smtp_secure: null,
                smtp_require_tls: null,
                twilio_account_sid: null,
                twilio_auth_token_encrypted: null,
                twilio_whatsapp_from: null,
                twilio_whatsapp_test_content_sid: null,
                twilio_whatsapp_alert_content_sid_expires: null,
                twilio_whatsapp_alert_content_sid_expired: null,
                twilio_whatsapp_alert_content_sid_endpoint_down: null,
                twilio_whatsapp_alert_content_sid_endpoint_recovered: null,
                twilio_whatsapp_weekly_digest_content_sid: null,
              },
            ],
          }),
        };

        const all = await systemSettings.getAllSettings(fakePool);

        // smtp_host: env takes precedence
        expect(all.smtp_host.value).to.equal("env-host.example.com");
        expect(all.smtp_host.source).to.equal("env");
        expect(all.smtp_host.locked).to.equal(true);

        // smtp_port: not in env, falls back to DB
        expect(all.smtp_port.value).to.equal("9999");
        expect(all.smtp_port.source).to.equal("database");
        expect(all.smtp_port.locked).to.equal(false);
      } finally {
        restore();
      }
    });
  });

  describe("isSmtpConfigured", () => {
    it("returns true when host, user, and pass are all available", async () => {
      const restore = setEnv({
        SMTP_HOST: "smtp.test.com",
        SMTP_USER: "user",
        SMTP_PASS: "pass",
      });
      try {
        systemSettings.invalidateCache();
        const fakePool = { query: async () => ({ rows: [] }) };
        const result = await systemSettings.isSmtpConfigured(fakePool);
        expect(result).to.equal(true);
      } finally {
        restore();
      }
    });

    it("returns false when host is missing", async () => {
      const restore = setEnv({
        SMTP_HOST: undefined,
        SMTP_USER: "user",
        SMTP_PASS: "pass",
      });
      try {
        systemSettings.invalidateCache();
        const fakePool = {
          query: async () => ({
            rows: [
              {
                smtp_host: null,
                smtp_user: null,
                smtp_pass_encrypted: null,
              },
            ],
          }),
        };
        const result = await systemSettings.isSmtpConfigured(fakePool);
        expect(result).to.equal(false);
      } finally {
        restore();
      }
    });
  });

  describe("isWhatsAppAvailable", () => {
    it("returns true when sid, token, and from are all set", async () => {
      const restore = setEnv({
        TWILIO_ACCOUNT_SID: "AC_test",
        TWILIO_AUTH_TOKEN: "token",
        TWILIO_WHATSAPP_FROM: "+14155238886",
      });
      try {
        systemSettings.invalidateCache();
        const fakePool = { query: async () => ({ rows: [] }) };
        const result = await systemSettings.isWhatsAppAvailable(fakePool);
        expect(result).to.equal(true);
      } finally {
        restore();
      }
    });

    it("returns false when any Twilio field is missing", async () => {
      const restore = setEnv({
        TWILIO_ACCOUNT_SID: "AC_test",
        TWILIO_AUTH_TOKEN: undefined,
        TWILIO_WHATSAPP_FROM: "+14155238886",
      });
      try {
        systemSettings.invalidateCache();
        const fakePool = {
          query: async () => ({
            rows: [
              {
                twilio_account_sid: null,
                twilio_auth_token_encrypted: null,
                twilio_whatsapp_from: null,
              },
            ],
          }),
        };
        const result = await systemSettings.isWhatsAppAvailable(fakePool);
        expect(result).to.equal(false);
      } finally {
        restore();
      }
    });
  });

  describe("Encryption round-trip", () => {
    it("encrypts and decrypts a value correctly", () => {
      const original = "my-secret-password-123";
      const encrypted = systemSettings.encrypt(original);
      expect(encrypted).to.be.a("string");
      expect(encrypted).to.not.equal(original);
      expect(encrypted).to.include(":"); // iv:tag:ciphertext format

      const decrypted = systemSettings.decrypt(encrypted);
      expect(decrypted).to.equal(original);
    });

    it("returns null for null input", () => {
      expect(systemSettings.encrypt(null)).to.equal(null);
      expect(systemSettings.decrypt(null)).to.equal(null);
    });

    it("masks secrets correctly", () => {
      expect(systemSettings.maskSecret("mysecretvalue")).to.equal("****alue");
      expect(systemSettings.maskSecret("ab")).to.equal("****");
      expect(systemSettings.maskSecret(null)).to.equal(null);
    });
  });
});
