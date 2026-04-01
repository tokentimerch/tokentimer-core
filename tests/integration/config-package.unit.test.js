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

describe("Config package unit coverage", () => {
  describe("network config", () => {
    it("parses offline mode and allowlist", async () => {
      const restore = setEnv({
        OFFLINE_MODE: "true",
        OUTBOUND_ALLOWLIST: "10.0.0.0/8, *.corp.local, smtp.internal",
      });
      try {
        const network = await importFresh("packages/config/src/network.js");
        const cfg = network.getNetworkConfig();
        expect(cfg.offlineMode).to.equal(true);
        expect(cfg.allowlist).to.deep.equal([
          "10.0.0.0/8",
          "*.corp.local",
          "smtp.internal",
        ]);
      } finally {
        restore();
      }
    });

    it("enforces allowlist only in offline mode", async () => {
      const network = await importFresh("packages/config/src/network.js");

      const restoreOnline = setEnv({
        OFFLINE_MODE: "false",
        OUTBOUND_ALLOWLIST: "",
      });
      try {
        expect(network.isAllowedHost("anything.example")).to.equal(true);
      } finally {
        restoreOnline();
      }

      const restoreOfflineNoList = setEnv({
        OFFLINE_MODE: "true",
        OUTBOUND_ALLOWLIST: "",
      });
      try {
        expect(network.isAllowedHost("anything.example")).to.equal(false);
      } finally {
        restoreOfflineNoList();
      }
    });

    it("matches wildcard, cidr, and exact host patterns", async () => {
      const restore = setEnv({
        OFFLINE_MODE: "true",
        OUTBOUND_ALLOWLIST: "*.corp.local,10.0.0.0/8,smtp.internal",
      });
      try {
        const network = await importFresh("packages/config/src/network.js");
        expect(network.isAllowedHost("api.corp.local")).to.equal(true);
        expect(network.isAllowedHost("corp.local")).to.equal(true);
        expect(network.isAllowedHost("10.10.1.2")).to.equal(true);
        expect(network.isAllowedHost("smtp.internal")).to.equal(true);
        expect(network.isAllowedHost("example.com")).to.equal(false);
      } finally {
        restore();
      }
    });

    it("supports webhook allow-all and extra hosts", async () => {
      const restore = setEnv({
        WEBHOOK_ALLOW_ALL_HOSTS: "false",
        WEBHOOK_PROVIDER_HOSTS: "hooks.custom.local",
        WEBHOOK_EXTRA_PROVIDER_HOSTS: "*.alerts.local",
      });
      try {
        const network = await importFresh("packages/config/src/network.js");
        expect(
          network.isWebhookAllowed("https://hooks.custom.local/path"),
        ).to.equal(true);
        expect(
          network.isWebhookAllowed("https://x.alerts.local/path"),
        ).to.equal(true);
        expect(
          network.isWebhookAllowed("https://not-allowed.local/path"),
        ).to.equal(false);
      } finally {
        restore();
      }
    });
  });

  describe("database config", () => {
    it("uses expected defaults", async () => {
      const restore = setEnv({
        DB_HOST: undefined,
        DB_PORT: undefined,
        DB_NAME: undefined,
        DB_USER: undefined,
        DB_PASSWORD: undefined,
        DB_SSL: undefined,
      });
      try {
        const db = await importFresh("packages/config/src/database.js");
        const cfg = db.getDatabaseConfig();
        expect(cfg.host).to.equal("localhost");
        expect(cfg.port).to.equal(5432);
        expect(cfg.database).to.equal("tokentimer");
        expect(cfg.user).to.equal("tokentimer");
        expect(cfg.password).to.equal(undefined);
        expect(cfg.ssl).to.equal(false);
      } finally {
        restore();
      }
    });

    it("builds ssl config for require mode and connection string", async () => {
      const restore = setEnv({
        DB_HOST: "postgres.internal",
        DB_PORT: "5544",
        DB_NAME: "tt",
        DB_USER: "alice",
        DB_PASSWORD: "secret",
        DB_SSL: "require",
      });
      try {
        const db = await importFresh("packages/config/src/database.js");
        const cfg = db.getDatabaseConfig();
        expect(cfg.ssl).to.deep.equal({ rejectUnauthorized: false, minVersion: "TLSv1.3" });
        expect(db.getConnectionString()).to.equal(
          "postgresql://alice:secret@postgres.internal:5544/tt?sslmode=require",
        );
      } finally {
        restore();
      }
    });
  });

  describe("index exports", () => {
    it("builds app and email config from environment", async () => {
      const restore = setEnv({
        TT_MODE: "oss",
        NODE_ENV: "test",
        APP_URL: "https://app.local",
        API_URL: "https://api.local",
        SMTP_HOST: "smtp1.local,smtp2.local",
        SMTP_PORT: "2525,2526",
        SMTP_USER: "u1,u2",
        SMTP_PASS: "p1,p2",
      });
      try {
        const config = await importFresh("packages/config/src/index.js");
        const app = config.getConfig();
        const email = config.getEmailConfig();
        expect(app.baseUrl).to.equal("https://app.local");
        expect(app.apiUrl).to.equal("https://api.local");
        expect(app.brandName).to.equal("TokenTimer");
        expect(email.accounts).to.have.length(2);
        expect(email.accounts[1].host).to.equal("smtp2.local");
        expect(email.accounts[1].port).to.equal(2526);
      } finally {
        restore();
      }
    });

    it("validates required production vars", async () => {
      const config = await importFresh("packages/config/src/index.js");
      const restoreBad = setEnv({
        NODE_ENV: "production",
        SESSION_SECRET: undefined,
        DB_PASSWORD: undefined,
      });
      try {
        expect(() => config.validateConfig()).to.throw(
          /SESSION_SECRET is required in production/,
        );
      } finally {
        restoreBad();
      }

      const restoreGood = setEnv({
        NODE_ENV: "production",
        SESSION_SECRET: "ok",
        DB_PASSWORD: "ok",
      });
      try {
        expect(() => config.validateConfig()).to.not.throw();
      } finally {
        restoreGood();
      }
    });
  });
});
