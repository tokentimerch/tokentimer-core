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

describe("Multi-SMTP Configuration", () => {
  it("parses multiple comma-separated SMTP accounts", async () => {
    const restore = setEnv({
      SMTP_HOST: "smtp1.example.com,smtp2.example.com,smtp3.example.com",
      SMTP_PORT: "587,2525,465",
      SMTP_USER: "user1@ex.com,user2@ex.com,user3@ex.com",
      SMTP_PASS: "pass1,pass2,pass3",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const email = config.getEmailConfig();

      expect(email.accounts).to.have.length(3);

      expect(email.accounts[0].host).to.equal("smtp1.example.com");
      expect(email.accounts[0].port).to.equal(587);
      expect(email.accounts[0].user).to.equal("user1@ex.com");
      expect(email.accounts[0].pass).to.equal("pass1");

      expect(email.accounts[1].host).to.equal("smtp2.example.com");
      expect(email.accounts[1].port).to.equal(2525);
      expect(email.accounts[1].user).to.equal("user2@ex.com");
      expect(email.accounts[1].pass).to.equal("pass2");

      expect(email.accounts[2].host).to.equal("smtp3.example.com");
      expect(email.accounts[2].port).to.equal(465);
      expect(email.accounts[2].user).to.equal("user3@ex.com");
      expect(email.accounts[2].pass).to.equal("pass3");

      // Primary should be the first one
      expect(email.host).to.equal("smtp1.example.com");
      expect(email.port).to.equal(587);
    } finally {
      restore();
    }
  });

  it("falls back to first account values when fewer ports/users are specified", async () => {
    const restore = setEnv({
      SMTP_HOST: "smtp1.example.com,smtp2.example.com",
      SMTP_PORT: "587",
      SMTP_USER: "user1@ex.com",
      SMTP_PASS: "pass1",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const email = config.getEmailConfig();

      expect(email.accounts).to.have.length(2);
      expect(email.accounts[1].host).to.equal("smtp2.example.com");
      expect(email.accounts[1].port).to.equal(587); // fallback to first
      expect(email.accounts[1].user).to.equal("user1@ex.com"); // fallback to first
    } finally {
      restore();
    }
  });

  it("handles single SMTP account (no commas)", async () => {
    const restore = setEnv({
      SMTP_HOST: "smtp.single.com",
      SMTP_PORT: "465",
      SMTP_USER: "solo@ex.com",
      SMTP_PASS: "solopass",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const email = config.getEmailConfig();

      expect(email.accounts).to.have.length(1);
      expect(email.accounts[0].host).to.equal("smtp.single.com");
      expect(email.accounts[0].port).to.equal(465);
    } finally {
      restore();
    }
  });
});

describe("Alert Config from ENV", () => {
  it("parses ALERT_THRESHOLDS including negative values", async () => {
    const restore = setEnv({
      ALERT_THRESHOLDS: "90,30,14,7,1,0,-7,-30",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const alert = config.getAlertConfig();

      expect(alert.thresholds).to.deep.equal([90, 30, 14, 7, 1, 0, -7, -30]);
    } finally {
      restore();
    }
  });

  it("uses default thresholds when env is not set", async () => {
    const restore = setEnv({ ALERT_THRESHOLDS: undefined });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const alert = config.getAlertConfig();

      expect(alert.thresholds).to.deep.equal([30, 14, 7, 1, 0]);
    } finally {
      restore();
    }
  });

  it("reads delivery window defaults from env", async () => {
    const restore = setEnv({
      DELIVERY_WINDOW_DEFAULT_START: "08:00",
      DELIVERY_WINDOW_DEFAULT_END: "18:00",
      DELIVERY_WINDOW_DEFAULT_TZ: "Europe/Zurich",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const alert = config.getAlertConfig();

      expect(alert.deliveryWindowStart).to.equal("08:00");
      expect(alert.deliveryWindowEnd).to.equal("18:00");
      expect(alert.deliveryWindowTz).to.equal("Europe/Zurich");
    } finally {
      restore();
    }
  });

  it("reads max attempts and retry delay from env", async () => {
    const restore = setEnv({
      ALERT_MAX_ATTEMPTS: "10",
      ALERT_RETRY_DELAY_MS: "60000",
    });
    try {
      const config = await importFresh("packages/config/src/index.js");
      const alert = config.getAlertConfig();

      expect(alert.maxAttempts).to.equal(10);
      expect(alert.retryDelayMs).to.equal(60000);
    } finally {
      restore();
    }
  });
});
