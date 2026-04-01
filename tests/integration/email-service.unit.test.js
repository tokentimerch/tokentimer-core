const { expect } = require("chai");
const Module = require("module");
const path = require("path");

function resolveEmailServiceModule() {
  const candidates = [
    path.join(__dirname, "..", "..", "apps", "api", "services", "emailService"),
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "saas",
      "services",
      "emailService",
    ),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error("Unable to resolve emailService module");
}

function withPatchedLoad(stubs, fn) {
  const originalLoad = Module._load;
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(stubs, request)) {
      return stubs[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return fn();
  } finally {
    Module._load = originalLoad;
  }
}

function makePromClientStub() {
  class Counter {
    labels() {
      return { inc() {} };
    }
  }
  class Histogram {
    labels() {
      return {
        observe() {},
        startTimer() {
          return () => {};
        },
      };
    }
  }
  class Gauge {
    labels() {
      return { set() {} };
    }
    set() {}
  }
  return { Counter, Histogram, Gauge };
}

function makeNodemailerStub({
  verifyOk = true,
  sendAccepted = ["ok@example.com"],
} = {}) {
  const calls = [];
  return {
    createTransport(options = {}) {
      calls.push(options);
      return {
        async verify() {
          if (!verifyOk) throw new Error("verify failed");
          return true;
        },
        async sendMail() {
          return { accepted: sendAccepted, response: "250 OK" };
        },
      };
    },
    __getCalls() {
      return calls;
    },
  };
}

function requireEmailServiceWithStubs(stubs = {}) {
  const resolved = resolveEmailServiceModule();
  delete require.cache[resolved];
  return withPatchedLoad(
    {
      nodemailer: makeNodemailerStub(),
      "prom-client": makePromClientStub(),
      "./systemSettings": {
        async isSmtpConfigured() {
          return false;
        },
        async getSettingValue() {
          return null;
        },
      },
      "../utils/logger.js": {
        logger: { info() {}, warn() {}, error() {}, debug() {} },
      },
      ...stubs,
    },
    () => require(resolved),
  );
}

describe("Email service unit coverage", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;
    delete process.env.SMTP_PORT;
    delete process.env.SMTP_SECURE;
    delete process.env.SMTP_REQUIRE_TLS;
    delete process.env.FROM_EMAIL;
  });

  after(() => {
    process.env = originalEnv;
  });

  it("reports SMTP not configured when env vars are missing", () => {
    const email = requireEmailServiceWithStubs();
    expect(Boolean(email.isSMTPConfigured())).to.equal(false);
  });

  it("reports SMTP configured when required env vars exist", () => {
    process.env.SMTP_HOST = "smtp.local";
    process.env.SMTP_USER = "user@smtp.local";
    process.env.SMTP_PASS = "secret";
    process.env.SMTP_PORT = "2525";
    const email = requireEmailServiceWithStubs();
    expect(Boolean(email.isSMTPConfigured())).to.equal(true);
  });

  it("resolves transporter from DB settings when pool is provided", async () => {
    const email = requireEmailServiceWithStubs({
      "./systemSettings": {
        async isSmtpConfigured() {
          return true;
        },
        async getSettingValue(_pool, key) {
          const map = {
            smtp_host: "smtp.db.local",
            smtp_port: "465",
            smtp_user: "db-user",
            smtp_pass: "db-pass",
          };
          return map[key] || null;
        },
      },
    });
    email.setPool({ fake: true });
    const transporter = await email.getResolvedTransporter();
    expect(transporter).to.be.an("object");
    expect(transporter.verify).to.be.a("function");
  });

  it("falls back to env transporter when DB settings are incomplete", async () => {
    process.env.SMTP_HOST = "smtp.env.local";
    process.env.SMTP_USER = "env-user";
    process.env.SMTP_PASS = "env-pass";
    process.env.SMTP_PORT = "2525";
    const email = requireEmailServiceWithStubs({
      "./systemSettings": {
        async isSmtpConfigured() {
          return false;
        },
        async getSettingValue() {
          return null;
        },
      },
    });
    email.setPool({ fake: true });
    const transporter = await email.getResolvedTransporter();
    expect(transporter).to.be.an("object");
    expect(transporter.sendMail).to.be.a("function");
  });

  it("applies SMTP_SECURE and SMTP_REQUIRE_TLS from env when creating transporter", () => {
    process.env.SMTP_HOST = "smtp.env.local";
    process.env.SMTP_USER = "env-user";
    process.env.SMTP_PASS = "env-pass";
    process.env.SMTP_PORT = "465";
    process.env.SMTP_SECURE = "true";
    process.env.SMTP_REQUIRE_TLS = "false";

    const nodemailerStub = makeNodemailerStub();
    requireEmailServiceWithStubs({ nodemailer: nodemailerStub });
    const calls = nodemailerStub.__getCalls();
    expect(calls.length).to.be.greaterThan(0);
    expect(calls[0].secure).to.equal(true);
    expect(calls[0].requireTLS).to.equal(false);
  });

  it("applies DB smtp_secure/smtp_require_tls overrides in resolved transporter", async () => {
    const nodemailerStub = makeNodemailerStub();
    const email = requireEmailServiceWithStubs({
      nodemailer: nodemailerStub,
      "./systemSettings": {
        async isSmtpConfigured() {
          return true;
        },
        async getSettingValue(_pool, key) {
          const map = {
            smtp_host: "smtp.db.local",
            smtp_port: "465",
            smtp_user: "db-user",
            smtp_pass: "db-pass",
            smtp_secure: "false",
            smtp_require_tls: "false",
          };
          return map[key] || null;
        },
      },
    });
    email.setPool({ fake: true });
    await email.getResolvedTransporter();
    const calls = nodemailerStub.__getCalls();
    expect(calls.length).to.be.greaterThan(0);
    const last = calls[calls.length - 1];
    expect(last.secure).to.equal(false);
    expect(last.requireTLS).to.equal(false);
  });

  it("generates template text/html and supports custom never-reply footer content", () => {
    process.env.FROM_EMAIL = "support@example.com";
    const email = requireEmailServiceWithStubs();
    const out = email.generateEmailTemplate({
      title: "Verify email",
      greeting: "Hi",
      content: "<p>Welcome</p>",
      buttonText: "Open",
      buttonUrl: "https://example.com/open",
      footerNote: "Custom note",
      plainTextContent: "Welcome text",
    });
    expect(out).to.be.an("object");
    expect(String(out.html)).to.include("Verify email");
    expect(String(out.text)).to.include("Welcome text");
    expect(String(out.html)).to.include("support@example.com");
  });

  it("returns SMTP not configured response for generic sendEmail when no account works", async () => {
    process.env.SMTP_HOST = "smtp.local";
    process.env.SMTP_USER = "u1,u2";
    process.env.SMTP_PASS = "p1,p2";
    process.env.SMTP_PORT = "2525";
    process.env.FROM_EMAIL = "support@example.com";
    const email = requireEmailServiceWithStubs({
      nodemailer: makeNodemailerStub({ verifyOk: false }),
    });
    const result = await email.sendEmail({
      to: "x@example.com",
      subject: "Test",
      text: "Body",
      html: "<p>Body</p>",
      type: "generic",
    });
    expect(result.success).to.equal(false);
    expect(String(result.error || result.providerError || "")).to.match(
      /(Failed to send email|SMTP|support@example.com|contact)/i,
    );
  });
});
