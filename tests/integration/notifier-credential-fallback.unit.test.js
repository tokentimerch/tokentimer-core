const { expect } = require("chai");
const path = require("node:path");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");

const workerSrc = path.join(__dirname, "..", "..", "apps", "worker", "src");
const whatsappModulePath = path.join(workerSrc, "notify", "whatsapp.js");
const emailModulePath = path.join(workerSrc, "notify", "email.js");
const dbModulePath = path.join(workerSrc, "db.js");

const workerRequire = createRequire(whatsappModulePath);

function encryptForSystemSettings(plaintext, sessionSecret) {
  const key = crypto.scryptSync(
    String(sessionSecret || ""),
    "tokentimer-settings-encryption",
    32,
  );
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(String(plaintext), "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${tag}:${encrypted}`;
}

async function importFresh(absPath) {
  const url =
    pathToFileURL(absPath).href +
    `?t=${Date.now()}_${Math.random().toString(36).slice(2)}`;
  return import(url);
}

describe("Worker notifier credential fallback", () => {
  let originalEnv;
  let axios;
  let axiosDefault;
  let nodemailer;
  let originalAxiosPost;
  let originalAxiosDefaultPost;
  let originalCreateTransport;
  let dbPool;
  let originalPoolQuery;

  before(async () => {
    axios = workerRequire("axios");
    const axiosModule = await import(pathToFileURL(workerRequire.resolve("axios")).href);
    axiosDefault = axiosModule.default || axios;
    nodemailer = workerRequire("nodemailer");
    const dbModule = await import(pathToFileURL(dbModulePath).href);
    dbPool = dbModule.pool;
  });

  beforeEach(() => {
    originalEnv = { ...process.env };
    originalAxiosPost = axios.post;
    originalAxiosDefaultPost = axiosDefault.post;
    originalCreateTransport = nodemailer.createTransport;
    originalPoolQuery = dbPool.query;

    process.env = { ...originalEnv };
    process.env.NODE_ENV = "production";
    process.env.SESSION_SECRET = "fallback-test-secret";
  });

  afterEach(() => {
    process.env = originalEnv;
    axios.post = originalAxiosPost;
    axiosDefault.post = originalAxiosDefaultPost;
    nodemailer.createTransport = originalCreateTransport;
    dbPool.query = originalPoolQuery;
  });

  it("uses env WhatsApp credentials when env is valid", async () => {
    process.env.TWILIO_ACCOUNT_SID = "env-sid";
    process.env.TWILIO_AUTH_TOKEN = "env-token";
    process.env.TWILIO_WHATSAPP_FROM = "+11111111111";

    const dbToken = encryptForSystemSettings(
      "db-token",
      process.env.SESSION_SECRET,
    );
    dbPool.query = async () => ({
      rows: [
        {
          twilio_account_sid: "db-sid",
          twilio_auth_token_encrypted: dbToken,
          twilio_whatsapp_from: "+22222222222",
        },
      ],
    });

    const authCalls = [];
    const { sendWhatsApp, setWhatsAppHttpPostOverride } = await importFresh(
      whatsappModulePath,
    );
    setWhatsAppHttpPostOverride(async (_url, _params, opts) => {
      authCalls.push(String(opts?.auth?.username || ""));
      return { status: 201, data: { sid: "SM_ENV_OK" } };
    });
    const result = await sendWhatsApp({
      to: "+41791234567",
      body: "hello",
    });

    expect(result.success, JSON.stringify(result)).to.equal(true);
    expect(authCalls[0]).to.equal("env-sid");
  });

  it("falls back to DB WhatsApp credentials on env auth failure", async () => {
    process.env.TWILIO_ACCOUNT_SID = "env-sid";
    process.env.TWILIO_AUTH_TOKEN = "env-token";
    process.env.TWILIO_WHATSAPP_FROM = "+11111111111";

    const dbToken = encryptForSystemSettings(
      "db-token",
      process.env.SESSION_SECRET,
    );
    dbPool.query = async () => ({
      rows: [
        {
          twilio_account_sid: "db-sid",
          twilio_auth_token_encrypted: dbToken,
          twilio_whatsapp_from: "+22222222222",
        },
      ],
    });

    const authCalls = [];
    const { sendWhatsApp, setWhatsAppHttpPostOverride } = await importFresh(
      whatsappModulePath,
    );
    setWhatsAppHttpPostOverride(async (_url, _params, opts) => {
      const sid = String(opts?.auth?.username || "");
      authCalls.push(sid);
      if (sid === "env-sid") {
        return {
          status: 401,
          data: { code: 20003, message: "Authenticate" },
        };
      }
      return { status: 201, data: { sid: "SM_DB_OK" } };
    });
    const result = await sendWhatsApp({
      to: "+41791234567",
      body: "hello",
    });

    expect(result.success, JSON.stringify(result)).to.equal(true);
    expect(authCalls).to.deep.equal(["env-sid", "db-sid"]);
  });

  it("uses DB WhatsApp credentials when env credentials are missing", async () => {
    delete process.env.TWILIO_ACCOUNT_SID;
    delete process.env.TWILIO_AUTH_TOKEN;
    delete process.env.TWILIO_WHATSAPP_FROM;

    const dbToken = encryptForSystemSettings(
      "db-token",
      process.env.SESSION_SECRET,
    );
    dbPool.query = async () => ({
      rows: [
        {
          twilio_account_sid: "db-sid",
          twilio_auth_token_encrypted: dbToken,
          twilio_whatsapp_from: "+22222222222",
        },
      ],
    });

    const authCalls = [];
    const { sendWhatsApp, setWhatsAppHttpPostOverride } = await importFresh(
      whatsappModulePath,
    );
    setWhatsAppHttpPostOverride(async (_url, _params, opts) => {
      authCalls.push(String(opts?.auth?.username || ""));
      return { status: 201, data: { sid: "SM_DB_ONLY_OK" } };
    });
    const result = await sendWhatsApp({
      to: "+41791234567",
      body: "hello",
    });

    expect(result.success, JSON.stringify(result)).to.equal(true);
    expect(authCalls[0]).to.equal("db-sid");
  });

  it("falls back to DB SMTP when env SMTP transport fails", async () => {
    process.env.SMTP_HOST = "env.smtp.local";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_USER = "env-user@example.com";
    process.env.SMTP_PASS = "env-pass";
    process.env.FROM_EMAIL = "env-from@example.com";

    const dbSmtpPass = encryptForSystemSettings(
      "db-smtp-pass",
      process.env.SESSION_SECRET,
    );

    let dbQueryCount = 0;
    dbPool.query = async () => {
      dbQueryCount += 1;
      return {
        rows: [
          {
            smtp_host: "db.smtp.local",
            smtp_port: "465",
            smtp_user: "db-user@example.com",
            smtp_pass_encrypted: dbSmtpPass,
            smtp_from_email: "db-from@example.com",
            smtp_from_name: "TokenTimer DB",
            smtp_secure: "true",
            smtp_require_tls: "true",
          },
        ],
      };
    };

    const createdHosts = [];
    nodemailer.createTransport = (options = {}) => {
      createdHosts.push(String(options.host || ""));
      const host = String(options.host || "");
      return {
        async verify() {
          return true;
        },
        async sendMail() {
          if (host === "env.smtp.local") {
            throw new Error("ECONNECTION env smtp unavailable");
          }
          return { accepted: ["ok@example.com"], response: "250 OK" };
        },
      };
    };

    const email = await importFresh(emailModulePath);
    const result = await email.sendEmailNotification({
      to: "recipient@example.com",
      subject: "Fallback test",
      text: "Hello",
      html: "<p>Hello</p>",
    });

    expect(result.success).to.equal(true);
    expect(createdHosts).to.include("env.smtp.local");
    expect(createdHosts).to.include("db.smtp.local");
    expect(dbQueryCount).to.be.greaterThan(0);
  });

  it("uses DB SMTP when env SMTP is not configured", async () => {
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_PORT;
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;

    const dbSmtpPass = encryptForSystemSettings(
      "db-smtp-pass",
      process.env.SESSION_SECRET,
    );

    dbPool.query = async () => ({
      rows: [
        {
          smtp_host: "db.smtp.local",
          smtp_port: "465",
          smtp_user: "db-user@example.com",
          smtp_pass_encrypted: dbSmtpPass,
          smtp_from_email: "db-from@example.com",
          smtp_from_name: "TokenTimer DB",
          smtp_secure: "true",
          smtp_require_tls: "true",
        },
      ],
    });

    const createdHosts = [];
    nodemailer.createTransport = (options = {}) => {
      createdHosts.push(String(options.host || ""));
      return {
        async verify() {
          return true;
        },
        async sendMail() {
          return { accepted: ["ok@example.com"], response: "250 OK" };
        },
      };
    };

    const email = await importFresh(emailModulePath);
    const result = await email.sendEmailNotification({
      to: "recipient@example.com",
      subject: "DB only test",
      text: "Hello",
      html: "<p>Hello</p>",
    });

    expect(result.success).to.equal(true);
    expect(createdHosts).to.include("db.smtp.local");
  });
});
