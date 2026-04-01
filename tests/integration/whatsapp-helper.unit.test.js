const { expect } = require("chai");
const path = require("node:path");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");

const workerModulePath = path.join(
  __dirname,
  "..",
  "..",
  "apps",
  "worker",
  "src",
  "notify",
  "whatsapp.js",
);
const workerRequire = createRequire(workerModulePath);

describe("WhatsApp helper unit coverage", () => {
  let axios;
  let loggerModule;
  let sendWhatsApp;
  let originalEnv;
  let originalPost;
  let originalInfo;
  let originalWarn;
  let originalError;

  before(async () => {
    axios = workerRequire("axios");
    loggerModule = await import(
      pathToFileURL(
        path.join(__dirname, "..", "..", "apps", "worker", "src", "logger.js"),
      ).href
    );
    ({ sendWhatsApp } = await import(pathToFileURL(workerModulePath).href));
  });

  beforeEach(() => {
    originalEnv = { ...process.env };
    originalPost = axios.post;
    originalInfo = loggerModule.logger.info;
    originalWarn = loggerModule.logger.warn;
    originalError = loggerModule.logger.error;
    loggerModule.logger.info = () => {};
    loggerModule.logger.warn = () => {};
    loggerModule.logger.error = () => {};
  });

  afterEach(() => {
    process.env = originalEnv;
    axios.post = originalPost;
    loggerModule.logger.info = originalInfo;
    loggerModule.logger.warn = originalWarn;
    loggerModule.logger.error = originalError;
  });

  it("returns dry-run success when WHATSAPP_DRY_RUN is enabled", async () => {
    process.env.NODE_ENV = "production";
    process.env.WHATSAPP_DRY_RUN = "true";
    const result = await sendWhatsApp({
      to: "+14155550100",
      body: "hello",
      idempotencyKey: "abc",
    });
    expect(result).to.deep.equal({ success: true, messageSid: "DRY_RUN_SID" });
  });

  it("returns not configured when credentials are missing", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.TWILIO_ACCOUNT_SID;
    delete process.env.TWILIO_AUTH_TOKEN;
    delete process.env.TWILIO_WHATSAPP_FROM;
    const result = await sendWhatsApp({ to: "+14155550100", body: "hello" });
    expect(result.success).to.equal(false);
    expect(result.code).to.equal("WHATSAPP_NOT_CONFIGURED");
  });

  it("rejects invalid recipients", async () => {
    process.env.NODE_ENV = "production";
    process.env.TWILIO_ACCOUNT_SID = "sid";
    process.env.TWILIO_AUTH_TOKEN = "token";
    process.env.TWILIO_WHATSAPP_FROM = "+14155559999";
    const result = await sendWhatsApp({ to: "", body: "hello" });
    expect(result).to.deep.include({
      success: false,
      code: "INVALID_RECIPIENT",
    });
  });

  it("requires a body when contentSid is not provided", async () => {
    process.env.NODE_ENV = "production";
    process.env.TWILIO_ACCOUNT_SID = "sid";
    process.env.TWILIO_AUTH_TOKEN = "token";
    process.env.TWILIO_WHATSAPP_FROM = "+14155559999";
    const result = await sendWhatsApp({ to: "+14155550100", body: "   " });
    expect(result).to.deep.include({
      success: false,
      code: "BODY_REQUIRED",
    });
  });
});
