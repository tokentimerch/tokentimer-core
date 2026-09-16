const { createRequire } = require("module");
const supertest = require("supertest");
const { expect } = require("chai");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");
const cookieParser = apiRequire("cookie-parser");
const { doubleCsrf } = apiRequire("csrf-csrf");
const {
  createCsrfExemptMiddleware,
  isCertOpsMachineTokenCsrfExemptPath,
} = require("../../apps/api/middleware/csrf-exempt");
const {
  resolveSessionCookieOptions,
  resolveCsrfCookieName,
} = require("../../apps/api/session-cookie-options.js");

function cookieHeaderValue(res, cookieName) {
  const headers = [].concat(res.headers["set-cookie"] || []);
  const prefix = `${cookieName}=`;
  for (const header of headers) {
    if (header.startsWith(prefix)) {
      return decodeURIComponent(header.slice(prefix.length).split(";")[0]);
    }
  }
  return undefined;
}

function buildEnforcedCsrfApp() {
  const app = express();
  const sessionCookieOptions = resolveSessionCookieOptions(process.env);
  const csrfCookieName = resolveCsrfCookieName(
    process.env,
    sessionCookieOptions,
  );
  const expressSessionCookie = sessionCookieOptions.secure
    ? { ...sessionCookieOptions, httpOnly: true, secure: true }
    : { ...sessionCookieOptions, httpOnly: true, secure: false };

  const { generateToken: generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
    getSecret: () => {
      if (!process.env.SESSION_SECRET) {
        throw new Error("SESSION_SECRET environment variable is required");
      }
      return process.env.SESSION_SECRET;
    },
    cookieName: csrfCookieName,
    cookieOptions: sessionCookieOptions.secure
      ? { ...expressSessionCookie, httpOnly: true, path: "/", secure: true }
      : { ...expressSessionCookie, httpOnly: true, path: "/", secure: false },
    getTokenFromRequest: (req) => req.headers["x-csrf-token"],
  });

  const csrfExempt = createCsrfExemptMiddleware(doubleCsrfProtection, {
    allowPath: isCertOpsMachineTokenCsrfExemptPath,
    skip: false,
  });

  app.use(cookieParser());
  app.use(express.json());
  app.use("/api", csrfExempt);
  app.use("/auth", csrfExempt);

  app.get("/api/csrf-token", (req, res) => {
    const csrfToken = generateCsrfToken(req, res, true, false);
    res.json({ csrfToken });
  });

  app.post("/auth/login", (_req, res) => {
    res.status(401).json({ error: "Invalid credentials" });
  });

  app.post("/auth/logout", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.use((err, req, res, next) => {
    if (err?.code === "EBADCSRFTOKEN") {
      return res.status(403).json({
        error: "Invalid CSRF token",
        code: err.code,
      });
    }

    return next(err);
  });

  return { app, csrfCookieName };
}

describe("CSRF login enforcement (skip:false)", () => {
  const originalSessionSecret = process.env.SESSION_SECRET;
  const originalNodeEnv = process.env.NODE_ENV;

  beforeEach(() => {
    process.env.SESSION_SECRET = "session-secret";
    process.env.NODE_ENV = "test";
  });

  afterEach(() => {
    if (originalSessionSecret === undefined) {
      delete process.env.SESSION_SECRET;
    } else {
      process.env.SESSION_SECRET = originalSessionSecret;
    }
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it("sets the real x-csrf-token cookie, not csrf-token", async () => {
    const { app, csrfCookieName } = buildEnforcedCsrfApp();
    expect(csrfCookieName).to.equal("x-csrf-token");

    const res = await supertest(app).get("/api/csrf-token").expect(200);
    const headers = [].concat(res.headers["set-cookie"] || []);
    expect(headers.some((header) => header.startsWith("x-csrf-token="))).to.equal(
      true,
    );
    expect(headers.some((header) => header.startsWith("csrf-token="))).to.equal(
      false,
    );
  });

  it("rejects POST /auth/login without X-CSRF-Token", async () => {
    const { app } = buildEnforcedCsrfApp();
    const res = await supertest(app)
      .post("/auth/login")
      .send({ email: "user@example.com", password: "wrong" });

    expect(res.status).to.equal(403);
    expect(res.body.code).to.equal("EBADCSRFTOKEN");
  });

  it("accepts POST /auth/login with the JSON csrf token (401 for bad creds is fine)", async () => {
    const { app } = buildEnforcedCsrfApp();
    const agent = supertest.agent(app);

    const tokenRes = await agent.get("/api/csrf-token").expect(200);
    expect(tokenRes.body.csrfToken).to.be.a("string").that.is.not.empty;

    const res = await agent
      .post("/auth/login")
      .set("X-CSRF-Token", tokenRes.body.csrfToken)
      .send({ email: "user@example.com", password: "wrong" });

    expect(res.status).to.not.equal(403);
    expect(res.status).to.equal(401);
  });

  it("rejects copying the CSRF cookie value into X-CSRF-Token", async () => {
    const { app, csrfCookieName } = buildEnforcedCsrfApp();
    const agent = supertest.agent(app);

    const tokenRes = await agent.get("/api/csrf-token").expect(200);
    const cookieValue = cookieHeaderValue(tokenRes, csrfCookieName);
    expect(cookieValue).to.be.a("string").that.is.not.empty;
    expect(cookieValue).to.not.equal(tokenRes.body.csrfToken);

    const res = await agent
      .post("/auth/login")
      .set("X-CSRF-Token", cookieValue)
      .send({ email: "user@example.com", password: "wrong" });

    expect(res.status).to.equal(403);
    expect(res.body.code).to.equal("EBADCSRFTOKEN");
  });

  it("allows POST /auth/logout without a CSRF header", async () => {
    const { app } = buildEnforcedCsrfApp();
    const res = await supertest(app).post("/auth/logout");

    expect(res.status).to.equal(200);
    expect(res.body.ok).to.equal(true);
  });
});
