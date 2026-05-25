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
} = require("../../apps/api/middleware/csrf-exempt");
const { requireAuth } = require("../../apps/api/middleware/auth");

function buildProductionCsrfApp() {
  const app = express();
  const {
    doubleCsrfProtection,
  } = doubleCsrf({
    getSecret: () => process.env.SESSION_SECRET,
    cookieName: "csrf-token",
    cookieOptions: {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      secure: true,
    },
    getTokenFromRequest: (req) => req.headers["x-csrf-token"],
  });

  app.use(cookieParser());
  app.use(express.json());
  app.use("/api", createCsrfExemptMiddleware(doubleCsrfProtection));
  app.post("/api/v1/integrations/azure-ad/scan", requireAuth, (req, res) => {
    const { token } = req.body || {};

    if (!token) {
      return res.status(400).json({ error: "token is required" });
    }

    return res.status(200).json({ ok: true });
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

  return app;
}

describe("Production CSRF worker exemption", () => {
  const originalWorkerApiKey = process.env.WORKER_API_KEY;
  const originalSessionSecret = process.env.SESSION_SECRET;

  afterEach(() => {
    if (originalWorkerApiKey === undefined) {
      delete process.env.WORKER_API_KEY;
    } else {
      process.env.WORKER_API_KEY = originalWorkerApiKey;
    }

    if (originalSessionSecret === undefined) {
      delete process.env.SESSION_SECRET;
    } else {
      process.env.SESSION_SECRET = originalSessionSecret;
    }
  });

  it("allows worker-authenticated Azure AD scan POSTs past CSRF", async () => {
    process.env.WORKER_API_KEY = "worker-key";
    process.env.SESSION_SECRET = "session-secret";

    const res = await supertest(buildProductionCsrfApp())
      .post("/api/v1/integrations/azure-ad/scan")
      .set("Authorization", "Bearer worker-key")
      .send({});

    expect(res.status).to.equal(400);
    expect(res.body.error).to.equal("token is required");
  });

  it("still rejects browser-style POSTs without CSRF in production mode", async () => {
    process.env.WORKER_API_KEY = "worker-key";
    process.env.SESSION_SECRET = "session-secret";

    const res = await supertest(buildProductionCsrfApp())
      .post("/api/v1/integrations/azure-ad/scan")
      .send({});

    expect(res.status).to.equal(403);
    expect(res.body.code).to.equal("EBADCSRFTOKEN");
  });

  it("does not exempt mismatched bearer tokens from CSRF", async () => {
    process.env.WORKER_API_KEY = "worker-key";
    process.env.SESSION_SECRET = "session-secret";

    const res = await supertest(buildProductionCsrfApp())
      .post("/api/v1/integrations/azure-ad/scan")
      .set("Authorization", "Bearer wrong-key")
      .send({});

    expect(res.status).to.equal(403);
    expect(res.body.code).to.equal("EBADCSRFTOKEN");
  });
});
