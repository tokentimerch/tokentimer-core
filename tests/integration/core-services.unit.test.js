const { expect } = require("chai");
const Module = require("module");

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

function requireFreshFromCandidates(candidates, stubs = {}) {
  let lastErr = null;
  for (const candidate of candidates) {
    try {
      return withPatchedLoad(stubs, () => {
        const resolved = require.resolve(candidate);
        delete require.cache[resolved];
        return require(candidate);
      });
    } catch (err) {
      lastErr = err;
      const isCandidateMissing =
        err &&
        err.code === "MODULE_NOT_FOUND" &&
        String(err.message || "").includes(candidate);
      if (isCandidateMissing) continue;
      throw err;
    }
  }
  throw (
    lastErr ||
    new Error(
      `Unable to resolve any candidate module: ${candidates.join(", ")}`,
    )
  );
}

function loadConstantsWith(parseLimitsImpl, loggerImpl = { debug() {} }) {
  return requireFreshFromCandidates(
    ["../../apps/api/config/constants", "../../apps/saas/config/constants"],
    {
      "../services/planLimits": { parseLimits: parseLimitsImpl },
      "../utils/logger": { logger: loggerImpl },
    },
  );
}

function loadAlertQueueWith(poolImpl) {
  return requireFreshFromCandidates(
    [
      "../../apps/api/services/alertQueue",
      "../../apps/saas/services/alertQueue",
    ],
    {
      "../db/database": { pool: poolImpl },
    },
  );
}

function loadWorkspaceWith(
  poolImpl,
  writeAuditImpl,
  loggerImpl = { warn() {}, error() {} },
) {
  return requireFreshFromCandidates(
    ["../../apps/api/services/workspace", "../../apps/saas/services/workspace"],
    {
      "../db/database": { pool: poolImpl },
      "./audit": { writeAudit: writeAuditImpl },
      "../utils/logger": { logger: loggerImpl },
    },
  );
}

describe("Core services unit coverage", () => {
  describe("config/constants", () => {
    const originalFetch = global.fetch;
    const originalPlanTokenLimits = process.env.PLAN_TOKEN_LIMITS;
    const originalPlanAlertLimits = process.env.PLAN_ALERT_LIMITS;

    beforeEach(() => {
      global.fetch = originalFetch;
      process.env.PLAN_TOKEN_LIMITS = originalPlanTokenLimits;
      process.env.PLAN_ALERT_LIMITS = originalPlanAlertLimits;
    });

    after(() => {
      global.fetch = originalFetch;
      process.env.PLAN_TOKEN_LIMITS = originalPlanTokenLimits;
      process.env.PLAN_ALERT_LIMITS = originalPlanAlertLimits;
    });

    it("initializes TOKEN_LIMITS and ALERT_LIMITS via parseLimits", () => {
      process.env.PLAN_TOKEN_LIMITS = "oss:111";
      process.env.PLAN_ALERT_LIMITS = "oss:222";
      const parseCalls = [];
      const constants = loadConstantsWith((raw, defaults) => {
        parseCalls.push({ raw, defaults });
        return { raw, defaults };
      });

      expect(parseCalls).to.have.length(2);
      expect(constants.TOKEN_LIMITS.raw).to.equal("oss:111");
      expect(constants.ALERT_LIMITS.raw).to.equal("oss:222");
    });

    it("rejects non-http webhook URLs", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);
      const result = await constants.testWebhookUrl(
        "ftp://example.com/hook",
        "generic",
      );
      expect(result.success).to.equal(false);
      expect(result.error).to.match(/http\(s\)/i);
    });

    it("enforces provider host allowlist for non-generic providers", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);
      const result = await constants.testWebhookUrl(
        "https://example.com/hook",
        "slack",
      );
      expect(result.success).to.equal(false);
      expect(result.error).to.match(/not allowed/i);
    });

    it("validates pagerduty routing key before request", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);
      const result = await constants.testWebhookUrl(
        "https://events.pagerduty.com/v2/enqueue",
        "pagerduty",
        "short",
      );
      expect(result.success).to.equal(false);
      expect(result.error).to.match(/routing key/i);
    });

    it("handles successful Slack and Discord responses", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);

      global.fetch = async (url, options) => {
        const parsed = JSON.parse(options.body);
        if (String(url).includes("slack")) {
          expect(parsed).to.have.property("text");
          return {
            status: 200,
            text: async () => "ok",
          };
        }
        expect(parsed).to.have.property("content");
        return {
          status: 204,
          text: async () => "",
        };
      };

      const slackRes = await constants.testWebhookUrl(
        "https://hooks.slack.com/services/test",
        "slack",
      );
      const discordRes = await constants.testWebhookUrl(
        "https://discord.com/api/webhooks/test",
        "discord",
      );

      expect(slackRes.success).to.equal(true);
      expect(discordRes.success).to.equal(true);
    });

    it("handles Teams and PagerDuty failure/success payload mapping", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);
      const validKey = "A".repeat(32);
      const calls = [];

      global.fetch = async (url, options) => {
        calls.push({ url, options });
        if (String(url).includes("office.com")) {
          return {
            status: 500,
            text: async () => "boom",
          };
        }
        return {
          status: 202,
          text: async () => JSON.stringify({ status: "success" }),
        };
      };

      const teamsRes = await constants.testWebhookUrl(
        "https://outlook.office.com/webhook/test",
        "teams",
      );
      const pdRes = await constants.testWebhookUrl(
        "https://events.pagerduty.com/v2/enqueue",
        "pagerduty",
        validKey,
      );

      expect(teamsRes.success).to.equal(false);
      expect(teamsRes.error).to.match(/Teams responded 500/i);
      expect(pdRes.success).to.equal(true);
      expect(calls).to.have.length(2);
    });

    it("returns timeout message on AbortError", async () => {
      const constants = loadConstantsWith((raw, defaults) => defaults);
      global.fetch = async () => {
        const err = new Error("aborted");
        err.name = "AbortError";
        throw err;
      };
      const res = await constants.testWebhookUrl(
        "https://any.local/hook",
        "generic",
      );
      expect(res.success).to.equal(false);
      expect(res.error).to.match(/Timed out/i);
    });
  });

  describe("services/alertQueue", () => {
    it("returns 0 without userId", async () => {
      const pool = {
        query: async () => {
          throw new Error("should not query");
        },
      };
      const { requeueAlertsCore } = loadAlertQueueWith(pool);
      const count = await requeueAlertsCore({});
      expect(count).to.equal(0);
    });

    it("builds workspace-scoped query excluding PLAN_LIMIT by default", async () => {
      let capturedSql = "";
      let capturedParams = [];
      const pool = {
        query: async (sql, params) => {
          capturedSql = String(sql);
          capturedParams = params;
          return { rowCount: 4 };
        },
      };
      const { requeueAlertsCore } = loadAlertQueueWith(pool);
      const count = await requeueAlertsCore({
        userId: "u1",
        workspaceId: "ws1",
      });

      expect(count).to.equal(4);
      expect(capturedParams).to.deep.equal(["ws1", "u1"]);
      expect(capturedSql).to.include(
        "aq.status = 'blocked' AND aq.error_message IS NOT NULL",
      );
      expect(capturedSql).to.include(
        "aq.error_message NOT ILIKE '%PLAN_LIMIT%'",
      );
    });

    it("builds global query and can include PLAN_LIMIT blocked alerts", async () => {
      let capturedSql = "";
      let capturedParams = [];
      const pool = {
        query: async (sql, params) => {
          capturedSql = String(sql);
          capturedParams = params;
          return { rowCount: 9 };
        },
      };
      const { requeueAlertsCore } = loadAlertQueueWith(pool);
      const count = await requeueAlertsCore({
        userId: "u2",
        includePlanLimitBlocked: true,
      });

      expect(count).to.equal(9);
      expect(capturedParams).to.deep.equal(["u2"]);
      expect(capturedSql).to.include("status = 'blocked'");
      expect(capturedSql).to.include("status IN ('failed','limit_exceeded')");
    });
  });

  describe("services/workspace", () => {
    it("returns early when user already has personal workspace", async () => {
      const queryLog = [];
      const pool = {
        query: async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params });
          if (text.includes("FROM workspace_invitations")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("SELECT DISTINCT role FROM workspace_memberships")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("SELECT 1 FROM workspaces WHERE created_by")) {
            return { rowCount: 1, rows: [{}] };
          }
          return { rowCount: 0, rows: [] };
        },
      };
      let auditCalls = 0;
      const writeAudit = async () => {
        auditCalls += 1;
      };
      const { ensureInitialWorkspaceForUser } = loadWorkspaceWith(
        pool,
        writeAudit,
      );

      await ensureInitialWorkspaceForUser(
        "user-1",
        "User.Name+tag@gmail.com",
        "Test User",
      );

      const createdWorkspace = queryLog.some((q) =>
        q.text.includes("INSERT INTO workspaces"),
      );
      expect(createdWorkspace).to.equal(false);
      expect(auditCalls).to.equal(0);
    });

    it("accepts invitations and bootstraps personal workspace when missing", async () => {
      const queryLog = [];
      const pool = {
        query: async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params });

          if (text.includes("FROM workspace_invitations")) {
            return {
              rowCount: 1,
              rows: [
                { id: "inv-1", workspace_id: "ws-invite", role: "member" },
              ],
            };
          }
          if (text.includes("SELECT DISTINCT role FROM workspace_memberships")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("SELECT 1 FROM workspaces WHERE created_by")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("SELECT id FROM workspace_contacts")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("INSERT INTO workspace_contacts")) {
            return { rowCount: 1, rows: [{ id: "contact-1" }] };
          }
          return { rowCount: 1, rows: [] };
        },
      };

      let auditCalls = 0;
      const writeAudit = async () => {
        auditCalls += 1;
      };

      const { ensureInitialWorkspaceForUser } = loadWorkspaceWith(
        pool,
        writeAudit,
      );
      await ensureInitialWorkspaceForUser(
        "user-2",
        "owner@example.com",
        "Owner Person",
      );

      expect(
        queryLog.some((q) =>
          q.text.includes(
            "UPDATE workspace_invitations SET accepted_at = NOW()",
          ),
        ),
      ).to.equal(true);
      expect(
        queryLog.some((q) =>
          q.text.includes(
            "INSERT INTO workspaces (id, name, plan, created_by)",
          ),
        ),
      ).to.equal(true);
      expect(
        queryLog.some((q) =>
          q.text.includes(
            "INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)",
          ),
        ),
      ).to.equal(true);
      expect(
        queryLog.some((q) =>
          q.text.includes("UPDATE workspace_settings SET contact_groups"),
        ),
      ).to.equal(true);
      expect(auditCalls).to.be.greaterThan(0);
    });
  });
});
