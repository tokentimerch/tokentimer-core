const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

function mockClient(handler) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params });
      return handler(String(sql), params);
    },
  };
}

describe("opNotifications helpers (worker, ESM)", () => {
  before(() => {
    process.env.NODE_ENV = "test";
  });

  describe("raiseOperationalNotification", () => {
    it("returns null without querying when required fields are missing", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      const id = await mod.raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "delivery",
      });
      expect(id).to.equal(null);
      expect(client.calls).to.have.length(0);
    });

    it("rejects invalid category/severity before querying", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      const id = await mod.raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "delivery",
        type: "delivery_blocked",
        severity: "urgent",
        dedupeKey: "k",
        title: "t",
      });
      expect(id).to.equal(null);
      expect(client.calls).to.have.length(0);
    });

    it("upserts on the open-incident dedupe key and returns the row id", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient((sql) => {
        expect(sql).to.match(
          /ON CONFLICT \(workspace_id, dedupe_key\) WHERE resolved_at IS NULL/,
        );
        return { rows: [{ id: "notif-1" }] };
      });
      const id = await mod.raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        tokenId: 7,
        category: "delivery",
        type: "delivery_blocked",
        severity: "critical",
        dedupeKey: "delivery_blocked:42",
        title: "Delivery blocked",
      });
      expect(id).to.equal("notif-1");
    });

    it("swallows DB errors and returns null", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient(() => {
        throw new Error("connection reset");
      });
      const id = await mod.raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "auto_sync",
        type: "auto_sync_failed",
        severity: "warning",
        dedupeKey: "auto_sync_failed:9",
        title: "Auto-sync failed",
      });
      expect(id).to.equal(null);
    });
  });

  describe("resolveOperationalNotification", () => {
    it("is a no-op without workspaceId or dedupeKey", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      await mod.resolveOperationalNotification(client, null, "k");
      await mod.resolveOperationalNotification(client, "ws-1", null);
      expect(client.calls).to.have.length(0);
    });

    it("resolves the open notification for the dedupe key", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const client = mockClient((sql, params) => {
        expect(sql).to.match(/resolved_at = NOW\(\)/);
        expect(params).to.deep.equal(["ws-1", "delivery_blocked:42"]);
        return { rowCount: 1 };
      });
      await mod.resolveOperationalNotification(
        client,
        "ws-1",
        "delivery_blocked:42",
      );
      expect(client.calls).to.have.length(1);
    });
  });

  describe("sendOperationalIncidentEmail", () => {
    const params = {
      notificationId: "notif-1",
      workspaceId: "ws-1",
      category: "delivery",
      title: "Delivery blocked",
    };

    function emailClient({
      cap = 0,
      recipients = ["admin@example.com"],
      ownerEmail = null,
      ownerWorkspaceId = null,
    } = {}) {
      const state = { claim: null, sent: false, completed: [] };
      const client = mockClient((sql, values) => {
        if (sql.includes("SET email_claim_id = $2")) {
          if (state.claim || state.sent) return { rows: [] };
          state.claim = values[1];
          return { rows: [{ id: values[0] }] };
        }
        if (sql.includes("pg_advisory_lock(")) return { rows: [{}] };
        if (sql.includes("pg_advisory_unlock(")) return { rows: [{}] };
        if (sql.includes("COUNT(*)::int AS c")) return { rows: [{ c: cap }] };
        if (sql.includes("wm.role = 'admin'")) {
          return { rows: recipients.map((email) => ({ email })) };
        }
        if (sql.includes("JOIN users u ON u.id = t.user_id")) {
          expect(sql).to.include("t.workspace_id = $2");
          return {
            rows:
              ownerEmail && values[1] === ownerWorkspaceId
                ? [{ email: ownerEmail }]
                : [],
          };
        }
        if (sql.includes("SET email_sent_at = CASE")) {
          expect(values[1]).to.equal(state.claim);
          state.sent = state.sent || values[2];
          state.claim = null;
          state.completed.push(values[2]);
          return { rowCount: 1 };
        }
        throw new Error(`unexpected query: ${sql}`);
      });
      return { client, state };
    }

    it("does nothing when required fields are missing", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client } = emailClient();
      await mod.sendOperationalIncidentEmail(client, { workspaceId: "ws-1" });
      expect(client.calls).to.have.length(0);
    });

    it("suppresses recursion when email is one of multiple failed channels", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client } = emailClient();
      await mod.sendOperationalIncidentEmail(client, {
        ...params,
        metadata: { failed_channels: ["webhooks", "EMAIL"] },
      });
      await mod.sendOperationalIncidentEmail(client, {
        ...params,
        metadata: { channel: "email" },
      });
      expect(client.calls).to.have.length(0);
    });

    it("uses a separate claim and marks sent only after successful delivery", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client, state } = emailClient({
        recipients: ["a@example.com", "b@example.com"],
      });
      const sentTo = [];
      await mod.sendOperationalIncidentEmail(client, params, async ({ to }) => {
        sentTo.push(to);
        return { success: true };
      });
      expect(sentTo).to.deep.equal(["a@example.com", "b@example.com"]);
      expect(state.completed).to.deep.equal([true]);
      expect(state.sent).to.equal(true);
      expect(
        client.calls.some((call) => call.sql.includes("pg_advisory_lock(")),
      ).to.equal(true);
      expect(
        client.calls.find((call) => call.sql.includes("pg_advisory_lock("))
          .params,
      ).to.deep.equal(["ws-1"]);
      expect(
        client.calls.some((call) => call.sql.includes("pg_advisory_unlock(")),
      ).to.equal(true);
      const claim = client.calls.find((call) =>
        call.sql.includes("SET email_claim_id = $2"),
      );
      expect(claim.sql).to.include("email_sent_at IS NULL");
      expect(claim.sql).to.include(
        "email_claimed_at < NOW() - INTERVAL '10 minutes'",
      );
    });

    it("includes only an in-workspace token owner, keeps admins, and deduplicates recipients", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const matching = emailClient({
        ownerEmail: "OWNER@example.com",
        ownerWorkspaceId: "ws-1",
        recipients: ["admin@example.com", "owner@example.com"],
      });
      const matchingSentTo = [];
      await mod.sendOperationalIncidentEmail(
        matching.client,
        { ...params, tokenId: 7 },
        async ({ to }) => {
          matchingSentTo.push(to);
          return { success: true };
        },
      );
      expect(matchingSentTo).to.deep.equal([
        "owner@example.com",
        "admin@example.com",
      ]);
      expect(
        matching.client.calls.find((call) =>
          call.sql.includes("JOIN users u ON u.id = t.user_id"),
        ).params,
      ).to.deep.equal([7, "ws-1"]);

      const mismatched = emailClient({
        ownerEmail: "foreign@example.com",
        ownerWorkspaceId: "ws-2",
        recipients: ["admin@example.com"],
      });
      const mismatchedSentTo = [];
      await mod.sendOperationalIncidentEmail(
        mismatched.client,
        { ...params, tokenId: 8 },
        async ({ to }) => {
          mismatchedSentTo.push(to);
          return { success: true };
        },
      );
      expect(mismatchedSentTo).to.deep.equal(["admin@example.com"]);
    });

    it("releases the claim after SMTP failure so a later attempt can deliver", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client, state } = emailClient();
      await mod.sendOperationalIncidentEmail(client, params, async () => ({
        success: false,
        error: "SMTP down",
      }));
      expect(state.sent).to.equal(false);
      expect(state.claim).to.equal(null);
      await mod.sendOperationalIncidentEmail(client, params, async () => ({
        success: true,
      }));
      expect(state.completed).to.deep.equal([false, true]);
      expect(state.sent).to.equal(true);
    });

    it("keeps no-recipient incidents unsent and retryable", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client, state } = emailClient({ recipients: [] });
      await mod.sendOperationalIncidentEmail(client, params, async () => {
        throw new Error("must not send");
      });
      expect(state.completed).to.deep.equal([false]);
      expect(state.sent).to.equal(false);
      expect(state.claim).to.equal(null);
    });

    it("keeps daily-cap-suppressed incidents unsent and retryable", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client, state } = emailClient({ cap: 10 });
      await mod.sendOperationalIncidentEmail(client, params, async () => {
        throw new Error("must not send");
      });
      expect(state.completed).to.deep.equal([false]);
      expect(state.sent).to.equal(false);
      expect(state.claim).to.equal(null);
    });

    it("does not claim an incident already claimed by another worker", async () => {
      const mod = await importFresh(
        "apps/worker/src/shared/opNotifications.js",
      );
      const { client, state } = emailClient();
      state.claim = "other-worker";
      await mod.sendOperationalIncidentEmail(client, params, async () => {
        throw new Error("must not send");
      });
      expect(
        client.calls.filter((call) =>
          call.sql.includes("SET email_claim_id = $2"),
        ),
      ).to.have.length(1);
      expect(
        client.calls.some((call) => call.sql.includes("COUNT(*)::int AS c")),
      ).to.equal(false);
      expect(state.claim).to.equal("other-worker");
    });
  });
});

describe("delivery blocked incident metadata", () => {
  it("persists every failed channel and suppresses email when email itself failed", async () => {
    const { raiseDeliveryBlockedIncident } = await importFresh(
      "apps/worker/src/delivery-worker.js",
    );
    let metadata;
    const client = mockClient((sql, params) => {
      if (sql.includes("INSERT INTO operational_notifications")) {
        metadata = JSON.parse(params[8]);
        return { rows: [{ id: "notif-1" }] };
      }
      throw new Error(`incident email must be suppressed: ${sql}`);
    });
    await raiseDeliveryBlockedIncident(
      client,
      { id: 42, workspace_id: "ws-1", token_id: 7, name: "Token" },
      "email: SMTP down; webhooks: 500",
      ["email", "webhooks"],
      "max_attempts",
    );
    expect(metadata.failed_channels).to.deep.equal(["email", "webhooks"]);
    expect(client.calls).to.have.length(1);
  });
});

describe("buildOperationalIncidentEmail", () => {
  it("links delivery incidents to Control Center", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { subject, html, text } = email.buildOperationalIncidentEmail({
      category: "delivery",
      title: "Delivery blocked: Prod cert",
      message: "Maximum delivery attempts reached",
      metadata: { workspace_name: "Acme", token_name: "Prod cert" },
    });
    expect(subject).to.equal("Delivery blocked: Prod cert");
    expect(html).to.include("/control-center");
    expect(html).to.include("Maximum delivery attempts reached");
    expect(html).to.include("Acme");
    expect(html).to.include("Prod cert");
    expect(text).to.include("Delivery blocked: Prod cert");
  });

  it("links auto-sync incidents to the import panel with the provider preselected", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html, text } = email.buildOperationalIncidentEmail({
      category: "auto_sync",
      title: "Auto-sync failing repeatedly: github",
      message: "Auto-sync run failed",
      metadata: {
        provider: "github",
        config_id: "legacy-config",
        workspace_id: "legacy-workspace",
      },
    });
    expect(html).to.include("import=github");
    expect(html).to.include("autoSyncManage=1");
    expect(html).to.not.include("autoSyncConfigId=");
    expect(html).to.not.include("workspace=");
    expect(html).to.include("Provider: GitHub");
    expect(text).to.include("Provider: GitHub");
    expect(text).to.not.include("Connection:");
    expect(text).to.not.include("Location:");
    expect(text).to.not.include("Region:");
    expect(text).to.not.include("N/A");
    expect(html).to.not.include("/control-center");
  });

  it("targets the exact config and renders available auto-sync context in HTML and text", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html, text } = email.buildOperationalIncidentEmail({
      category: "auto_sync",
      title: "Auto-sync failing repeatedly: gitlab",
      message: "Bad credentials",
      metadata: {
        provider: "gitlab",
        auto_sync_config_id: "cfg/one two",
        workspace_id: "ws/one two",
        connection_key: "Production GitLab",
        location: "gitlab.company.com",
      },
    });
    expect(html).to.include(
      "?import=gitlab&amp;autoSyncManage=1&amp;autoSyncConfigId=cfg%2Fone%20two&amp;workspace=ws%2Fone%20two",
    );
    expect(text).to.include(
      "?import=gitlab&autoSyncManage=1&autoSyncConfigId=cfg%2Fone%20two&workspace=ws%2Fone%20two",
    );
    for (const line of [
      "Provider: GitLab",
      "Connection: Production GitLab",
      "Config ID: cfg/one two",
      "Location: gitlab.company.com",
    ]) {
      expect(html).to.include(line);
      expect(text).to.include(line);
    }
    expect(html).to.not.include("Region:");
    expect(html).to.not.include("Project:");
  });

  it("shows region or project only when that provider context exists", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const aws = email.buildOperationalIncidentEmail({
      category: "auto_sync",
      title: "AWS sync failed",
      metadata: { provider: "aws", region: "eu-central-1" },
    });
    expect(aws.html).to.include("Region: eu-central-1");
    expect(aws.text).to.include("Region: eu-central-1");
    expect(aws.html).to.not.include("Project:");
    const gcp = email.buildOperationalIncidentEmail({
      category: "auto_sync",
      title: "GCP sync failed",
      metadata: { provider: "gcp", project_id: "project-123" },
    });
    expect(gcp.html).to.include("Project: project-123");
    expect(gcp.text).to.include("Project: project-123");
    expect(gcp.html).to.not.include("Region:");
  });

  it("escapes every auto-sync context value and omits placeholder values", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html, text } = email.buildOperationalIncidentEmail({
      category: "auto_sync",
      title: "Auto-sync failed",
      message: "<error>",
      metadata: {
        provider: "<provider>",
        auto_sync_config_id: 'cfg"<id>',
        connection_key: "<connection>",
        location: "<location>",
        region: "N/A",
        project_id: "undefined",
      },
    });
    for (const raw of [
      "<error>",
      "<provider>",
      "<connection>",
      "<location>",
      "<id>",
    ]) {
      expect(html).to.not.include(raw);
      expect(html).to.include(raw.replace("<", "&lt;").replace(">", "&gt;"));
    }
    expect(html).to.include("autoSyncConfigId=cfg%22%3Cid%3E");
    expect(html).to.not.include("Region:");
    expect(html).to.not.include("Project:");
    expect(text).to.include("Connection: <connection>");
    expect(text).to.include("Location: <location>");
  });

  it("escapes HTML in the message and context lines", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html } = email.buildOperationalIncidentEmail({
      category: "delivery",
      title: "Delivery blocked",
      message: "<script>alert(1)</script>",
      metadata: { workspace_name: "<b>Acme</b>" },
    });
    expect(html).to.not.include("<script>");
    expect(html).to.include("&lt;script&gt;");
    expect(html).to.include("&lt;b&gt;Acme&lt;/b&gt;");
  });

  it("omits the context line block when no workspace/token name is provided", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html } = email.buildOperationalIncidentEmail({
      category: "delivery",
      title: "Delivery blocked",
      message: "Maximum delivery attempts reached",
      metadata: {},
    });
    expect(html).to.include("Maximum delivery attempts reached");
  });

  it("escapes HTML in the title itself, which producers derive from the alert/token name", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html } = email.buildOperationalIncidentEmail({
      category: "delivery",
      title: "Delivery blocked: <img src=x onerror=alert(1)>",
      message: "Maximum delivery attempts reached",
      metadata: {},
    });
    expect(html).to.not.include("<img src=x onerror=alert(1)>");
    expect(html).to.include("&lt;img src=x onerror=alert(1)&gt;");
  });
});

describe("generateEmailTemplate", () => {
  it("escapes HTML in the title used for <title> and <h1>", async () => {
    const email = await importFresh("apps/worker/src/notify/email.js");
    const { html } = email.generateEmailTemplate({
      title: '<script>alert("xss")</script>',
      content: "<p>body</p>",
    });
    expect(html).to.not.include('<script>alert("xss")</script>');
    expect(html).to.include("&lt;script&gt;");
  });
});
