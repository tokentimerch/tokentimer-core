const router = require("express").Router();
const { pool } = require("../db/database");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
  requireWorkspaceManager,
} = require("../services/rbac");
const { writeAudit } = require("../services/audit");

// Rename references under the same row lock as the destination itself. Never
// infer a rename from array position or from a possibly shared endpoint.
router.post(
  "/api/v1/workspaces/:id/webhooks/rename",
  requireAuth,
  getApiLimiter(),
  loadWorkspace,
  requireWorkspaceMembership,
  requireWorkspaceManager,
  async (req, res, next) => {
    const previousName = String(req.body?.previousName || "").trim();
    const name = String(req.body?.name || "").trim();
    if (!previousName || !name || name.length > 120)
      return res
        .status(400)
        .json({ error: "A webhook name of 1–120 characters is required" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        "SELECT webhook_urls, contact_groups FROM workspace_settings WHERE workspace_id=$1 FOR UPDATE",
        [req.workspace.id],
      );
      const webhooks = rows[0]?.webhook_urls || [];
      const matches = webhooks.filter((w) => w.name === previousName);
      if (
        matches.length !== 1 ||
        webhooks.some(
          (w) =>
            w.name !== previousName &&
            String(w.name).toLowerCase() === name.toLowerCase(),
        )
      ) {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({
            error:
              "The webhook changed or its new name is already used. Refresh and try again.",
          });
      }
      const replacement = req.body.webhook;
      if (
        replacement &&
        (typeof replacement !== "object" ||
          replacement.name !== name ||
          typeof replacement.url !== "string" ||
          !replacement.url.startsWith("https://"))
      ) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invalid webhook configuration" });
      }
      const allowed = [
        "kind",
        "url",
        "severity",
        "template",
        "routingKey",
        "verified",
        "verifiedUrl",
      ];
      const updated = { ...matches[0], name };
      if (replacement)
        for (const key of allowed)
          if (Object.hasOwn(replacement, key)) updated[key] = replacement[key];
      const groups = (rows[0].contact_groups || []).map((g) => ({
        ...g,
        ...(Array.isArray(g.webhook_names)
          ? {
              webhook_names: [
                ...new Set(
                  g.webhook_names.map((n) => (n === previousName ? name : n)),
                ),
              ],
            }
          : {}),
        ...(g.webhook_name === previousName ? { webhook_name: name } : {}),
      }));
      await client.query(
        "UPDATE workspace_settings SET webhook_urls=$2::jsonb,contact_groups=$3::jsonb WHERE workspace_id=$1",
        [
          req.workspace.id,
          JSON.stringify(webhooks.map((w) => (w === matches[0] ? updated : w))),
          JSON.stringify(groups),
        ],
      );
      await writeAudit({
        client,
        actorUserId: req.user.id,
        subjectUserId: req.user.id,
        action: "WEBHOOK_RENAMED",
        workspaceId: req.workspace.id,
        metadata: { previousName, name },
      });
      await client.query("COMMIT");
      return res.json({ success: true });
    } catch (error) {
      await client.query("ROLLBACK");
      return next(error);
    } finally {
      client.release();
    }
  },
);
const { resolvedTokenWorkspaceSql } = require("@tokentimer/alert-eligibility");
const readAccess = [
  requireAuth,
  getApiLimiter(),
  loadWorkspace,
  requireWorkspaceMembership,
];
const manageAccess = [...readAccess, requireWorkspaceManager];
const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function findIncident(db, req, lock = false) {
  if (!uuid.test(req.params.incidentId || "")) return null;
  const { rows } = await db.query(
    `SELECT p.* FROM pagerduty_incidents p JOIN tokens t ON t.id=p.token_id_snapshot
    WHERE p.id=$1 AND p.workspace_id=$2 AND ${resolvedTokenWorkspaceSql("t")}=p.workspace_id ${lock ? "FOR UPDATE OF p" : ""}`,
    [req.params.incidentId, req.workspace.id],
  );
  return rows[0];
}

router.get(
  "/api/v1/workspaces/:id/tokens/:tokenId/pagerduty-incidents",
  ...readAccess,
  async (req, res, next) => {
    if (!/^[1-9]\d*$/.test(req.params.tokenId))
      return res.status(400).json({ error: "Invalid token ID" });
    try {
      const { rows } = await pool.query(
        `SELECT p.id,p.state,p.original_expiration,p.resolution_reason,p.operator_reason,
      p.trigger_accepted_at,p.resolved_at,p.acknowledged_at,p.last_error,p.retry_exhausted,
      a.requested_at AS acknowledge_requested_at,a.accepted_at AS acknowledge_accepted_at,
      a.last_error AS acknowledge_error,a.exhausted AS acknowledge_exhausted
      FROM pagerduty_incidents p JOIN tokens t ON t.id=p.token_id_snapshot
      LEFT JOIN pagerduty_ack_requests a ON a.incident_id=p.id AND a.cancelled_at IS NULL
      WHERE p.workspace_id=$1 AND t.id=$2 AND ${resolvedTokenWorkspaceSql("t")}=p.workspace_id
      ORDER BY p.created_at DESC,p.id LIMIT 20`,
        [req.workspace.id, req.params.tokenId],
      );
      return res.json({
        incidents: rows,
        canManage: ["admin", "workspace_manager"].includes(
          req.authz?.workspaceRole,
        ),
      });
    } catch (error) {
      return next(error);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/pagerduty-incidents/:incidentId/actions",
  ...manageAccess,
  async (req, res, next) => {
    const action = req.body?.action;
    const reason =
      typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
    if (
      !["acknowledge", "resolve"].includes(action) ||
      (action === "resolve" &&
        (req.body.confirmed !== true ||
          reason.length < 5 ||
          reason.length > 1000))
    )
      return res
        .status(400)
        .json({
          error:
            "Resolve requires confirmation and a reason of 5–1000 characters",
        });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Share the worker's lock: an accepted manual intent cannot race a provider
      // dispatch or be overwritten by a stale reconciliation snapshot.
      if (!uuid.test(req.params.incidentId || "")) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Incident not found" });
      }
      const lock = await client.query(
        "SELECT pg_try_advisory_xact_lock(hashtextextended('pagerduty:' || $1::text,0)) AS owned",
        [req.params.incidentId],
      );
      if (!lock.rows[0].owned) {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({ error: "Incident is being processed. Try again shortly." });
      }
      const incident = await findIncident(client, req, true);
      if (!incident) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Incident not found" });
      }
      if (incident.state !== "open" || !incident.trigger_accepted_at) {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({ error: "Only an open, delivered incident can be acted on" });
      }
      let changed;
      if (action === "acknowledge") {
        changed = await client.query(
          `INSERT INTO pagerduty_ack_requests(incident_id,requested_by) VALUES($1,$2)
        ON CONFLICT(incident_id) DO UPDATE SET
          requested_by=EXCLUDED.requested_by,requested_at=NOW(),attempts=0,
          exhausted=FALSE,last_error=NULL,next_attempt_at=NOW()
        WHERE pagerduty_ack_requests.exhausted
          AND pagerduty_ack_requests.accepted_at IS NULL
          AND pagerduty_ack_requests.cancelled_at IS NULL
        RETURNING incident_id`,
          [incident.id, req.user.id],
        );
      } else {
        changed = await client.query(
          `UPDATE pagerduty_incidents SET state='resolve_pending',resolution_reason='manual_resolve',
        operator_reason=$2,requested_by=$3,manual_suppression_active=TRUE,recovery_expiration=original_expiration,resolve_requested_at=NOW(),
        action_attempts=0,retry_exhausted=FALSE,last_error=NULL,next_attempt_at=NOW(),updated_at=NOW() WHERE id=$1 RETURNING id`,
          [incident.id, reason, req.user.id],
        );
        await client.query(
          "UPDATE pagerduty_ack_requests SET cancelled_at=NOW() WHERE incident_id=$1 AND accepted_at IS NULL",
          [incident.id],
        );
      }
      if (changed.rowCount)
        await writeAudit({
          client,
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: `PAGERDUTY_${action.toUpperCase()}_REQUESTED`,
          targetType: "token",
          targetId: incident.token_id_snapshot,
          workspaceId: req.workspace.id,
          metadata: {
            incident_id: incident.id,
            ...(action === "resolve" ? { reason } : {}),
          },
        });
      await client.query("COMMIT");
      return res.status(202).json({ success: true, status: "queued" });
    } catch (error) {
      await client.query("ROLLBACK");
      return next(error);
    } finally {
      client.release();
    }
  },
);

module.exports = router;
